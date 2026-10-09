import sys

if sys.version_info < (3, 11):
    sys.exit("Python 3.11 or newer is required to run this analyzer.")

import argparse
import base64
import binascii
import json
import io
from functools import lru_cache
import logging
import re
import subprocess
import signal
import threading
import time
import xml.etree.ElementTree as ET
from collections import defaultdict
from datetime import datetime, timezone

VERSION = "2.1.0"
DEFAULT_KEY_WIDTH = 45
DEFAULT_COUNT_WIDTH = 7
DEFAULT_PROGRESS_WIDTH = 80
DEFAULT_DEBUG_VALUE_WIDTH = 160
logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Dependencies
# ---------------------------------------------------------------------------
def ensure_package(package_name, import_name=None):
    if import_name is None:
        import_name = package_name
    try:
        __import__(import_name)
        return
    except ImportError as e:
        print(
            f"Import failed for '{import_name}': {e}",
            file=sys.stderr,
        )
    print(f"Installing missing package: {package_name}")
    subprocess.check_call([
        sys.executable,
        "-m",
        "pip",
        "install",
        package_name,
    ])

def ensure_dependencies():
    ensure_package("azure-servicebus", "azure.servicebus")
    ensure_package("azure-identity", "azure.identity")
    ensure_package("wcf", "wcf")
    try:
        get_wcf_decoder()  # Import and register WCF records once.
    except ImportError:
        logger.exception("Unable to initialize the WCF binary parser")
        raise

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def utc_now():
    return datetime.now(timezone.utc)

def format_timestamp(value):
    if value is None:
        return ""
    if isinstance(value, datetime):
        if value.tzinfo is None:
            value = value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc).strftime(
            "%Y-%m-%d %H:%M:%S"
        )
    return str(value)

def normalize_namespace(namespace):
    namespace = namespace.strip()
    suffix = ".servicebus.windows.net"
    if not namespace.endswith(suffix):
        namespace += suffix
    return namespace

def print_overwrite(text, width=DEFAULT_PROGRESS_WIDTH):
    print(f"\r{text:<{width}}", end="", flush=True)
# ---------------------------------------------------------------------------
# Message body
# ---------------------------------------------------------------------------
def get_message_body_bytes(message):
    try:
        body = message.body
        if body is None:
            return b""
        if isinstance(body, str):
            return body.encode("utf-8")
        if isinstance(body, (bytes, bytearray, memoryview)):
            return bytes(body)
        return b"".join(
            part.encode("utf-8") if isinstance(part, str) else bytes(part)
            for part in body
        )
    except Exception:
        logger.exception("Unable to extract message body")
        return b""
# ---------------------------------------------------------------------------
# JSON handling
# ---------------------------------------------------------------------------
def find_cache_key_in_json(value):
    if isinstance(value, dict):
        preferred_names = (
            "cacheKey",
            "cache_key",
            "CacheKey",
            "key",
            "Key",
            "cachekey",
        )
        for name in preferred_names:
            if name in value and isinstance(
                value[name],
                str,
            ):
                return value[name]
        for child in value.values():
            result = find_cache_key_in_json(child)
            if result:
                return result
    elif isinstance(value, list):
        for child in value:
            result = find_cache_key_in_json(child)
            if result:
                return result
    return None

def handle_json_message(body_bytes):
    try:
        text = body_bytes.decode(
            "utf-8",
            errors="strict",
        )
        data = json.loads(text)
        value = find_cache_key_in_json(data)
        if value:
            return {
                "format": "JSON",
                "extracted_value": value,
            }
        return {
            "format": "JSON",
            "extracted_value": "[No cache key in JSON]",
        }
    except Exception:
        return {
            "format": "JSON",
            "extracted_value": "[Invalid JSON]",
        }
# ---------------------------------------------------------------------------
# XML handling
# ---------------------------------------------------------------------------
def find_cache_key_in_xml(element):
    preferred_names = {
        "cachekey",
        "cache_key",
        "key",
        "cache",
        "cacheid",
        "cacheidentifier",
    }
    tag_name = element.tag
    if isinstance(tag_name, str):
        if "}" in tag_name:
            tag_name = tag_name.rsplit("}", 1)[1]
        if tag_name.lower() in preferred_names:
            if element.text and element.text.strip():
                return element.text.strip()
    for name, value in element.attrib.items():
        attribute_name = name
        if "}" in attribute_name:
            attribute_name = attribute_name.rsplit(
                "}",
                1,
            )[1]
        if attribute_name.lower() in preferred_names:
            if value:
                return value
    for child in element:
        result = find_cache_key_in_xml(child)
        if result:
            return result
    return None

def handle_xml_message(body_bytes):
    try:
        root = ET.fromstring(body_bytes)
        value = find_cache_key_in_xml(root)
        if value:
            return {
                "format": "XML",
                "extracted_value": value,
            }
        return {
            "format": "XML",
            "extracted_value": "[No cache key in XML]",
        }
    except Exception:
        return {
            "format": "XML",
            "extracted_value": "[Invalid XML]",
        }
# ---------------------------------------------------------------------------
# WCF Binary XML handling
# ---------------------------------------------------------------------------
WCF_FORMAT = "WCF Binary XML"

def wcf_result(value):
    return {"format": WCF_FORMAT, "extracted_value": value}

def local_xml_name(name):
    name = str(name)
    return name.rsplit("}", 1)[-1] if "}" in name else name
@lru_cache(maxsize=1)
def get_wcf_decoder():
    """Resolve WCF parser once, not once for every message."""
    from wcf.records.base import Record
    from wcf.records import print_records
    import wcf.records.text  # noqa: F401 - registers record types
    import wcf.records.attributes  # noqa: F401
    import wcf.records.elements  # noqa: F401
    return Record.parse, print_records

def decode_wcf_xml(body_bytes):
    parse_records, print_records = get_wcf_decoder()
    records = parse_records(io.BytesIO(body_bytes))
    output = io.StringIO()
    print_records(records, fp=output)
    return output.getvalue()

def parse_wcf_xml(xml_text):
    if logger.isEnabledFor(logging.DEBUG):
        logger.debug("=== Decoded WCF XML Output ===")
        logger.debug(xml_text)
        logger.debug("===============================")
    try:
        return ET.fromstring(xml_text)
    except ET.ParseError as e:
        logger.debug("WCF decoded but XML parsing failed: %s", e)
        return None

def find_wcf_parameter(root):
    for element in root.iter():
        if local_xml_name(element.tag) == "Parameter":
            return element
    return None

def get_parameter_type(element):
    for name, value in element.attrib.items():
        if local_xml_name(name).lower() == "type":
            return (value or "").strip()
    return ""

def get_parameter_type_name(parameter_type):
    return parameter_type.split(":", 1)[-1].lower()

def read_7bit_encoded_int(data, offset):
    value = 0
    shift = 0
    for index in range(5):
        if offset + index >= len(data):
            return None, None
        byte = data[offset + index]
        value |= (byte & 0x7F) << shift
        if not byte & 0x80:
            return value, offset + index + 1
        shift += 7
    return None, None

def is_serialization_metadata(value):
    return any(marker in value for marker in ("Version=", "Culture=", "PublicKeyToken="))

def is_useful_binary_string(value):
    if not value or len(value) < 4 or is_serialization_metadata(value):
        return False
    return sum(ch.isprintable() for ch in value) / len(value) >= 0.95

def extract_nrbf_strings(data):
    values = []
    seen = set()
    offset = 0
    while offset < len(data):
        length, start = read_7bit_encoded_int(data, offset)
        if length is None or start is None or length < 4 or length > 4096:
            offset += 1
            continue
        end = start + length
        if end > len(data):
            offset += 1
            continue
        try:
            value = data[start:end].decode("utf-8").strip()
        except UnicodeDecodeError:
            offset += 1
            continue
        if not is_useful_binary_string(value):
            offset += 1
            continue
        if value not in seen:
            seen.add(value)
            values.append(value)
        # This candidate had a valid .NET length-prefixed string boundary.
        # Continue after the string so bytes inside it cannot become false
        # nested strings such as "diachase..." from "Mediachase...".
        offset = end
    return values

def extract_printable_binary_strings(data):
    values = []
    seen = set()
    for match in re.findall(rb"[\x20-\x7e]{4,}", data):
        value = match.decode("ascii", errors="ignore").strip()
        if not is_useful_binary_string(value) or value in seen:
            continue
        seen.add(value)
        values.append(value)
    return values

def looks_like_dotnet_type(value):
    if not value or " " in value or "," in value or "|" in value:
        return False
    parts = value.split(".")
    if len(parts) < 2:
        return False
    identifier = re.compile(r"^[A-Za-z_][A-Za-z0-9_`+]*$")
    return all(identifier.fullmatch(part) for part in parts)

def dotnet_type_score(value):
    score = value.count(".") * 10
    leaf = value.rsplit(".", 1)[-1]
    if leaf.endswith("EventArgs"):
        score += 100
    elif leaf.endswith(("Event", "Args", "Message")):
        score += 50
    if leaf and leaf[0].isupper():
        score += 10
    return score

def select_dotnet_type(values):
    candidates = [value for value in values if looks_like_dotnet_type(value)]
    if not candidates:
        return None
    return max(candidates, key=lambda value: (dotnet_type_score(value), -values.index(value)))

def decode_base64_parameter(value):
    if not value:
        return None
    try:
        raw = base64.b64decode(re.sub(r"\s+", "", value), validate=True)
    except (ValueError, binascii.Error):
        return None
    values = extract_nrbf_strings(raw)
    if not values:
        values = extract_printable_binary_strings(raw)
    return select_dotnet_type(values) or (values[0] if values else None)

# Extraction rules are data, not a growing chain of parameter-type checks.
# Keys are normalized WCF i:type local names (case-insensitive).
MESSAGE_EXTRACTORS = {
    "string": {"strategy": "text", "label": "String", "fallback": "[Empty string]", "wildcards": True},
    "base64binary": {"strategy": "base64", "label": "Base64Binary", "fallback": "[No extracted binary value]", "wildcards": False},
    "remotepushmessage": {
        "strategy": "embedded_json", "label": "RemotePushMessage",
        "field": "Data.$type", "fallback_field": "Topic",
        "strip_assembly": True, "fallback": "[Value not extracted]", "wildcards": False,
    },
    "statemessage": {
        "strategy": "xml_child", "label": "StateMessage", "field": "Type",
        "prefix": "StateMessage_", "fallback": "StateMessage_[unknown state]", "wildcards": False,
    },
}

def nested_json_value(payload, path):
    for part in path.split("."):
        if not isinstance(payload, dict):
            return None
        payload = payload.get(part)
    return payload if isinstance(payload, str) and payload.strip() else None

def extract_embedded_json(parameter, rule):
    for child in parameter.iter():
        if "BackingField" not in local_xml_name(child.tag):
            continue
        try:
            payload = json.loads((child.text or "").strip())
        except (ValueError, TypeError):
            continue
        value = nested_json_value(payload, rule["field"])
        if value:
            return value.split(",", 1)[0].strip() if rule.get("strip_assembly") else value
        value = nested_json_value(payload, rule["fallback_field"])
        if value:
            return value
    return None

def extract_xml_child(parameter, field):
    for child in parameter.iter():
        if child is not parameter and local_xml_name(child.tag) == field:
            return (child.text or "").strip() or None
    return None

def extract_wcf_parameter(parameter):
    """Return (source label, extracted value) using the configured rule."""
    parameter_type = get_parameter_type(parameter)
    rule = MESSAGE_EXTRACTORS.get(get_parameter_type_name(parameter_type))
    if rule is None:
        return "OtherParameter", parameter_type or "[Parameter has no type]"
    strategy = rule["strategy"]
    if strategy == "text":
        value = (parameter.text or "").strip()
    elif strategy == "base64":
        value = decode_base64_parameter((parameter.text or "").strip())
    elif strategy == "embedded_json":
        value = extract_embedded_json(parameter, rule)
    elif strategy == "xml_child":
        child_value = extract_xml_child(parameter, rule["field"])
        value = rule.get("prefix", "") + child_value if child_value else None
    else:
        raise ValueError(f"Unsupported extraction strategy: {strategy}")
    return rule["label"], value or rule["fallback"]

def handle_wcf_binary_message(body_bytes):
    """Validate WCF by parsing records once; never label arbitrary bytes WCF."""
    try:
        xml_text = decode_wcf_xml(body_bytes)
        root = parse_wcf_xml(xml_text)
    except Exception:
        logger.debug("WCF Binary XML parsing failed", exc_info=True)
        return {"format": "Unknown Binary", "extracted_value": "[Unrecognized binary format]"}
    if root is None:
        return {"format": "Unknown Binary", "extracted_value": "[Invalid decoded XML]"}
    # A successful record parse is not sufficient by itself to prove the
    # payload is an application event. Require a Parameter element.
    parameter = find_wcf_parameter(root)
    if parameter is None:
        return {"format": WCF_FORMAT, "extracted_value": "Unknown WCF Event"}
    try:
        kind, value = extract_wcf_parameter(parameter)
        return {"format": WCF_FORMAT, "extracted_value": value, "value_kind": kind}
    except Exception:
        logger.debug("WCF parameter extraction failed", exc_info=True)
        return {"format": WCF_FORMAT, "extracted_value": "[Extraction error]", "value_kind": "OtherParameter"}
# ---------------------------------------------------------------------------
# Format detection and dispatch
# ---------------------------------------------------------------------------
def detect_format(body_bytes):
    """Recognize textual candidates; binary content requires actual parsing."""
    if not body_bytes:
        return "empty"
    # UTF-8 BOM is permitted for textual messages.
    stripped = body_bytes.lstrip(b" \t\r\n")
    if stripped.startswith(b"\xef\xbb\xbf"):
        stripped = stripped[3:].lstrip(b" \t\r\n")
    if stripped.startswith((b"{", b"[")):
        return "json"
    if stripped.startswith(b"<"):
        return "xml"
    return "binary_candidate"

def handle_message_body(body_bytes):
    message_format = detect_format(body_bytes)
    if message_format == "empty":
        return {"format": "Empty", "extracted_value": "[Empty message body]"}
    if message_format == "json":
        # Invalid JSON remains classified as JSON, not WCF.
        return handle_json_message(body_bytes)
    if message_format == "xml":
        # Invalid XML remains classified as XML, not WCF.
        return handle_xml_message(body_bytes)
    return handle_wcf_binary_message(body_bytes)

def process_message(message):
    body_bytes = get_message_body_bytes(message)
    result = handle_message_body(body_bytes)
    result["message_id"] = str(
        getattr(message, "message_id", "") or ""
    )
    result["sequence_number"] = getattr(
        message,
        "sequence_number",
        None,
    )
    result["enqueued_time"] = getattr(
        message,
        "enqueued_time_utc",
        None,
    )
    result["body_size"] = len(body_bytes)
    return result
# ---------------------------------------------------------------------------
# Risk calculation & Fast Pattern Matching / Grouping
# ---------------------------------------------------------------------------
def calculate_age_seconds(enqueued_time):
    if not enqueued_time:
        return None
    try:
        if enqueued_time.tzinfo is None:
            enqueued_time=enqueued_time.replace(tzinfo=timezone.utc)
        now=datetime.now(timezone.utc)
        return max(0.0,(now-enqueued_time).total_seconds())
    except Exception:
        return None

def format_elapsed(seconds):
    """Format a duration as hours:minutes:seconds.milliseconds."""
    total_ms = max(0, round(seconds * 1000))
    hours, remainder = divmod(total_ms, 3_600_000)
    minutes, remainder = divmod(remainder, 60_000)
    secs, millis = divmod(remainder, 1000)
    return f"{hours:02d}:{minutes:02d}:{secs:02d}.{millis:03d}"

def format_age(seconds):
    if seconds is None:
        return "-"
    if seconds<60:
        return f"{seconds:.1f}s"
    if seconds<3600:
        minutes=int(seconds//60)
        secs=int(seconds%60)
        return f"{minutes}m {secs:02d}s"
    if seconds<86400:
        hours=int(seconds//3600)
        minutes=int((seconds%3600)//60)
        return f"{hours}h {minutes:02d}m"
    days=int(seconds//86400)
    hours=int((seconds%86400)//3600)
    return f"{days}d {hours:02d}h"

def is_variable_component(value):
    if not value:
        return False
    if value.isdigit():
        return True
    if re.fullmatch(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}",value):
        return True
    if re.fullmatch(r"[0-9a-fA-F]{8,}",value) and any(ch.isdigit() for ch in value):
        return True
    if re.fullmatch(r"\d+(?:-\d+)+",value):
        return True
    return False

def fixed_pattern_chars(pattern):
    return len(re.sub(r"[^A-Za-z0-9]","",pattern.replace("*","")))

def wildcard_component(value):
    if is_variable_component(value):
        return "*"
    match=re.fullmatch(r"(.+?[_-])(\d{3,})",value)
    if match:
        return f"{match.group(1)}*"
    return None

def pattern_candidates_for_value(value,max_wildcards):
    candidates=set()
    # Discover variable fields anywhere in colon-structured keys.
    # Examples:
    # EP:DOR:<guid>:default:ICart -> EP:DOR:*:default:ICart
    # EP:DOR:<guid>:googlepay_buynow_<id>:ICart
    #   -> EP:DOR:*:googlepay_buynow_*:ICart
    parts=value.split(":")
    variable_parts=[]
    for index,part in enumerate(parts):
        wildcarded=wildcard_component(part)
        if wildcarded:
            variable_parts.append((index,wildcarded))
    for index,wildcarded in variable_parts:
        candidate=parts.copy()
        candidate[index]=wildcarded
        candidates.add(":".join(candidate))
    if max_wildcards>=2:
        for left in range(len(variable_parts)):
            for right in range(left+1,len(variable_parts)):
                candidate=parts.copy()
                left_index,left_value=variable_parts[left]
                right_index,right_value=variable_parts[right]
                candidate[left_index]=left_value
                candidate[right_index]=right_value
                candidates.add(":".join(candidate))
    # Terminal variable component after a structural delimiter.
    match=re.fullmatch(r"(.+[:_/|])([^:/_|]+)",value)
    if match and is_variable_component(match.group(2)):
        candidates.add(f"{match.group(1)}*")
    # Numeric ID followed by a stable suffix.
    for match in re.finditer(r"\d{3,}",value):
        prefix=value[:match.start()]
        suffix=value[match.end():]
        if suffix and re.search(r"[A-Za-z]",suffix):
            candidates.add(f"{prefix}*{suffix}")
    # Numeric terminal after '_' or '-'.
    match=re.fullmatch(r"(.+?[_-])(\d{3,})",value)
    if match:
        candidates.add(f"{match.group(1)}*")
    # Numeric terminal directly after text.
    match=re.fullmatch(r"(.+?[A-Za-z])(\d{3,})",value)
    if match:
        candidates.add(f"{match.group(1)}*")
    # Two variable spans with a stable suffix such as __CatalogContent.
    if max_wildcards>=2:
        match=re.fullmatch(r"(.+?[:_/|])([^:/_|]+)([:_/|])(.+?)(__[A-Za-z][A-Za-z0-9_]*)",value)
        if match and is_variable_component(match.group(2)):
            candidates.add(f"{match.group(1)}*{match.group(3)}*{match.group(5)}")
    return candidates

def discover_patterns(values,min_support=3,max_wildcards=2,show_progress=True):
    values=list(dict.fromkeys(values))
    total=len(values)
    if total<min_support:
        return []
    candidate_values=defaultdict(set)
    for index,value in enumerate(values,1):
        for pattern in pattern_candidates_for_value(value,max_wildcards):
            if pattern.count("*")<=max_wildcards and fixed_pattern_chars(pattern)>=3:
                candidate_values[pattern].add(value)
        if show_progress and (index==total or index%100==0):
            print_overwrite(f"Discovering patterns {index}/{total}")
    if show_progress:
        print()
    patterns=[]
    for pattern,matched in candidate_values.items():
        if len(matched)<min_support:
            continue
        patterns.append({
            "pattern":pattern,
            "values":matched,
            "wildcards":pattern.count("*"),
            "fixed_chars":fixed_pattern_chars(pattern),
        })
    patterns.sort(key=lambda item:(item["wildcards"],-item["fixed_chars"],-len(item["values"]),item["pattern"]))
    return patterns

def normalize_enqueue_time(value):
    if not isinstance(value, datetime):
        return None
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)

def group_kind(message):
    return message.get("value_kind") or "Value"

def build_exact_groups(messages):
    groups = defaultdict(list)
    for message in messages:
        value = message.get("extracted_value", "")
        if value and message.get("format") != "Unknown Binary":
            groups[(group_kind(message), value)].append(message)
    return groups

def message_group_result(key, messages, kind=None):
    ages = [calculate_age_seconds(item.get("enqueued_time")) for item in messages]
    ages = [age for age in ages if age is not None]
    return {"key": key, "kind": kind or group_kind(messages[0]),
            "count": len(messages), "ages": ages,
            "enqueued_times": [normalize_enqueue_time(item.get("enqueued_time")) for item in messages]}

def sort_message_groups(groups):
    groups.sort(key=lambda item: (-item["count"], item["kind"], item["key"]))
    return groups

def build_exact_group_results(exact_groups):
    return sort_message_groups([
        message_group_result(value, messages, kind)
        for (kind, value), messages in exact_groups.items()
    ])

def pattern_specificity(pattern):
    text=pattern["pattern"]
    return (
        pattern["wildcards"],
        -pattern["fixed_chars"],
        -len(text),
        text,
    )

def build_pattern_group_results(exact_groups, patterns, pattern_min_count=2):
    groups = []
    represented_values = set()
    # Only actual string values are eligible for wildcard discovery.
    for pattern in sorted(patterns, key=pattern_specificity):
        available_values = [v for v in pattern["values"] if v not in represented_values]
        if len(available_values) < pattern_min_count:
            continue
        messages = []
        for value in available_values:
            messages.extend(exact_groups.get(("String", value), []))
        represented_values.update(available_values)
        groups.append(message_group_result(pattern["pattern"], messages, "String"))
    for (kind, value), messages in exact_groups.items():
        if kind != "String" or value not in represented_values:
            groups.append(message_group_result(value, messages, kind))
    return sort_message_groups(groups)

def group_messages(messages, pattern_grouping=True, pattern_min_count=2, pattern_max_wildcards=2):
    exact_groups = build_exact_groups(messages)
    if not exact_groups:
        return []
    if not pattern_grouping:
        return build_exact_group_results(exact_groups)
    string_values = [value for kind, value in exact_groups if kind == "String"]
    patterns = discover_patterns(string_values, min_support=pattern_min_count,
                                 max_wildcards=pattern_max_wildcards) if string_values else []
    return build_pattern_group_results(exact_groups, patterns, pattern_min_count)

def truncate_text(value, width):
    value = str(value)
    if width <= 0 or len(value) <= width:
        return value
    return value[:width] if width <= 3 else value[:width - 3] + "..."

def build_analysis_report(groups,total_messages,min_pct=1.0,top=10,full_values=False):
    if not groups or total_messages<=0:
        return "No extracted values found."
    eligible=[]
    for group in groups:
        pct=(group["count"]/total_messages)*100.0
        if pct>=min_pct:
            item=dict(group)
            item["percentage"]=pct
            eligible.append(item)
    eligible=sort_message_groups(eligible)
    displayed=eligible if top<=0 else eligible[:top]
    if not displayed:
        return f"No groups meet the minimum {min_pct:.2f}% threshold.\nAnalyzed messages: {total_messages}"
    key_width = max(DEFAULT_KEY_WIDTH, *(len(str(g["key"])) for g in displayed)) if full_values else DEFAULT_KEY_WIDTH
    pct_width=13
    age_width=10
    kind_width = 19
    lines=[
        f"{'Count':>{DEFAULT_COUNT_WIDTH}} | {'% of messages':>{pct_width}} | {'Source':<{kind_width}} | {'Value / Pattern':<{key_width}} | {'Avg age':>{age_width}}",
        f"{'-'*DEFAULT_COUNT_WIDTH}-+-{'-'*pct_width}-+-{'-'*kind_width}-+-{'-'*key_width}-+-{'-'*age_width}",
    ]
    displayed_count=0
    for group in displayed:
        count=group["count"]
        displayed_count+=count
        key=str(group["key"]) if full_values else truncate_text(group["key"],key_width)
        ages=group.get("ages",[])
        average_age=sum(ages)/len(ages) if ages else None
        lines.append(
            f"{count:>{DEFAULT_COUNT_WIDTH},} | {group['percentage']:>{pct_width}.2f} | "
            f"{truncate_text(group['kind'], kind_width):<{kind_width}} | "
            f"{key:<{key_width}} | {format_age(average_age):>{age_width}}"
        )
    represented_pct=(displayed_count/total_messages)*100.0
    summary=f"{len(displayed)} groups cover {represented_pct:.2f}% of {total_messages:,} analyzed messages."
    if min_pct>0:
        summary+=f" Groups below {min_pct:.2f}% are excluded."
    lines.extend(["",summary])
    return "\n".join(lines)

def build_throughput_report(messages, groups, elapsed, top, full_values=False):
    """Report rates by Service Bus enqueue time, never collector receive time."""
    from collections import Counter
    from datetime import timedelta
    timestamps = [normalize_enqueue_time(m.get("enqueued_time")) for m in messages]
    valid = [t for t in timestamps if t is not None]
    lines = ["Sampled enqueue-time throughput (not total subscription traffic)",
             "------------------------------------------------------------------",
             f"Captured messages: {len(messages):,}",
             f"Messages with enqueue timestamp: {len(valid):,}",
             f"Missing enqueue timestamp: {len(messages)-len(valid):,}"]
    if not valid:
        return "\n".join(lines + ["No enqueue timestamps available for rate calculations."])
    start = min(valid).replace(microsecond=0)
    end = max(valid).replace(microsecond=0)
    # One-second inclusive span; no silent compression to collection duration.
    span = int((end-start).total_seconds()) + 1
    seconds = Counter(int((t-start).total_seconds()) for t in valid)
    peak = max(seconds.values(), default=0)
    lines += [f"First enqueued: {format_timestamp(start)} UTC",
              f"Last enqueued:  {format_timestamp(max(valid))} UTC",
              f"Enqueue span: {span:,} seconds",
              f"Average sampled msg/s: {len(valid)/span:.2f}",
              f"Peak sampled msg/s (1-second bucket): {peak:,}", "",
              f"{'Enqueue minute (UTC)':<20} | {'Messages':>10} | {'Avg msg/s':>11} | {'Peak msg/s':>11}",
              "-"*65]
    # UTC wall-clock minute buckets. First and last minute may be partial.
    minute_start = start.replace(second=0)
    final_minute = end.replace(second=0)
    while minute_start <= final_minute:
        window_start = max(start, minute_start)
        window_end = min(end + timedelta(seconds=1), minute_start + timedelta(minutes=1))
        width = (window_end-window_start).total_seconds()
        first_index = int((window_start-start).total_seconds())
        last_index = int((window_end-start).total_seconds())
        total = sum(seconds.get(i, 0) for i in range(first_index, last_index))
        minute_peak = max((seconds.get(i, 0) for i in range(first_index, last_index)), default=0)
        lines.append(f"{minute_start.strftime('%Y-%m-%d %H:%M'):<20} | {total:>10,} | {total/width:>11.2f} | {minute_peak:>11,}" +
                     (f"  (partial {width:.0f}s)" if width < 60 else ""))
        minute_start += timedelta(minutes=1)
    lines += ["", "Per source / value (sampled enqueue-time rates)",
              f"{'Count':>10} | {'Avg msg/s':>11} | {'Peak msg/s':>11} | {'Source':<19} | Value / Pattern",
              "-"*112]
    displayed = groups if top <= 0 else groups[:top]
    for group in displayed:
        group_times = [t for t in group["enqueued_times"] if t is not None]
        group_seconds = Counter(int((t-start).total_seconds()) for t in group_times)
        group_peak = max(group_seconds.values(), default=0)
        lines.append(f"{len(group_times):>10,} | {len(group_times)/span:>11.2f} | "
                     f"{group_peak:>11,} | {truncate_text(group['kind'], 19):<19} | "
                     f"{str(group['key']) if full_values else truncate_text(group['key'], DEFAULT_KEY_WIDTH)}")
    lines += ["", "Rates are based on enqueued_time_utc, including older captured messages.",
              "Competing consumers and redelivery mean this is sampled traffic only."]
    return "\n".join(lines)

def write_output_file(filename,report,collection_started,collection_ended,elapsed,args,message_count,stop_reason):
    lines=[
        f"Namespace: {normalize_namespace(args.namespace)}",
        f"Topic: {args.topic_name}",
        f"Subscription: {args.subscription_name}",
        f"Mode: {'Peek' if args.peek else 'Peek-Lock'}",
        f"Messages analyzed: {message_count}",
        f"Duration limit (minutes): {args.duration if args.duration is not None else 'none'}",
        f"Message limit: {args.sample_size if args.sample_size is not None else 'none'}",
        f"Stop reason: {stop_reason}",
        f"Collection started: {format_timestamp(collection_started)}",
        f"Collection ended: {format_timestamp(collection_ended)}",
        f"Collection time: {format_elapsed(elapsed)}",
        "",
        report,
        "",
    ]
    with open(filename,"w",encoding="utf-8") as output_file:
        output_file.write("\n".join(lines))

def get_servicebus_client(args):
    from azure.servicebus import ServiceBusClient
    fully_qualified_namespace = normalize_namespace(
        args.namespace
    )
    if (
        args.shared_access_policy_name
        and args.shared_access_policy_key
    ):
        connection_string = (
            f"Endpoint=sb://{fully_qualified_namespace}/;"
            f"SharedAccessKeyName="
            f"{args.shared_access_policy_name};"
            f"SharedAccessKey="
            f"{args.shared_access_policy_key}"
        )
        return ServiceBusClient.from_connection_string(
            connection_string
        )
    if args.aad_username:
        from azure.identity import InteractiveBrowserCredential
        credential = InteractiveBrowserCredential(
            username=args.aad_username
        )
    else:
        from azure.identity import DefaultAzureCredential
        credential = DefaultAzureCredential()
    return ServiceBusClient(
        fully_qualified_namespace=fully_qualified_namespace,
        credential=credential,
    )

def abandon_message(receiver, message):
    try:
        receiver.abandon_message(message)
    except Exception:
        logger.exception("Error abandoning message")

def abandon_pending_messages(receiver,pending_messages):
    if not pending_messages:
        return
    print(f"\nAbandoning {len(pending_messages)} outstanding message(s)...")
    previous_sigint=None
    if threading.current_thread() is threading.main_thread():
        previous_sigint=signal.getsignal(signal.SIGINT)
        signal.signal(signal.SIGINT,signal.SIG_IGN)
    try:
        for message in list(pending_messages):
            abandon_message(receiver,message)
        pending_messages.clear()
    finally:
        if previous_sigint is not None:
            signal.signal(signal.SIGINT,previous_sigint)

def create_subscription_receiver(client, args):
    return client.get_subscription_receiver(
        topic_name=args.topic_name,
        subscription_name=args.subscription_name,
        prefetch_count=0,
    )

def receive_message_batch(receiver, batch_size, use_peek_lock, sequence_number, wait):
    if use_peek_lock:
        return receiver.receive_messages(max_message_count=batch_size, max_wait_time=wait)
    if sequence_number is None:
        return receiver.peek_messages(max_message_count=batch_size)
    return receiver.peek_messages(max_message_count=batch_size, sequence_number=sequence_number)

def next_peek_sequence_number(batch, current):
    if not batch:
        return current
    last = getattr(batch[-1], "sequence_number", None)
    return last + 1 if last is not None else current

def get_message_id(message):
    return str(getattr(message, "message_id", "") or "")

def release_pending_message(receiver, message, pending_messages):
    abandon_message(receiver, message)
    if message in pending_messages:
        pending_messages.remove(message)

class ProgressReporter:
    """Limit terminal writes; --debug still prints individual decoded messages."""
    def __init__(self, args, interval=0.5):
        self.args = args
        self.interval = interval
        self.last_print = float("-inf")
    def update(self, result, count, elapsed, force=False):
        if self.args.debug:
            value = truncate_text(result.get("extracted_value", ""), DEFAULT_DEBUG_VALUE_WIDTH)
            print(f"\n[{count}] {result.get('format', '')} -> {value}")
        if not force and elapsed - self.last_print < self.interval:
            return
        limit = str(self.args.sample_size) if self.args.sample_size is not None else "unlimited"
        print_overwrite(f"Collected {count}/{limit} | elapsed {format_elapsed(elapsed)}")
        self.last_print = elapsed

def fetch_messages(client, args, use_peek_lock):
    messages, seen_sequences, pending_messages = [], set(), []
    receiver = create_subscription_receiver(client, args)
    sequence_number = None
    start = time.monotonic()
    deadline = start + args.duration * 60 if args.duration is not None else None
    stop_reason = "unknown"
    progress = ProgressReporter(args)
    try:
        while True:
            now = time.monotonic()
            if args.sample_size is not None and len(messages) >= args.sample_size:
                stop_reason = "message limit reached"
                break
            if deadline is not None and now >= deadline:
                stop_reason = "duration reached"
                break
            batch_size = min(500, args.sample_size - len(messages)) if args.sample_size is not None else 500
            # Peek-Lock receive is bounded by the remaining collection duration.
            # Peek API has no timeout argument, so its in-flight call may overrun slightly.
            wait = min(args.polling, max(0.01, deadline - now)) if deadline is not None else args.polling
            try:
                batch = receive_message_batch(
                    receiver, batch_size, use_peek_lock, sequence_number, wait
                )
            except KeyboardInterrupt:
                stop_reason = "interrupted"
                break
            except Exception as exc:
                logger.error("Error receiving messages: %s", exc)
                if deadline is None or time.monotonic() < deadline:
                    time.sleep(min(1, max(0, deadline - time.monotonic())) if deadline else 1)
                continue
            if not batch:
                if not use_peek_lock:
                    time.sleep(min(0.5, max(0, deadline - time.monotonic())) if deadline else 0.5)
                continue
            if use_peek_lock:
                pending_messages.extend(batch)
            else:
                sequence_number = next_peek_sequence_number(batch, sequence_number)
            for message in batch:
                # A batch can take time to decode; honor the deadline per message.
                now = time.monotonic()
                if deadline is not None and now >= deadline:
                    stop_reason = "duration reached"
                    break
                if args.sample_size is not None and len(messages) >= args.sample_size:
                    stop_reason = "message limit reached"
                    break
                try:
                    # Sequence number is stable even when message_id is empty or reused.
                    seq = getattr(message, "sequence_number", None)
                    identity = (("sequence", seq) if seq is not None else
                                ("id", get_message_id(message)) if get_message_id(message) else
                                ("object", id(message)))
                    if identity not in seen_sequences:
                        seen_sequences.add(identity)
                        # Record observation time before potentially expensive decoding.
                        observed_second = now - start
                        result = process_message(message)
                        result["observed_second"] = observed_second
                        messages.append(result)
                        progress.update(result, len(messages), time.monotonic() - start)
                except KeyboardInterrupt:
                    stop_reason = "interrupted"
                    break
                except Exception:
                    logger.exception("Error processing message")
                finally:
                    if use_peek_lock:
                        release_pending_message(receiver, message, pending_messages)
            if stop_reason != "unknown":
                break
    except KeyboardInterrupt:
        stop_reason = "interrupted"
    finally:
        if use_peek_lock:
            abandon_pending_messages(receiver, pending_messages)
        try:
            receiver.close()
        except Exception:
            logger.exception("Error closing receiver")
        if messages:
            progress.update(messages[-1], len(messages), time.monotonic() - start, force=True)
        print()
    return messages, time.monotonic() - start, stop_reason

def parse_args():
    parser=argparse.ArgumentParser(description="Analyze Azure Service Bus cache invalidation messages.")
    # Connection and authentication.
    parser.add_argument("-n","--namespace",required=True,help="Service Bus namespace")
    parser.add_argument("-s","--subscription",dest="subscription_name",required=True,help="Subscription name")
    parser.add_argument("-t","--topic",dest="topic_name",default="mysiteevents",help="Service Bus topic name")
    parser.add_argument("-p","--shared-access-policy-name",help="SAS policy name")
    parser.add_argument("-k","--shared-access-policy-key",help="SAS policy key")
    parser.add_argument("--aad-username",help="Azure AD username")
    # Normal analysis controls.
    parser.add_argument("-m","--size",dest="sample_size",type=int,default=None,help="Maximum messages (default: 100 if --duration is omitted)")
    parser.add_argument("--duration",type=float,default=None,metavar="MINUTES",help="Collect for at most this many minutes")
    parser.add_argument("-o","--output",help="Write the final analysis report to a file")
    parser.add_argument("--top",type=int,default=10,help="Maximum groups to display (default: 10; 0 = unlimited)")
    parser.add_argument("--min-pct",type=float,default=1.0,help="Minimum percentage of analyzed messages to display (default: 1.0; 0 = disabled)")
    parser.add_argument("--peek",action="store_true",help="Use Peek instead of Peek-Lock")
    parser.add_argument("--polling",type=int,default=5,help="Receive wait time (default: 5)")
    # Pattern grouping controls.
    parser.add_argument("--no-pattern-grouping",action="store_true",help="Disable pattern grouping")
    parser.add_argument("--pattern-min-count",type=int,default=3,help="Minimum distinct keys required to form a pattern (default: 3)")
    parser.add_argument("--pattern-max-wildcards",type=int,default=2,help="Maximum wildcards in a discovered pattern (default: 2)")
    # Diagnostics.
    parser.add_argument("--debug",action="store_true",help="Show debug logging")
    parser.add_argument("--version",action="version",version=VERSION)
    args = parser.parse_args()
    if args.duration is not None and (not __import__("math").isfinite(args.duration) or args.duration <= 0):
        parser.error("--duration must be a positive finite number")
    if args.sample_size is not None and args.sample_size <= 0:
        parser.error("--size must be positive")
    if args.polling <= 0:
        parser.error("--polling must be positive")
    if args.sample_size is None and args.duration is None:
        args.sample_size = 100
    return args

def main():
    args = parse_args()
    logging.basicConfig(
        level=(
            logging.DEBUG
            if args.debug
            else logging.ERROR
        ),
        format=(
            "%(asctime)s "
            "%(levelname)s "
            "%(message)s"
        ),
    )
    ensure_dependencies()
    collection_started = utc_now()
    print(
        f"Namespace: "
        f"{normalize_namespace(args.namespace)}"
    )
    print(
        f"Topic: {args.topic_name}"
    )
    print(
        f"Subscription: "
        f"{args.subscription_name}"
    )
    print(
        f"Mode: "
        f"{'Peek' if args.peek else 'Peek-Lock'}\n"
    )
    client = None
    try:
        client = get_servicebus_client(args)
        messages, collection_elapsed, stop_reason = fetch_messages(
            client, args, use_peek_lock=not args.peek
        )
        groups = group_messages(
            messages,
            pattern_grouping=(
                not args.no_pattern_grouping
            ),
            pattern_min_count=(
                args.pattern_min_count
            ),
            pattern_max_wildcards=(
                args.pattern_max_wildcards
            ),
        )
        # Capture rate measures this analyzer's collection speed, not the real consumer.
        capture_rate = len(messages) / collection_elapsed if collection_elapsed > 0 else 0.0
        capture_section = (f"Analyzer capture rate: {capture_rate:.2f} messages/s "
                           f"({len(messages):,} unique messages / {format_elapsed(collection_elapsed)} collection time)\n"
                           "Capture rate is not the subscription's arrival rate or the competing consumer's processing rate.")
        report = (build_analysis_report(groups, len(messages), args.min_pct, args.top)
                  + "\n\n" + build_throughput_report(messages, groups, collection_elapsed, args.top)
                  + "\n\n" + capture_section)
        file_report = (build_analysis_report(groups, len(messages), args.min_pct, args.top, full_values=True)
                       + "\n\n" + build_throughput_report(messages, groups, collection_elapsed, args.top, full_values=True)
                       + "\n\n" + capture_section)
        print(f"Stop reason: {stop_reason}")
        print()
        print(report)
    except KeyboardInterrupt:
        return 130
    finally:
        if client is not None:
            try:
                client.close()
            except Exception:
                logger.exception(
                    "Error closing client"
                )
    collection_ended = utc_now()
    elapsed = (
        collection_ended - collection_started
    ).total_seconds()
    print()
    print(
        f"Collection started:    "
        f"{format_timestamp(collection_started)} UTC"
    )
    print(
        f"Collection ended:    "
        f"{format_timestamp(collection_ended)} UTC"
    )
    print(
        f"Collection time:     "
        f"{format_elapsed(elapsed)}"
    )
    if args.output:
        write_output_file(
            args.output,
            file_report,
            collection_started,
            collection_ended,
            elapsed,
            args,
            len(messages),
            stop_reason,
        )
        print(f"Output written to: {args.output}")
    return 0
if __name__ == "__main__":
    sys.exit(main())
