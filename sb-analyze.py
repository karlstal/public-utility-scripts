import sys

if sys.version_info < (3, 11):
    sys.exit("Python 3.11 or newer is required to run this analyzer.")

import argparse
import base64
import binascii
import json
import io
import os
import math
from functools import lru_cache
import logging
import re
import subprocess
import signal
import threading
import time
import xml.etree.ElementTree as ET
from collections import defaultdict, Counter
from datetime import datetime, timezone, timedelta

VERSION = "2.4.1"
DEFAULT_KEY_WIDTH = 80
DEFAULT_COUNT_WIDTH = 7
DEFAULT_PROGRESS_WIDTH = 95
DEFAULT_DEBUG_VALUE_WIDTH = 160
logger = logging.getLogger(__name__)

# Structural / Identifier Regexes
RE_DOTNET_IDENTIFIER = re.compile(r"^[A-Za-z_][A-Za-z0-9_`+]*$")
RE_PRINTABLE_ASCII = re.compile(rb"[\x20-\x7e]{4,}")
RE_NON_ALPHANUM = re.compile(r"[^A-Za-z0-9]")
RE_WHITESPACE = re.compile(r"\s+")

# Dynamic Suffix Protection Regex (Culture Codes, GUIDs, and Numeric IDs)
RE_DYNAMIC_SUFFIX = re.compile(
    r"^[a-z]{2,3}(-[A-Za-z0-9]+)+$|"  # Culture codes (zh-Hans, en-US, sv-SE)
    r"^[0-9a-fA-F]{8}(-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}$|"  # GUIDs
    r"^\d+$"  # Pure integer IDs
)

# Universal Entropy Inspection Regexes
RE_LOW_ENTROPY_TEXT = re.compile(r"^[A-Za-z_]+(-[A-Za-z0-9]+)?$")
RE_HIGH_ENTROPY_ID = re.compile(
    r"^\d+$|"                                  # Pure integers
    r"^(?=.*\d)[A-Za-z0-9_-]{6,}$"             # Alphanumeric mix >= 6 chars with at least one digit
)

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
        print(f"Import failed for '{import_name}': {e}", file=sys.stderr)
    print(f"Installing missing package: {package_name}")
    subprocess.check_call([sys.executable, "-m", "pip", "install", package_name])

def ensure_dependencies():
    ensure_package("azure-servicebus", "azure.servicebus")
    ensure_package("azure-identity", "azure.identity")
    ensure_package("wcf", "wcf")
    try:
        get_wcf_decoder()
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
        return value.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
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
# Message Body & Deserialization
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

def find_cache_key_in_json(value):
    if isinstance(value, dict):
        preferred_names = ("cacheKey", "cache_key", "CacheKey", "key", "Key", "cachekey")
        for name in preferred_names:
            if name in value and isinstance(value[name], str):
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
        text = body_bytes.decode("utf-8", errors="strict")
        data = json.loads(text)
        value = find_cache_key_in_json(data)
        if value:
            return {"format": "JSON", "extracted_value": value}
        return {"format": "JSON", "extracted_value": "[No cache key in JSON]"}
    except Exception:
        return {"format": "JSON", "extracted_value": "[Invalid JSON]"}

def find_cache_key_in_xml(element):
    preferred_names = {"cachekey", "cache_key", "key", "cache", "cacheid", "cacheidentifier"}
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
            attribute_name = attribute_name.rsplit("}", 1)[1]
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
            return {"format": "XML", "extracted_value": value}
        return {"format": "XML", "extracted_value": "[No cache key in XML]"}
    except Exception:
        return {"format": "XML", "extracted_value": "[Invalid XML]"}

WCF_FORMAT = "WCF Binary XML"

def local_xml_name(name):
    name = str(name)
    return name.rsplit("}", 1)[-1] if "}" in name else name

@lru_cache(maxsize=1)
def get_wcf_decoder():
    from wcf.records.base import Record
    from wcf.records import print_records
    import wcf.records.text  # noqa: F401
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
    try:
        return ET.fromstring(xml_text)
    except ET.ParseError:
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
        offset = end
    return values

def extract_printable_binary_strings(data):
    values = []
    seen = set()
    for match in RE_PRINTABLE_ASCII.finditer(data):
        value = match.group().decode("ascii", errors="ignore").strip()
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
    return all(RE_DOTNET_IDENTIFIER.fullmatch(part) for part in parts)

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
        raw = base64.b64decode(RE_WHITESPACE.sub("", value), validate=True)
    except (ValueError, binascii.Error):
        return None
    values = extract_nrbf_strings(raw)
    if not values:
        values = extract_printable_binary_strings(raw)
    return select_dotnet_type(values) or (values[0] if values else None)

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
        child_value = extract_xml_child(parameter, field=rule["field"])
        value = rule.get("prefix", "") + child_value if child_value else None
    else:
        raise ValueError(f"Unsupported extraction strategy: {strategy}")
    return rule["label"], value or rule["fallback"]

def handle_wcf_binary_message(body_bytes):
    try:
        xml_text = decode_wcf_xml(body_bytes)
        root = parse_wcf_xml(xml_text)
    except Exception:
        return {"format": "Unknown Binary", "extracted_value": "[Unrecognized binary format]"}
    if root is None:
        return {"format": "Unknown Binary", "extracted_value": "[Invalid decoded XML]"}
    parameter = find_wcf_parameter(root)
    if parameter is None:
        return {"format": WCF_FORMAT, "extracted_value": "Unknown WCF Event"}
    try:
        kind, value = extract_wcf_parameter(parameter)
        return {"format": WCF_FORMAT, "extracted_value": value, "value_kind": kind}
    except Exception:
        return {"format": WCF_FORMAT, "extracted_value": "[Extraction error]", "value_kind": "OtherParameter"}

def detect_format(body_bytes):
    if not body_bytes:
        return "empty"
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
        return handle_json_message(body_bytes)
    if message_format == "xml":
        return handle_xml_message(body_bytes)
    return handle_wcf_binary_message(body_bytes)

def process_message(message):
    body_bytes = get_message_body_bytes(message)
    result = handle_message_body(body_bytes)
    result["message_id"] = str(getattr(message, "message_id", "") or "")
    result["sequence_number"] = getattr(message, "sequence_number", None)
    result["enqueued_time"] = getattr(message, "enqueued_time_utc", None)
    result["body_size"] = len(body_bytes)
    return result

# ---------------------------------------------------------------------------
# Type-Aware Structural Grouping
# ---------------------------------------------------------------------------
def calculate_age_seconds(enqueued_time, captured_at=None):
    if not enqueued_time:
        return None
    try:
        if enqueued_time.tzinfo is None:
            enqueued_time = enqueued_time.replace(tzinfo=timezone.utc)
        ref_time = captured_at or utc_now()
        if ref_time.tzinfo is None:
            ref_time = ref_time.replace(tzinfo=timezone.utc)
        return max(0.0, (ref_time - enqueued_time).total_seconds())
    except Exception:
        return None

def format_elapsed(seconds):
    total_ms = max(0, round(seconds * 1000))
    hours, remainder = divmod(total_ms, 3_600_000)
    minutes, remainder = divmod(remainder, 60_000)
    secs, millis = divmod(remainder, 1000)
    return f"{hours:02d}:{minutes:02d}:{secs:02d}.{millis:03d}"

def format_age(seconds):
    if seconds is None:
        return "-"
    if seconds < 60:
        return f"{seconds:.1f}s"
    if seconds < 3600:
        minutes = int(seconds // 60)
        secs = int(seconds % 60)
        return f"{minutes}m {secs:02d}s"
    if seconds < 86400:
        hours = int(seconds // 3600)
        minutes = int((seconds % 3600) // 60)
        return f"{hours}h {minutes:02d}m"
    days = int(seconds // 86400)
    hours = int((seconds % 86400) // 3600)
    return f"{days}d {hours:02d}h"

def fixed_pattern_chars(pattern):
    return len(RE_NON_ALPHANUM.sub("", pattern.replace("*", "")))

def is_high_entropy_value(val: str) -> bool:
    val = str(val).strip()
    return bool(RE_HIGH_ENTROPY_ID.match(val))

def get_slot_min_support(slot_values: set, term_support: int = 5) -> int:
    if not slot_values:
        return term_support

    text_count = sum(1 for v in slot_values if RE_LOW_ENTROPY_TEXT.match(str(v).strip()))
    if text_count / len(slot_values) >= 0.5:
        return term_support

    high_entropy_count = sum(1 for v in slot_values if is_high_entropy_value(v))
    if high_entropy_count / len(slot_values) >= 0.5:
        return 1

    return term_support

def split_key_structure(value):
    parts = re.split(r"([:/|])", value)
    if parts and RE_DYNAMIC_SUFFIX.match(parts[-1]):
        return parts
    return parts

def discover_patterns(exact_groups, pattern_term_min_count=5, show_progress=True):
    string_entries = [(v, len(msgs)) for (kind, v), msgs in exact_groups.items() if kind == "String"]
    if not string_entries:
        return []

    values = [item[0] for item in string_entries]

    templates = defaultdict(list)
    for value in values:
        parts = split_key_structure(value)
        template_key = (len(parts), tuple(parts[1::2]))
        templates[template_key].append((value, parts))

    patterns = []
    
    for (num_parts, _), items in templates.items():
        token_indices = list(range(0, num_parts, 2))
        
        prefix_groups = defaultdict(list)
        for value, parts in items:
            prefix = parts[0] if num_parts > 1 else value
            prefix_groups[prefix].append((value, parts))

        for prefix, p_items in prefix_groups.items():
            slot_unique = defaultdict(set)
            for value, parts in p_items:
                for idx in token_indices:
                    slot_unique[idx].add(parts[idx])

            cp = p_items[0][1].copy()
            has_wildcard = False
            
            for idx in token_indices:
                slot_vals = slot_unique[idx]
                min_req = get_slot_min_support(slot_vals, term_support=pattern_term_min_count)
                if len(slot_vals) >= min_req:
                    cp[idx] = "*"
                    has_wildcard = True

            if has_wildcard:
                pattern_str = "".join(cp)
                patterns.append({
                    "pattern": pattern_str,
                    "values": {val for val, _ in p_items},
                    "wildcards": pattern_str.count("*"),
                    "fixed_chars": fixed_pattern_chars(pattern_str),
                })

    patterns.sort(key=lambda item: (-item["fixed_chars"], item["pattern"]))
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
    ages = [
        calculate_age_seconds(item.get("enqueued_time"), item.get("captured_at")) 
        for item in messages
    ]
    ages = [age for age in ages if age is not None]
    return {
        "key": key,
        "kind": kind or group_kind(messages[0]),
        "count": len(messages),
        "ages": ages,
        "enqueued_times": [normalize_enqueue_time(item.get("enqueued_time")) for item in messages]
    }

def sort_message_groups(groups):
    groups.sort(key=lambda item: (-item["count"], item["kind"], item["key"]))
    return groups

def build_exact_group_results(exact_groups):
    return sort_message_groups([
        message_group_result(value, messages, kind)
        for (kind, value), messages in exact_groups.items()
    ])

def build_pattern_group_results(exact_groups, patterns):
    groups = []
    represented_values = set()

    for pattern in patterns:
        available_values = [v for v in pattern["values"] if v not in represented_values]
        if not available_values:
            continue
            
        messages = []
        for value in available_values:
            messages.extend(exact_groups.get(("String", value), []))
            
        represented_values.update(available_values)
        groups.append(message_group_result(pattern["pattern"], messages, "String"))

    for (kind, value), messages in exact_groups.items():
        if kind == "String" and value in represented_values:
            continue
        groups.append(message_group_result(value, messages, kind))

    return sort_message_groups(groups)

def group_messages(messages, pattern_grouping=True, pattern_term_min_count=5):
    exact_groups = build_exact_groups(messages)
    if not exact_groups:
        return []
    if not pattern_grouping:
        return build_exact_group_results(exact_groups)
        
    patterns = discover_patterns(
        exact_groups,
        pattern_term_min_count=pattern_term_min_count,
    )
    return build_pattern_group_results(exact_groups, patterns)

def truncate_text(value, width):
    value = str(value)
    if width <= 0 or len(value) <= width:
        return value
    return value[:width] if width <= 3 else value[:width - 3] + "..."

def build_analysis_report(groups, total_messages, min_pct=1.0, top=10, full_values=False):
    if not groups or total_messages <= 0:
        return "No extracted values found."
    eligible = []
    for group in groups:
        pct = (group["count"] / total_messages) * 100.0
        if pct >= min_pct:
            item = dict(group)
            item["percentage"] = pct
            eligible.append(item)
    eligible = sort_message_groups(eligible)
    displayed = eligible if top <= 0 else eligible[:top]
    if not displayed:
        return f"No groups meet the minimum {min_pct:.2f}% threshold.\nAnalyzed messages: {total_messages}"
    
    key_width = max(DEFAULT_KEY_WIDTH, *(len(str(g["key"])) for g in displayed)) if full_values else DEFAULT_KEY_WIDTH
    pct_width = 13
    age_width = 10
    kind_width = 19
    
    header = f"{'Count':>{DEFAULT_COUNT_WIDTH}} | {'% of messages':>{pct_width}} | {'Source':<{kind_width}} | {'Value / Pattern':<{key_width}} | {'Avg age':>{age_width}}"
    divider = f"{'-'*DEFAULT_COUNT_WIDTH}-+-{'-'*pct_width}-+-{'-'*kind_width}-+-{'-'*key_width}-+-{'-'*age_width}"
    
    lines = [header, divider]
    displayed_count = 0
    for group in displayed:
        count = group["count"]
        displayed_count += count
        key = str(group["key"]) if full_values else truncate_text(group["key"], key_width)
        ages = group.get("ages", [])
        average_age = sum(ages) / len(ages) if ages else None
        lines.append(
            f"{count:>{DEFAULT_COUNT_WIDTH},} | {group['percentage']:>{pct_width}.2f} | "
            f"{truncate_text(group['kind'], kind_width):<{kind_width}} | "
            f"{key:<{key_width}} | {format_age(average_age):>{age_width}}"
        )
    represented_pct = (displayed_count / total_messages) * 100.0
    summary = f"{len(displayed)} groups cover {represented_pct:.2f}% of {total_messages:,} analyzed messages."
    if min_pct > 0:
        summary += f" Groups below {min_pct:.2f}% are excluded."
    lines.extend(["", summary])
    return "\n".join(lines)

def build_throughput_report(messages, groups, elapsed, top, full_values=False):
    timestamps = [normalize_enqueue_time(m.get("enqueued_time")) for m in messages]
    valid = [t for t in timestamps if t is not None]
    lines = [
        "Sampled enqueue-time throughput (not total subscription traffic)",
        "------------------------------------------------------------------",
        f"Captured messages: {len(messages):,}",
        f"Messages with enqueue timestamp: {len(valid):,}",
        f"Missing enqueue timestamp: {len(messages)-len(valid):,}"
    ]
    if not valid:
        return "\n".join(lines + ["No enqueue timestamps available for rate calculations."])
    start = min(valid).replace(microsecond=0)
    end = max(valid).replace(microsecond=0)
    span = int((end - start).total_seconds()) + 1
    seconds = Counter(int((t - start).total_seconds()) for t in valid)
    peak = max(seconds.values(), default=0)
    lines += [
        f"First enqueued: {format_timestamp(start)} UTC",
        f"Last enqueued:  {format_timestamp(max(valid))} UTC",
        f"Enqueue span: {span:,} seconds",
        f"Average sampled msg/s: {len(valid)/span:.2f}",
        f"Peak sampled msg/s (1-second bucket): {peak:,}", "",
        f"{'Enqueue minute (UTC)':<20} | {'Messages':>10} | {'Avg msg/s':>11} | {'Peak msg/s':>11}",
        "-" * 65
    ]
    minute_start = start.replace(second=0)
    final_minute = end.replace(second=0)
    while minute_start <= final_minute:
        window_start = max(start, minute_start)
        window_end = min(end + timedelta(seconds=1), minute_start + timedelta(minutes=1))
        width = (window_end - window_start).total_seconds()
        first_index = int((window_start - start).total_seconds())
        last_index = int((window_end - start).total_seconds())
        total = sum(seconds.get(i, 0) for i in range(first_index, last_index))
        minute_peak = max((seconds.get(i, 0) for i in range(first_index, last_index)), default=0)
        lines.append(
            f"{minute_start.strftime('%Y-%m-%d %H:%M'):<20} | {total:>10,} | {total/width:>11.2f} | {minute_peak:>11,}" +
            (f"  (partial {width:.0f}s)" if width < 60 else "")
        )
        minute_start += timedelta(minutes=1)

    displayed = groups if top <= 0 else groups[:top]
    actual_key_width = max(DEFAULT_KEY_WIDTH, *(len(str(g["key"])) for g in displayed)) if (full_values and displayed) else DEFAULT_KEY_WIDTH
    per_source_divider_len = 10 + 3 + 11 + 3 + 11 + 3 + 19 + 3 + actual_key_width

    lines += [
        "", "Per source / value (sampled enqueue-time rates)",
        f"{'Count':>10} | {'Avg msg/s':>11} | {'Peak msg/s':>11} | {'Source':<19} | Value / Pattern",
        "-" * per_source_divider_len
    ]
    for group in displayed:
        group_times = [t for t in group["enqueued_times"] if t is not None]
        group_seconds = Counter(int((t - start).total_seconds()) for t in group_times)
        group_peak = max(group_seconds.values(), default=0)
        lines.append(
            f"{len(group_times):>10,} | {len(group_times)/span:>11.2f} | "
            f"{group_peak:>11,} | {truncate_text(group['kind'], 19):<19} | "
            f"{str(group['key']) if full_values else truncate_text(group['key'], actual_key_width)}"
        )
    lines += [
        "", "Rates are based on enqueued_time_utc, including older captured messages.",
        "Competing consumers and redelivery mean this is sampled traffic only."
    ]
    return "\n".join(lines)

def write_output_file(filename, report, collection_started, collection_ended, elapsed, args, message_count, stop_reason):
    lines = [
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
    with open(filename, "w", encoding="utf-8") as output_file:
        output_file.write("\n".join(lines))

# ---------------------------------------------------------------------------
# Management & Auto-Discovery with Activity Inspection
# ---------------------------------------------------------------------------
def get_servicebus_admin_client(args):
    from azure.servicebus.management import ServiceBusAdministrationClient
    fully_qualified_namespace = normalize_namespace(args.namespace)
    if args.shared_access_policy_name and args.shared_access_policy_key:
        connection_string = (
            f"Endpoint=sb://{fully_qualified_namespace}/;"
            f"SharedAccessKeyName={args.shared_access_policy_name};"
            f"SharedAccessKey={args.shared_access_policy_key}"
        )
        return ServiceBusAdministrationClient.from_connection_string(connection_string)
    if args.aad_username:
        from azure.identity import InteractiveBrowserCredential
        credential = InteractiveBrowserCredential(username=args.aad_username)
    else:
        from azure.identity import DefaultAzureCredential
        credential = DefaultAzureCredential()
    return ServiceBusAdministrationClient(
        fully_qualified_namespace=fully_qualified_namespace,
        credential=credential,
    )

def discover_and_select_subscription(args):
    print(f"Discovering active subscriptions for topic '{args.topic_name}' in '{normalize_namespace(args.namespace)}'...")
    try:
        admin_client = get_servicebus_admin_client(args)
        subscriptions = []
        with admin_client:
            sub_runtime_properties = admin_client.list_subscriptions_runtime_properties(topic_name=args.topic_name)
            for sub in sub_runtime_properties:
                active = getattr(sub, "active_message_count", 0)
                dlq = getattr(sub, "dead_letter_message_count", 0)
                scheduled = getattr(sub, "scheduled_message_count", 0)
                accessed_at = getattr(sub, "accessed_at_utc", None)
                
                subscriptions.append({
                    "name": sub.name,
                    "active": active,
                    "dlq": dlq,
                    "scheduled": scheduled,
                    "accessed_at": accessed_at
                })
    except Exception as exc:
        print(f"\n[Error] Failed to auto-discover subscriptions: {exc}", file=sys.stderr)
        print("Please specify a subscription manually using '-s / --subscription'.", file=sys.stderr)
        sys.exit(2)

    if not subscriptions:
        print(f"\n[Error] No subscriptions found for topic '{args.topic_name}'.", file=sys.stderr)
        sys.exit(2)

    if len(subscriptions) == 1:
        selected = subscriptions[0]
        print(f"Auto-selected sole subscription: {selected['name']}")
        print(f"(Active: {selected['active']:,} | DLQ: {selected['dlq']:,})\n")
        return selected["name"]

    print(f"\nAvailable subscriptions for topic '{args.topic_name}':")
    max_name_len = max((len(s["name"]) for s in subscriptions), default=0)
    
    for idx, sub in enumerate(subscriptions, start=1):
        name_padded = sub["name"].ljust(max_name_len)
        base_info = f"  [{idx:2d}] {name_padded}   (Active: {sub['active']:>7,}, DLQ: {sub['dlq']:>5,})"
        extras = []
        
        accessed_at = sub["accessed_at"]
        if accessed_at and accessed_at.year > 1:
            age_seconds = calculate_age_seconds(accessed_at)
            extras.append(f"Last active: {format_age(age_seconds)} ago")
        else:
            extras.append("Last active: Never")

        if sub["scheduled"] > 0:
            extras.append(f"Scheduled: {sub['scheduled']:,}")
            
        if extras:
            print(f"{base_info}   [{' | '.join(extras)}]")
        else:
            print(base_info)

    if not sys.stdin.isatty():
        print(f"\n[Error] Multiple subscriptions found, but stdin is non-interactive. "
              f"Please specify '-s / --subscription'.", file=sys.stderr)
        sys.exit(2)

    while True:
        try:
            choice = input(f"\nSelect subscription [1-{len(subscriptions)}]: ").strip()
            if choice.isdigit():
                num = int(choice)
                if 1 <= num <= len(subscriptions):
                    selected = subscriptions[num - 1]["name"]
                    print(f"Selected: {selected}\n")
                    return selected
            print(f"Invalid choice. Please enter a number between 1 and {len(subscriptions)}.")
        except (KeyboardInterrupt, EOFError):
            print("\nOperation cancelled by user.")
            sys.exit(130)

def get_servicebus_client(args):
    from azure.servicebus import ServiceBusClient
    fully_qualified_namespace = normalize_namespace(args.namespace)
    if args.shared_access_policy_name and args.shared_access_policy_key:
        connection_string = (
            f"Endpoint=sb://{fully_qualified_namespace}/;"
            f"SharedAccessKeyName={args.shared_access_policy_name};"
            f"SharedAccessKey={args.shared_access_policy_key}"
        )
        return ServiceBusClient.from_connection_string(connection_string)
    if args.aad_username:
        from azure.identity import InteractiveBrowserCredential
        credential = InteractiveBrowserCredential(username=args.aad_username)
    else:
        from azure.identity import DefaultAzureCredential
        credential = DefaultAzureCredential()
    return ServiceBusClient(
        fully_qualified_namespace=fully_qualified_namespace,
        credential=credential,
    )

def friendly_servicebus_error(exc, args):
    from azure.servicebus.exceptions import (
        MessagingEntityNotFoundError, ServiceBusAuthenticationError,
        ServiceBusAuthorizationError, ServiceBusConnectionError,
        ServiceBusError,
    )
    if isinstance(exc, MessagingEntityNotFoundError):
        return ("fatal", f"Topic '{args.topic_name}' or subscription "
                f"'{args.subscription_name}' does not exist in "
                f"'{normalize_namespace(args.namespace)}'. Check the names and namespace.")
    if isinstance(exc, ServiceBusAuthenticationError):
        return ("fatal", "Authentication failed. Check your credentials and Azure login.")
    if isinstance(exc, ServiceBusAuthorizationError):
        return ("fatal", "Access denied. The identity or SAS policy needs Listen permission "
                "for this subscription.")
    if isinstance(exc, ServiceBusConnectionError):
        return ("retry", "Could not connect to Azure Service Bus. Check network connectivity "
                "and firewall settings.")
    if isinstance(exc, (TimeoutError, ConnectionError)):
        return ("retry", "The connection timed out or was interrupted.")
    if isinstance(exc, ServiceBusError):
        return ("retry" if getattr(exc, "is_transient", False) else "stop",
                f"Service Bus operation failed ({type(exc).__name__}).")
    return ("stop", f"Unexpected error ({type(exc).__name__}): {exc}")

def show_operational_error(message, exc, debug=False):
    print(f"\n{message}", file=sys.stderr)
    if debug:
        logger.exception("Operation details")

class InitialCollectionError(Exception):
    pass

def abandon_message(receiver, message):
    try:
        receiver.abandon_message(message)
        return True
    except (AttributeError, Exception) as exc:
        logger.debug("Unable to abandon message during cleanup: %s", exc)
        return False

def abandon_pending_messages(receiver, pending_messages):
    if not pending_messages:
        return
    print(f"\nAbandoning {len(pending_messages)} outstanding message(s)...")
    previous_sigint = None
    if threading.current_thread() is threading.main_thread():
        previous_sigint = signal.getsignal(signal.SIGINT)
        signal.signal(signal.SIGINT, signal.SIG_IGN)
    try:
        for message in list(pending_messages):
            abandon_message(receiver, message)
        pending_messages.clear()
    finally:
        if previous_sigint is not None:
            signal.signal(signal.SIGINT, previous_sigint)

def create_subscription_receiver(client, args):
    return client.get_subscription_receiver(
        topic_name=args.topic_name,
        subscription_name=args.subscription_name,
        prefetch_count=0,
    )

def receive_message_batch(receiver, batch_size, use_peek_lock, sequence_number, wait_time):
    if use_peek_lock:
        return receiver.receive_messages(max_message_count=batch_size, max_wait_time=wait_time)
    if sequence_number is None:
        return receiver.peek_messages(max_message_count=batch_size)
    return receiver.peek_messages(max_message_count=batch_size, sequence_number=sequence_number)

def next_peek_sequence_number(batch, current):
    if not batch:
        return current
    last = getattr(batch[-1], "sequence_number", None)
    return last + 1 if last is not None else current

def release_pending_message(receiver, message, pending_messages):
    if abandon_message(receiver, message) and message in pending_messages:
        pending_messages.remove(message)

class ProgressReporter:
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
        
        elapsed_str = format_elapsed(elapsed)
        if self.args.duration is not None:
            expected_seconds = self.args.duration * 60.0
            elapsed_str += f" / {format_elapsed(expected_seconds)}"
            
        print_overwrite(f"Collected {count}/{limit} | elapsed {elapsed_str}")
        self.last_print = elapsed

def fetch_messages(client, args, use_peek_lock):
    messages, pending_messages = [], []
    receiver = None
    sequence_number = None
    start = time.monotonic()
    deadline = start + args.duration * 60 if args.duration is not None else None
    stop_reason = "unknown"
    progress = ProgressReporter(args)
    consecutive_errors = 0
    outage_started = None
    next_outage_notice = None
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
            wait_time = min(args.wait_time, max(0.01, deadline - now)) if deadline is not None else args.wait_time
            try:
                if receiver is None:
                    receiver = create_subscription_receiver(client, args)
                batch = receive_message_batch(
                    receiver, batch_size, use_peek_lock, sequence_number, wait_time
                )
            except KeyboardInterrupt:
                stop_reason = "interrupted"
                break
            except Exception as exc:
                category, message = friendly_servicebus_error(exc, args)
                if category != "retry":
                    if not messages:
                        raise InitialCollectionError(message) from exc
                    stop_reason = f"collection aborted: {message}"
                    show_operational_error(
                        f"Collection stopped: {message} ({len(messages)} messages preserved)",
                        exc, args.debug)
                    break

                consecutive_errors += 1
                now = time.monotonic()
                if outage_started is None:
                    outage_started = now
                    next_outage_notice = now + 60
                    show_operational_error(
                        f"Connection interrupted: {message} Reconnecting until collection ends...",
                        exc, args.debug)
                elif now >= next_outage_notice:
                    elapsed_outage = now - outage_started
                    print(f"\nStill disconnected ({format_elapsed(elapsed_outage)}); "
                          f"{len(messages):,} messages preserved.", file=sys.stderr)
                    next_outage_notice = now + 60

                if receiver is not None:
                    if use_peek_lock and pending_messages:
                        abandon_pending_messages(receiver, pending_messages)
                    try:
                        receiver.close()
                    except Exception:
                        logger.debug("Could not close disconnected receiver", exc_info=True)
                    receiver = None
                backoff = min(60, 2 ** min(consecutive_errors - 1, 6))
                if deadline is not None:
                    backoff = min(backoff, max(0, deadline - time.monotonic()))
                if backoff > 0:
                    time.sleep(backoff)
                continue
            if outage_started is not None:
                print(f"\nConnection restored after "
                      f"{format_elapsed(time.monotonic() - outage_started)}. "
                      f"Resuming collection ({len(messages):,} messages captured).")
                outage_started = None
                next_outage_notice = None
            consecutive_errors = 0
            if not batch:
                if not use_peek_lock:
                    time.sleep(min(0.5, max(0, deadline - time.monotonic())) if deadline else 0.5)
                continue
            if use_peek_lock:
                pending_messages.extend(batch)
            else:
                sequence_number = next_peek_sequence_number(batch, sequence_number)
            for message in batch:
                now = time.monotonic()
                captured_at = utc_now()
                if deadline is not None and now >= deadline:
                    stop_reason = "duration reached"
                    break
                if args.sample_size is not None and len(messages) >= args.sample_size:
                    stop_reason = "message limit reached"
                    break
                try:
                    observed_second = now - start
                    result = process_message(message)
                    result["observed_second"] = observed_second
                    result["captured_at"] = captured_at
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
        if use_peek_lock and receiver is not None:
            abandon_pending_messages(receiver, pending_messages)
        try:
            if receiver is not None:
                receiver.close()
        except Exception:
            logger.exception("Error closing receiver")
        
        if messages:
            progress.update(messages[-1], len(messages), time.monotonic() - start, force=True)
        print()
    return messages, time.monotonic() - start, stop_reason

def parse_args():
    parser = argparse.ArgumentParser(description="Analyze Azure Service Bus cache invalidation messages.")
    parser.add_argument("-n", "--namespace", required=True, help="Service Bus namespace")
    parser.add_argument("-s", "--subscription", dest="subscription_name", default=None, help="Subscription name (auto-discovered if omitted)")
    parser.add_argument("-t", "--topic", dest="topic_name", default="mysiteevents", help="Service Bus topic name")
    parser.add_argument("-p", "--shared-access-policy-name", default="Test", help="SAS policy name (default: Test)")
    parser.add_argument("-k", "--shared-access-policy-key", help="SAS policy key")
    parser.add_argument("--aad-username", help="Azure AD username")
    parser.add_argument("-m", "--size", dest="sample_size", type=int, default=None, help="Maximum messages (default: 100 if --duration is omitted)")
    parser.add_argument("--duration", type=float, default=None, metavar="MINUTES", help="Collect for at most this many minutes")
    parser.add_argument("-o", "--output", help="Write the final analysis report to a file")
    parser.add_argument("--top", type=int, default=10, help="Maximum groups to display (default: 10; 0 = unlimited)")
    parser.add_argument("--min-pct", type=float, default=1.0, help="Minimum percentage of analyzed messages to display (default: 1.0; 0 = disabled)")
    parser.add_argument("--peek", action="store_true", help="Use Peek instead of Peek-Lock")
    parser.add_argument("-w", "--wait", dest="wait_time", type=float, default=5.0, help="Receive wait time in seconds (default: 5.0)")
    parser.add_argument("--no-pattern-grouping", action="store_true", help="Disable pattern grouping")
    parser.add_argument("--pattern-term-min-count", type=int, default=5, help="Minimum distinct text terms required to collapse a text slot (default: 5)")
    parser.add_argument("--debug", action="store_true", help="Show debug logging")
    parser.add_argument("--version", action="version", version=VERSION)
    args = parser.parse_args()
    if args.duration is not None and (not math.isfinite(args.duration) or args.duration <= 0):
        parser.error("--duration must be a positive finite number")
    if args.sample_size is not None and args.sample_size <= 0:
        parser.error("--size must be positive")
    if args.wait_time <= 0:
        parser.error("--wait must be positive")
    if args.sample_size is None and args.duration is None:
        args.sample_size = 100
    return args

def main():
    args = parse_args()
    logging.basicConfig(
        level=logging.DEBUG if args.debug else logging.ERROR,
        format="%(asctime)s %(levelname)s %(message)s",
    )
    ensure_dependencies()

    if args.subscription_name is None:
        args.subscription_name = discover_and_select_subscription(args)

    collection_started = utc_now()
    print(f"Namespace: {normalize_namespace(args.namespace)}")
    print(f"Topic: {args.topic_name}")
    print(f"Subscription: {args.subscription_name}")
    print(f"Mode: {'Peek' if args.peek else 'Peek-Lock'}\n")
    client = None
    try:
        client = get_servicebus_client(args)
        messages, collection_elapsed, stop_reason = fetch_messages(
            client, args, use_peek_lock=not args.peek
        )
        groups = group_messages(
            messages,
            pattern_grouping=(not args.no_pattern_grouping),
            pattern_term_min_count=args.pattern_term_min_count,
        )
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
    except InitialCollectionError as exc:
        show_operational_error(f"Cannot start collection: {exc}", exc, args.debug)
        return 2
    except Exception as exc:
        _, message = friendly_servicebus_error(exc, args)
        show_operational_error(f"Analyzer failed: {message}", exc, args.debug)
        return 2
    except KeyboardInterrupt:
        return 130
    finally:
        if client is not None:
            try:
                client.close()
            except Exception:
                logger.exception("Error closing client")
    collection_ended = utc_now()
    elapsed = (collection_ended - collection_started).total_seconds()
    print()
    print(f"Collection started:    {format_timestamp(collection_started)} UTC")
    print(f"Collection ended:      {format_timestamp(collection_ended)} UTC")
    print(f"Collection time:       {format_elapsed(elapsed)}")
    if args.output:
        try:
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
        except OSError as exc:
            show_operational_error(f"Could not write report '{args.output}': {exc}", exc, args.debug)
            return 3
        print(f"Output written to: {args.output}")
    return 1 if stop_reason.startswith("collection aborted:") else 0

if __name__ == "__main__":
    sys.exit(main())