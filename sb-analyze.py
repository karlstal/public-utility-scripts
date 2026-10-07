import argparse
import base64
import binascii
import itertools
import json
import logging
import re
import subprocess
import sys
import signal
import threading
import time
import xml.etree.ElementTree as ET
from collections import defaultdict
from datetime import datetime, timezone
VERSION = "2.0.1"
DEFAULT_KEY_WIDTH = 120
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
        from wcf.records.base import Record
        import wcf.records.text
        import wcf.records.attributes
        import wcf.records.elements
        from wcf.records import print_records
        logger.debug(
            "WCF imports OK; %d record types registered",
            len(Record.records),
        )
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
        if isinstance(body, bytes):
            return body
        if isinstance(body, bytearray):
            return bytes(body)
        if isinstance(body, memoryview):
            return body.tobytes()
        if isinstance(body, str):
            return body.encode("utf-8")
        result = bytearray()
        for part in body:
            if isinstance(part, bytes):
                result.extend(part)
            elif isinstance(part, bytearray):
                result.extend(part)
            elif isinstance(part, memoryview):
                result.extend(part.tobytes())
            elif isinstance(part, str):
                result.extend(part.encode("utf-8"))
            else:
                result.extend(bytes(part))
        return bytes(result)
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

def decode_wcf_xml(body_bytes):
    import io
    from wcf.records.base import Record
    from wcf.records import print_records
    import wcf.records.text
    import wcf.records.attributes
    import wcf.records.elements
    source = io.BytesIO(body_bytes)
    records = Record.parse(source)
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

def extract_wcf_parameter_value(parameter):
    parameter_type = get_parameter_type(parameter)
    type_name = get_parameter_type_name(parameter_type)
    value = (parameter.text or "").strip()
    if type_name == "string":
        return value or "[Empty String Parameter]"
    if type_name == "base64binary":
        return decode_base64_parameter(value) or parameter_type or "base64Binary"
    if parameter_type:
        return parameter_type
    return "[Parameter has no type]"

def handle_wcf_binary_message(body_bytes):
    try:
        xml_text = decode_wcf_xml(body_bytes)
    except Exception:
        logger.exception("Unable to decode WCF Binary XML")
        return wcf_result(f"Unparsed WCF Binary: {len(body_bytes)} bytes")
    try:
        root = parse_wcf_xml(xml_text)
        if root is None:
            return wcf_result("Decoded WCF but invalid XML")
        parameter = find_wcf_parameter(root)
        if parameter is None:
            return wcf_result("Unknown WCF Event")
        return wcf_result(extract_wcf_parameter_value(parameter))
    except Exception:
        logger.exception("WCF decoded successfully but parameter extraction failed")
        return wcf_result("WCF parameter extraction error")

# ---------------------------------------------------------------------------
# Format detection

# ---------------------------------------------------------------------------

def detect_format(body_bytes):
    if not body_bytes:
        return "empty"
    stripped=body_bytes.lstrip()
    if stripped.startswith((b"{",b"[")):
        return "json"
    if stripped.startswith((b"<",b"\xef\xbb\xbf<")):
        return "xml"
    return "wcf"

def handle_message_body(body_bytes):
    message_format = detect_format(body_bytes)
    if message_format == "json":
        return handle_json_message(body_bytes)
    if message_format == "xml":
        return handle_xml_message(body_bytes)
    if message_format == "wcf":
        return handle_wcf_binary_message(body_bytes)
    return {
        "format": "unknown",
        "extracted_value": "[Empty message body]",
    }

# ---------------------------------------------------------------------------
# Message processing

# ---------------------------------------------------------------------------

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


def build_exact_groups(messages):
    groups = defaultdict(list)
    for message in messages:
        value = message.get("extracted_value", "")
        if value:
            groups[value].append(message)
    return groups

def message_group_result(key,messages):
    ages=[
        calculate_age_seconds(item.get("enqueued_time"))
        for item in messages
    ]
    ages=[age for age in ages if age is not None]
    return {
        "key":key,
        "count":len(messages),
        "ages":ages,
    }



def sort_message_groups(groups):
    groups.sort(key=lambda item: (-item["count"], item["key"]))
    return groups

def build_exact_group_results(exact_groups):
    return sort_message_groups([
        message_group_result(value, messages)
        for value, messages in exact_groups.items()
    ])

def pattern_specificity(pattern):
    text=pattern["pattern"]
    return (
        pattern["wildcards"],
        -pattern["fixed_chars"],
        -len(text),
        text,
    )


def build_pattern_group_results(exact_groups,patterns,pattern_min_count=2):
    groups=[]
    represented_values=set()

    # Most specific patterns claim keys first. A key can belong to only one
    # displayed pattern, making group counts mutually exclusive.
    for pattern in sorted(patterns,key=pattern_specificity):
        available_values=[
            value for value in pattern["values"]
            if value not in represented_values
        ]
        if len(available_values)<pattern_min_count:
            continue

        messages=[]
        for value in available_values:
            messages.extend(exact_groups.get(value,[]))

        represented_values.update(available_values)
        groups.append(message_group_result(pattern["pattern"],messages))

    # Exact keys that were not claimed by a qualifying pattern remain visible.
    for value,messages in exact_groups.items():
        if value not in represented_values:
            groups.append(message_group_result(value,messages))

    return sort_message_groups(groups)

def group_messages(
    messages,
    pattern_grouping=True,
    pattern_min_count=2,
    pattern_max_wildcards=2,
):
    exact_groups = build_exact_groups(messages)
    if not exact_groups:
        return []
    if not pattern_grouping:
        return build_exact_group_results(exact_groups)
    patterns = discover_patterns(
        exact_groups.keys(),
        min_support=pattern_min_count,
        max_wildcards=pattern_max_wildcards,
    )
    return build_pattern_group_results(
        exact_groups,
        patterns,
        pattern_min_count,
    )

def truncate_text(value, width):
    value = str(value)
    if width <= 0 or len(value) <= width:
        return value
    return value[:width] if width <= 3 else value[:width - 3] + "..."

def build_analysis_report(groups,total_messages,min_pct=1.0,top=10):
    if not groups or total_messages<=0:
        return "No extracted cache keys found."
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
    pct_width=13
    age_width=10
    lines=[
        f"{'Count':<{DEFAULT_COUNT_WIDTH}} | {'% of messages':>{pct_width}} | {'Cache key / pattern':<{DEFAULT_KEY_WIDTH}} | {'Avg age':>{age_width}}",
        f"{'-'*DEFAULT_COUNT_WIDTH}-+-{'-'*pct_width}-+-{'-'*DEFAULT_KEY_WIDTH}-+-{'-'*age_width}",
    ]
    displayed_count=0
    for group in displayed:
        count=group["count"]
        displayed_count+=count
        key=truncate_text(group["key"],DEFAULT_KEY_WIDTH)
        ages=group.get("ages",[])
        average_age=sum(ages)/len(ages) if ages else None
        lines.append(
            f"{count:<{DEFAULT_COUNT_WIDTH}} | {group['percentage']:>{pct_width}.2f} | "
            f"{key:<{DEFAULT_KEY_WIDTH}} | {format_age(average_age):>{age_width}}"
        )
    represented_pct=(displayed_count/total_messages)*100.0
    summary=f"{len(displayed)} groups cover {represented_pct:.2f}% of {total_messages:,} analyzed messages."
    if min_pct>0:
        summary+=f" Groups below {min_pct:.2f}% are excluded."
    lines.extend(["",summary])
    return "\n".join(lines)




def write_output_file(filename,report,collection_started,collection_ended,elapsed,args,message_count):
    lines=[
        f"Namespace: {normalize_namespace(args.namespace)}",
        f"Topic: {args.topic_name}",
        f"Subscription: {args.subscription_name}",
        f"Mode: {'Peek' if args.peek else 'Peek-Lock'}",
        f"Messages analyzed: {message_count}",
        f"Collection started: {format_timestamp(collection_started)}",
        f"Collection ended: {format_timestamp(collection_ended)}",
        f"Collection time: {elapsed:.1f} seconds",
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

def receive_message_batch(receiver, batch_size, args, use_peek_lock, sequence_number):
    if use_peek_lock:
        return receiver.receive_messages(
            max_message_count=batch_size,
            max_wait_time=args.polling,
        )
    if sequence_number is None:
        return receiver.peek_messages(max_message_count=batch_size)
    return receiver.peek_messages(
        max_message_count=batch_size,
        sequence_number=sequence_number,
    )

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

def is_duplicate_message(message, message_ids):
    message_id = get_message_id(message)
    if not message_id:
        return False
    if message_id in message_ids:
        return True
    message_ids.add(message_id)
    return False

def print_processed_message(result,count,total,debug):
    if debug:
        value = truncate_text(result.get("extracted_value", ""),DEFAULT_DEBUG_VALUE_WIDTH)
        print(f"\\n[{count}/{total}] {result.get('format', '')} -> {value}")
    print_overwrite(f"Collected {count}/{total}")

def process_received_message(
    receiver,
    message,
    messages,
    message_ids,
    pending_messages,
    args,
    use_peek_lock,
):
    try:
        if is_duplicate_message(message, message_ids):
            return
        result = process_message(message)
        messages.append(result)
        print_processed_message(result,len(messages),args.sample_size,args.debug)
    except Exception:
        logger.exception("Error processing message")
    finally:
        if use_peek_lock:
            release_pending_message(receiver, message, pending_messages)

def fetch_messages(client, args, use_peek_lock):
    messages = []
    message_ids = set()
    pending_messages = []
    receiver = create_subscription_receiver(client, args)
    sequence_number = None
    interrupted = False
    try:
        while len(messages) < args.sample_size and not interrupted:
            batch_size = min(500, args.sample_size - len(messages))
            try:
                batch = receive_message_batch(receiver, batch_size, args, use_peek_lock, sequence_number)
            except KeyboardInterrupt:
                interrupted = True
                break
            except Exception as e:
                logger.error("Error receiving messages: %s", e)
                time.sleep(1)
                continue
            if not batch:
                time.sleep(1)
                continue
            if use_peek_lock:
                pending_messages.extend(batch)
            else:
                sequence_number = next_peek_sequence_number(batch, sequence_number)
            for message in batch:
                if len(messages) >= args.sample_size:
                    break
                try:
                    process_received_message(receiver, message, messages, message_ids, pending_messages, args, use_peek_lock)
                except KeyboardInterrupt:
                    interrupted = True
                    break
    except KeyboardInterrupt:
        interrupted = True
    finally:
        if interrupted:
            print()
            print(f"Collection interrupted. Analyzing {len(messages)} collected messages...")
            if use_peek_lock:
                abandon_pending_messages(receiver, pending_messages)
        elif messages:
            print()
        try:
            receiver.close()
        except Exception:
            logger.exception("Error closing receiver")
    return messages

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
    parser.add_argument("-m","--size",dest="sample_size",type=int,default=100,help="Sample size (default: 100)")
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
    return parser.parse_args()

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
        messages = fetch_messages(
            client,
            args,
            use_peek_lock=not args.peek,
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
        report=build_analysis_report(groups,len(messages),args.min_pct,args.top)
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
        f"{format_timestamp(collection_started)}"
    )
    print(
        f"Collection ended:    "
        f"{format_timestamp(collection_ended)}"
    )
    print(
        f"Collection time:     "
        f"{elapsed:.1f} seconds"
    )
    if args.output:
        write_output_file(
            args.output,
            report,
            collection_started,
            collection_ended,
            elapsed,
            args,
            len(messages),
        )
        print(f"Output written to: {args.output}")
    return 0
if __name__ == "__main__":
    sys.exit(main())
