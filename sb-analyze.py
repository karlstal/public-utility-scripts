__version__ = "1.0.3"

import subprocess
import sys

MIN_PYTHON = (3, 8)  

if sys.version_info < MIN_PYTHON:
    sys.stderr.write(f"ERROR: This script requires Python {MIN_PYTHON[0]}.{MIN_PYTHON[1]} or higher.\n")
    sys.exit(1)

# Ensure required packages
def ensure_package(package):
    try:
        __import__(package)
    except ImportError:
        subprocess.check_call([sys.executable, "-m", "pip", "install", package],
                              stdout=subprocess.DEVNULL,
                              stderr=subprocess.DEVNULL)

ensure_package("azure-servicebus")
ensure_package("azure-identity")

import warnings
import shutil
import logging
import re
import time
import argparse
import json
import xml.etree.ElementTree as ET
import itertools

from datetime import datetime, timezone
from azure.servicebus import ServiceBusClient, ServiceBusReceivedMessage
from azure.servicebus.exceptions import (
    ServiceBusAuthenticationError,
    ServiceBusError,
    ServiceBusServerBusyError,
    MessagingEntityNotFoundError,
)
from azure.core.exceptions import ResourceNotFoundError, ClientAuthenticationError
from azure.identity import InteractiveBrowserCredential
from collections import defaultdict


# --- Logging Setup ---
logger = logging.getLogger(__name__)
args = None

# --- Pattern Matching ---
def extract_message_body(message: str) -> str | None:
    try:
        pattern = r"XMLSchema[^a-zA-Z]{0,3}([^@]+)@"
        matches = re.findall(pattern, message)
        if len(matches) >= 2:
            return re.sub(r'^[\s\u200b\xa0]+|[\s\u200b\xa0]+$', '', matches[1])
    except Exception as e:
        logger.error(f"Error extracting value: {e} from message: {message}")
    return None


def detect_format(body_bytes):
    try:
        text = body_bytes.decode('utf-8',errors='ignore')
    except UnicodeDecodeError:
        return 'binary'

    try:
        json.loads(text)
        return 'json'
    except json.JSONDecodeError:
        pass

    try:
        ET.fromstring(text)
        return 'xml'
    except ET.ParseError:
        pass

    return 'text'


def calculate_risk(enqueued_at: datetime, expires_at: datetime, now: datetime = None) -> float:
    """Calculate risk as % elapsed time relative to total lifetime."""
    now = now or datetime.now(timezone.utc)
    total_lifetime = (expires_at - enqueued_at).total_seconds()
    time_left = (expires_at - now).total_seconds()

    if time_left <= 0:
        return 100.0  # expired
    if total_lifetime <= 0:
        return 0.0
    return max(0.0, min(100.0, (1 - time_left / total_lifetime) * 100))


def calculate_time_remaining(expires_at: datetime, now: datetime = None) -> float:
    """Calculate remaining time in seconds until expiry."""
    now = now or datetime.now(timezone.utc)
    remaining = (expires_at - now).total_seconds()
    return max(0.0, remaining)


def process_message(msg):
    content_type = (msg.content_type or "").lower()
    try:
        body_bytes = b"".join(msg.body)
        body_text = body_bytes.decode('utf-8', errors="ignore")

        now = datetime.now(timezone.utc)

        enqueued_at = getattr(msg, "enqueued_time_utc", None) or getattr(msg, "enqueued_at", None)
        expires_at = getattr(msg, "expires_at_utc", None)

        risk = None
        time_remaining = None

        if enqueued_at and expires_at:
            # Make sure datetime objects are timezone aware (assume UTC if not)
            if enqueued_at.tzinfo is None:
                enqueued_at = enqueued_at.replace(tzinfo=timezone.utc)
            if expires_at.tzinfo is None:
                expires_at = expires_at.replace(tzinfo=timezone.utc)

            risk = calculate_risk(enqueued_at, expires_at, now)
            time_remaining = calculate_time_remaining(expires_at, now)

        if not content_type:
            content_type = detect_format(body_bytes)

        if content_type == "json" or "json" in content_type:
            result = handle_json_message(body_text)
        elif content_type == "xml" or "xml" in content_type:
            result = handle_xml_message(body_text)
        else:
            result = {"extracted_value": extract_message_body(body_text)}

        # Attach risk and time remaining if available
        if risk is not None:
            result["risk"] = risk
        if time_remaining is not None:
            result["time_remaining_seconds"] = time_remaining

        result["body"] = body_text
        return result

    except Exception as e:
        print(f"Failed to process message: {e}")
        logger.warning(f"Failed to process message: {e}")
        return None


def handle_json_message(data: str):
    try:
        print("🔍 JSON Content:\n", text)
        obj = json.loads(text)
        message = obj.get("message", "[No 'message' field found]")
        return {"extracted_value": message}
    except Exception as e:
        logger.error(f"Error parsing JSON: {e}")
        return {"extracted_value": "[Invalid JSON]"}


def handle_xml_message(data: str):
    try:
        print("🔍 XML Content:\n", text)
        root = ET.fromstring(text)
        message_elem = root.find("message")
        message = message_elem.text if message_elem is not None else "[No <message> element found]"
        return {"extracted_value": message}
    except Exception as e:
        logger.error(f"Error parsing XML: {e}")
        return {"extracted_value": "[Invalid XML]"}

# --- Connection Setup ---
def get_servicebus_client(
    namespace: str,
    use_aad: bool = False,
    aad_username: str = None,
    shared_access_policy_name: str = None,
    shared_access_policy_key: str = None
) -> ServiceBusClient:
    """
    Returns an authenticated ServiceBusClient using either Azure AD or Shared Access Signature.
    """
    fully_qualified_namespace = f"{namespace}.servicebus.windows.net"

    if use_aad:
        try:
            credential = InteractiveBrowserCredential(username=aad_username)
            credential.get_token("https://servicebus.azure.net/.default")
            return ServiceBusClient(fully_qualified_namespace, credential)
        except ClientAuthenticationError as e:
            print(f"[AUTH ERROR] Azure AD authentication failed: {e.message}")
            sys.exit(1)
    else:
        if not (shared_access_policy_name and shared_access_policy_key):
            raise ValueError("Shared Access Key and Policy Name must be provided when not using Azure AD.")
        conn_str = (
            f"Endpoint=sb://{fully_qualified_namespace}/;"
            f"SharedAccessKeyName={shared_access_policy_name};"
            f"SharedAccessKey={shared_access_policy_key}"
        )
        return ServiceBusClient.from_connection_string(conn_str)


def print_overwrite(message: str):
    if not hasattr(print_overwrite, "_spinner"):
        print_overwrite._spinner = itertools.cycle("|/-\\")
        print_overwrite._last_msg = None

    spin_char = next(print_overwrite._spinner)
    full_msg = f"{message} {spin_char}"

    if full_msg != print_overwrite._last_msg:
        width = shutil.get_terminal_size().columns
        sys.stdout.write('\r' + ' ' * width + '\r')
        sys.stdout.write(full_msg[:width])
        sys.stdout.flush()
        print_overwrite._last_msg = full_msg

# --- Peek Messages ---
def peek_messages(client: ServiceBusClient,
                  topic: str,
                  subscription: str,
                  message_sample_count: int,
                  polling_interval: int) -> list[ServiceBusReceivedMessage]:
    all_messages = []
    from_seq_supported = True  # Assume it's supported, disable if warned
    sequence_number = None
    seen_message_ids = set()
    removed_dupes = 0

    print(f"Collecting {message_sample_count} messages from topic: {topic}, subscription: {subscription}, namespace: {args.namespace} ...")
    try:
        receiver = client.get_subscription_receiver(topic_name=topic, subscription_name=subscription)
    except (ServiceBusAuthenticationError, MessagingEntityNotFoundError) as e:
        logger.error(f"Authentication failed: {e}")
        print("Authentication to Azure Service Bus failed. Please check your credentials.")
        sys.exit(1)

    with warnings.catch_warnings():
        warnings.simplefilter("ignore", UserWarning)

        try:
            with receiver:
                while len(all_messages) < message_sample_count:
                    try:
                        to_fetch = min(500, message_sample_count - len(all_messages))
                        kwargs = {"max_message_count": to_fetch}
                        if from_seq_supported and sequence_number is not None:
                            kwargs["from_sequence_number"] = sequence_number

                        print_overwrite(f'Peeking {to_fetch} messages (Sequence number: {sequence_number}). {len(all_messages)} messages collected so far...')

                        batch = receiver.peek_messages(**kwargs)
                        if not batch:
                            logger.info("No messages received.")
                            time.sleep(polling_interval)
                            continue

                        new_seq = getattr(batch[-1], "sequence_number", None)
                        if isinstance(new_seq, int):
                            sequence_number = new_seq + 1
                            if sequence_number > 1e15:
                                logger.info(f"Suspiciously high sequence number: {sequence_number}. Skipping sequence-based peeking next iteration.")
                                from_seq_supported = False
                                sequence_number = None
                        else:
                            logger.warning("No valid sequence_number found on last message. Skipping sequence-based peeking next iteration.")
                            from_seq_supported = False
                            sequence_number = None

                        logger.info(f"Received {len(batch)} messages.")
                        for msg in batch:
                            if msg.message_id not in seen_message_ids:
                                all_messages.append(msg)
                                seen_message_ids.add(msg.message_id)
                            else:
                                removed_dupes += 1

                        if not sequence_number:
                            time.sleep(polling_interval)
                    except TypeError as e:
                        if "from_sequence_number" in str(e):
                            logger.warning("from_sequence_number not supported; Disabling sequence-based peeking")
                            from_seq_supported = False
                            sequence_number = None
                            continue
                        logger.error(f"Type error: {e}")
                        break
                    except ServiceBusServerBusyError:
                        logger.warning("Server busy. Try again later.")
                        time.sleep(5)
                        continue
                    except ServiceBusAuthenticationError as e:
                        logger.error(f"Authentication failed: {e}")
                        print("Authentication to Azure Service Bus failed. Please check your credentials.")
                        break
                    except ServiceBusError as e:
                        logger.error(f"Service Bus error: {e}")
                        time.sleep(5)
                        continue
                    except ResourceNotFoundError as e:
                        logger.error(f"MessagingEntityNotFoundError error: {e}")
                        print("MessagingEntityNotFoundError")
                        sys.exit(1)
                    except KeyboardInterrupt:
                        break
                    except Exception as e:
                        logger.error(f"Unexpected error: {e}")
                        time.sleep(5)
                        continue
        except MessagingEntityNotFoundError as e:
            print(f"Error: The messaging entity was not found. Details: {e}")
            sys.exit(1)
        except Exception as e:
            print(f"An unexpected error occurred: {e}")
            sys.exit(1)

    print(f"\nPeeking completed. {len(all_messages)} messages collected. {removed_dupes} duplicates removed.")
    return all_messages

import xml.etree.ElementTree as ET

def decode_and_print_xml(binary_xml):
    try:
        # Decode binary data to string (assuming UTF-8 encoding)
        xml_string = binary_xml.decode('utf-16')
    except UnicodeDecodeError as e:
        print(f"Error decoding binary data: {e}")
        return

    try:
        # Parse XML string to an ElementTree element
        root = ET.fromstring(xml_string)
    except ET.ParseError as e:
        print(f"Error parsing XML: {e}")
        return

    # Recursive function to print all elements with indentation
    def print_element(elem, indent=0):
        space = '  ' * indent
        # Print tag and attributes (if any)
        attrs = ' '.join([f'{k}="{v}"' for k, v in elem.attrib.items()])
        print(f"{space}<{elem.tag} {attrs}>".strip())
        
        # Print text if exists and not just whitespace
        if elem.text and elem.text.strip():
            print(f"{space}  Text: {elem.text.strip()}")

        # Recursively print children
        for child in elem:
            print_element(child, indent + 1)

        print(f"{space}</{elem.tag}>")

    # Print the whole XML starting from root
    print_element(root)


# --- Group messages based one extracted value which is hopefully the cache key -
def group_messages(messages: list, prefix_length: int | None = None, min_count: int | None = None) -> dict:
    grouped = defaultdict(lambda: {"count": 0, "risks": []})
    seen_full = set()

    for msg in messages:
        result = process_message(msg)
        
        val = result.get("extracted_value") if result else None
        if not val:
            continue

        val = val.strip()
        # Get the risk if any from process_message result
        risk = result.get("risk")

        if prefix_length:
            prefix = val[:prefix_length]
            if prefix in seen_full:
                key = prefix + "..."
                grouped[key]["count"] += 1
                if risk is not None:
                    grouped[key]["risks"].append(risk)
            elif prefix in grouped:
                key = prefix + "..."
                # Move existing count to new key with ...
                grouped[key]["count"] += grouped[prefix]["count"]
                grouped[key]["risks"].extend(grouped[prefix]["risks"])
                grouped.pop(prefix)
                grouped[key]["count"] += 1
                if risk is not None:
                    grouped[key]["risks"].append(risk)
                seen_full.add(prefix)
            else:
                grouped[prefix]["count"] = 1
                if risk is not None:
                    grouped[prefix]["risks"] = [risk]
        else:
            grouped[val]["count"] += 1
            if risk is not None:
                grouped[val]["risks"].append(risk)

    # Filter out entries with count lower than min_count (if min_count is specified)
    if min_count is not None:
        grouped = {k: v for k, v in grouped.items() if v["count"] >= min_count}

    return dict(grouped)


def display_counts(extracted_values: dict, output_file: str = None):
    MAX_WIDTH = 120
    COUNT_WIDTH = 8
    RISK_WIDTH = 16
    VALUE_WIDTH = MAX_WIDTH - COUNT_WIDTH - RISK_WIDTH - 7

    if not extracted_values:
        logger.info("No values found.")
        return

    lines = []
    header = f"{'Count':<{COUNT_WIDTH}} | {'Risk to expire %':<{RISK_WIDTH}} | Extracted Value"
    divider = "-" * MAX_WIDTH

    lines.append(f"{len(extracted_values)} grouped extracted values from topic: {args.topic_name}, subscription: {args.subscription_name}, namespace: {args.namespace}")
    lines.append(divider)
    lines.append(header)
    lines.append(divider)

    # Sort by count desc or by avg risk if you prefer
    for val, data in sorted(extracted_values.items(), key=lambda x: x[1]['count'], reverse=True):
        count = data['count']
        risks = data.get('risks', [])
        avg_risk = sum(risks) / len(risks) if risks else 0
        clean_val = val.replace("\n", " ").replace("\r", " ")
        truncated_val = (clean_val[:VALUE_WIDTH - 3] + "...") if len(clean_val) > VALUE_WIDTH else clean_val
        lines.append(f"{str(count):<{COUNT_WIDTH}} | {avg_risk:>{RISK_WIDTH}.1f} | {truncated_val}")

    lines.append(divider)

    output_text = "\n".join(lines)
    if output_file:
        with open(output_file, "w", encoding="utf-8") as f:
            f.write(output_text + "\n")
        print(f"\nResults written to {output_file}")
    else:
        print(output_text)


# --- Main ---
def main():
    global args

    parser = argparse.ArgumentParser(description=f"Analyze Service Bus Tool v{__version__}")

    parser.add_argument("-n", "--namespace", required=True, help="Azure Service Bus namespace")
    parser.add_argument("-t", "--topic_name", required=False, default="mysiteevents",help="Topic name")
    parser.add_argument("-s", "--subscription_name", required=True, help="Subscription name")
    parser.add_argument("-p", "--shared_access_policy_name", required=False, help="Shared access policy name")
    parser.add_argument("-k", "--shared_access_policy_key", required=False, help="Shared access policy key")
    parser.add_argument("-u", "--aad_username", required=False, help="Azure AD user email to login interactively")
    parser.add_argument("-m", "--message_sample", type=int, default=256, help="Number of messages to collect")
    parser.add_argument("-l", "--log_level", default="ERROR", help="Logging level (e.g. DEBUG, INFO, WARNING, ERROR)")
    parser.add_argument("-i", "--polling", type=int, default=2, help="Polling interval in seconds")
    parser.add_argument("-o", "--output", help="Write results to specified file instead of stdout.")
    parser.add_argument("-x", "--prefix-length", type=int, default=None,
                        help="Optional prefix length to group extracted values by.")
    parser.add_argument("-mc", "--min-count", type=int, default=None,
                        help="Optional lower threshold for count")
    
    # Show help if no arguments are given
    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)
    
    args = parser.parse_args()

    logging.basicConfig(level=getattr(logging, args.log_level.upper(), logging.INFO),
                        format="%(asctime)s [%(levelname)s] %(message)s")

    use_aad = bool(args.aad_username)
    use_sas = bool(args.shared_access_policy_name) and bool(args.shared_access_policy_key)

    if use_aad is False and use_sas is False:
        print("No authenetication method provided. You need to supply either AAD username or a Shared Access Policy configuration. AAD authentication require that your account has the correct permissions.")
        sys.exit(-1)

    client = get_servicebus_client(
        namespace=args.namespace,
        use_aad=use_aad,
        aad_username=args.aad_username,
        shared_access_policy_name=args.shared_access_policy_name,
        shared_access_policy_key=args.shared_access_policy_key
    )

    print("Service Bus connection established.")

    messages = peek_messages(
        client=client,
        topic=args.topic_name,
        subscription=args.subscription_name,
        message_sample_count=args.message_sample,
        polling_interval=args.polling
    )

    counts = group_messages(messages, prefix_length=args.prefix_length, min_count=args.min_count)
    display_counts(counts, output_file=args.output)

if __name__ == "__main__":
    main()
