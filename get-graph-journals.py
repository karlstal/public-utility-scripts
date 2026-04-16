import base64
import requests
import argparse
import json
import os

# Global base URL for journal streams
BASE_URL = "https://cg.optimizely.com/journal/stream/"

def build_auth_header(app_key, secret):
    """Builds the Authorization header once."""
    credentials = f"{app_key}:{secret}"
    encoded_credentials = base64.b64encode(credentials.encode("utf-8")).decode("utf-8")
    headers = {
        "Authorization": f"Basic {encoded_credentials}",
        "Content-Type": "application/json"
    }
    return headers

def retrieve_journal(journal_id, headers, timeout=30):
    """
    Retrieve a single journal safely with error handling.
    
    :param journal_id: Journal ID to retrieve
    :param headers: Auth headers
    :param timeout: Request timeout in seconds
    :return: JSON data dict if successful, None if failed
    """
    url = f"{BASE_URL}{journal_id}"
    try:
        response = requests.get(url, headers=headers, timeout=timeout)
        response.raise_for_status()  # Raise exception for HTTP errors (4xx, 5xx)
        try:
            return response.json()
        except json.JSONDecodeError:
            print(f"[ERROR] Failed to parse JSON for journal {journal_id}:")
            print(response.text)
            return None
    except requests.exceptions.HTTPError as e:
        print(f"[ERROR] HTTP error for journal {journal_id}: {e}")
    except requests.exceptions.Timeout:
        print(f"[ERROR] Request timed out for journal {journal_id}")
    except requests.exceptions.RequestException as e:
        print(f"[ERROR] Request failed for journal {journal_id}: {e}")
    
    return None

def pretty_print_json(journal_id,data, file=None):
    """Pretty-print JSON data. If file is provided, writes output to file."""
    output = json.dumps(data, indent=4)
    if file:
        with open(file, "a", encoding="utf-8") as f:
            f.write(f"Journal ID: {journal_id}\n")
            f.write(f"{output}\n")
        print(f"Output written to {file}")
    else:
        print(output)

def filter_journal_entries(journal_data, valid_statuses=(200, 201)):
    """
    Filter journal entries where index.Status is NOT in valid_statuses.
    Expects journal_data to have 'items' key.
    """
    filtered = []
    items = journal_data.get("items", [])
    for entry in items:
        index = entry.get("index", {})
        status = index.get("Status")
        if status not in valid_statuses:
            filtered.append(entry)
    return filtered

def main():
    parser = argparse.ArgumentParser(description="Retrieve and optionally filter Optimizely journals")
    parser.add_argument("--journal_ids", required=True, help="Comma-separated list of Journal IDs to retrieve")
    parser.add_argument("--app_key", required=True, help="App Key (username)")
    parser.add_argument("--secret", required=True, help="Secret (password)")
    parser.add_argument("--only_failures", action="store_true",
                        help="Show only entries where Status is not 200 or 201")
    parser.add_argument("--output_file", help="Optional file path to write output instead of printing")
    args = parser.parse_args()

    headers = build_auth_header(args.app_key, args.secret)
    journal_ids = [jid.strip() for jid in args.journal_ids.split(",")]

    if os.path.exists(args.output_file) :
        open(args.output_file, "w").close()  # clear file

    for journal_id in journal_ids:
        print(f"\n=== Retrieving journal: {journal_id} ===")
        data = retrieve_journal(journal_id, headers)
        if data is None:
            print(f"Skipping journal {journal_id} due to errors.")
            continue

        if args.only_failures:
            filtered_entries = filter_journal_entries(data, valid_statuses=(200, 201))
            print(f"Filtered entries where Status is NOT 200 or 201: {len(filtered_entries)}")
            pretty_print_json(journal_id,filtered_entries, file=args.output_file)
        else:
            print("All entries:")
            pretty_print_json(journal_id,data, file=args.output_file)

if __name__ == "__main__":
    main()