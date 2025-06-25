import json
import argparse
import requests
import os
from pprint import pprint

try:
    from colorama import Fore, Style, init
    init(autoreset=True)
    COLOR_ENABLED = True
except ImportError:
    COLOR_ENABLED = False


def find_nested_keys(data, parent_key="", depth=0, parent_structure=None, types_chain=""):
    """Recursively find deeply nested keys in a JSON structure, capturing their parent structure and type chain."""
    if isinstance(data, dict):
        if "type" in data:
            types_chain += f"{data['type']}->"

        for key, value in data.items():
            new_key = f"{parent_key}.{key}" if parent_key else key
            yield (new_key, depth, parent_structure or data, types_chain.rstrip("->"))
            yield from find_nested_keys(value, new_key, depth + 1, data, types_chain)
    
    elif isinstance(data, list):
        for index, item in enumerate(data):
            new_key = f"{parent_key}[{index}]"
            yield from find_nested_keys(item, new_key, depth + 1, data, types_chain)


def load_json(source):
    """Load JSON from a file or URL."""
    if source.startswith("http://") or source.startswith("https://"):
        response = requests.get(source)
        response.raise_for_status()
        return response.json()
    elif os.path.exists(source):
        with open(source, "r", encoding="utf-8") as file:
            return json.load(file)
    else:
        raise FileNotFoundError(f"'{source}' is not a valid file path or URL.")


def format_output(key, depth, types_chain):
    """Format the printed output with optional colors."""
    depth_str = f"Depth {depth}"
    if COLOR_ENABLED:
        depth_str = f"{Fore.CYAN}Depth {depth}{Style.RESET_ALL}"
        key = f"{Fore.YELLOW}{key}{Style.RESET_ALL}"
        if types_chain:
            types_chain = f"{Fore.GREEN}Types chain:{Style.RESET_ALL} {types_chain}"
    else:
        if types_chain:
            types_chain = f"Types chain: {types_chain}"
    return f"{depth_str}: {key}\n{types_chain if types_chain else ''}"


def main():
    parser = argparse.ArgumentParser(description="Identify deeply nested elements in JSON output from Search & Navigation index mappings")
    parser.add_argument("json_source", type=str, help="Path to a mappings (JSON file or Mapping REST API URL")
    parser.add_argument("--min-depth", type=int, default=3, help="Only show keys nested deeper than this depth.")
    args = parser.parse_args()

    data = load_json(args.json_source)
    
    nested_keys = sorted(find_nested_keys(data), key=lambda x: x[1], reverse=True)
    filtered_keys = [item for item in nested_keys if item[1] >= args.min_depth]

    if not filtered_keys:
        print("No keys found beyond the specified depth.")
        return

    for key, depth, _, types_chain in filtered_keys:
        print(format_output(key, depth, types_chain))
        print("-" * 60)


if __name__ == "__main__":
    main()
