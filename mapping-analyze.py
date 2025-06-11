import argparse
import re
import json
import requests
import sys


def validate_url(url):
    url_pattern = re.compile(r'^(https?://[a-zA-Z0-9.-]+(:\d+)?(/.*)?)$')
    if not url_pattern.match(url):
        raise ValueError("Invalid URL format. Please ensure it starts with http:// or https://.")


def format_size(bytes_val):
    for unit in ['bytes', 'KB', 'MB', 'GB', 'TB']:
        if bytes_val < 1024:
            return f"{bytes_val:.2f} {unit}"
        bytes_val /= 1024
    return f"{bytes_val:.2f} PB"


def get_mappings(url, verbose=False):
    mapping_url = f"{url}/*/_mapping"
    if verbose:
        print(f"Fetching mappings from {mapping_url}...")
    response = requests.get(mapping_url)
    if response.status_code == 200:
        return response.json()
    else:
        raise Exception(f"Error getting mappings: {response.status_code}, {response.text}")


def get_counts(url, type_path, verbose=False):
    count_url = f"{url}/{type_path}/_count"
    if verbose:
        print(f"Fetching count for Content Type '{type_path}' from {count_url}...")
    count_response = requests.get(count_url)
    if count_response.status_code == 200:
        return count_response.json()['count']
    else:
        raise Exception(f"Error getting count for Content Type '{type_path}': {count_response.status_code}, {count_response.text}")


def get_sample_documents(url, type_path, sample_size=10, verbose=False):
    search_url = f"{url}/{type_path}/_search"
    query = {
        "size": sample_size,
        "query": {
            "match_all": {}
        }
    }
    if verbose:
        print(f"Fetching {sample_size} sample documents for Content Type '{type_path}' from {search_url}...")
    response = requests.post(search_url, json=query)
    if response.status_code == 200:
        return response.json().get('hits', {}).get('hits', [])
    else:
        print(f"Error getting documents for Content Type '{type_path}': {response.status_code}, {response.text}")
        return []


def calculate_property_sizes(documents):
    property_sizes = {}
    for doc in documents:
        for prop, value in doc.get('_source', {}).items():
            if prop not in property_sizes:
                property_sizes[prop] = 0
            property_sizes[prop] += len(json.dumps(value))
    return property_sizes


def extract_all_types(mappings_node, path=None, collected=None):
    if collected is None:
        collected = {}
    if path is None:
        path = []

    if not isinstance(mappings_node, dict):
        return collected

    if 'properties' in mappings_node:
        full_path = '/'.join(path)
        if '_default_' not in full_path:
            collected[full_path] = mappings_node['properties']
    elif 'mappings' in mappings_node:
        for sub_key, sub_mapping in mappings_node['mappings'].items():
            extract_all_types(sub_mapping, path + [sub_key], collected)
    else:
        for key, sub_mapping in mappings_node.items():
            if isinstance(sub_mapping, dict):
                extract_all_types(sub_mapping, path + [key], collected)

    return collected


class OutputHandler:
    def __init__(self, file):
        self.file = file
        if file:
            with open(self.file, 'w', encoding='utf-8') as f:
                f.write('')  # Clear file first

    def write(self, data):
        if self.file:
            with open(self.file, 'a', encoding='utf-8') as f:
                f.write(data)
        else:
            print(data, end = '')

    def flush(self):
        pass


def print_mappings_info(mappings, url, show_types, show_size, show_properties, verbose, top_n=None, output_file=None, min_size_mb=None):
    output_handler = OutputHandler(output_file)

    for index_name, index_data in mappings.items():
        output_handler.write(f"\nIndex: {index_name}\n")
        mapping_data = index_data.get('mappings', {})
        all_types = extract_all_types(mapping_data)

        output_handler.write(f"Total Types Found: {len(all_types)}\n")
        type_summaries = []

        for type_path, properties in all_types.items():
            print(f"Analyzing type: {type_path}...")
            type_info = {
                'type_path': type_path,
                'properties': properties,
                'count': 0,
                'estimated_size': 0,
                'property_sizes': {}
            }

            try:
                if show_types or show_size:
                    type_info['count'] = get_counts(url, type_path, verbose)
            except Exception as e:
                print(f"Error retrieving count for content type '{type_path}': {e}")
                continue

            if show_size:
                print("  Fetching sample documents...")
                sample_documents = get_sample_documents(url, type_path, verbose=verbose)
                property_sizes = calculate_property_sizes(sample_documents)
                type_info['property_sizes'] = property_sizes
                estimated_size = (
                    sum(property_sizes.values()) * type_info['count'] / len(sample_documents)
                    if sample_documents else 0
                )
                type_info['estimated_size'] = estimated_size

            type_summaries.append(type_info)

        if show_size and min_size_mb is not None:
            type_summaries = [t for t in type_summaries if t['estimated_size'] >= min_size_mb * 1024 * 1024]

        type_summaries.sort(key=lambda x: (-x['count'], -x['estimated_size']))

        if top_n is not None:
            type_summaries = type_summaries[:top_n]

        total_estimated_size = sum(t['estimated_size'] for t in type_summaries)

        for t in type_summaries:
            output_handler.write(f"\nContent Type: {t['type_path']}\n")
            if show_types:
                output_handler.write(f"  Count: {t['count']}\n")
            if show_size:
                output_handler.write(f"  Estimated Total Size: {format_size(t['estimated_size'])}\n")

            if show_properties:
                prop_sizes = t.get('property_sizes', {})
                sorted_props = sorted(t['properties'].items(), key=lambda item: -prop_sizes.get(item[0], 0))
                output_handler.write("  Properties:\n")
                for prop, _ in sorted_props:
                    size_str = f" - Size: {format_size(prop_sizes.get(prop, 0))}" if show_size else ""
                    output_handler.write(f"    {prop}{size_str}\n")

        if show_size:
            output_handler.write(f"\nTotal Estimated Size for Displayed Types: {format_size(total_estimated_size)}\n")

    if output_file:
        print(f"Done. Output written to: {output_file}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Analyze Elasticsearch mappings, types, properties')
    parser.add_argument('url', type=str, help='Elasticsearch URL including index name (e.g., https://host/private_key/index_name)')
    parser.add_argument('-t', action='store_true', help='Show types and their counts')
    parser.add_argument('-s', action='store_true', help='Show estimated sizes for types')
    parser.add_argument('-p', action='store_true', help='Show properties for each type')
    parser.add_argument('-v', action='store_true', help='Enable verbose output for progress logging')
    parser.add_argument('-n', type=int, default=None, help='Limit to top N types by count')
    parser.add_argument('--output', type=str, help='Output to file instead of printing to console')
    parser.add_argument('--min-size-mb', type=float, help='Exclude types with estimated size below this many MB')

    args = parser.parse_args()

    try:
        validate_url(args.url)
        url = args.url.rstrip('/')
        mappings = get_mappings(url, args.v)
        print_mappings_info(
            mappings,
            url,
            show_types=args.t,
            show_size=args.s,
            show_properties=args.p,
            verbose=args.v,
            top_n=args.n,
            output_file=args.output,
            min_size_mb=args.min_size_mb
        )
    except ValueError as ve:
        print(f"Validation Error: {ve}")
    except Exception as e:
        print(f"Exception: {e}")
