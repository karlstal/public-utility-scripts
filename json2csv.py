import os
import json
import csv
import re
import argparse
import zipfile
import tempfile
from datetime import datetime
import heapq

# Constants
MAX_DEPTH = 4

# Columns to extract
columns = [
    {"csv_name": "Date", "json_key": "time", "transform": lambda x: x if x else ""},
    {"csv_name": "ResultDescription", "json_key": "resultDescription",
     "transform": lambda x: x.replace("\n", " ").replace("\r", " ").strip() if x else ""},
    {"csv_name": "Host", "json_key": "Host", "transform": lambda x: x},
    {"csv_name": "Level", "json_key": "level", "transform": lambda x: x},
    {"csv_name": "Container Id", "json_key": "containerId", "transform": lambda x: x},
    {"csv_name": "Operation Name", "json_key": "operationName", "transform": lambda x: x},
]

LOG_LEVELS = {"error": 1, "warning": 2, "informational": 3, "debug": 4}


def extract_data(log_line, loglevel, verbose=False):
    match = re.search(r'{.*}', log_line)
    if not match:
        if verbose:
            print(f"No JSON object found in line: {log_line.strip()}")
        return None

    try:
        log_data = json.loads(match.group(0))
        log_level = log_data.get("level", "").lower()
        if LOG_LEVELS.get(log_level, 0) > LOG_LEVELS.get(loglevel, 0):
            return None

        extracted = {c["csv_name"]: c["transform"](log_data.get(c["json_key"], ""))
                     for c in columns}
        return extracted
    except json.JSONDecodeError:
        return None


def parse_timestamp(ts: str, convert_to_local: bool):
    if not ts:
        return None
    try:
        ts = ts.replace("Z", "+00:00")
        ts = re.sub(r'(\.\d{6})\d+', r'\1', ts)
        dt = datetime.fromisoformat(ts)
        if convert_to_local and dt.tzinfo is not None:
            dt = dt.astimezone()
        return dt
    except Exception:
        return None


def json_file_iterator(file_path, loglevel, verbose):
    """Yield extracted rows one by one from a JSON file."""
    with open(file_path, 'r', encoding='utf-8') as f:
        for line in f:
            data = extract_data(line, loglevel, verbose)
            if data:
                data["_parsedDate"] = parse_timestamp(data["Date"], False)
                yield data


def process_directory(directory, loglevel, verbose):
    files = []
    for root, dirs, file_names in os.walk(directory):        
        for name in file_names:
            path = os.path.join(root, name)
            if looks_like_json_file(path):
                files.append(path)
    return files


def process_zip_file(zip_path, verbose):
    temp_dir = tempfile.TemporaryDirectory()
    with zipfile.ZipFile(zip_path, 'r') as zip_ref:
        zip_ref.extractall(temp_dir.name)
    files = process_directory(temp_dir.name, loglevel=None, verbose=verbose)
    return files, temp_dir  # keep temp_dir alive until done


def merge_streams(file_paths, output_file, delimiter, loglevel, verbose, localtime):
    iterators = [json_file_iterator(fp, loglevel, verbose) for fp in file_paths]

    heap = []
    for i, it in enumerate(iterators):
        try:
            row = next(it)
            heap.append((row["_parsedDate"] or datetime.min, i, row, it))
        except StopIteration:
            continue

    heapq.heapify(heap)

    with open(output_file, 'w', newline='', encoding='utf-8') as out:
        writer = csv.DictWriter(out, fieldnames=[c["csv_name"] for c in columns], delimiter=delimiter)
        writer.writeheader()

        prev_date = None
        empty_row = {c["csv_name"]: "" for c in columns}

        while heap:
            cur_date, i, row, it = heapq.heappop(heap)

            # Insert empty row for time gaps > 50ms
            if prev_date and cur_date:
                diff_ms = (cur_date - prev_date).total_seconds() * 1000
                if diff_ms > 50:
                    writer.writerow(empty_row)
            prev_date = cur_date

            # Remove internal helper key before writing
            row_to_write = {k: v for k, v in row.items() if k != "_parsedDate"}
            writer.writerow(row_to_write)

            try:
                next_row = next(it)
                heapq.heappush(heap, (next_row["_parsedDate"] or datetime.min, i, next_row, it))
            except StopIteration:
                continue


def looks_like_json_file(file_path, lines_to_check=5):
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            for _ in range(lines_to_check):
                if re.search(r'{.*}', f.readline()):
                    return True
    except Exception:
        pass
    return False


def process_input(input_path, output_file, delimiter, verbose, loglevel, localtime):
    if os.path.isdir(input_path):
        files = process_directory(input_path, loglevel, verbose)
        merge_streams(files, output_file, delimiter, loglevel, verbose, localtime)
    elif os.path.isfile(input_path):
        if input_path.lower().endswith('.zip'):
            files, temp_dir = process_zip_file(input_path, verbose)
            merge_streams(files, output_file, delimiter, loglevel, verbose, localtime)
            temp_dir.cleanup()
        elif looks_like_json_file(input_path):
            merge_streams([input_path], output_file, delimiter, loglevel, verbose, localtime)
        else:
            raise ValueError("Input must be JSON or ZIP")
    else:
        raise ValueError("Invalid input path")


def compact_path(path, base_path):
    relative = os.path.relpath(path, base_path)
    parts = relative.split(os.sep)
    if len(parts) > MAX_DEPTH:
        parts = ["..."] + parts[-MAX_DEPTH:]
    return os.sep.join(parts)


def main():
    parser = argparse.ArgumentParser(description="Extract fields from JSON logs and export to CSV")
    parser.add_argument("log_directory_or_file")
    parser.add_argument("output_file")
    parser.add_argument("-d", "--delimiter", default="\t")
    parser.add_argument("-v", "--verbose", action="store_true")
    parser.add_argument("-l", "--loglevel", choices=LOG_LEVELS.keys(), default="debug")
    parser.add_argument("--localtime", action="store_true", help="Convert timestamps to local system time")

    args = parser.parse_args()

    process_input(
        args.log_directory_or_file,
        args.output_file,
        args.delimiter,
        args.verbose,
        args.loglevel,
        args.localtime
    )


if __name__ == "__main__":
    main()