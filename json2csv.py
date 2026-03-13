import os
import json
import csv
import re
import argparse
import zipfile
import tempfile
from datetime import datetime

# Constants
MAX_DEPTH = 4

# Columns to extract
columns = [
    {
        "csv_name": "Date",
        "json_key": "time",
        "transform": lambda x: x if x else ""
    },
    {
        "csv_name": "ResultDescription",
        "json_key": "resultDescription",
        "transform": lambda x: x.replace("\n", " ").replace("\r", " ").strip() if x else ""
    },
    {"csv_name": "Host", "json_key": "Host", "transform": lambda x: x},
    {"csv_name": "Level", "json_key": "level", "transform": lambda x: x},
    {"csv_name": "Container Id", "json_key": "containerId", "transform": lambda x: x},
    {"csv_name": "Operation Name", "json_key": "operationName", "transform": lambda x: x},
]

# Log levels
LOG_LEVELS = {
    "error": 1,
    "warning": 2,
    "informational": 3,
    "debug": 4,
}

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
            if verbose:
                print(f"Skipping line due to log level: {log_level}")
            return None

        extracted = {}
        for column in columns:
            value = log_data.get(column["json_key"], "")
            extracted[column["csv_name"]] = column["transform"](value)

        return extracted

    except json.JSONDecodeError as e:
        if verbose:
            print(f"Failed to decode JSON: {e}\nLine: {log_line.strip()}")
        return None


def parse_timestamp(ts: str, convert_to_local: bool):
    if not ts:
        return None
    try:
        ts = ts.replace("Z", "+00:00")
        ts = re.sub(r'(\.\d{6})\d+', r'\1', ts)  # trim to microseconds
        dt = datetime.fromisoformat(ts)

        if convert_to_local and dt.tzinfo is not None:
            dt = dt.astimezone()

        return dt
    except Exception:
        return None


def process_json_file(
    file_path, writers, verbose, base_path,
    loglevel, separated, localtime
):
    if verbose:
        print(f"Processing file: {compact_path(file_path, base_path)}")

    total_lines = 0
    written_lines = 0
    empty_row = {col["csv_name"]: "" for col in columns}
    prev_date = None
    extracted_rows = []

    with open(file_path, 'r', encoding='utf-8') as file:
        for line in file:
            total_lines += 1
            data = extract_data(line, loglevel, verbose)
            if data:
                data["_parsedDate"] = parse_timestamp(data["Date"], localtime)
                extracted_rows.append(data)
                written_lines += 1

    extracted_rows.sort(
        key=lambda x: x["_parsedDate"] if x["_parsedDate"] else datetime.min
    )

    for row in extracted_rows:
        cur_date = row["_parsedDate"]

        if not separated:
            if cur_date and prev_date:
                diff_ms = (cur_date - prev_date).total_seconds() * 1000
                if diff_ms > 50:
                    writers["common"].writerow(empty_row)

            prev_date = cur_date
            writers["common"].writerow(
                {k: v for k, v in row.items() if k != "_parsedDate"}
            )
        else:
            host = row["Host"]
            writer = writers.get(host)
            if not writer:
                writer = create_csv_writer(host, base_path)
                writers[host] = writer

            writer.writerow(
                {k: v for k, v in row.items() if k != "_parsedDate"}
            )

    if verbose:
        print(
            f"Finished file: {compact_path(file_path, base_path)} — "
            f"Total: {total_lines}, Written: {written_lines}, "
            f"Skipped: {total_lines - written_lines}"
        )


def create_csv_writer(host, base_path):
    output_file = f"{host}.csv"
    fieldnames = [column["csv_name"] for column in columns]
    mode = 'a' if os.path.exists(output_file) else 'w'

    csvfile = open(output_file, mode, newline='', encoding='utf-8')
    writer = csv.DictWriter(csvfile, fieldnames=fieldnames)

    if mode == 'w':
        writer.writeheader()

    print(f"Output path: {output_file}")
    return writer


def process_directory(directory, writers, verbose, base_path, loglevel, separated, localtime):
    if verbose:
        print(f"Processing directory: {compact_path(directory, base_path)}")

    for root, dirs, files in os.walk(directory):
        dirs.sort()
        files.sort()
        for file in files:
            file_path = os.path.join(root, file)
            if looks_like_json_file(file_path):
                process_json_file(
                    file_path, writers, verbose, base_path,
                    loglevel, separated, localtime
                )


def process_zip_file(zip_path, writers, verbose, base_path, loglevel, separated, localtime):
    with tempfile.TemporaryDirectory() as temp_dir:
        with zipfile.ZipFile(zip_path, 'r') as zip_ref:
            zip_ref.extractall(temp_dir)
            if verbose:
                print(f"Extracted ZIP to: {temp_dir}")

            process_directory(
                temp_dir, writers, verbose, base_path,
                loglevel, separated, localtime
            )


def compact_path(path, base_path):
    relative = os.path.relpath(path, base_path)
    parts = relative.split(os.sep)
    if len(parts) > MAX_DEPTH:
        parts = ['...'] + parts[-MAX_DEPTH:]
    return os.sep.join(parts)


def looks_like_json_file(file_path, lines_to_check=5):
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            for _ in range(lines_to_check):
                if re.search(r'{.*}', f.readline()):
                    return True
    except Exception:
        pass
    return False


def process_input(
    input_path, output_file, delimiter,
    verbose, loglevel, separated, localtime
):
    base_path = os.getcwd()
    input_path = os.path.abspath(input_path)
    output_file = os.path.abspath(output_file)

    writers = {}

    if separated:
        if os.path.isdir(input_path):
            process_directory(input_path, writers, verbose, base_path, loglevel, separated, localtime)
        elif os.path.isfile(input_path):
            if input_path.lower().endswith('.zip'):
                process_zip_file(input_path, writers, verbose, base_path, loglevel, separated, localtime)
            elif looks_like_json_file(input_path):
                process_json_file(input_path, writers, verbose, base_path, loglevel, separated, localtime)
            else:
                raise ValueError("Input must be JSON or ZIP")
        else:
            raise ValueError("Invalid input path")
    else:
        with open(output_file, 'w', newline='', encoding='utf-8') as csvfile:
            writer = csv.DictWriter(
                csvfile,
                fieldnames=[c["csv_name"] for c in columns],
                delimiter=delimiter
            )
            writer.writeheader()

            writers["common"] = writer

            if os.path.isdir(input_path):
                process_directory(input_path, writers, verbose, base_path, loglevel, separated, localtime)
            elif os.path.isfile(input_path):
                if input_path.lower().endswith('.zip'):
                    process_zip_file(input_path, writers, verbose, base_path, loglevel, separated, localtime)
                elif looks_like_json_file(input_path):
                    process_json_file(input_path, writers, verbose, base_path, loglevel, separated, localtime)
                else:
                    raise ValueError("Input must be JSON or ZIP")
            else:
                raise ValueError("Invalid input path")


def main():
    parser = argparse.ArgumentParser(
        description="Extract fields from JSON logs and export to CSV"
    )

    parser.add_argument("log_directory_or_file")
    parser.add_argument("output_file")
    parser.add_argument("-d", "--delimiter", default="\t")
    parser.add_argument("-v", "--verbose", action="store_true")
    parser.add_argument(
        "-l", "--loglevel",
        choices=LOG_LEVELS.keys(),
        default="debug"
    )
    parser.add_argument("--separated", action="store_true")
    parser.add_argument(
        "--localtime",
        action="store_true",
        help="Convert timestamps to local system time"
    )

    args = parser.parse_args()

    process_input(
        args.log_directory_or_file,
        args.output_file,
        args.delimiter,
        args.verbose,
        args.loglevel,
        args.separated,
        args.localtime
    )


if __name__ == "__main__":
    main()
