import os
import json
import csv
import re
import argparse
import zipfile
import tempfile

# Constants
MAX_DEPTH = 4

# Array to define the columns you want to extract and their JSON keys
columns = [
    {"csv_name": "Date", "json_key": "time", "transform": lambda x: x},
    {"csv_name": "ResultDescription", "json_key": "resultDescription", "transform": lambda x: x.strip() if x else ""},
    {"csv_name": "Host", "json_key": "Host", "transform": lambda x: x},
    {"csv_name": "Level", "json_key": "level", "transform": lambda x: x},
    {"csv_name": "Container Id", "json_key": "containerId", "transform": lambda x: x},
    {"csv_name": "Operation Name", "json_key": "operationName", "transform": lambda x: x},
]

# Define log levels and their hierarchy
LOG_LEVELS = {
    "error": 1,
    "warning": 2,
    "informational": 3,
    "debug": 4,
}

# Function to extract specified columns from a log line
def extract_data(log_line, loglevel):
    match = re.search(r'{.*}', log_line)
    if match:
        try:
            log_data = json.loads(match.group(0))
            log_level = log_data.get("level", "").lower()
            if LOG_LEVELS.get(log_level, 0) <= LOG_LEVELS.get(loglevel, 0):
                extracted_data = {}
                for column in columns:
                    value = log_data.get(column["json_key"], "")
                    transformed_value = column["transform"](value)
                    extracted_data[column["csv_name"]] = transformed_value
                return extracted_data
        except json.JSONDecodeError:
            return None
    return None

# Function to process a single JSON file
def process_json_file(file_path, writers, verbose, base_path, loglevel, separated):
    if verbose:
        relative_path = compact_path(file_path, base_path)
        print(f"Processing file: {relative_path}")
    
    with open(file_path, 'r', encoding='utf-8') as file:
        for line in file:
            extracted_data = extract_data(line, "debug")
            if extracted_data:
                host = extracted_data["Host"]
                if separated:
                    writer = writers.get(host)
                    if not writer:
                        writer = create_csv_writer(host, file_path, separated)
                        writers[host] = writer
                    writer.writerow(extracted_data)
                else:
                    # In single CSV mode, write to the common file
                    writers['common'].writerow(extracted_data)

# Function to create a new CSV writer for a specific host
def create_csv_writer(host, file_path, separated):
    output_file = f"{host}.csv" if separated else file_path
    fieldnames = [column["csv_name"] for column in columns]
    mode = 'w' if not os.path.exists(output_file) else 'a'
    
    csvfile = open(output_file, mode, newline='', encoding='utf-8')
    writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
    
    if not os.path.exists(output_file):
        writer.writeheader()  # Write header if it's a new file
    
    print(f"Output path: {output_file}")
    
    return writer

# Function to process all files in a directory recursively
def process_directory(directory, writers, verbose, base_path, loglevel, separated):
    if verbose:
        relative_path = compact_path(directory, base_path)
        print(f"Processing directory: {relative_path}")
    for root, dirs, files in os.walk(directory):
        dirs.sort()
        files.sort()
        for file in files:
            if file.endswith('.json'):
                file_path = os.path.join(root, file)
                process_json_file(file_path, writers, verbose, base_path, loglevel, separated)

# Helper function to compact the paths
def compact_path(path, base_path):
    relative_path = os.path.relpath(path, base_path)
    path_parts = relative_path.split(os.sep)
    filename = path_parts[-1]
    directories = path_parts[:-1]
    if len(directories) > MAX_DEPTH:
        directories = ['...'] + directories[-MAX_DEPTH:]
    return os.sep.join(directories + [filename])

# Function to handle .ZIP files
def process_zip_file(zip_path, writers, verbose, base_path, loglevel, separated):
    with tempfile.TemporaryDirectory() as temp_dir:
        with zipfile.ZipFile(zip_path, 'r') as zip_ref:
            zip_ref.extractall(temp_dir)
            if verbose:
                print(f"Extracted ZIP file to temporary directory: {temp_dir}")
            process_directory(temp_dir, writers, verbose, base_path, loglevel, separated)

# Function to handle both directory and file inputs
def process_input(input_path, output_file, delimiter, verbose, loglevel, separated):
    base_path = os.getcwd()
    input_path = os.path.abspath(input_path)
    output_file = os.path.abspath(output_file)
    
    if verbose:
        print(f"Input path: {compact_path(input_path, base_path)}")
        print(f"Output path: {compact_path(output_file, base_path)}")
    
    writers = {}  # Dictionary to hold CSV writers for each host
    
    if separated:
        # Process the directory or file and create separate files per host
        if os.path.isdir(input_path):
            process_directory(input_path, writers, verbose, base_path, loglevel, separated)
        elif os.path.isfile(input_path):
            if input_path.lower().endswith('.zip'):
                process_zip_file(input_path, writers, verbose, base_path, loglevel, separated)
            elif input_path.lower().endswith('.json'):
                process_json_file(input_path, writers, verbose, base_path, loglevel, separated)
            else:
                raise ValueError("The input file must have a .json or .zip extension.")
        else:
            raise ValueError(f"The provided path '{input_path}' is neither a directory nor a file.")
    else:
        # Process into a single CSV file
        with open(output_file, 'w', newline='', encoding='utf-8') as csvfile:
            fieldnames = [column["csv_name"] for column in columns]
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames, delimiter=delimiter)
            writer.writeheader()
            
            if os.path.isdir(input_path):
                process_directory(input_path, {'common': writer}, verbose, base_path, loglevel, separated)
            elif os.path.isfile(input_path):
                if input_path.lower().endswith('.zip'):
                    process_zip_file(input_path, {'common': writer}, verbose, base_path, loglevel, separated)
                elif input_path.lower().endswith('.json'):
                    process_json_file(input_path, {'common': writer}, verbose, base_path, loglevel, separated)
                else:
                    raise ValueError("The input file must have a .json or .zip extension.")
            else:
                raise ValueError(f"The provided path '{input_path}' is neither a directory nor a file.")

def main():
    parser = argparse.ArgumentParser(
        description="Extract specific fields from JSON logs and save them to a CSV file."
    )
    parser.add_argument(
        "log_directory_or_file",
        help="Path to a directory containing JSON logs, a single JSON log file, or a ZIP file with logs.",
    )
    parser.add_argument(
        "output_file",
        help="Path to the output file where extracted data will be saved.",
    )
    parser.add_argument(
        "-d", "--delimiter",
        default="\t",
        help="Delimiter for the output file. Default is a tab character.",
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose mode for detailed logging of processing steps.",
    )
    parser.add_argument(
        "-l", "--loglevel",
        choices=LOG_LEVELS.keys(),
        default="debug",
        help=(
            "Filter logs by level. Options are 'error', 'warning', 'informational', "
            "and 'debug'. Default is 'debug'."
        ),
    )
    parser.add_argument(
        "--separated", 
        action="store_true",
        help="Whether to generate separate files for each host.",
    )

    args = parser.parse_args()
    process_input(
        args.log_directory_or_file,
        args.output_file,
        args.delimiter,
        args.verbose,
        args.loglevel,
        args.separated
    )

if __name__ == "__main__":
    main()
