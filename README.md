# public-utility-scripts

A collection of utility scripts for various system and data analysis tasks.

## Contents

### Scripts

- **`http-deps.sh`**  
  Checks outgoing HTTP connections from a Linux container.  
  Useful for investigating SNAT port exhaustion.

- **`sb-analyze.py`**  
  Analyzes and aggregates messages passing through Azure Service Bus.
  Useful for investigating service bus congestion.

- **`mapping-analyze.py`**  
  Analyzes Elasticsearch index mappings.

- **`json2csv.py`**  
  Converts multiple JSON files into a single CSV file.  
  Supports ZIP files and nested directory structures.

  - **`mapping-depth.py`**  
  Analyze depth in S&N mappings. Useful for investigating deeply nested structures.

