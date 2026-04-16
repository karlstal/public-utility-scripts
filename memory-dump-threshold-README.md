# memory-dump-threshold.sh

A Bash script designed to monitor .NET applications running in Azure App Service (Linux) environments. It automatically creates memory dumps when the process exceeds specified memory usage or thread count thresholds.

## Prerequisites

- Linux environment (Azure App Service Linux containers)
- `dotnet-dump` tool installed and accessible at `/tools/dotnet-dump` (default path)
- Target .NET process running
- Appropriate permissions to access `/proc/<PID>/` and create files in the dump directory

## Installation

1. **Download the script:**
   ```bash
   curl -L -o /home/site/wwwroot/memory-dump-threshold.sh \
     https://raw.githubusercontent.com/karlstal/public-utility-scripts/main/memory-dump-threshold.sh
   ```

2. **Make it executable:**
   ```bash
   chmod +x /home/site/wwwroot/memory-dump-threshold.sh
   ```

3. **Navigate to the directory:**
   ```bash
   cd /home/site/wwwroot
   ```

## Usage

### Basic Syntax
```bash
./memory-dump-threshold.sh --pid <process_id> [options]
```

### Options

- `--pid <process_id>`: **Required.** The process ID of the .NET application to monitor
- `--threshold <percent>`: Memory usage threshold as a percentage (default: 85%)
- `--thread-threshold <count>`: Thread count threshold (default: disabled)
- `--run-once`: Create a single dump when threshold is exceeded, then exit
- `--stop`: Stop a running monitor process
- `--help` or `-h`: Display usage information

### Finding the Process ID

Get the PID of your .NET process:
```bash
ps aux | grep dotnet
```

### Examples

**Monitor memory usage with default 85% threshold:**
```bash
nohup ./memory-dump-threshold.sh --pid 1234 > /home/LogFiles/AS/monitor.log 2>&1 &
```

**Monitor with custom memory threshold:**
```bash
nohup ./memory-dump-threshold.sh --pid 1234 --threshold 90 > /home/LogFiles/AS/monitor.log 2>&1 &
```

**Monitor thread count:**
```bash
nohup ./memory-dump-threshold.sh --pid 1234 --thread-threshold 100 > /home/LogFiles/AS/monitor.log 2>&1 &
```

**Monitor both memory and threads:**
```bash
nohup ./memory-dump-threshold.sh --pid 1234 --threshold 85 --thread-threshold 100 > /home/LogFiles/AS/monitor.log 2>&1 &
```

**Run once (single dump when threshold exceeded):**
```bash
./memory-dump-threshold.sh --pid 1234 --threshold 87 --run-once
```

**Stop the monitor:**
```bash
./memory-dump-threshold.sh --stop
```

## How It Works

The script continuously monitors the specified process by:

1. **Memory Monitoring:** Reads RSS (Resident Set Size) from `/proc/<PID>/status` and compares against total system memory
2. **Thread Monitoring:** Reads thread count from `/proc/<PID>/status` (when `--thread-threshold` is specified)
3. **Dump Creation:** When any threshold is exceeded, uses `dotnet-dump collect` to create a memory dump
4. **Logging:** Outputs status messages to stdout (redirect to a log file when running in background)

## Dump Location

Memory dumps are saved to `/home/LogFiles/AS/` with filenames in the format:
```
dump_<PID>_<TIMESTAMP>.dmp
```

Example: `dump_1234_20231201_143022.dmp`

## Accessing Dumps

In Azure App Service, download dumps via:
- **Kudu Console:** Navigate to `/home/LogFiles/AS/` in the file explorer
- **App Service Editor:** Access via `/newui` path in the file manager

## Stopping the Monitor

To stop a background monitor process:
```bash
./memory-dump-threshold.sh --stop
```

This reads the PID from `/tmp/memory-monitor.pid` and terminates the process gracefully.

## Troubleshooting

- **Permission Issues:** Ensure the script has access to `/proc/<PID>/` and write permissions to `/home/LogFiles/AS/`
- **dotnet-dump Not Found:** Verify `dotnet-dump` is installed at `/tools/dotnet-dump` or update `DOTNET_DUMP_CMD` in the script
- **Process Not Found:** Confirm the PID is correct and the process is still running
- **Stale PID File:** If the monitor doesn't stop properly, manually remove `/tmp/memory-monitor.pid`

## Configuration

You can modify these defaults in the script:
- `THRESHOLD`: Default memory threshold (85%)
- `DOTNET_DUMP_CMD`: Path to dotnet-dump executable
- `DUMP_DIR`: Directory for saving dumps
- `SLEEP_SECONDS`: Monitoring interval (10 seconds)