# dotnet-dump-threshold.sh

A Bash script designed to monitor .NET applications running in Azure App Service (Linux) environments. It automatically creates a memory dump when the process exceeds a memory usage threshold, a thread count threshold, or either of the two.

The two triggers are independent: specify `--memory-threshold`, `--thread-threshold`, or both. A threshold you do not specify is not monitored, and a dump is collected as soon as *either* configured threshold is crossed.

> Previously named `memory-dump-threshold.sh`. The old `--threshold` flag still works as an alias for `--memory-threshold`.

## Prerequisites

- Linux environment (Azure App Service Linux containers)
- `dotnet-dump` tool installed and accessible at `/tools/dotnet-dump` (default path)
- Target .NET process running
- Appropriate permissions to access `/proc/<PID>/` and create files in the dump directory

## Installation

1. **Download the script:**
   ```bash
   curl -L -o /home/site/wwwroot/dotnet-dump-threshold.sh \
     https://raw.githubusercontent.com/karlstal/public-utility-scripts/main/dotnet-dump-threshold.sh
   ```

2. **Make it executable:**
   ```bash
   chmod +x /home/site/wwwroot/dotnet-dump-threshold.sh
   ```

3. **Navigate to the directory:**
   ```bash
   cd /home/site/wwwroot
   ```

## Usage

### Basic Syntax
```bash
./dotnet-dump-threshold.sh --pid <process_id> [options]
```

### Options

- `--pid <process_id>`: **Required.** The process ID of the .NET application to monitor
- `--memory-threshold <percent>`: Memory usage threshold as a percentage (1-100). Not monitored unless given. Also accepted as `--threshold`
- `--thread-threshold <count>`: Thread count threshold. Not monitored unless given
- `--max-dumps <count>`: Maximum number of dumps to write before exiting (default: 3)
- `--run-once`: Create a single dump when threshold is exceeded, then exit (equivalent to `--max-dumps 1`)
- `--stop`: Stop a running monitor process
- `--help` or `-h`: Display usage information

If you specify neither threshold, the script falls back to monitoring memory at 85% and says so in the log.

### Dump Limits

A process that crosses a threshold usually stays there, so the monitor would
otherwise dump every 10 seconds and fill the `/home` file share. The monitor
writes at most `--max-dumps` dumps (3 by default) and then exits on its own.
Lower it for large heaps — each dump is roughly the size of the process's
committed memory, and `dotnet-dump collect` pauses the app while it runs.

The monitor also gives up after 3 consecutive `dotnet-dump` failures rather than
retrying forever.

### Finding the Process ID

Get the PID of your .NET process:
```bash
ps aux | grep dotnet
```

### Examples

**Monitor memory only (default 85% threshold):**
```bash
nohup ./dotnet-dump-threshold.sh --pid 1234 > /home/LogFiles/AS/monitor.log 2>&1 &
```

**Monitor memory only, custom threshold:**
```bash
nohup ./dotnet-dump-threshold.sh --pid 1234 --memory-threshold 90 > /home/LogFiles/AS/monitor.log 2>&1 &
```

**Monitor thread count only:**
```bash
nohup ./dotnet-dump-threshold.sh --pid 1234 --thread-threshold 200 > /home/LogFiles/AS/monitor.log 2>&1 &
```

**Monitor both — dump on whichever fires first:**
```bash
nohup ./dotnet-dump-threshold.sh --pid 1234 --memory-threshold 85 --thread-threshold 200 > /home/LogFiles/AS/monitor.log 2>&1 &
```

**Run once (single dump when a threshold is exceeded):**
```bash
./dotnet-dump-threshold.sh --pid 1234 --memory-threshold 87 --run-once
```

**Allow at most two dumps:**
```bash
nohup ./dotnet-dump-threshold.sh --pid 1234 --memory-threshold 87 --max-dumps 2 > /home/LogFiles/AS/monitor.log 2>&1 &
```

**Stop the monitor:**
```bash
./dotnet-dump-threshold.sh --stop
```

## How It Works

The script continuously monitors the specified process by:

1. **Memory Monitoring:** Reads RSS (Resident Set Size) from `/proc/<PID>/status` and compares against total system memory (when `--memory-threshold` is specified)
2. **Thread Monitoring:** Reads thread count from `/proc/<PID>/status` (when `--thread-threshold` is specified)
3. **Dump Creation:** When either threshold is exceeded, uses `dotnet-dump collect` to create a memory dump, up to `--max-dumps` times. Both thresholds being over the line in the same cycle still produces a single dump
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
./dotnet-dump-threshold.sh --stop
```

This reads the PID from `/tmp/dotnet-dump-monitor.pid` and terminates the process gracefully.

## Troubleshooting

- **Permission Issues:** Ensure the script has access to `/proc/<PID>/` and write permissions to `/home/LogFiles/AS/`
- **dotnet-dump Not Found:** Verify `dotnet-dump` is installed at `/tools/dotnet-dump` or update `DOTNET_DUMP_CMD` in the script
- **Process Not Found:** Confirm the PID is correct and the process is still running
- **Stale PID File:** If the monitor doesn't stop properly, manually remove `/tmp/dotnet-dump-monitor.pid`

## Configuration

You can modify these defaults in the script:
- `DEFAULT_MEM_THRESHOLD`: Memory threshold used when no threshold is specified (85%)
- `MAX_DUMPS`: Dump cap (3)
- `DOTNET_DUMP_CMD`: Path to dotnet-dump executable
- `DUMP_DIR`: Directory for saving dumps
- `SLEEP_SECONDS`: Monitoring interval (10 seconds)