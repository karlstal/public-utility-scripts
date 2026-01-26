
#!/bin/bash

# ----------------------------
# Default Values
# ----------------------------
THRESHOLD=85
PID=""
RUN_ONCE=false
LOCKFILE="/tmp/memory-monitor.lock"
DUMP_DIR="/home/LogFiles/AS"

# ----------------------------
# Parse Parameters
# ----------------------------
while [[ "$#" -gt 0 ]]; do
    case $1 in
        --threshold) THRESHOLD="$2"; shift ;;
        --pid) PID="$2"; shift ;;
        --run-once) RUN_ONCE=true ;;
        *) echo "Unknown parameter: $1"; exit 1 ;;
    esac
    shift
done

# ----------------------------
# Validate PID provided
# ----------------------------
if [ -z "$PID" ]; then
    echo "Error: You must specify --pid <process_id>"
    exit 1
fi

# ----------------------------
# Validate PID exists
# ----------------------------
if [ ! -d "/proc/$PID" ]; then
    echo "Error: Process with PID $PID does not exist"
    exit 1
fi

# ----------------------------
# Ensure only one instance runs
# ----------------------------
if [ -f "$LOCKFILE" ]; then
    echo "Monitor already running. Exiting."
    exit 0
fi

echo $$ > "$LOCKFILE"

# ----------------------------
# Ensure dump folder exists
# ----------------------------
mkdir -p "$DUMP_DIR"

echo "Monitoring PID $PID with memory threshold ${THRESHOLD}%..."
echo "Dump directory: $DUMP_DIR"

# ----------------------------
# Monitoring loop
# ----------------------------
while true; do
    TOTAL=$(grep MemTotal /proc/meminfo | awk '{print $2}')
    USED=$(grep VmRSS /proc/$PID/status | awk '{print $2}')
    PERCENT=$((100 * USED / TOTAL))

    if [ $PERCENT -ge $THRESHOLD ]; then
        TIMESTAMP=$(date +%Y%m%d_%H%M%S)
        DUMP_PATH="$DUMP_DIR/dump_$TIMESTAMP.dmp"

        echo "Memory threshold exceeded: ${PERCENT}%. Creating dump at ${DUMP_PATH}..."
        dotnet-dump collect -p "$PID" -o "$DUMP_PATH"
        echo "Dump complete."

        if [ "$RUN_ONCE" = true ]; then
            echo "Run-once mode enabled. Exiting."
            rm -f "$LOCKFILE"
            exit 0
        fi
    fi

    sleep 10
done
