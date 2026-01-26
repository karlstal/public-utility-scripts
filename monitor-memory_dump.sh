#INSTRUCTIONS
# Download script
# curl -L -o /home/site/wwwroot/monitor-memory_dump.sh https://raw.githubusercontent.com/karlstal/public-utility-scripts/main/monitor-memory_dump.sh

#change permissions to allow running as executable
# chmod +x /home/site/wwwroot/monitor-memory_dump.sh

# cd /home/site/wwwroot

# Get PID of dotnet process
# ps aux | grep dotnet


# This starts the script in the background (nohup ending in & does this)
# nohup bash /home/site/wwwroot/monitor-memory_dump.sh --pid 39 --threshold 87 --run-once \
# > /home/LogFiles/AS/monitor.log 2>&1 &


# To stop the script run this. 
# /home/site/wwwroot/monitor-memory_dump.sh --stop

# Once dump is complete, download it from the LogFiles/AS folder path in the azure app service file manager (accessible with /newui path). 

#!/usr/bin/env bash
set -u

# ----------------------------
# Defaults
# ----------------------------
THRESHOLD=85
TARGET_PID=""
RUN_ONCE=false
STOP=false

PIDFILE="/tmp/memory-monitor.pid"
DUMP_DIR="/home/LogFiles/AS"
SLEEP_SECONDS=10

usage() {
  cat <<EOF
Usage:
  Start monitoring:
    $0 --pid <dotnet_pid> [--threshold <percent>] [--run-once]

  Stop monitoring (kills the background monitor started earlier):
    $0 --stop

Examples:
  nohup $0 --pid 1234 --threshold 87 --run-once > /home/LogFiles/AS/monitor.log 2>&1 &
  $0 --stop
EOF
}

# ----------------------------
# Parse Parameters
# ----------------------------
while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --threshold) THRESHOLD="$2"; shift ;;
    --pid) TARGET_PID="$2"; shift ;;
    --run-once) RUN_ONCE=true ;;
    --stop) STOP=true ;;
    --help|-h) usage; exit 0 ;;
    *) echo "Unknown parameter: $1"; usage; exit 1 ;;
  esac
  shift
done

# ----------------------------
# Stop mode
# ----------------------------
if [[ "$STOP" == true ]]; then
  if [[ ! -f "$PIDFILE" ]]; then
    echo "No PID file found at $PIDFILE. Monitor may not be running."
    exit 0
  fi

  MON_PID="$(cat "$PIDFILE" 2>/dev/null || true)"

  if [[ -z "${MON_PID:-}" ]]; then
    echo "PID file exists but is empty/corrupt. Removing $PIDFILE."
    rm -f "$PIDFILE"
    exit 1
  fi

  if [[ -d "/proc/$MON_PID" ]]; then
    echo "Stopping monitor (PID $MON_PID)..."
    kill "$MON_PID" 2>/dev/null || true

    # Wait briefly for it to exit
    for _ in {1..10}; do
      [[ -d "/proc/$MON_PID" ]] || break
      sleep 1
    done

    # If still running, force kill
    if [[ -d "/proc/$MON_PID" ]]; then
      echo "Monitor did not stop gracefully; forcing kill -9..."
      kill -9 "$MON_PID" 2>/dev/null || true
    fi

    echo "Monitor stopped."
  else
    echo "Monitor PID $MON_PID is not running. Cleaning up stale PID file."
  fi

  rm -f "$PIDFILE"
  exit 0
fi

# ----------------------------
# Start mode validation
# ----------------------------
if [[ -z "$TARGET_PID" ]]; then
  echo "Error: You must specify --pid <process_id> (unless using --stop)."
  usage
  exit 1
fi

if [[ ! -d "/proc/$TARGET_PID" ]]; then
  echo "Error: Process with PID $TARGET_PID does not exist."
  exit 1
fi

# ----------------------------
# Ensure only one monitor runs (PID file)
# ----------------------------
if [[ -f "$PIDFILE" ]]; then
  EXISTING="$(cat "$PIDFILE" 2>/dev/null || true)"
  if [[ -n "${EXISTING:-}" && -d "/proc/$EXISTING" ]]; then
    echo "Monitor already running (PID $EXISTING). Use '$0 --stop' to stop it."
    exit 0
  else
    echo "Found stale PID file. Removing $PIDFILE."
    rm -f "$PIDFILE"
  fi
fi

echo "$$" > "$PIDFILE"

# Always clean up PID file on exit (including kill/term)
cleanup() { rm -f "$PIDFILE"; }
trap cleanup EXIT INT TERM

# ----------------------------
# Ensure dump folder exists
# ----------------------------
mkdir -p "$DUMP_DIR"

echo "Monitoring target PID $TARGET_PID with memory threshold ${THRESHOLD}%..."
echo "Monitor PID: $$"
echo "Dump directory: $DUMP_DIR"
echo "PID file: $PIDFILE"

# ----------------------------
# Monitor Loop
# ----------------------------
while true; do
  # If the target process exited, stop monitoring
  if [[ ! -d "/proc/$TARGET_PID" ]]; then
    echo "Target PID $TARGET_PID no longer exists. Exiting monitor."
    exit 0
  fi

  TOTAL=$(grep MemTotal /proc/meminfo | awk '{print $2}')
  USED=$(grep VmRSS /proc/"$TARGET_PID"/status | awk '{print $2}')
  PERCENT=$((100 * USED / TOTAL))

  if [[ "$PERCENT" -ge "$THRESHOLD" ]]; then
    TIMESTAMP=$(date +%Y%m%d_%H%M%S)
    DUMP_PATH="$DUMP_DIR/dump_${TARGET_PID}_${TIMESTAMP}.dmp"

    echo "Threshold exceeded: ${PERCENT}% (PID $TARGET_PID). Creating dump at ${DUMP_PATH}..."
    dotnet-dump collect -p "$TARGET_PID" -o "$DUMP_PATH"
    echo "Dump complete."

    if [[ "$RUN_ONCE" == true ]]; then
      echo "Run-once enabled. Exiting."
      exit 0
    fi
  fi

  sleep "$SLEEP_SECONDS"
done
