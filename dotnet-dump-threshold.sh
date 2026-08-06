#!/usr/bin/env bash
#INSTRUCTIONS
# Collects a dotnet-dump when a process crosses a memory and/or thread-count
# threshold. Either trigger can be used on its own, or both together.

# Download script
# curl -L -o /home/site/wwwroot/dotnet-dump-threshold.sh https://raw.githubusercontent.com/karlstal/public-utility-scripts/main/dotnet-dump-threshold.sh

#change permissions to allow running as executable
# chmod +x /home/site/wwwroot/dotnet-dump-threshold.sh

# cd /home/site/wwwroot

# Get PID of dotnet process
# ps aux | grep dotnet


# This starts the script in the background (nohup ending in & does this)
# nohup bash /home/site/wwwroot/dotnet-dump-threshold.sh --pid 39 --memory-threshold 87 --run-once \
# > /home/LogFiles/AS/monitor.log 2>&1 &

# Both triggers at once:
# nohup bash /home/site/wwwroot/dotnet-dump-threshold.sh --pid 39 --memory-threshold 87 --thread-threshold 200 \
# > /home/LogFiles/AS/monitor.log 2>&1 &

# Without --run-once the monitor writes at most 3 dumps (override with --max-dumps)
# and then exits, so it cannot fill the /home file share.


# To stop the script run this.
# /home/site/wwwroot/dotnet-dump-threshold.sh --stop

# Once dump is complete, download it from the LogFiles/AS folder path in the azure app service file manager (accessible with /newui path).

set -u

# ----------------------------
# Defaults
# ----------------------------
# Both triggers are optional and independent. Empty means "not monitored".
# If neither is given, memory monitoring falls back to DEFAULT_MEM_THRESHOLD.
MEM_THRESHOLD=""
THREAD_THRESHOLD=""
DEFAULT_MEM_THRESHOLD=85

TARGET_PID=""
RUN_ONCE=false
STOP=false

# Hard cap on how many dumps this monitor will ever write, so a process that
# stays above the threshold cannot fill the /home file share.
MAX_DUMPS=3

# Give up if dotnet-dump fails this many times in a row.
MAX_CONSECUTIVE_FAILURES=3

# Path to dotnet-dump executable; override if needed
DOTNET_DUMP_CMD="/tools/dotnet-dump"

PIDFILE="/tmp/dotnet-dump-monitor.pid"
DUMP_DIR="/home/LogFiles/AS"
SLEEP_SECONDS=10

usage() {
  cat <<EOF
Usage:
  Start monitoring:
    $0 --pid <dotnet_pid> [--memory-threshold <percent>] [--thread-threshold <count>]
       [--max-dumps <count>] [--run-once]

  A dump is collected when EITHER threshold is crossed. Specify one or both;
  a threshold that is not given is not monitored. With neither, memory
  monitoring defaults to ${DEFAULT_MEM_THRESHOLD}%.

  --threshold is accepted as an alias for --memory-threshold.

  At most --max-dumps dumps (default $MAX_DUMPS) are written before the monitor exits.

  If dotnet-dump is not in your PATH, set DOTNET_DUMP_CMD in the script or
  make sure the executable exists at /tools/dotnet-dump.

  Stop monitoring (kills the background monitor started earlier):
    $0 --stop

Examples:
  # memory only, single dump
  nohup $0 --pid 1234 --memory-threshold 87 --run-once > /home/LogFiles/AS/monitor.log 2>&1 &

  # threads only
  nohup $0 --pid 1234 --thread-threshold 200 > /home/LogFiles/AS/monitor.log 2>&1 &

  # both triggers, at most 2 dumps
  nohup $0 --pid 1234 --memory-threshold 87 --thread-threshold 200 --max-dumps 2 > /home/LogFiles/AS/monitor.log 2>&1 &

  $0 --stop
EOF
}

require_value() {
  # $1 = flag name, $2 = value (may be empty/unset)
  if [[ -z "${2:-}" ]]; then
    echo "Error: $1 requires a value."
    usage
    exit 1
  fi
}

# Positive integer check; guards against typos such as --threshold 8o, which
# bash arithmetic would otherwise silently evaluate as 0 and dump immediately.
require_uint() {
  # $1 = flag name, $2 = value, $3 = min, $4 = max (optional)
  if [[ ! "$2" =~ ^[0-9]+$ ]]; then
    echo "Error: $1 must be a whole number (got '$2')."
    exit 1
  fi
  if [[ "$2" -lt "$3" ]] || { [[ -n "${4:-}" ]] && [[ "$2" -gt "$4" ]]; }; then
    echo "Error: $1 is out of range (got '$2')."
    exit 1
  fi
}

# ----------------------------
# Parse Parameters
# ----------------------------
while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --memory-threshold|--threshold) require_value "$1" "${2:-}"; MEM_THRESHOLD="$2"; shift ;;
    --pid) require_value "$1" "${2:-}"; TARGET_PID="$2"; shift ;;
    --thread-threshold) require_value "$1" "${2:-}"; THREAD_THRESHOLD="$2"; shift ;;
    --max-dumps) require_value "$1" "${2:-}"; MAX_DUMPS="$2"; shift ;;
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

# Nothing to watch: keep the historical behaviour of monitoring memory.
if [[ -z "$MEM_THRESHOLD" && -z "$THREAD_THRESHOLD" ]]; then
  MEM_THRESHOLD="$DEFAULT_MEM_THRESHOLD"
  echo "No threshold specified; defaulting to --memory-threshold ${MEM_THRESHOLD}."
fi

require_uint "--pid" "$TARGET_PID" 1
require_uint "--max-dumps" "$MAX_DUMPS" 1
[[ -n "$MEM_THRESHOLD" ]] && require_uint "--memory-threshold" "$MEM_THRESHOLD" 1 100
[[ -n "$THREAD_THRESHOLD" ]] && require_uint "--thread-threshold" "$THREAD_THRESHOLD" 1

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

# Always clean up PID file on exit (including kill/term).
# The signal handler must exit explicitly: bash defers the trap until the
# current 'sleep' returns, and without the exit the loop would carry on
# running with the PID file already deleted.
cleanup() { rm -f "$PIDFILE"; }
on_signal() {
  echo "Received termination signal. Stopping monitor."
  cleanup
  exit 143
}
trap cleanup EXIT
trap on_signal INT TERM

# ----------------------------
# Ensure dump folder exists
# ----------------------------
mkdir -p "$DUMP_DIR"

# verify dotnet-dump executable
if [[ ! -x "$DOTNET_DUMP_CMD" ]]; then
  echo "Error: dotnet-dump not found or not executable at $DOTNET_DUMP_CMD"
  exit 1
fi

# Read a single field from /proc/<pid>/status; empty if unavailable
read_status_field() {
  grep "^$1:" /proc/"$TARGET_PID"/status 2>/dev/null | awk '{print $2}'
}

echo "Monitoring target PID $TARGET_PID..."
if [[ -n "$MEM_THRESHOLD" ]]; then
  echo "Memory threshold: ${MEM_THRESHOLD}% (current: $(read_status_field VmRSS) kB RSS)"
else
  echo "Memory threshold: not monitored"
fi
if [[ -n "$THREAD_THRESHOLD" ]]; then
  echo "Thread threshold: ${THREAD_THRESHOLD} (current: $(read_status_field Threads) threads)"
else
  echo "Thread threshold: not monitored"
fi
echo "Monitor PID: $$"
echo "Dump directory: $DUMP_DIR"
echo "PID file: $PIDFILE"
if [[ "$RUN_ONCE" == true ]]; then
  echo "Maximum dumps: 1 (--run-once)"
else
  echo "Maximum dumps: $MAX_DUMPS"
fi

# ----------------------------
# Monitor Loop
# ----------------------------
DUMP_COUNT=0
FAILURE_COUNT=0

while true; do
  # If the target process exited, stop monitoring
  if [[ ! -d "/proc/$TARGET_PID" ]]; then
    echo "Target PID $TARGET_PID no longer exists. Exiting monitor."
    exit 0
  fi

  DUMP_TRIGGERED=false

  # The target can exit between the /proc check above and these reads, which
  # leaves the values empty. Warn and skip; the check at the top of the next
  # iteration exits cleanly.
  if [[ -n "$MEM_THRESHOLD" ]]; then
    TOTAL=$(grep '^MemTotal:' /proc/meminfo 2>/dev/null | awk '{print $2}')
    USED=$(read_status_field VmRSS)

    if [[ -z "$USED" || -z "$TOTAL" || "$TOTAL" -eq 0 ]]; then
      echo "Warning: could not read memory counters for PID $TARGET_PID. Skipping this check."
    else
      PERCENT=$((100 * USED / TOTAL))
      if [[ "$PERCENT" -ge "$MEM_THRESHOLD" ]]; then
        echo "Memory threshold exceeded: ${PERCENT}% >= ${MEM_THRESHOLD}% (PID $TARGET_PID)."
        DUMP_TRIGGERED=true
      fi
    fi
  fi

  if [[ -n "$THREAD_THRESHOLD" ]]; then
    THREADS=$(read_status_field Threads)

    if [[ -z "$THREADS" ]]; then
      echo "Warning: could not read thread count for PID $TARGET_PID. Skipping this check."
    elif [[ "$THREADS" -ge "$THREAD_THRESHOLD" ]]; then
      echo "Thread threshold exceeded: ${THREADS} >= ${THREAD_THRESHOLD} threads (PID $TARGET_PID)."
      DUMP_TRIGGERED=true
    fi
  fi

  if [[ "$DUMP_TRIGGERED" == true ]]; then
    if [[ "$RUN_ONCE" == true ]]; then
      DUMP_LIMIT=1
    else
      DUMP_LIMIT="$MAX_DUMPS"
    fi

    TIMESTAMP=$(date +%Y%m%d_%H%M%S)
    DUMP_PATH="$DUMP_DIR/dump_${TARGET_PID}_${TIMESTAMP}.dmp"

    echo "Creating dump $((DUMP_COUNT + 1)) of ${DUMP_LIMIT} at ${DUMP_PATH}..."
    if "$DOTNET_DUMP_CMD" collect -p "$TARGET_PID" -o "$DUMP_PATH"; then
      DUMP_COUNT=$((DUMP_COUNT + 1))
      FAILURE_COUNT=0
      echo "Dump complete (${DUMP_COUNT}/${DUMP_LIMIT}): $DUMP_PATH"
    else
      RC=$?
      FAILURE_COUNT=$((FAILURE_COUNT + 1))
      echo "Error: dotnet-dump exited with code $RC. No usable dump at $DUMP_PATH."
      if [[ "$FAILURE_COUNT" -ge "$MAX_CONSECUTIVE_FAILURES" ]]; then
        echo "dotnet-dump failed $FAILURE_COUNT times in a row. Exiting monitor."
        exit 1
      fi
    fi

    if [[ "$DUMP_COUNT" -ge "$DUMP_LIMIT" ]]; then
      echo "Maximum dump count (${DUMP_LIMIT}) reached. Exiting monitor."
      exit 0
    fi
  fi

  sleep "$SLEEP_SECONDS"
done
