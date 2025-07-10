#!/bin/bash

# Run the following command to download this script and make it executable:
# curl -s https://raw.githubusercontent.com/karlstal/public-utility-scripts/refs/heads/main/http-deps.sh -o http-deps.sh && chmod +x http-deps.sh
# When done is can be run as follows:
# ./http-deps.sh

# Script for polling current connections, excluding incoming connections
# on ports 80, 443, and 2222, but including outgoing connections to those ports.

# Install netstat if missing
if ! command -v netstat &> /dev/null; then
    echo "net-tools not found. Installing..."
    apt-get update && apt-get install -y net-tools
fi

# Default: do not group by PID
GROUP_BY_PID=0

# Parse args
for arg in "$@"; do
    if [[ "$arg" == "--group-by-pid" || "$arg" == "-p" ]]; then
        GROUP_BY_PID=1
    fi
done

# Sorting logic
if [[ $GROUP_BY_PID -eq 1 ]]; then
    SORT_CMD='sort -k4,4nr'
else
    SORT_CMD='sort -k4,4nr'
fi

while true; do
    echo "Polling current connections, specifically excluding incoming connections on ports 80, 443, and 2222..."
    echo ""

    printf "%-45s %-8s %-20s %-8s %s\n" "Remote Address:Port" "PID" "Process" "Total" "States (Count)"
    printf '%.0s-' {1..100}; echo

    netstat -natp 2>/dev/null | awk -v group_by_pid="$GROUP_BY_PID" '
    /ESTABLISHED|TIME_WAIT|CLOSE_WAIT|FIN_WAIT/ {
        split($4, laddr, ":");
        split($5, faddr, ":");
        localPort = (length(laddr) > 2 ? laddr[length(laddr)] : laddr[2]);
        foreignAddr = $5;
        state = $6;

        split($7, pidprog, "/");
        pid = pidprog[1];
        prog = pidprog[2];

        if (pid == "" || pid == "-") pid = "N/A";
        if (prog == "" || prog == "-") prog = "kernel";

        if (localPort !~ /^(80|443|2222)$/) {
            key = foreignAddr;
            if (group_by_pid == 1) {
                key = key " " pid " " prog;
            } else {
                key = key " " prog;
            }
            state_counts[key " " state]++;
            total_counts[key]++;
            pid_map[key] = pid;
            prog_map[key] = prog;
        }
    }
    END {
        for (k in total_counts) {
            split(k, parts, " ");
            remote = parts[1];
            if (group_by_pid == 1) {
                pid = parts[2];
                prog = parts[3];
            } else {
                pid = pid_map[k];
                prog = prog_map[k];
            }

            key_base = k;
            slen = 0;
            delete state_list_arr;
            for (s in state_counts) {
                if (s ~ "^" key_base " ") {
                    split(s, segs, " ");
                    state = segs[length(segs)];
                    state_list_arr[slen++] = state "(" state_counts[s] ")";
                }
            }

            state_list = state_list_arr[0];
            for (i = 1; i < slen; i++) {
                state_list = state_list " " state_list_arr[i];
            }

            printf "%-45s %-8s %-20s %-8d %s\n", remote, pid, prog, total_counts[k], state_list;
        }
    }' | eval "$SORT_CMD"

    printf '%.0s-' {1..100}; echo
    echo "Poll complete. Waiting for 10 seconds..."
    sleep 10
    echo ""
done
