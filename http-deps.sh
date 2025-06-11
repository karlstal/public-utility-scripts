#!/bin/bash

# Run the following command to download this script and make it executable:
# curl -s https://raw.githubusercontent.com/karlstal/public-utility-scripts/refs/heads/main/http-deps.sh -o http-deps.sh && chmod +x http-deps.sh
# When done is can be run as follows:
# ./http-deps.sh

 
# Script for polling current connections, excluding incoming connections
# on ports 80, 443, and 2222, but including outgoing connections to those ports.
# This script focuses on readability, correct data presentation, and IPv6 support.
 
# Check if netstat is installed
if ! command -v netstat &> /dev/null; then
    echo "net-tools not found. Installing..."
    apt-get update && apt-get install -y net-tools
fi
 
# Default: do not group by PID
GROUP_BY_PID=0

# Parse arguments
for arg in "$@"; do
    if [[ "$arg" == "--group-by-pid" || "$arg" == "-p" ]]; then
        GROUP_BY_PID=1
    fi
done

while true; do
    echo "Polling current connections, specifically excluding incoming connections on ports 80, 443, and 2222..."
    echo "--------------------------------------------------------------------------------"
    if [[ $GROUP_BY_PID -eq 1 ]]; then
        printf "%-45s %-8s %-8s %s\n" "Remote Address:Port" "PID" "Total" "States (Count)"
    else
        printf "%-45s %-8s %s\n" "Remote Address:Port" "Total" "States (Count)"
    fi
    echo "--------------------------------------------------------------------------------"
    netstat -natp | awk -v group_by_pid="$GROUP_BY_PID" '/ESTABLISHED|TIME_WAIT|CLOSE_WAIT|FIN_WAIT/ {
        split($4, laddr, ":");
        split($5, faddr, ":");
        if (length(laddr) > 2) { localPort=laddr[length(laddr)]; } else { localPort=laddr[2]; }
        if (length(faddr) > 2) { foreignPort=faddr[length(faddr)]; } else { foreignPort=faddr[2]; }
        split($7, pidprog, "/");
        pid = pidprog[1];
        if (localPort !~ /^(80|443|2222)$/)
            print $5, $6, pid
    }' | sort | uniq -c | sort -rn | \
    awk -v group_by_pid="$GROUP_BY_PID" '{
        # $2 = Remote Address:Port, $3 = State, $4 = PID
        if (group_by_pid == 1) {
            key = $2 " " $4;
            remote_addr = $2;
            pid = $4;
        } else {
            key = $2;
            remote_addr = $2;
            pid = "";
        }
        remote_addr_pid_state[key " " $3]+=$1;
        remote_addr_pid_total[key]+=$1;
        states[key]=states[key] " " $3 "(" $1 ")";
    }
    END {
        for (key in remote_addr_pid_total) {
            split(key, arr, " ");
            remote_addr = arr[1];
            pid = (group_by_pid == 1 ? arr[2] : "");
            if (group_by_pid == 1)
                printf "%-45s %-8s %-8d %s\n", remote_addr, pid, remote_addr_pid_total[key], states[key];
            else
                printf "%-45s %-8d %s\n", remote_addr, remote_addr_pid_total[key], states[key];
        }
    }' | sort -k3,3nr
    echo "--------------------------------------------------------------------------------"
    echo "Poll complete. Waiting for 10 seconds..."
    sleep 10
    echo ""
done