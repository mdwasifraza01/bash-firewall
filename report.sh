#!/usr/bin/env bash
#
# report.sh - summarise packets blocked by fw.sh.
#
# Reads firewall log lines (prefix "FW-DROP:") and prints the most frequent
# source IPs, destination ports and protocols.
#
# Usage: ./report.sh [-n top] [-l logfile]
#   -n N     how many entries to show per table (default: 10)
#   -l FILE  log file to read (default: /var/log/firewall.log if present,
#            otherwise the kernel log via journalctl / kern.log / dmesg)

set -euo pipefail

TOP=10
LOG_FILE="${FW_LOG_FILE:-/var/log/firewall.log}"

while getopts "n:l:h" opt; do
    case $opt in
        n) TOP=$OPTARG ;;
        l) LOG_FILE=$OPTARG ;;
        h|*) sed -n '2,11p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit 0 ;;
    esac
done

[[ $TOP =~ ^[0-9]+$ && $TOP -ge 1 ]] || { echo "-n must be a positive number" >&2; exit 1; }

read_logs() {
    if [[ -r $LOG_FILE ]]; then
        cat "$LOG_FILE"
    elif command -v journalctl >/dev/null 2>&1 && journalctl -k --no-pager >/dev/null 2>&1; then
        journalctl -k --no-pager
    elif [[ -r /var/log/kern.log ]]; then
        cat /var/log/kern.log
    else
        dmesg 2>/dev/null || true
    fi
}

LOGS=$( { read_logs | grep 'FW-DROP:'; } || true )

if [[ -z $LOGS ]]; then
    echo "No blocked packets found in the logs yet."
    echo "(Trigger some with: nmap -Pn <this-host> from another machine.)"
    exit 0
fi

# top_field <FIELD>  e.g. SRC, DPT, PROTO
top_field() {
    { grep -oE "\\b$1=[^ ]+" <<< "$LOGS" \
        | cut -d= -f2 \
        | sort | uniq -c | sort -rn \
        | head -n "$TOP" \
        | awk '{printf "  %7d  %s\n", $1, $2}'; } || true
}

total=$(grep -c . <<< "$LOGS")

echo "=== Firewall report ==="
echo "Total blocked packets logged: $total"
echo
echo "--- Top $TOP source IPs ---"
top_field SRC
echo
echo "--- Top $TOP targeted ports ---"
top_field DPT
echo
echo "--- Protocols ---"
top_field PROTO
