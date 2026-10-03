#!/usr/bin/env bash
#
# autoban.sh - ban IPs with repeated failed SSH logins (a tiny fail2ban).
#
# Reads the SSH auth log, counts "Failed password" attempts per IP and bans
# every address at or above the threshold using fw.sh.
#
# Usage: sudo ./autoban.sh [-t threshold] [-l logfile] [-n]
#   -t N     ban after N failed attempts (default: 5)
#   -l FILE  auth log to read (default: /var/log/auth.log, falls back to journalctl)
#   -n       dry run: show what would be banned without banning
#
# Environment:
#   FW_WHITELIST  space-separated IPs that are never banned (default: 127.0.0.1)
#
# Cron example (every 5 minutes):
#   */5 * * * * /opt/bash-firewall/autoban.sh >> /var/log/autoban.log 2>&1

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BLOCKLIST_FILE="${FW_BLOCKLIST_FILE:-$SCRIPT_DIR/blocklist.txt}"
WHITELIST="${FW_WHITELIST:-127.0.0.1}"
THRESHOLD=5
AUTH_LOG="/var/log/auth.log"
DRY=0

while getopts "t:l:nh" opt; do
    case $opt in
        t) THRESHOLD=$OPTARG ;;
        l) AUTH_LOG=$OPTARG ;;
        n) DRY=1 ;;
        h|*) sed -n '2,17p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit 0 ;;
    esac
done

[[ $THRESHOLD =~ ^[0-9]+$ && $THRESHOLD -ge 1 ]] || { echo "threshold must be a positive number" >&2; exit 1; }

read_auth_log() {
    if [[ -r $AUTH_LOG ]]; then
        cat "$AUTH_LOG"
    elif command -v journalctl >/dev/null 2>&1; then
        journalctl -u ssh -u sshd --no-pager 2>/dev/null
    else
        echo "cannot read $AUTH_LOG and journalctl is unavailable" >&2
        return 1
    fi
}

# Output: "<count> <ip>", highest count first.
failed_attempts() {
    read_auth_log \
        | grep 'Failed password' \
        | grep -oE 'from ([0-9]{1,3}\.){3}[0-9]{1,3}' \
        | awk '{print $2}' \
        | sort | uniq -c | sort -rn || true
}

is_whitelisted() {
    local ip=$1 w
    for w in $WHITELIST; do
        [[ $w == "$ip" ]] && return 0
    done
    return 1
}

is_banned() {
    [[ -f $BLOCKLIST_FILE ]] && grep -qxF "$1" "$BLOCKLIST_FILE"
}

banned_now=0
while read -r count ip; do
    [[ -n ${ip:-} ]] || continue
    (( count >= THRESHOLD )) || continue
    if is_whitelisted "$ip"; then
        echo "skip $ip ($count failures) - whitelisted"
        continue
    fi
    if is_banned "$ip"; then
        continue
    fi
    if (( DRY )); then
        echo "would ban $ip ($count failed logins)"
    else
        echo "banning $ip ($count failed logins)"
        "$SCRIPT_DIR/fw.sh" ban "$ip"
    fi
    banned_now=$((banned_now + 1))
done < <(failed_attempts)

echo "done: $banned_now address(es) $( (( DRY )) && echo 'would be' || echo 'newly' ) banned (threshold: $THRESHOLD)"
