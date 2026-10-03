#!/usr/bin/env bash
#
# test_firewall.sh - black-box test of a machine running fw.sh.
#
# Run this from a SECOND machine (another VM or your host), not from the
# firewall machine itself.
#
# Usage: ./test_firewall.sh <target-ip>
#
# Environment:
#   ALLOWED_PORTS  ports your rules.conf allows   (default: "22 80 443")
#   BLOCKED_PORTS  ports that should be dropped   (default: "23 3306 8080")
#   EXPECT_PING    "yes" or "no"                  (default: yes)
#
# A DROPped port times out ("filtered"). An allowed port either connects
# ("open") or is refused instantly ("closed" - nothing is listening, but the
# firewall let the packet through). Both count as reachable.

set -uo pipefail

TARGET=${1:-}
[[ -n $TARGET ]] || { sed -n '2,18p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit 2; }

ALLOWED_PORTS=${ALLOWED_PORTS:-"22 80 443"}
BLOCKED_PORTS=${BLOCKED_PORTS:-"23 3306 8080"}
EXPECT_PING=${EXPECT_PING:-yes}

pass=0
fail=0

probe() {
    local rc=0
    timeout 3 bash -c "exec 3<>/dev/tcp/$1/$2" 2>/dev/null || rc=$?
    case $rc in
        0)   echo open ;;
        124) echo filtered ;;
        *)   echo closed ;;
    esac
}

report() { # report <ok|bad> <message>
    if [[ $1 == ok ]]; then
        printf '  PASS  %s\n' "$2"; pass=$((pass + 1))
    else
        printf '  FAIL  %s\n' "$2"; fail=$((fail + 1))
    fi
}

echo "Testing firewall on $TARGET"
echo

echo "Allowed ports (should be reachable):"
for p in $ALLOWED_PORTS; do
    state=$(probe "$TARGET" "$p")
    if [[ $state != filtered ]]; then report ok "tcp/$p is reachable ($state)"
    else report bad "tcp/$p is filtered but should be allowed"; fi
done

echo
echo "Blocked ports (should be dropped):"
for p in $BLOCKED_PORTS; do
    state=$(probe "$TARGET" "$p")
    if [[ $state == filtered ]]; then report ok "tcp/$p is dropped (filtered)"
    else report bad "tcp/$p answered ($state) but should be dropped"; fi
done

echo
echo "ICMP:"
if ping -c 1 -W 2 "$TARGET" >/dev/null 2>&1; then got=yes; else got=no; fi
if [[ $got == "$EXPECT_PING" ]]; then report ok "ping answered: $got (expected $EXPECT_PING)"
else report bad "ping answered: $got (expected $EXPECT_PING)"; fi

echo
echo "Result: $pass passed, $fail failed"
echo "Tip: for a fuller picture also run:  nmap -Pn -sS -p- $TARGET"
[[ $fail -eq 0 ]]
