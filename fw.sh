#!/usr/bin/env bash
#
# fw.sh - Bash Firewall Manager
#
# A small, readable iptables-based firewall manager driven by a simple
# rules file (rules.conf). Intended for learning and for Linux lab VMs.
#
# Usage: sudo ./fw.sh <command> [args]     (run ./fw.sh help for details)
#
# Set FW_DRY_RUN=1 to print the iptables commands instead of running them.

set -euo pipefail

VERSION="1.0.0"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RULES_FILE="${FW_RULES_FILE:-$SCRIPT_DIR/rules.conf}"
BLOCKLIST_FILE="${FW_BLOCKLIST_FILE:-$SCRIPT_DIR/blocklist.txt}"
BACKUP_DIR="${FW_BACKUP_DIR:-$SCRIPT_DIR/backups}"
LOG_PREFIX="FW-DROP: "
SSH_PORT="${FW_SSH_PORT:-22}"
SSH_RATE_HITS="${FW_SSH_RATE_HITS:-4}"       # new SSH connections ...
SSH_RATE_SECONDS="${FW_SSH_RATE_SECONDS:-60}" # ... allowed per this many seconds
DRY_RUN="${FW_DRY_RUN:-0}"

# ---------------------------------------------------------------- helpers --

if [[ -t 1 ]]; then
    RED=$'\033[31m'; GREEN=$'\033[32m'; YELLOW=$'\033[33m'; RESET=$'\033[0m'
else
    RED=""; GREEN=""; YELLOW=""; RESET=""
fi

info() { printf '%s[+]%s %s\n' "$GREEN" "$RESET" "$*"; }
warn() { printf '%s[!]%s %s\n' "$YELLOW" "$RESET" "$*" >&2; }
die()  { printf '%s[x]%s %s\n' "$RED" "$RESET" "$*" >&2; exit 1; }

# Run iptables, or just print the command in dry-run mode.
ipt() {
    if [[ "$DRY_RUN" == "1" ]]; then
        echo "[dry-run] iptables $*"
    else
        iptables "$@"
    fi
}

need_root() {
    [[ "$DRY_RUN" == "1" ]] && return 0
    [[ $EUID -eq 0 ]] || die "this command must be run as root (use sudo)"
    command -v iptables >/dev/null 2>&1 || die "iptables is not installed"
}

# True if our firewall chains are currently loaded.
is_active() {
    iptables -n -L FW_RULES >/dev/null 2>&1
}

usage() {
    cat <<EOF
Bash Firewall Manager v$VERSION

Usage: sudo $0 <command> [arguments]

Firewall control:
  start                         Apply the firewall (default: drop all incoming)
  stop                          Remove all rules and accept all traffic
  restart                       Re-apply the firewall from rules.conf
  status                        Show whether it is active, plus live counters

Rule management (edits rules.conf, reloads if active):
  list                          Show the rules in rules.conf (numbered)
  add <allow|deny> <proto> [port] [source]
                                e.g.  add allow tcp 8080
                                      add allow tcp 22 192.168.1.0/24
                                      add deny udp 5353
                                      add allow icmp
  remove <number>               Remove rule number N (see 'list')

IP blocking:
  ban <ip[/cidr]>               Block an address (survives restarts)
  unban <ip[/cidr]>             Remove an address from the blocklist
  banned                        List blocked addresses

Backup and reporting:
  save                          Save current iptables state to backups/
  restore [file]                Restore latest (or given) backup
  report [-n N]                 Top blocked IPs / ports from the logs

Environment:
  FW_DRY_RUN=1                  Print iptables commands without running them
  FW_RULES_FILE, FW_BLOCKLIST_FILE, FW_BACKUP_DIR, FW_SSH_PORT
EOF
}

# ------------------------------------------------------------- validation --

valid_port() {
    local p=$1 a b
    if [[ $p =~ ^[0-9]+$ ]]; then
        (( 10#$p >= 1 && 10#$p <= 65535 ))
    elif [[ $p =~ ^([0-9]+):([0-9]+)$ ]]; then
        a=${BASH_REMATCH[1]}; b=${BASH_REMATCH[2]}
        (( 10#$a >= 1 && 10#$b <= 65535 && 10#$a <= 10#$b ))
    else
        return 1
    fi
}

valid_ip() {
    local ip=$1 addr mask octet
    [[ $ip =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}(/[0-9]{1,2})?$ ]] || return 1
    addr=${ip%%/*}
    if [[ $ip == */* ]]; then
        mask=${ip##*/}
        (( 10#$mask <= 32 )) || return 1
    fi
    local IFS=.
    for octet in $addr; do
        (( 10#$octet <= 255 )) || return 1
    done
}

# Validate a parsed rule; prints a reason on failure.
validate_rule() {
    local action=$1 proto=$2 port=$3 src=$4
    [[ $action == allow || $action == deny ]] \
        || { echo "action must be 'allow' or 'deny'"; return 1; }
    case $proto in
        tcp|udp)
            [[ -n $port ]] || { echo "a port is required for $proto"; return 1; }
            valid_port "$port" || { echo "invalid port '$port' (use 1-65535 or a range like 8000:8100)"; return 1; }
            ;;
        icmp) ;;
        *) echo "protocol must be tcp, udp or icmp"; return 1 ;;
    esac
    if [[ -n $src ]] && ! valid_ip "$src"; then
        echo "invalid source address '$src'"
        return 1
    fi
}

# Parse one rules.conf line into R_ACTION / R_PROTO / R_PORT / R_SRC.
# Returns 2 for blank/comment lines, 1 for malformed lines.
parse_rule_line() {
    local line=${1%%#*}
    local -a f
    local max=4
    read -r -a f <<< "$line"
    (( ${#f[@]} )) || return 2
    R_ACTION=${f[0],,}
    R_PROTO=${f[1]:-}
    R_PROTO=${R_PROTO,,}
    R_PORT=""
    R_SRC=""
    if [[ $R_PROTO == icmp ]]; then
        max=3
        R_SRC=${f[2]:-}
    else
        R_PORT=${f[2]:-}
        R_SRC=${f[3]:-}
    fi
    (( ${#f[@]} <= max )) || return 1
}

count_rules() {
    local n=0 line rc
    [[ -f $RULES_FILE ]] || { echo 0; return; }
    while IFS= read -r line || [[ -n $line ]]; do
        rc=0; parse_rule_line "$line" || rc=$?
        [[ $rc -eq 2 ]] && continue
        n=$((n + 1))
    done < "$RULES_FILE"
    echo "$n"
}

# ------------------------------------------------------------ rule loading --

apply_rule() {
    local target args
    if [[ $R_ACTION == allow ]]; then target=ACCEPT; else target=FW_LOG; fi
    args=(-A FW_RULES -p "$R_PROTO")
    [[ -n $R_SRC ]] && args+=(-s "$R_SRC")
    if [[ $R_PROTO == icmp ]]; then
        args+=(--icmp-type echo-request)
    else
        args+=(--dport "$R_PORT")
    fi
    ipt "${args[@]}" -j "$target"
}

load_rules() {
    [[ -f $RULES_FILE ]] || die "rules file not found: $RULES_FILE"
    local line lineno=0 n=0 rc msg
    while IFS= read -r line || [[ -n $line ]]; do
        lineno=$((lineno + 1))
        rc=0; parse_rule_line "$line" || rc=$?
        [[ $rc -eq 2 ]] && continue
        if [[ $rc -ne 0 ]]; then
            warn "$RULES_FILE:$lineno skipped (too many fields): $line"
            continue
        fi
        if ! msg=$(validate_rule "$R_ACTION" "$R_PROTO" "$R_PORT" "$R_SRC"); then
            warn "$RULES_FILE:$lineno skipped ($msg): $line"
            continue
        fi
        apply_rule
        n=$((n + 1))
    done < "$RULES_FILE"
    info "loaded $n rule(s) from $(basename "$RULES_FILE")"
}

load_blocklist() {
    local ip n=0
    [[ -f $BLOCKLIST_FILE ]] || return 0
    while IFS= read -r ip || [[ -n $ip ]]; do
        ip=${ip%%#*}; ip=${ip//[[:space:]]/}
        [[ -z $ip ]] && continue
        if valid_ip "$ip"; then
            ipt -A FW_BLOCKLIST -s "$ip" -j FW_LOG
            n=$((n + 1))
        else
            warn "blocklist: ignoring invalid entry '$ip'"
        fi
    done < "$BLOCKLIST_FILE"
    info "loaded $n blocked address(es)"
}

# Warn (don't fail) if the ruleset would lock out SSH.
check_ssh_rule() {
    if ! grep -Eqi "^[[:space:]]*allow[[:space:]]+tcp[[:space:]]+${SSH_PORT}([[:space:]]|$)" "$RULES_FILE" 2>/dev/null; then
        warn "no 'allow tcp $SSH_PORT' rule found - if you are connected over SSH you will be locked out!"
    fi
}

# -------------------------------------------------------------- commands ---

cmd_start() {
    need_root
    [[ -f $RULES_FILE ]] || die "rules file not found: $RULES_FILE"
    check_ssh_rule
    info "applying firewall..."

    # Start from a clean slate (flush rules, delete our chains).
    ipt -P INPUT ACCEPT
    ipt -P FORWARD ACCEPT
    ipt -P OUTPUT ACCEPT
    ipt -F
    ipt -X

    # Our own chains keep the ruleset organised and easy to reload.
    ipt -N FW_BLOCKLIST   # banned IPs
    ipt -N FW_GUARD       # scan / flood protection
    ipt -N FW_RULES       # user rules from rules.conf
    ipt -N FW_LOG         # log (rate limited) and drop

    # Logging chain: log at a limited rate so a flood cannot fill the disk.
    ipt -A FW_LOG -m limit --limit 10/minute --limit-burst 20 \
        -j LOG --log-prefix "$LOG_PREFIX" --log-level 4
    ipt -A FW_LOG -j DROP

    # Guard chain: drop malformed scan packets and limit floods.
    ipt -A FW_GUARD -p tcp --tcp-flags ALL NONE -j DROP          # NULL scan
    ipt -A FW_GUARD -p tcp --tcp-flags ALL ALL -j DROP           # XMAS scan
    ipt -A FW_GUARD -p tcp --tcp-flags SYN,FIN SYN,FIN -j DROP
    ipt -A FW_GUARD -p tcp --tcp-flags SYN,RST SYN,RST -j DROP
    ipt -A FW_GUARD -p tcp --syn -m limit --limit 50/second --limit-burst 100 -j RETURN
    ipt -A FW_GUARD -p tcp --syn -j DROP                         # SYN flood
    ipt -A FW_GUARD -p icmp --icmp-type echo-request -m limit --limit 5/second --limit-burst 10 -j RETURN
    ipt -A FW_GUARD -p icmp --icmp-type echo-request -j DROP     # ping flood
    # SSH brute-force throttle: too many NEW connections per window are dropped.
    ipt -A FW_GUARD -p tcp --dport "$SSH_PORT" -m conntrack --ctstate NEW \
        -m recent --name SSH --set
    ipt -A FW_GUARD -p tcp --dport "$SSH_PORT" -m conntrack --ctstate NEW \
        -m recent --name SSH --update --seconds "$SSH_RATE_SECONDS" --hitcount "$SSH_RATE_HITS" -j DROP

    # INPUT chain order matters: loopback, replies, bad packets, then ours.
    ipt -A INPUT -i lo -j ACCEPT
    ipt -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    ipt -A INPUT -m conntrack --ctstate INVALID -j DROP
    ipt -A INPUT -j FW_BLOCKLIST
    ipt -A INPUT -j FW_GUARD
    ipt -A INPUT -j FW_RULES
    ipt -A INPUT -j FW_LOG

    load_blocklist
    load_rules

    # Default policies last, so we never lock ourselves out mid-way.
    ipt -P INPUT DROP
    ipt -P FORWARD DROP
    ipt -P OUTPUT ACCEPT

    info "firewall is ACTIVE (default: drop incoming, allow outgoing)"
}

cmd_stop() {
    need_root
    ipt -P INPUT ACCEPT
    ipt -P FORWARD ACCEPT
    ipt -P OUTPUT ACCEPT
    ipt -F
    ipt -X
    info "firewall is STOPPED (all traffic allowed)"
}

cmd_restart() {
    cmd_start
}

cmd_status() {
    if [[ "$DRY_RUN" == "1" ]]; then
        info "dry-run mode: status needs a real firewall to query"
        return 0
    fi
    need_root
    if is_active; then
        info "firewall is ACTIVE"
    else
        warn "firewall is INACTIVE (run: sudo $0 start)"
    fi
    echo
    echo "== Default policies =="
    iptables -S | grep -- '^-P' || true
    echo
    echo "== INPUT chain =="
    iptables -L INPUT -n -v --line-numbers
    if is_active; then
        echo
        echo "== FW_RULES (packet/byte counters) =="
        iptables -L FW_RULES -n -v --line-numbers
        echo
        echo "== FW_BLOCKLIST =="
        iptables -L FW_BLOCKLIST -n -v --line-numbers
    fi
}

cmd_list() {
    [[ -f $RULES_FILE ]] || die "rules file not found: $RULES_FILE"
    local i=0 line rc
    printf '%-4s %-7s %-6s %-12s %s\n' "#" "ACTION" "PROTO" "PORT" "SOURCE"
    while IFS= read -r line || [[ -n $line ]]; do
        rc=0; parse_rule_line "$line" || rc=$?
        [[ $rc -eq 2 ]] && continue
        i=$((i + 1))
        printf '%-4s %-7s %-6s %-12s %s\n' "$i" "$R_ACTION" "$R_PROTO" "${R_PORT:--}" "${R_SRC:-any}"
    done < "$RULES_FILE"
    (( i > 0 )) || echo "(no rules defined)"
}

cmd_add() {
    [[ $# -ge 2 ]] || die "usage: add <allow|deny> <tcp|udp|icmp> [port] [source]"
    local rc=0 msg
    parse_rule_line "$*" || rc=$?
    [[ $rc -eq 0 ]] || die "malformed rule: $*"
    if ! msg=$(validate_rule "$R_ACTION" "$R_PROTO" "$R_PORT" "$R_SRC"); then
        die "$msg"
    fi
    echo "$*" >> "$RULES_FILE"
    info "added: $*"
    if is_active 2>/dev/null; then
        cmd_start
    else
        info "firewall not active - rule will apply on next start"
    fi
}

cmd_remove() {
    local n=${1:-}
    [[ $n =~ ^[0-9]+$ ]] || die "usage: remove <number>   (see '$0 list')"
    local total tmp
    total=$(count_rules)
    (( n >= 1 && n <= total )) || die "no rule number $n (there are $total)"
    tmp=$(mktemp)
    awk -v n="$n" '
        { line = $0; sub(/#.*/, "", line)
          if (line ~ /[^[:space:]]/) { c++; if (c == n) next }
          print }
    ' "$RULES_FILE" > "$tmp"
    cat "$tmp" > "$RULES_FILE"   # keep original file ownership/permissions
    rm -f "$tmp"
    info "removed rule #$n"
    if is_active 2>/dev/null; then
        cmd_start
    fi
}

cmd_ban() {
    local ip=${1:-}
    [[ -n $ip ]] || die "usage: ban <ip[/cidr]>"
    valid_ip "$ip" || die "invalid IP address: $ip"
    need_root
    touch "$BLOCKLIST_FILE"
    if grep -qxF "$ip" "$BLOCKLIST_FILE"; then
        info "$ip is already in the blocklist"
    else
        echo "$ip" >> "$BLOCKLIST_FILE"
        info "banned $ip"
    fi
    if is_active 2>/dev/null; then
        iptables -C FW_BLOCKLIST -s "$ip" -j FW_LOG 2>/dev/null \
            || ipt -A FW_BLOCKLIST -s "$ip" -j FW_LOG
    elif [[ "$DRY_RUN" == "1" ]]; then
        ipt -A FW_BLOCKLIST -s "$ip" -j FW_LOG
    fi
}

cmd_unban() {
    local ip=${1:-}
    [[ -n $ip ]] || die "usage: unban <ip[/cidr]>"
    valid_ip "$ip" || die "invalid IP address: $ip"
    need_root
    if [[ -f $BLOCKLIST_FILE ]] && grep -qxF "$ip" "$BLOCKLIST_FILE"; then
        local tmp
        tmp=$(mktemp)
        grep -vxF "$ip" "$BLOCKLIST_FILE" > "$tmp" || true
        cat "$tmp" > "$BLOCKLIST_FILE"
        rm -f "$tmp"
        info "removed $ip from blocklist"
    else
        warn "$ip was not in the blocklist"
    fi
    if is_active 2>/dev/null; then
        iptables -D FW_BLOCKLIST -s "$ip" -j FW_LOG 2>/dev/null || true
    fi
}

cmd_banned() {
    if [[ -s $BLOCKLIST_FILE ]]; then
        cat "$BLOCKLIST_FILE"
    else
        echo "(blocklist is empty)"
    fi
}

cmd_save() {
    need_root
    local file="$BACKUP_DIR/iptables-$(date +%Y%m%d-%H%M%S).rules"
    if [[ "$DRY_RUN" == "1" ]]; then
        echo "[dry-run] iptables-save > $file"
        return 0
    fi
    mkdir -p "$BACKUP_DIR"
    iptables-save > "$file"
    info "saved current rules to $file"
}

cmd_restore() {
    need_root
    local file=${1:-}
    if [[ -z $file ]]; then
        file=$(ls -1t "$BACKUP_DIR"/*.rules 2>/dev/null | head -n 1 || true)
        [[ -n $file ]] || die "no backups found in $BACKUP_DIR"
    fi
    [[ -f $file ]] || die "backup file not found: $file"
    if [[ "$DRY_RUN" == "1" ]]; then
        echo "[dry-run] iptables-restore < $file"
        return 0
    fi
    iptables-restore < "$file"
    info "restored rules from $file"
}

cmd_report() {
    "$SCRIPT_DIR/report.sh" "$@"
}

# ------------------------------------------------------------------ main ---

main() {
    local cmd=${1:-help}
    shift || true
    case "$cmd" in
        start)           cmd_start ;;
        stop)            cmd_stop ;;
        restart)         cmd_restart ;;
        status)          cmd_status ;;
        list)            cmd_list ;;
        add)             cmd_add "$@" ;;
        remove|rm)       cmd_remove "$@" ;;
        ban)             cmd_ban "$@" ;;
        unban)           cmd_unban "$@" ;;
        banned)          cmd_banned ;;
        save)            cmd_save ;;
        restore)         cmd_restore "$@" ;;
        report)          cmd_report "$@" ;;
        help|-h|--help)  usage ;;
        version|--version) echo "$VERSION" ;;
        *)               warn "unknown command: $cmd"; echo; usage; exit 1 ;;
    esac
}

main "$@"
