# Bash Firewall Manager

A lightweight Linux firewall manager written entirely in Bash. It turns a simple, human-readable rules file into a hardened **iptables** ruleset, and adds the tooling around it: IP banning, SSH brute-force protection, log reports, backups, and a black-box test script.

Built as a learning project to understand how packet filtering, connection tracking, and rate limiting work under the hood.

> **Use it on a lab VM.** `fw.sh start` flushes existing iptables rules (including ones added by Docker, libvirt, etc.) and sets the default INPUT policy to DROP. See [Safety notes](#safety-notes).

## Features

- **Simple rules file**: write `allow tcp 443` instead of long iptables commands
- **Default deny**: incoming traffic is dropped unless a rule allows it; outgoing is allowed
- **Stateful filtering**: replies to your own connections are accepted via connection tracking; invalid packets are dropped
- **Scan and flood protection**: drops NULL/XMAS/malformed TCP packets, rate-limits SYN and ping floods
- **SSH brute-force throttling**: limits new SSH connections per source per minute
- **IP blocklist**: `ban` / `unban` addresses, persisted across restarts
- **Auto-ban**: `autoban.sh` bans IPs with repeated failed SSH logins (a mini fail2ban)
- **Rate-limited logging**: dropped packets are logged without letting a flood fill the disk
- **Reports**: top blocked IPs, ports, and protocols
- **Backup / restore** of the live ruleset
- **Dry-run mode**: see every iptables command before running anything
- **Input validation**: bad ports, IPs, or protocols are rejected with a clear message

## How it works

```
 incoming packet
       │
       ▼
 INPUT chain (policy: DROP)
   1. loopback traffic            → ACCEPT
   2. ESTABLISHED / RELATED       → ACCEPT   (replies to your own connections)
   3. INVALID                     → DROP
   4. FW_BLOCKLIST                → banned IPs  → FW_LOG
   5. FW_GUARD                    → scan filters, SYN/ping flood limits, SSH throttle
   6. FW_RULES                    → your rules from rules.conf (first match wins)
   7. FW_LOG                      → log (rate limited) + DROP
```

The firewall lives in its own chains (`FW_BLOCKLIST`, `FW_GUARD`, `FW_RULES`, `FW_LOG`), so the ruleset stays organised and can be reloaded cleanly.

## Requirements

- Linux with `iptables` (works with the `iptables-nft` backend on modern Ubuntu/Debian)
- Bash 4+
- Root privileges (`sudo`) for anything that changes the firewall
- Optional: `nmap` for testing, `rsyslog` for a dedicated log file

## Quick start

```bash
git clone https://github.com/mdwasifraza01/bash-firewall.git
cd bash-firewall
chmod +x *.sh

# 1. Preview what would happen. Nothing is changed.
FW_DRY_RUN=1 ./fw.sh start

# 2. Look at / edit your rules
./fw.sh list
nano rules.conf

# 3. Apply for real
sudo ./fw.sh start
sudo ./fw.sh status
```

If you get locked out, reboot the VM (rules are not persistent by default) or use the VM console and run `sudo ./fw.sh stop`.

## Rules file

`rules.conf` takes one rule per line:

```
<allow|deny> <tcp|udp> <port | start:end> [source-ip[/cidr]]
<allow|deny> icmp [source-ip[/cidr]]
```

```
allow tcp 22                    # SSH from anywhere
allow tcp 80                    # HTTP
allow tcp 443                   # HTTPS
allow tcp 22 192.168.1.0/24     # SSH only from the local network
allow tcp 8000:8100             # a port range
allow icmp                      # ping
deny  tcp 23                    # block (and log) telnet
```

Rules are checked top to bottom and the first match wins. Anything not matched is logged and dropped. You can also manage rules from the command line:

```bash
./fw.sh add allow tcp 8080
./fw.sh add allow tcp 22 10.0.0.0/8
./fw.sh list
./fw.sh remove 3
```

## Commands

| Command | Description |
|---|---|
| `start` / `stop` / `restart` | Apply, remove, or reload the firewall |
| `status` | Show active state, policies, and packet counters |
| `list` | Show numbered rules from `rules.conf` |
| `add <allow\|deny> <proto> [port] [source]` | Add a rule (reloads if active) |
| `remove <n>` | Remove rule number *n* |
| `ban <ip[/cidr]>` / `unban <ip[/cidr]>` / `banned` | Manage the blocklist |
| `save` / `restore [file]` | Back up and restore the live iptables state |
| `report [-n N]` | Summarise blocked traffic |

## Logging and reports

Dropped packets are logged by the kernel with the prefix `FW-DROP:`. `report.sh` finds them via `journalctl -k`, `/var/log/kern.log`, or `dmesg`.

For a dedicated log file (optional, needs rsyslog), create `/etc/rsyslog.d/10-firewall.conf`:

```
:msg, contains, "FW-DROP:" /var/log/firewall.log
& stop
```

Then run `sudo systemctl restart rsyslog`. `report.sh` automatically prefers `/var/log/firewall.log` when it exists.

```bash
./report.sh          # top 10
./report.sh -n 20    # top 20
```

## Auto-ban for SSH brute force

```bash
sudo ./autoban.sh -n          # dry run: show who would be banned
sudo ./autoban.sh -t 5        # ban anyone with 5+ failed password attempts
FW_WHITELIST="127.0.0.1 192.168.1.10" sudo -E ./autoban.sh   # never ban these
```

Run it every 5 minutes with cron:

```
*/5 * * * * /opt/bash-firewall/autoban.sh >> /var/log/autoban.log 2>&1
```

## Testing

From a **second machine** (another VM or your host), compare behaviour before and after enabling the firewall:

```bash
# Black-box checks: allowed ports reachable, blocked ports dropped, ping as expected
ALLOWED_PORTS="22 80 443" BLOCKED_PORTS="23 3306 8080" ./test_firewall.sh <firewall-vm-ip>

# Full port scan
nmap -Pn -sS -p- <firewall-vm-ip>
```

Expected results with the default `rules.conf`: only ports 22, 80, and 443 appear reachable; every other port shows as **filtered** (dropped, no reply). Run the same scan with the firewall stopped to see the difference. This makes a good before/after section for a report.

You can also test the SSH throttle by opening several new SSH connections in quick succession; after the limit is reached, new attempts are dropped until the window passes.

## Running on boot

Rules are not persistent by default. To apply them at boot, create `/etc/systemd/system/bash-firewall.service`:

```ini
[Unit]
Description=Bash Firewall Manager
After=network-pre.target
Before=network.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/opt/bash-firewall/fw.sh start
ExecStop=/opt/bash-firewall/fw.sh stop

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now bash-firewall
```

## Project structure

```
bash-firewall/
├── fw.sh             # main manager (start/stop/add/ban/save/...)
├── rules.conf        # your firewall rules
├── autoban.sh        # ban IPs with repeated failed SSH logins
├── report.sh         # summary of blocked traffic
├── test_firewall.sh  # black-box test, run from another machine
├── README.md
├── LICENSE
└── .gitignore
```

## Safety notes

- **Don't lock yourself out.** Make sure `rules.conf` allows SSH (`allow tcp 22`) before starting the firewall over an SSH session. `fw.sh` warns you if it can't find such a rule.
- `start` **flushes all existing iptables rules** in the filter table, including those added by other tools (Docker, libvirt, ufw, ...).
- **IPv4 only.** IPv6 traffic is not filtered by these rules. Disable IPv6 on the lab VM or extend the script with `ip6tables`.
- Only the `filter` table is managed (no NAT or mangle rules).
- This is an educational project, not a replacement for a production firewall. For real servers, consider `nftables`, `firewalld`, or `ufw`.

## Ideas for improvement

- IPv6 support with `ip6tables`
- Port the backend to `nftables`
- Time-limited bans (auto-expire after N hours)
- Per-service rule profiles (web, mail, database)
- GeoIP blocking
- A small web dashboard for logs and bans
- Automated tests with network namespaces

## License

MIT, see [LICENSE](LICENSE).
