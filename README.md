# DroidNet Sentinel

![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)
![Python](https://img.shields.io/badge/Python-3.10%2B-blue)
![Platform](https://img.shields.io/badge/Platform-Android%20%7C%20Linux-green)
![Tests](https://img.shields.io/badge/Tests-pytest-blue)

> Autonomous Wi-Fi network auditor for Android (Termux) and Linux.
> Powered by Nmap, Python and Flask.

DroidNet Sentinel discovers live hosts, fingerprints services, classifies
risk, looks up known exploits and CVEs, and tracks how the network
changes between scans — all from a single CLI plus a polished web
Command Center.

---

## Table of contents

- [Disclaimer](#disclaimer)
- [Highlights](#highlights)
- [Quick start](#quick-start)
- [Usage](#usage)
- [Modules](#modules)
- [Configuration](#configuration)
- [Architecture](#architecture)
- [Database](#database)
- [Risk levels](#risk-levels)
- [Telegram alerts](#telegram-alerts)
- [Security notes](#security-notes)
- [License](#license)

---

## Disclaimer

> Use only on networks you own or are explicitly authorised to test.
> Unauthorised scanning, ARP spoofing and deauthentication are illegal
> in most jurisdictions. The author assumes no liability for misuse.

---

## Highlights

| | |
|---|---|
| **Discovery**       | ARP ping sweep on the local /24 (`nmap -sn`) |
| **Deep scan**       | Top 100 TCP ports + version detection (`-F -sV -T4`) |
| **Risk engine**     | Per-host classification: MINIMAL / LOW / MEDIUM / CRITICAL / UNKNOWN |
| **Diff history**    | Tracks new hosts, disappeared hosts, port changes between scans |
| **Exploit lookup**  | Local Exploit-DB search via `searchsploit` |
| **CVE monitoring**  | NVD cross-reference with impact analysis |
| **Active response** | Manual or automatic ARP cut on untrusted hosts |
| **Deauth**          | 802.11 deauth frames via Scapy (single client / broadcast) |
| **Web dashboard**   | Authenticated Flask UI with scan history, diffs and in-app help |
| **Alerting**        | OS notifications and Telegram bot |
| **Cross-platform**  | Same codebase on Android (Termux) and Linux |

---

## Quick start

### Android — Termux

```bash
pkg install python nmap termux-api
git clone https://github.com/kahz12/DroidNet-Sentinel.git
cd DroidNet-Sentinel
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python main.py
```

### Linux — Debian / Ubuntu / Kali

```bash
sudo apt install python3 python3-pip python3-venv nmap dsniff libnotify-bin wireless-tools
git clone https://github.com/kahz12/DroidNet-Sentinel.git
cd DroidNet-Sentinel
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python main.py
```

**Optional tools** — install only the modules you need:

| Tool | Module | Install |
|---|---|---|
| `searchsploit` (exploitdb) | Hunter      | `apt install exploitdb`, or clone the repo on Termux |
| `scapy`                    | Deauther    | `pip install scapy` |
| `iw` / `airmon-ng`         | Deauther    | `apt install iw aircrack-ng` |
| `arpspoof` (dsniff)        | Spoofer     | `apt install dsniff` (Linux only) |

> **Termux notes.** `dsniff` is not packaged for Termux, so the Spoofer
> module is Linux-only. The Hunter module needs `searchsploit` cloned
> manually from `gitlab.com/exploit-database/exploitdb`. Most stock
> Android Wi-Fi chips do not support monitor-mode injection, so the
> Deauther typically requires an external USB adapter.

---

## Usage

### Interactive menu

```bash
python main.py
```

```
[1]  Sentinel — Quick scan      Single-pass scan of the current network
[2]  Sentinel — Daemon mode     Continuous background scanning + alerts
[3]  Hunter — Exploit lookup    Match the latest report against Exploit-DB
[4]  CVE Watcher                Cross-check the network against recent CVEs
[5]  Dashboard — Command Center Launch the web UI on http://127.0.0.1:5000
[6]  Spoofer — Manual ARP cut   Cut a single host off the LAN  (root)
[7]  Deauther — 802.11 deauth   Boot a client off the AP        (root)
[8]  Saved reports              Browse the JSON reports under reports/
[9]  Help & user guide          Built-in user guide
[0]  Exit
```

Option **[9]** opens an in-CLI guide covering features, risk levels,
safety notes and a CLI cheat-sheet. The web dashboard ships the same
guide under **/help**.

### Command line

Every menu option has a non-interactive equivalent — useful for cron
and scripts:

```bash
python main.py scan                     # one-shot scan
python main.py daemon                   # continuous scan
python main.py hunt                     # Hunter
python main.py cve                      # CVE Watcher
python main.py dashboard [--expose]     # web UI (loopback by default)
python main.py reports                  # list saved reports
python main.py spoof  VICTIM GATEWAY    # ARP cut
python main.py deauth MAC BSSID --iface wlan0mon
python main.py db purge [--days N]      # prune old scans
```

Add `--help` to any subcommand for its full flag set.

---

## Modules

### Sentinel — core scanner
`droidnet/modules/sentinel.py`

1. Reads SSID and local IP via the platform abstraction layer.
2. Ping-sweeps the local /24 with ARP detection.
3. Deep-scans every live host (top 100 TCP ports + version detection).
4. Classifies risk and persists the result to `sentinel.db` and a
   timestamped JSON file under `reports/`.
5. Optionally launches an ARP cut against hosts not in `trusted_ips`.
6. Emits an OS notification and a Telegram alert.

Daemon mode loops every 5 minutes and re-scans whenever the SSID
changes or 6 hours have elapsed.

Discovery and service results use Nmap's [XML output](https://nmap.org/book/output-formats-xml-output.html).
Completed scans with zero hosts are saved so the dashboard can show
disappeared devices. Failed discoveries are retried on the next cycle;
failed, unreachable or inconclusive host scans have risk `UNKNOWN`.

`Ctrl+C` stops the daemon and cleans up automatic ARP responses. The same
host is not given duplicate response jobs; changes to the network or trust
list revoke obsolete jobs. A one-shot scan with `--auto-cut` waits for
`Ctrl+C` while responses are active. Restoration is attempted on exit;
its success still depends on the network and operating system.
On interruption, queued scans are cancelled; any Nmap commands already
running finish or hit their 120-second timeout before shutdown completes.

### Hunter — exploit lookup
`droidnet/modules/hunter.py`

Parses the latest scan, extracts product names from Nmap version
strings, and queries the local Exploit-DB via `searchsploit --json`.
Shows up to 5 matches per service.

Lookup results are cached only for the current Hunter run. Failed lookups
remain distinguishable from successful searches with no matches.

### CVE Watcher
`droidnet/modules/cve_watcher.py`

Pulls the most recent scan, parses service banners, queries the NIST
NVD for CVEs published in the last 120 days, classifies the attack
vector (RCE, DoS, privilege escalation, auth bypass, info disclosure),
and stores deduplicated alerts in `cve_alerts`. Set `NVD_API_KEY` for
higher rate limits.

Queries paginate through all results and use an exact publication window
of 1–120 days. Failed queries produce an explicit incomplete analysis,
not a clean result. Keyword matches are labelled **candidates** until
the affected versions are verified; their applicability is not established
by matching the product name alone. Publication-window filtering does not
cover all older vulnerabilities.

### Dashboard — Command Center
`droidnet/web/dashboard.py`

Authenticated Flask UI with session login, CSRF protection and a
5-attempts-per-minute rate limit on `/login`. The credential check is
constant-time. Auto-generated passwords are written to
`~/.sentinel/credentials` with mode `0600` instead of being printed.

| Route | Description |
|---|---|
| `/login`, `/logout`         | Session auth |
| `/`                         | Dashboard — scan cards, summary tiles, diff view |
| `/help`                     | Built-in user guide |
| `/api/reports`              | Paginated scan JSON (array) |
| `/api/scan/<id>/diff`       | Diff for one scan vs the previous one |

### Spoofer — ARP MitM
`droidnet/modules/spoofer.py`

Bidirectional ARP poisoning via two managed `arpspoof` processes, with
a Scapy fallback when available. Processes are cleaned up on `Ctrl+C`
or startup failure. Requires root and suitable socket permissions.

### Deauther — 802.11 deauth
`droidnet/modules/deauther.py`

Crafts and injects 802.11 deauth frames (type `0xC0`, reason `7`) via
Scapy. Targets a single MAC or broadcast. Requires root and a
monitor-mode-capable interface. Has no effect on WPA3 APs with MFP
(802.11w) enabled, by design.

---

## Configuration

### `config.json`

Optional file at the project root:

```json
{
    "excluded_ips":      ["192.168.1.100"],
    "trusted_ips":       ["192.168.1.1", "192.168.1.100"],
    "db_retention_days": 90
}
```

| Field | Description |
|---|---|
| `excluded_ips`      | IPs skipped by Nmap (typically your own device) |
| `trusted_ips`       | Trusted IPs or CIDR ranges; self and gateway are also protected |
| `db_retention_days` | Used by `db purge` (default `90`) |

The file is schema-validated at load: unexpected types fall back to
defaults instead of crashing. If the file is missing, Sentinel runs
with empty lists.

### Environment variables

| Variable           | Description                                        | Default   |
|---|---|---|
| `TELEGRAM_TOKEN`   | Telegram bot token                                 | unset     |
| `TELEGRAM_CHAT_ID` | Numeric Telegram chat ID                           | unset     |
| `SENTINEL_USER`    | Dashboard username                                 | `admin`   |
| `SENTINEL_PASS`    | Dashboard password                                 | auto-generated, persisted to `~/.sentinel/credentials` (mode 0600) |
| `SENTINEL_SECRET`  | Flask session secret                               | random    |
| `NVD_API_KEY`      | NVD API key for higher CVE Watcher rate limits     | unset     |

---

## Architecture

```
main.py
  +-- droidnet/cli/        argparse + interactive Rich menu
  +-- droidnet/core/       database, env probe, notifier, risk engine
  +-- droidnet/modules/    sentinel, hunter, cve_watcher, spoofer, deauther
  +-- droidnet/platform/   cross-platform helpers (Android / Linux)
  +-- droidnet/web/        Flask dashboard + /help guide
```

The platform layer auto-selects the right tool for the current OS:

| Capability       | Android (Termux)               | Linux                  |
|---|---|---|
| Wi-Fi info       | `termux-wifi-connectioninfo`   | `nmcli`                |
| Notifications    | `termux-notification`          | `notify-send`          |
| Network iface    | `ip route`                     | `ip route` / `nmcli`   |

---

## Database

Scan results live in `sentinel.db` (SQLite, auto-created):

```
scans       id, network, scan_time, total_devices, created_at
hosts       id, scan_id -> scans.id, ip, risk
ports       id, host_id -> hosts.id, port_entry
cve_alerts  id, cve_id, severity, score, service, ip, summary,
            impact, network, scan_id -> scans.id, created_at
            UNIQUE(cve_id, ip, service, network)
```

`get_all_scans_with_diffs()` enriches each record with `new_ips`,
`gone_ips` and `port_changes` against the previous scan of the same
network. JSON files under `reports/` are written in parallel for
portability.

The dashboard batch-loads hosts and ports. `/api/reports?page=1&per_page=20`
returns at most 20 scans by default, with a maximum page size of 100.
The JSON body remains an array; `X-Total-Count`, `X-Page`, `X-Per-Page`
and the `Link` header describe pagination. Integrations that previously
fetched the entire history in one request must follow the next-page link.
The Python `get_all_scans()` API still supports unbounded exports, and
the documented `get_known_ips(network)` API is retained for compatibility.

---

## Risk levels

Hosts are scored from the set of open TCP ports they expose:

| Level    | Trigger ports                                     | Colour |
|---|---|---|
| CRITICAL | FTP (21), Telnet (23), SMB (139, 445), RDP (3389) | red    |
| MEDIUM   | HTTP (80, 8080), DNS (53), SSDP (1900), NFS (2049)| yellow |
| LOW      | Any other open port                               | blue   |
| MINIMAL  | No open ports                                     | green  |
| UNKNOWN  | Failed, unreachable or inconclusive scan           | yellow |

The dashboard shows the same legend inline plus a "What does this
mean?" link to `/help`.

---

## Telegram alerts

When `TELEGRAM_TOKEN` and `TELEGRAM_CHAT_ID` are set, Sentinel sends a
short summary after every scan cycle. SSIDs and service banners are
escaped before interpolation so they cannot inject Markdown into the
message. If the variables are unset, the notification step is silently
skipped.

---

## Security notes

- The dashboard binds to `127.0.0.1` by default. Use `--expose` only
  behind a TLS proxy (nginx / caddy); credentials travel in plaintext
  over plain HTTP.
- Login is rate-limited to 5 attempts per minute per IP and protected
  by a per-session CSRF token.
- Auto-generated dashboard passwords are persisted at
  `~/.sentinel/credentials` with mode `0600`, never printed to stdout.
- All `subprocess` calls take list arguments (no `shell=True`) and TLS
  verification is never disabled. These invariants are enforced by
  AST-based regression tests in `tests/test_security_invariants.py`.

## Development checks

```bash
pip install -r requirements-dev.txt
python -m pytest -q
python -m ruff check droidnet main.py tests --select F,E9,B
python -m vulture droidnet main.py --min-confidence 80
```

Tests simulate scanning, packet transmission, interface changes and
external API requests. Database tests use temporary files. Real Wi-Fi
hardware and external-service integration require separate validation.
Scapy may be unavailable in restricted environments; operational modules
report this without preventing unrelated imports or tests.
- Spoofer and Deauther are offensive primitives. Run them only against
  targets you own or are authorised to test.

---

## License

Released under the [MIT License](LICENSE). Built with care by Ale.
