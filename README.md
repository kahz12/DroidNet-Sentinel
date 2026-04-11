# DroidNet Sentinel

![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)
![Python](https://img.shields.io/badge/Python-3.10%2B-blue)
![Platform](https://img.shields.io/badge/Platform-Android%20%7C%20Linux-green)

> Autonomous WiFi network auditor built for Android (Termux) and Linux — powered by Nmap, Python, and Flask.

DroidNet Sentinel is a modular, cross-platform network security toolkit that performs automated WiFi auditing directly from an Android device via Termux or any Linux machine. It discovers live hosts, performs deep port and service scans, classifies risk levels, looks up public exploits, cuts off unknown devices via ARP spoofing, and exposes a persistent web dashboard — all from a single unified CLI.

```
 ██████╗ ██████╗  ██████╗ ██╗██████╗ ███╗   ██╗███████╗████████╗
 ██╔══██╗██╔══██╗██╔═══██╗██║██╔══██╗████╗  ██║██╔════╝╚══██╔══╝
 ██║  ██║██████╔╝██║   ██║██║██║  ██║██╔██╗ ██║█████╗     ██║
 ██║  ██║██╔══██╗██║   ██║██║██║  ██║██║╚██╗██║██╔══╝     ██║
 ██████╔╝██║  ██║╚██████╔╝██║██████╔╝██║ ╚████║███████╗   ██║
 ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚═╝╚═════╝ ╚═╝  ╚═══╝╚══════╝   ╚═╝
 ███████╗███████╗███╗   ██╗████████╗██╗███╗   ██╗███████╗██╗
 ██╔════╝██╔════╝████╗  ██║╚══██╔══╝██║████╗  ██║██╔════╝██║
 ███████╗█████╗  ██╔██╗ ██║   ██║   ██║██╔██╗ ██║█████╗  ██║
 ╚════██║██╔══╝  ██║╚██╗██║   ██║   ██║██║╚██╗██║██╔══╝  ██║
 ███████║███████╗██║ ╚████║   ██║   ██║██║ ╚████║███████╗███████╗
 ╚══════╝╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚═╝╚═╝  ╚═══╝╚══════╝╚══════╝
```

---

## Table of Contents

- [Disclaimer](#disclaimer)
- [Features](#features)
- [Architecture](#architecture)
- [Project Structure](#project-structure)
- [Requirements](#requirements)
- [Installation](#installation)
- [Configuration](#configuration)
- [Usage](#usage)
  - [Interactive Menu](#interactive-menu)
  - [CLI Flags (Non-Interactive)](#cli-flags-non-interactive)
- [Modules](#modules)
  - [Sentinel — Core Scanner](#sentinel--core-scanner)
  - [Hunter — Exploit Lookup](#hunter--exploit-lookup)
  - [CVE-Watcher — CVE Monitor](#cve-watcher--cve-monitor)
  - [Dashboard — Command Center](#dashboard--command-center)
  - [Spoofer — ARP MitM](#spoofer--arp-mitm)
  - [Deauther — 802.11 Deauth](#deauther--80211-deauth)
- [Database](#database)
- [Risk Classification](#risk-classification)
- [Telegram Alerts](#telegram-alerts)
- [Workflow](#workflow)

---

## Disclaimer

> **This tool is intended strictly for educational purposes and authorized network security auditing.**
>
> Only use DroidNet Sentinel on networks you own or have explicit written permission to test. Unauthorized network scanning, ARP spoofing, and deauthentication attacks are **illegal** in most jurisdictions and may violate computer fraud laws. The author assumes no liability and is not responsible for any misuse or damage caused by this tool.

---

## Features

| Category | Feature |
|---|---|
| **Discovery** | ARP-based ping sweep (`nmap -sn`) on the local /24 subnet |
| **Scanning** | Deep port scan — top 100 TCP ports with version detection (`-F -sV -T4`) |
| **Risk Analysis** | Automatic classification: MINIMAL / LOW / MEDIUM / CRITICAL based on open ports |
| **Persistence** | Dual storage: flat JSON files + SQLite database (`sentinel.db`) |
| **Historical Diff** | Per-scan comparison: new devices, disappeared hosts, port changes |
| **Exploit Lookup** | Local Exploit-DB search via `searchsploit` (Hunter module) |
| **CVE Monitoring** | Real-time CVE cross-referencing via NIST NVD API with impact analysis (CVE-Watcher module) |
| **Active Response** | ARP poisoning of unknown/untrusted hosts (Spoofer module) |
| **Deauthentication** | 802.11 deauth frames via Scapy — single client or broadcast (Deauther module) |
| **Web Dashboard** | Flask-based Command Center with session auth, scan history, and diff view |
| **Alerting** | Dual-channel: local OS notifications + Telegram bot |
| **Cross-platform** | Native support for Android (Termux) and Linux — same codebase |
| **Daemon mode** | Continuous background scanning every 5 minutes, re-scans on SSID change |

---

## Architecture

```
main.py
  ├── droidnet/cli/
  │   ├── args.py          ← argparse flags for non-interactive use
  │   └── menu.py          ← interactive Rich terminal menu
  │
  ├── droidnet/core/
  │   ├── database.py      ← SQLite layer (scans / hosts / ports schema)
  │   ├── env.py           ← system capability detection (root, tools, monitor mode)
  │   └── notifier.py      ← dual notifications (OS + Telegram)
  │
  ├── droidnet/modules/
  │   ├── sentinel.py      ← ping sweep + deep scan + ARP response + report save
  │   ├── hunter.py        ← exploit lookup via searchsploit
  │   ├── cve_watcher.py   ← CVE monitoring via NIST NVD API + impact analysis
  │   ├── spoofer.py       ← ARP poisoning (bidirectional, dsniff)
  │   └── deauther.py      ← 802.11 deauth frames (Scapy)
  │
  ├── droidnet/platform/
  │   └── utils.py         ← WiFi info, interface detection, privilege checks
  │
  └── droidnet/web/
      └── dashboard.py     ← Flask app — login, dashboard, JSON API
```

The platform abstraction layer (`platform/utils.py`) automatically selects the right tool for the current environment:

| Task | Android (Termux) | Linux |
|---|---|---|
| WiFi info | `termux-wifi-connectioninfo` | `nmcli` |
| Notifications | `termux-notification` | `notify-send` |
| Network interface | `ip route` | `ip route` / `nmcli` |

---

## Project Structure

```
DroidNet-Sentinel/
├── main.py                        # Entry point (interactive menu + CLI flags)
├── requirements.txt               # Python dependencies
├── config.json                    # User config: excluded/trusted IPs  [not committed]
├── sentinel.db                    # SQLite database (auto-created on first scan)
│
├── droidnet/
│   ├── __init__.py                # Package version
│   ├── config.py                  # Centralised paths, intervals, Telegram config
│   │
│   ├── cli/
│   │   ├── __init__.py
│   │   ├── args.py                # Argument parser
│   │   └── menu.py                # Interactive menu loop + banner
│   │
│   ├── core/
│   │   ├── __init__.py
│   │   ├── database.py            # SQLite persistence layer
│   │   ├── env.py                 # System capability detection
│   │   └── notifier.py            # Notification dispatcher
│   │
│   ├── modules/
│   │   ├── __init__.py
│   │   ├── sentinel.py            # Core scanner
│   │   ├── hunter.py              # Exploit lookup
│   │   ├── cve_watcher.py         # CVE monitoring + impact analysis
│   │   ├── spoofer.py             # ARP spoofing
│   │   └── deauther.py            # 802.11 deauthentication
│   │
│   ├── platform/
│   │   ├── __init__.py
│   │   └── utils.py               # Cross-platform abstraction
│   │
│   └── web/
│       ├── __init__.py
│       └── dashboard.py           # Flask web dashboard
│
└── reports/                       # JSON scan reports (auto-created)
    └── <SSID>_<timestamp>.json
```

---

## Requirements

### Python

- Python 3.10 or higher
- pip packages listed in `requirements.txt`

### System Tools

| Tool | Purpose | Required |
|---|---|---|
| `nmap` | Host discovery and port scanning | Yes |
| `arpspoof` (dsniff) | ARP poisoning (Spoofer module) | Optional |
| `searchsploit` (exploitdb) | Local exploit lookup (Hunter module) | Optional |
| `scapy` | 802.11 deauthentication frames (Deauther module) | Optional |
| `iw` / `airmon-ng` | Monitor mode management (Deauther module) | Optional |
| `termux-api` | Notifications and WiFi info on Android | Android only |
| `nmcli` | WiFi info on Linux | Linux only |
| `notify-send` (libnotify) | Desktop notifications on Linux | Linux only |

### Platform Notes

- **Android:** Root access is required only for Spoofer and Deauther. The core Sentinel scanner runs without root.
- **Deauther on Android:** Most built-in Android WiFi chips do not support monitor mode injection. An external USB adapter with monitor mode support is required.
- **WPA3 + MFP:** Deauthentication attacks are ineffective against access points with Management Frame Protection (MFP) enabled, as designed per the 802.11w standard.

---

## Installation

### Android — Termux

```bash
# 1. Update packages
pkg update && pkg upgrade

# 2. Install system dependencies
pkg install python nmap dsniff termux-api

# 3. (Optional) Install exploit database
pkg install exploitdb

# 4. Clone the repository
git clone https://github.com/kahz12/DroidNet-Sentinel.git
cd DroidNet-Sentinel

# 5. Install Python dependencies
pip install -r requirements.txt
```

### Linux — Ubuntu / Debian / Kali

```bash
# 1. Install system dependencies
sudo apt update
sudo apt install python3 python3-pip nmap dsniff libnotify-bin wireless-tools

# 2. (Optional) Install exploit database
sudo apt install exploitdb

# 3. (Optional) Install Scapy for the Deauther module
pip install scapy

# 4. Clone the repository
git clone https://github.com/kahz12/DroidNet-Sentinel.git
cd DroidNet-Sentinel

# 5. Install Python dependencies
pip install -r requirements.txt
```

---

## Configuration

### config.json

Create `config.json` in the project root to define excluded and trusted hosts:

```json
{
    "excluded_ips": ["192.168.1.100"],
    "trusted_ips":  ["192.168.1.1", "192.168.1.100"]
}
```

| Field | Description |
|---|---|
| `excluded_ips` | IPs skipped by Nmap (add your own device's IP here) |
| `trusted_ips` | Known/trusted IPs — any IP not in this list is treated as a potential intruder and may be ARP-spoofed |

If `config.json` does not exist, Sentinel runs with empty exclusion and trust lists.

### Environment Variables

| Variable | Description | Default |
|---|---|---|
| `TELEGRAM_TOKEN` | Telegram Bot API token from BotFather | — |
| `TELEGRAM_CHAT_ID` | Numeric Telegram chat ID to receive alerts | — |
| `SENTINEL_USER` | Dashboard login username | `admin` |
| `SENTINEL_PASS` | Dashboard login password | `sentinel` |
| `SENTINEL_SECRET` | Flask session secret key (auto-generated if absent) | random |
| `NVD_API_KEY` | NIST NVD API key for higher rate limits (CVE-Watcher) | — |

Set persistent variables in your shell profile:

```bash
# ~/.bashrc or ~/.zshrc
export TELEGRAM_TOKEN="7xxxxxxxxx:AAxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
export TELEGRAM_CHAT_ID="123456789"
export SENTINEL_USER="myuser"
export SENTINEL_PASS="mysecurepassword"
```

> **Security:** Always change the default dashboard credentials before exposing the server on a network. Use a strong, unique `SENTINEL_SECRET` to protect session cookies.

---

## Usage

### Interactive Menu

Launch the full interactive terminal UI:

```bash
python main.py
```

The menu presents the following options:

```
[1]  Sentinel — Quick scan       Scan the network and display results
[2]  Sentinel — Daemon mode      Continuous background scanning
[3]  Hunter — Search exploits    Analyse last report against Exploit-DB
[4]  Dashboard — Command Center  Start web server on :5000
[5]  Spoofer — Manual ARP cut    Cut access to a specific IP
[6]  Deauther — 802.11 Deauth    Disconnect a device from the AP
[7]  View saved reports          List previous audits
[8]  CVE-Watcher — CVE Alerts    Cross-reference scanned network with recent CVEs
[0]  Exit
```

### CLI Flags (Non-Interactive)

All modules are also accessible directly via command-line flags, suitable for scripting and automation:

```bash
# Single network scan
python main.py --scan

# Continuous daemon mode (scans every 5 min, re-scans on SSID change)
python main.py --daemon

# Look up exploits for services found in the last scan
python main.py --hunt

# Start the web dashboard on port 5000
python main.py --dashboard

# List all saved scan reports
python main.py --reports

# Monitor recent CVEs against scanned services
python main.py --cve-watch

# ARP spoof a specific device (requires root)
python main.py --spoof <VICTIM_IP> <GATEWAY_IP> [INTERFACE]
# Example:
python main.py --spoof 192.168.1.105 192.168.1.1 wlan0

# Deauthenticate a specific client (requires root + monitor mode)
python main.py --deauth <TARGET_MAC> <BSSID> <INTERFACE>
# Example — single client:
python main.py --deauth A1:B2:C3:D4:E5:F6 AA:BB:CC:DD:EE:FF wlan0mon
# Example — broadcast (all clients):
python main.py --deauth broadcast AA:BB:CC:DD:EE:FF wlan0mon
```

---

## Modules

### Sentinel — Core Scanner

`droidnet/modules/sentinel.py`

The main scanning engine. Performs a full network audit cycle:

1. **WiFi discovery** — reads current SSID and local IP via the platform abstraction layer.
2. **Ping sweep** — `nmap -sn <subnet>/24` with ARP detection; fast and silent on LAN.
3. **Deep scan** — `nmap -F -sV -T4 <ip>` on every live host (top 100 TCP ports, version detection).
4. **Risk evaluation** — classifies each host as MINIMAL / LOW / MEDIUM / CRITICAL.
5. **Persistence** — writes a timestamped JSON file under `reports/` and saves to `sentinel.db`.
6. **Active response** — launches ARP spoofing threads against unknown IPs (not in `trusted_ips`).
7. **Alerting** — sends a summary via OS notification and Telegram.

**Daemon mode** (`--daemon`) loops every 300 seconds and automatically re-scans when the network SSID changes or 6 hours have elapsed since the last full scan.

---

### Hunter — Exploit Lookup

`droidnet/modules/hunter.py`

Parses the most recent JSON scan report, extracts software names from Nmap version strings, and queries the local Exploit-DB via `searchsploit --json`. Displays up to 5 matching CVEs/exploits per service in the terminal.

**Requires:** `exploitdb` package (`pkg install exploitdb` on Termux, `apt install exploitdb` on Debian/Kali).

---

### CVE-Watcher — CVE Monitor

`droidnet/modules/cve_watcher.py`

Monitors recently published CVEs and cross-references them against the services and versions detected by Sentinel on your network. Uses the NIST National Vulnerability Database (NVD) public API.

**Flow:**

1. **Load scan data** — retrieves the most recent scan with identified services from `sentinel.db`.
2. **Parse service banners** — extracts product name and version from Nmap output (e.g. `Apache httpd 2.4.29`, `OpenSSH 7.6p1`).
3. **Query NVD** — searches for CVEs published in the last 120 days matching each detected service. Falls back to product-only queries when version-specific searches return no results.
4. **Impact analysis** — analyses each CVE description to classify the attack vector (remote code execution, denial of service, privilege escalation, authentication bypass, information disclosure) and generates an actionable summary.
5. **Persistence** — stores alerts in the `cve_alerts` table (deduplicated by CVE + IP + service).
6. **Alerting** — sends a formatted summary via OS notification and Telegram with severity breakdown.

**Output:** A Rich terminal table sorted by severity (CRITICAL first), showing CVE ID, CVSS score, affected service, impacted IPs, and the impact summary.

**Optional:** Set the `NVD_API_KEY` environment variable for higher API rate limits (without a key, NVD allows ~5 requests per 30 seconds).

```bash
# Via interactive menu: option [8]
# Via CLI:
python main.py --cve-watch
```

---

### Dashboard — Command Center

`droidnet/web/dashboard.py`

A Flask-based web interface that provides a persistent view of all historical scan data stored in `sentinel.db`.

**Authentication:**

All routes are protected by session-based login. Credentials are configured via environment variables (`SENTINEL_USER`, `SENTINEL_PASS`). The credential comparison uses `hmac.compare_digest` to prevent timing-based attacks.

| Route | Method | Description |
|---|---|---|
| `/login` | GET / POST | Login form |
| `/logout` | GET | End session and redirect to login |
| `/` | GET | HTML dashboard — all scans with diff view |
| `/api/reports` | GET | All scans as raw JSON |
| `/api/scan/<id>/diff` | GET | Diff data for a specific scan vs the previous one |

**Dashboard features:**

- Scan cards sorted newest-first, each showing network SSID, scan timestamp, and device count.
- Per-host risk badges (MINIMAL / LOW / MEDIUM / CRITICAL) with colour coding.
- `[NEW]` badge on devices not seen in the previous scan of the same network.
- Disappeared hosts listed per scan card.
- Per-host port change diff (added ports in green, removed ports in red) when comparing consecutive scans.

Access the dashboard from any device on the local network:

```
http://<device-ip>:5000
```

---

### Spoofer — ARP MitM

`droidnet/modules/spoofer.py`

Performs bidirectional ARP poisoning against a target using `arpspoof` (dsniff). Two daemon threads continuously send forged ARP replies — one to the target (impersonating the gateway) and one to the gateway (impersonating the target). Restores legitimate ARP entries on `Ctrl+C`.

**Requires:** root, `dsniff` package.

```bash
# Via interactive menu: option [5]
# Via CLI:
python main.py --spoof 192.168.1.105 192.168.1.1 wlan0
```

---

### Deauther — 802.11 Deauth

`droidnet/modules/deauther.py`

Crafts and injects IEEE 802.11 deauthentication frames (type `0xC0`, reason code 7) using Scapy. Supports targeting a single client MAC or broadcasting to all clients on an access point. Automatically enables monitor mode on the specified interface if supported.

**Requires:** root, Scapy, a wireless interface capable of packet injection (monitor mode). Does not affect WPA3 access points with MFP (802.11w) enabled.

```bash
# Via interactive menu: option [6]
# Via CLI:
python main.py --deauth A1:B2:C3:D4:E5:F6 AA:BB:CC:DD:EE:FF wlan0mon
python main.py --deauth broadcast AA:BB:CC:DD:EE:FF wlan0mon
```

---

## Database

All scan results are persisted to `sentinel.db` (SQLite, auto-created at project root) using the following schema:

```sql
scans
  id            INTEGER  PRIMARY KEY AUTOINCREMENT
  network       TEXT     -- SSID name
  scan_time     TEXT     -- YYYYmmdd_HHMMSS timestamp
  total_devices INTEGER  -- number of hosts discovered
  created_at    TEXT     -- UTC datetime of database insertion

hosts
  id      INTEGER  PRIMARY KEY AUTOINCREMENT
  scan_id INTEGER  → scans.id  (ON DELETE CASCADE)
  ip      TEXT     -- host IP address
  risk    TEXT     -- MÍNIMO / BAJO / MEDIO / CRÍTICO

ports
  id         INTEGER  PRIMARY KEY AUTOINCREMENT
  host_id    INTEGER  → hosts.id  (ON DELETE CASCADE)
  port_entry TEXT     -- raw Nmap port line, e.g. "80/tcp open http Apache 2.4.51"

cve_alerts
  id          INTEGER  PRIMARY KEY AUTOINCREMENT
  cve_id      TEXT     -- CVE identifier, e.g. "CVE-2024-12345"
  severity    TEXT     -- CRITICAL / HIGH / MEDIUM / LOW / UNKNOWN
  score       REAL     -- CVSS base score (nullable)
  service     TEXT     -- matched service string, e.g. "Apache httpd 2.4.29"
  ip          TEXT     -- affected host IP
  summary     TEXT     -- CVE description (truncated to 500 chars)
  impact      TEXT     -- generated impact analysis
  network     TEXT     -- SSID of the scanned network
  scan_id     INTEGER  → scans.id  (ON DELETE SET NULL)
  created_at  TEXT     -- UTC datetime of alert creation
  UNIQUE(cve_id, ip, service)
```

The `get_all_scans_with_diffs()` function compares each scan against the immediately preceding scan on the same network and enriches each record with:

- `new_ips` — list of IPs not present in the previous scan
- `gone_ips` — list of IPs that disappeared since the previous scan
- `port_changes` — `{ip: {"added": [...], "removed": [...]}}` per host

JSON flat files under `reports/` are still written in parallel for portability and backwards compatibility.

---

## Risk Classification

Hosts are classified based on open TCP ports detected by Nmap:

| Level | Trigger ports | Colour |
|---|---|---|
| **CRITICAL** | FTP (21), Telnet (23), SMB (139, 445), RDP (3389) | Red |
| **MEDIUM** | HTTP (80, 8080), DNS (53), UPnP (1900), NFS (2049) | Yellow |
| **LOW** | Any other open port not in the above sets | Blue |
| **MINIMAL** | No open ports / all ports closed | Green |

---

## Telegram Alerts

When `TELEGRAM_TOKEN` and `TELEGRAM_CHAT_ID` are set, Sentinel sends a formatted summary message after every scan cycle:

```
🛡️ DroidNet Sentinel Report

📡 Network: MyHomeWiFi
🎯 Live targets: 4
⚠️ Check the Command Center for details.
```

If the variables are not set, the notification step is silently skipped.

---

## Workflow

```
WiFi connected
       │
       ▼
  Ping sweep (nmap -sn /24)
       │
       ▼
  Deep scan on live hosts
  (nmap -F -sV -T4)
       │
       ├──────────────────────────────────────────────┐
       │                                              │
  IP in trusted_ips?                        IP unknown / untrusted
  → Risk classify only                      → ARP spoof thread launched
  → Save to DB + JSON                       → Save to DB + JSON
       │                                              │
       └──────────────┬───────────────────────────────┘
                      │
                      ▼
              OS notification
              + Telegram alert
                      │
                      ▼
              Hunter — searchsploit
              query on open services
                      │
                      ▼
              CVE-Watcher — query NVD
              for recent CVEs matching
              detected services + versions
              → impact analysis + alerts
                      │
                      ▼
              Dashboard — historical
              view with per-scan diffs
```

---

Developed with care by Ale.

---

## License

This project is licensed under the [MIT License](LICENSE) — see the `LICENSE` file for details.
