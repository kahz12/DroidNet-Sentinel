# DroidNet Sentinel — User Guide

A complete, practical guide to installing, configuring and operating
DroidNet Sentinel. It is written for a reader who has never used the tool
before and ends with reference material you will come back to.

A shorter overview lives in the project [README](../README.md). The Spanish
version of this guide is [`user-guide.es.md`](user-guide.es.md).

---

## Table of contents

1. [What DroidNet Sentinel is](#1-what-droidnet-sentinel-is)
2. [Authorized use only](#2-authorized-use-only)
3. [How it works](#3-how-it-works)
4. [Requirements](#4-requirements)
5. [Installation](#5-installation)
6. [Optional tools](#6-optional-tools)
7. [First run and the interactive menu](#7-first-run-and-the-interactive-menu)
8. [Command-line reference](#8-command-line-reference)
9. [Configuration](#9-configuration)
10. [The modules in depth](#10-the-modules-in-depth)
11. [Risk levels](#11-risk-levels)
12. [Notifications](#12-notifications)
13. [The web dashboard](#13-the-web-dashboard)
14. [Where data is stored](#14-where-data-is-stored)
15. [Running with and without root](#15-running-with-and-without-root)
16. [Troubleshooting](#16-troubleshooting)
17. [Frequently asked questions](#17-frequently-asked-questions)
18. [Development and testing](#18-development-and-testing)
19. [Glossary](#19-glossary)

---

## 1. What DroidNet Sentinel is

DroidNet Sentinel is a Wi-Fi network auditor for Android (through Termux)
and Linux. From a single command-line tool it:

- discovers the live hosts on your local network,
- scans their open TCP ports and identifies the software behind them,
- classifies each host by risk,
- looks up public exploits and known vulnerabilities (CVEs) for the
  detected software,
- tracks how the network changes between scans,
- and can, on request, cut an untrusted host off the network.

It also ships a web dashboard (the Command Center) that shows the scan
history with per-host detail and the differences between consecutive scans.

The same codebase runs on a Linux laptop and on an Android phone inside
Termux. Not every capability is available on every platform; the
differences are called out throughout this guide.

---

## 2. Authorized use only

DroidNet Sentinel is a security auditing tool. Several of its features are
intrusive: port scanning, ARP cutting and 802.11 deauthentication can
disrupt a network and are illegal in most jurisdictions when performed
without authorization.

Use it only on:

- a network you own, or
- a network you have explicit, documented permission to test.

The scanning and monitoring features (Sentinel, Hunter, CVE Watcher,
dashboard) are read-only with respect to other devices. The active-response
features (Spoofer, Deauther, and `scan --auto-cut`) deliberately interfere
with other devices and must never be pointed at a network or host you are
not authorized to disrupt. You are responsible for how you use this tool.

---

## 3. How it works

A single entry point, `main.py`, offers an interactive menu and a set of
non-interactive subcommands. Under it, the code is organized in layers:

```
main.py
  cli/        argument parsing and the interactive Rich menu
  core/       database, environment probe, notifier, risk engine, markup
  modules/    sentinel, hunter, cve_watcher, spoofer, deauther
  platform/   cross-platform helpers (Android / Linux)
  web/        the Flask dashboard and its /help guide
```

A normal scan cycle, performed by the Sentinel module, is:

1. Read the current SSID and the local IP address.
2. Ping-sweep the local `/24` subnet to find live hosts.
3. Scan each live host: first its ports, then the software versions on the
   ports that are open.
4. Classify each host by risk from the set of ports it exposes.
5. Save the result to the SQLite database and to a timestamped JSON file.
6. Optionally cut untrusted hosts, then send notifications.

The other modules build on the results of a scan: Hunter and CVE Watcher
read the latest saved scan, and the dashboard reads the whole history.

---

## 4. Requirements

### Python

- Python 3.10 or newer.

### Python packages (installed with pip)

| Package  | Purpose                                   | Required          |
|----------|-------------------------------------------|-------------------|
| requests | HTTP client for NVD, Vulners and Exploit-DB | Yes             |
| rich     | Terminal UI (tables, colours, the menu)   | Yes               |
| flask    | The web dashboard                         | Yes               |
| scapy    | Deauther, and the Spoofer fallback        | Optional          |

The required packages are pinned to compatible ranges in
`requirements.txt`. `scapy` is listed there too but is only needed for the
Deauther and for the Spoofer's fallback mode; the rest of the tool works
without it.

### System tools

`nmap` is required for all scanning. Everything else is optional and only
needed by a specific module; see [Optional tools](#6-optional-tools).

---

## 5. Installation

### Linux (Debian, Ubuntu, Kali, and similar)

```bash
sudo apt install python3 python3-pip python3-venv nmap dsniff libnotify-bin iw
git clone https://github.com/kahz12/DroidNet-Sentinel.git
cd DroidNet-Sentinel
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python main.py
```

The `apt` line installs more than the minimum so that every module works:
`nmap` (scanning), `dsniff` (the Spoofer's `arpspoof`), `libnotify-bin`
(desktop notifications), and `iw` (reading the Wi-Fi network name and
putting an interface into monitor mode). If you only intend to scan, `nmap`
alone is enough.

### Android (Termux)

```bash
pkg install python nmap termux-api
git clone https://github.com/kahz12/DroidNet-Sentinel.git
cd DroidNet-Sentinel
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python main.py
```

Install the Termux:API companion app as well, so that
`termux-wifi-connectioninfo` and `termux-notification` work.

Termux limitations:

- `dsniff` is not packaged for Termux, so the Spoofer module is Linux-only.
- Most built-in Android Wi-Fi chips cannot do monitor mode or packet
  injection, so the Deauther usually needs an external USB adapter.
- `searchsploit` is not packaged for Termux. Hunter works without it (see
  [Hunter](#102-hunter-exploit-lookup)); to use it, clone it manually (below).

### Verifying the installation

```bash
python main.py
```

You should see the banner and the interactive menu. If `nmap` is missing,
scanning will not work; install it before continuing.

---

## 6. Optional tools

Each of these enables one module. Install only what you need.

| Tool                       | Enables                         | Linux install                         |
|----------------------------|---------------------------------|---------------------------------------|
| `nmap`                     | All scanning (required)         | `apt install nmap`                    |
| `iw`                       | Wi-Fi network name; monitor mode| `apt install iw`                      |
| `nmcli` (NetworkManager)   | Wi-Fi network name (preferred)  | not needed if `iw` is installed       |
| `libnotify-bin`            | Desktop notifications           | `apt install libnotify-bin`           |
| `searchsploit` (exploitdb) | Hunter (optional, see 10.2)     | Kali: `apt install exploitdb`; others: see notes |
| `dsniff` (`arpspoof`)      | Spoofer (Linux only)            | `apt install dsniff`                  |
| `aircrack-ng` (`aireplay-ng`) | Deauther injection self-test | `apt install aircrack-ng`             |
| `scapy`                    | Deauther; Spoofer fallback      | `pip install scapy`                   |

Notes:

- The tool reads the current Wi-Fi name from `nmcli` first and, if that is
  not available, from `iw`. Either one is enough. Without either, every
  network is stored under a generic label and the scan history cannot tell
  them apart.
- `searchsploit` is packaged only on Kali (`apt install exploitdb`). On
  Ubuntu, Debian and other distributions, clone the Exploit-DB repository
  into `/opt/exploitdb`, the path its bundled `.searchsploit_rc` expects, and
  link the script into your `PATH`:

  ```bash
  sudo git clone --depth 1 https://gitlab.com/exploit-database/exploitdb.git /opt/exploitdb
  sudo ln -sf /opt/exploitdb/searchsploit /usr/local/bin/searchsploit
  searchsploit vsftpd 2.3.4    # check: lists the vsftpd 2.3.4 backdoor
  ```

  Update it later with `sudo searchsploit -u`.
- On Termux there is no `/opt`. Clone the repository into your home, link
  the script, and give `searchsploit` a copy of its configuration that points
  at the clone (it reads `~/.searchsploit_rc` before its bundled one):

  ```bash
  git clone --depth 1 https://gitlab.com/exploit-database/exploitdb.git ~/exploitdb
  ln -s ~/exploitdb/searchsploit $PREFIX/bin/searchsploit
  sed "s|/opt/exploitdb|$HOME/exploitdb|" ~/exploitdb/.searchsploit_rc > ~/.searchsploit_rc
  ```

  Hunter works without `searchsploit` in any case (see
  [Hunter](#102-hunter-exploit-lookup)).

---

## 7. First run and the interactive menu

Run the tool with no arguments to open the menu:

```bash
python main.py
```

The menu is:

```
[1]  Sentinel — Quick scan      Single-pass scan of the current network
[2]  Sentinel — Daemon mode     Continuous background scanning + alerts
[3]  Hunter — Exploit lookup    Match the latest scan against Exploit-DB
[4]  CVE Watcher                Cross-check the network against known CVEs
[5]  Dashboard — Command Center Launch the web UI on http://127.0.0.1:5000
[6]  Spoofer — Manual ARP cut   Cut a single host off the LAN   (root)
[7]  Deauther — 802.11 deauth   Boot a client off the AP        (root)
[8]  Saved reports              Browse the JSON reports under reports/
[9]  Help and user guide        Built-in quick guide
[0]  Exit
```

What each option does:

- **[1] Quick scan.** Runs one full scan cycle of the current network and
  returns to the menu. Before scanning it asks whether to enable the
  automatic ARP cut of untrusted hosts; the default is no, because cutting
  is disruptive.
- **[2] Daemon mode.** Keeps scanning in a loop. It re-scans the network
  every time the Wi-Fi network changes or six hours pass, and checks every
  five minutes. Press `Ctrl+C` to stop; it cleans up any active ARP
  responses before returning.
- **[3] Hunter.** Reads the most recent scan and searches Exploit-DB for
  each detected service.
- **[4] CVE Watcher.** Reads the most recent scan and matches each detected
  service version against the NVD. It asks whether to run a full audit of
  all publication dates, or the default watch of the last 120 days.
- **[5] Dashboard.** Starts the Flask web interface on
  `http://127.0.0.1:5000` and prints the login credentials or where to find
  them. Press `Ctrl+C` to stop it.
- **[6] Spoofer.** Prompts for a victim IP, gateway IP and interface, then
  performs a bidirectional ARP cut. Requires root.
- **[7] Deauther.** Prompts for a target MAC (or `broadcast`), the access
  point BSSID and a monitor-mode interface, then sends deauth frames.
  Requires root and compatible hardware.
- **[8] Saved reports.** Lists the JSON reports saved under `reports/`.
- **[9] Help.** Shows a built-in quick guide. The dashboard ships the same
  guide under `/help`.
- **[0] Exit.** Leaves the tool. `Ctrl+C` also exits.

---

## 8. Command-line reference

Every menu action has a non-interactive equivalent, which is what you use
for scripts, cron jobs or remote sessions. The general form is:

```bash
python main.py [global options] <command> [command options]
```

### Global options

| Option          | Effect                                                    |
|-----------------|-----------------------------------------------------------|
| `-v`, `--verbose` | DEBUG-level logging on screen.                          |
| `-q`, `--quiet`   | Errors only on screen. Full logs are still written to the log file. |

### Commands

```bash
python main.py scan [--auto-cut]
python main.py daemon [--auto-cut]
python main.py hunt
python main.py cve [--all-time]
python main.py dashboard [--expose]
python main.py reports
python main.py spoof VICTIM_IP GATEWAY_IP [--iface IFACE]
python main.py deauth TARGET_MAC BSSID --iface IFACE [--channel N] [--count N]
python main.py db purge [--days N]
```

| Command     | Description                                                          |
|-------------|---------------------------------------------------------------------|
| `scan`      | One full scan cycle, then exit.                                     |
| `daemon`    | Continuous scanning until `Ctrl+C`.                                 |
| `hunt`      | Exploit lookup against the latest scan.                            |
| `cve`       | CVE Watcher. With `--all-time`, audit CVEs of any date; otherwise the last 120 days. Alias: `cve-watch`. |
| `dashboard` | Start the web UI. With `--expose`, bind to all interfaces (LAN) instead of loopback. |
| `reports`   | List the saved JSON reports.                                       |
| `spoof`     | ARP-cut a single host. `--iface` defaults to the detected interface. Requires root. |
| `deauth`    | Send 802.11 deauth frames. `--iface` is required; `--channel` locks to one channel (otherwise it hops 1/6/11); `--count` is the number of frames (0 means unlimited). Requires root. |
| `db purge`  | Delete scans older than `--days` (default 90).                     |

Add `--help` to any command for its exact flags, for example
`python main.py deauth --help`.

Examples:

```bash
# One scan, quiet, for a cron job
python main.py -q scan

# Continuous monitoring with automatic cutting of untrusted hosts
python main.py daemon --auto-cut

# Full vulnerability audit of the detected software
python main.py cve --all-time

# Expose the dashboard to the LAN (only behind a TLS proxy)
python main.py dashboard --expose

# Cut one host off the network
python main.py spoof 192.168.1.50 192.168.1.1

# Deauthenticate a single client on channel 6
python main.py deauth AA:BB:CC:DD:EE:FF 11:22:33:44:55:66 --iface wlan0mon --channel 6

# Delete scans older than 30 days
python main.py db purge --days 30
```

### Legacy flags

Older flag-style invocations (`--scan`, `--daemon`, `--hunt`,
`--dashboard`, `--reports`, `--cve-watch`, `--spoof`, `--deauth`) still
work but print a deprecation notice. Prefer the subcommands above.

---

## 9. Configuration

### config.json

An optional file named `config.json` at the project root tunes a few
behaviours. If it is missing, the tool runs with empty lists and the
default retention. Example:

```json
{
    "excluded_ips":      ["192.168.1.100"],
    "trusted_ips":       ["192.168.1.1", "192.168.1.50"],
    "db_retention_days": 90
}
```

| Field               | Meaning                                                            |
|---------------------|-------------------------------------------------------------------|
| `excluded_ips`      | IP addresses (or CIDR ranges) skipped by scanning. Your own device is always skipped. |
| `trusted_ips`       | IPs or CIDR ranges that are never cut. The local host and the gateway are always protected even if they are not listed. |
| `db_retention_days` | How many days of scans `db purge` keeps (default 90).             |

The file is validated when loaded. Entries of the wrong type fall back to
their defaults rather than crashing the tool, and list entries that are not
valid IP addresses or CIDR ranges are dropped with a warning.

### Environment variables

| Variable           | Purpose                                        | Default                                   |
|--------------------|------------------------------------------------|-------------------------------------------|
| `TELEGRAM_TOKEN`   | Telegram bot token for alerts                  | unset (Telegram alerts disabled)          |
| `TELEGRAM_CHAT_ID` | Numeric Telegram chat ID                       | unset (Telegram alerts disabled)          |
| `SENTINEL_USER`    | Dashboard username                             | `admin`                                   |
| `SENTINEL_PASS`    | Dashboard password                             | auto-generated and saved to `~/.sentinel/credentials` (mode 0600) |
| `SENTINEL_SECRET`  | Flask session secret key                       | random per start                          |
| `NVD_API_KEY`      | NVD API key for higher CVE Watcher rate limits | unset (slower rate limit)                 |
| `VULNERS_API_KEY`  | Vulners API key; Hunter source without searchsploit | unset (Exploit-DB catalogue is used) |
| `DROIDNET_LOG_DIR` | Directory for the log file                     | `logs/` under the project root            |

Set the ones you need before launching, for example:

```bash
export SENTINEL_USER="operator"
export SENTINEL_PASS="a-strong-password"
export TELEGRAM_TOKEN="123456:abcdef..."
export TELEGRAM_CHAT_ID="987654321"
python main.py dashboard
```

To persist them, put them in a `.env` file at the project root, one
`NAME=value` per line (`export`, quotes and `#` comments are accepted):

```bash
VULNERS_API_KEY="your-key"
TELEGRAM_TOKEN="123456:abcdef..."
TELEGRAM_CHAT_ID="987654321"
```

The file is read at start-up and is ignored by git. A variable already set
in the environment takes precedence over the file. Use the variable names
from the table above; a line that is not `NAME=value` is ignored. Since the
file holds secrets, make it readable only by you: `chmod 600 .env`.
Alternatively, add the `export` lines to your shell profile (`~/.bashrc` or
`~/.zshrc`).

---

## 10. The modules in depth

### 10.1 Sentinel (the scanner)

Sentinel is the core. A scan cycle does the following:

1. **Read the network.** It determines the current Wi-Fi name and your
   local IP. On Linux the name comes from `nmcli`, or from `iw` when
   NetworkManager is not in use. Without either, the network is labelled
   generically and the history cannot distinguish one network from another.
2. **Discovery.** A ping sweep of the local `/24` finds live hosts. When a
   first attempt fails entirely (not merely an empty network), it is retried
   on the next cycle.
3. **Per-host scan, in two passes.** First, the top 100 TCP ports are
   scanned quickly. Then, only on the ports found open, a slower version
   detection identifies the software. Splitting the work matters: version
   detection can be slow when a service does not answer probes, and a slow
   or failed version pass still keeps the open-port list, so the host is
   still assessed. Each pass has its own time budget.
4. **Risk classification.** Each host is scored from the ports it exposes
   (see [Risk levels](#11-risk-levels)). A host whose ports are all closed
   or filtered is reported as protected. A host that could not be scanned
   is scanned once more after all the others have finished; if that also
   fails, it is `UNKNOWN`.
5. **Persistence.** The result is written to the SQLite database and to a
   timestamped JSON file under `reports/`. A completed scan that finds no
   hosts is saved too, so the dashboard can show that devices disappeared.
6. **Active response and alerts (optional).** With `--auto-cut`, untrusted
   hosts are cut. In all cases an OS notification and, if configured, a
   Telegram alert are sent.

**Daemon mode** repeats this cycle. It checks every five minutes and
re-scans whenever the Wi-Fi network changes or six hours have elapsed since
the last scan of the current network. Press `Ctrl+C` to stop; it waits for
any running scans to finish or hit their timeout, and restores any ARP
responses it started. Restoration is attempted on exit but its success
still depends on the network and operating system.

### 10.2 Hunter (exploit lookup)

Hunter reads the most recent saved scan that found at least one service,
which is the same scan CVE Watcher analyses, extracts the product name and
version from each service, and searches Exploit-DB. The scan comes from the
history database, not from the JSON files under `reports/`. Up to five
matches are shown per service.

Hunter uses the first source available:

1. **`searchsploit`**, if installed: the local Exploit-DB, fully offline.
2. **Vulners**, if `VULNERS_API_KEY` is set. Vulners does not answer
   clients without a key. The key is sent in a request header, never in a
   URL, and is removed from any error message.
3. **The Exploit-DB catalogue** otherwise. Hunter downloads Exploit-DB's
   public index (`files_exploits.csv`, about 10 MB) to `exploitdb_cache/` on
   first use and searches it offline. It is revalidated once a week, which
   costs no download while it is unchanged, and an existing copy keeps
   working without internet. It is also used when a Vulners lookup fails.

As with `searchsploit`, an exploit only counts when its title covers the
detected version: dnsmasq 2.85 does not match "Dnsmasq < 2.78". A failed lookup is reported as such and stays distinct from a
successful search that simply found nothing. Results are cached only for the
duration of a single Hunter run.

### 10.3 CVE Watcher

CVE Watcher reads the most recent scan and matches each detected service
version against the NIST National Vulnerability Database (NVD). It has two
modes:

```bash
python main.py cve              # watch: CVEs published in the last 120 days
python main.py cve --all-time   # full audit: CVEs of any publication date
```

- **Watch mode** is for spotting newly disclosed vulnerabilities. It is the
  default and is the right mode to run regularly.
- **Full audit** matches against CVEs of any date. This is the mode that
  surfaces long-known vulnerabilities in old software, for example an
  outdated router firmware. The interactive menu asks which mode to run.

For each service, NVD is queried two ways:

- **By CPE** (a precise product-and-version identifier): NVD's own match of
  the exact version against each CVE. A single product can be filed under
  more than one vendor name in NVD, in which case every name is queried and
  the results are merged without duplicates.
- **By description search**: to catch CVEs that NVD has published but not
  yet analyzed (which a CPE query cannot see). A description hit is kept only
  when the text names the product immediately followed by affected versions
  that cover the detected version; otherwise it is discarded as noise. These
  are labelled **candidates** to signal that their applicability is inferred
  from the description, not confirmed by NVD.

Each match is scored (CVSS 3.1, 3.0, 4.0 or 2.0, whichever NVD provides),
given a plain-language impact summary, and stored in the `cve_alerts` table.
Alerts are announced once: a re-detection notifies again only when its
severity changes or a candidate is later confirmed by CPE. A query that
fails produces an explicit "incomplete" result rather than a false "nothing
found". Responses are cached on disk for 24 hours, keyed separately per
mode, so a re-run on the same day uses the cache and does not wait between
requests.

Services that nmap reports without a version cannot be matched against any
affected range. Samba, for example, often appears as `Samba smbd 3.X - 4.X`,
and Postfix rarely announces a version at all. Such services are not queried;
the run ends with a "Not checked, version not detected" line naming them, so
the absence of matches is never read as a clean result for them. Versions are
also normalized before matching: MariaDB announces itself as
`5.5.5-<real version>` for compatibility with old MySQL clients, and the real
version after the prefix is the one used.

Set `NVD_API_KEY` to raise the request rate limit.

### 10.4 Dashboard

See [The web dashboard](#13-the-web-dashboard).

### 10.5 Spoofer (ARP cut)

The Spoofer performs a bidirectional ARP poisoning attack that cuts a single
host off the network: it tells the victim that the gateway is at your MAC,
and the gateway that the victim is at your MAC, so traffic between them stops
flowing. It prefers two managed `arpspoof` processes (from `dsniff`) and
falls back to a Scapy implementation when `arpspoof` is not available and
`scapy` is installed. On `Ctrl+C` or a startup failure the processes are
stopped and ARP tables are repaired. It requires root. `dsniff` is not
available on Termux, so the Spoofer is Linux-only.

### 10.6 Deauther (802.11 deauthentication)

The Deauther crafts and injects 802.11 deauthentication frames (management
frame type `0xC0`, reason code 7) to disconnect a single client or every
client on an access point (broadcast). It requires root and an interface in
monitor mode; it uses `iw` to switch the interface and, when available,
`aireplay-ng` to test whether the chipset can actually inject frames. If no
channel is given it hops across channels 1, 6 and 11. It has no effect on
WPA3 access points with Management Frame Protection (802.11w) enabled; this
is by design of the protocol, not a limitation of the tool. Most built-in
Android chips cannot inject, so on a phone this usually requires an external
USB adapter.

---

## 11. Risk levels

Each host is scored from the set of open TCP ports it exposes. Only the
port number is considered, not the service banner.

| Level    | Triggered by                                                   | Meaning                                              |
|----------|----------------------------------------------------------------|------------------------------------------------------|
| CRITICAL | FTP (21), Telnet (23), NetBIOS (139), SMB (445), RDP (3389)    | A high-risk service that should not be exposed.      |
| MEDIUM   | HTTP (80, 8080), DNS (53), SSDP (1900), NFS (2049), MQTT (1883, 8883), CoAP (5683) | An exposed service worth a closer look. |
| LOW      | Any other open port                                            | Open ports, lower impact.                            |
| MINIMAL  | No open ports (all closed or filtered)                         | Reachable but exposes nothing.                       |
| UNKNOWN  | A failed, unreachable or inconclusive scan                     | The host could not be assessed; retry before drawing conclusions. |

The classification is a single, shared rule, so the terminal table, the
database and the dashboard always agree. In the dashboard, an UNKNOWN host
is shown as not assessed rather than healthy, so a scan error is never
mistaken for a clean result.

---

## 12. Notifications

After each scan cycle, Sentinel sends a short notification. There are two
channels.

### Desktop or Termux notification

On Linux this uses `notify-send` (from `libnotify-bin`); on Termux it uses
`termux-notification`. If neither is available, the message is printed to the
terminal instead.

### Telegram

To receive alerts in Telegram:

1. Create a bot with `@BotFather` in Telegram and copy its token.
2. Find your numeric chat ID (several public bots report it, for example by
   messaging `@userinfobot`).
3. Export both values before launching:

   ```bash
   export TELEGRAM_TOKEN="123456:abcdef..."
   export TELEGRAM_CHAT_ID="987654321"
   ```

When both variables are set, a summary is sent after every scan and for CVE
alerts. Messages use Telegram's HTML formatting, and all
network-controlled text (network names, service banners) is escaped so it
cannot break or inject into the message. If Telegram rejects a message or
the network fails, the reason is reported on screen and in the log, and the
scan continues; the bot token is never printed in those messages. If the
variables are not set, the Telegram step is skipped silently.

A note on CVE alerts: an alert is sent once. If you configure Telegram after
alerts were already stored, those existing alerts are not re-sent; only new
alerts, severity changes and candidate-to-CPE confirmations trigger a new
message.

---

## 13. The web dashboard

Start it with:

```bash
python main.py dashboard
```

It serves on `http://127.0.0.1:5000` by default. The console prints the
username and either the password or the path where an auto-generated
password was saved.

### Logging in

- The username comes from `SENTINEL_USER` (default `admin`).
- The password comes from `SENTINEL_PASS`. If you do not set it, a strong
  password is generated and written to `~/.sentinel/credentials` with
  owner-only permissions (mode 0600), rather than printed where logs might
  capture it. Read it with `cat ~/.sentinel/credentials`.

Login is protected by a per-session CSRF token, a constant-time credential
check, and a rate limit of five attempts per minute per IP address.

### Pages and API

| Route                   | Description                                           |
|-------------------------|-------------------------------------------------------|
| `/login`, `/logout`     | Session authentication.                               |
| `/`                     | The dashboard: scan cards, summary tiles, diff view.  |
| `/alerts`               | CVE alerts, most urgent first, with filters.          |
| `/help`                 | The built-in user guide.                              |
| `/api/reports`          | Scan history as JSON.                                 |
| `/api/scan/<id>/diff`   | The diff of one scan against the previous one.        |
| `/api/alerts`           | CVE alerts as JSON, with the same filters as `/alerts`. |

`/api/reports` returns a JSON array. Without parameters it returns the full
history. With `page` and `per_page` it paginates (default 20 per page,
maximum 100); the `X-Total-Count`, `X-Page`, `X-Per-Page` and `Link`
response headers describe the pagination, and the `Link` header points to
the next page.

### CVE alerts

The **CVE alerts** page (`/alerts`, linked from the top navigation) lists the
vulnerabilities CVE Watcher has matched, ordered by severity, then CVSS
score, then most recent. Each row shows the severity, the score, the CVE
identifier (linked to its NVD page), the host and network, the affected
service, how it was matched, and when it was first detected (UTC). Expanding
a row shows the impact summary and the CVE description.

- **Match: CPE** means NVD itself matched the exact detected version.
  **Candidate** means NVD has not analyzed the CVE yet and the affected
  versions were read from its description; verify it before acting.
- The filters at the top narrow the list by network and severity. Choosing
  a host from a row, or from a scan card, adds a host filter.
- On the main dashboard, a **CVE alerts** tile shows the total and how many
  are critical or high, and every host with alerts carries a badge such as
  "4 CVEs", coloured by its worst alert, that opens the page filtered to
  that host.

`/api/alerts` returns the same data as a JSON array and accepts the same
`network`, `ip` and `severity` query parameters. The page and the API only
read the alerts; they are produced by running `python main.py cve`.

### Exposing it to the network

By default the dashboard binds to loopback only, so it is reachable from the
same machine. To make it reachable from the LAN:

```bash
python main.py dashboard --expose
```

Do this only behind a TLS-terminating reverse proxy such as nginx or caddy.
Over plain HTTP the login credentials travel in clear text. The startup
banner warns about this when you use `--expose`.

---

## 14. Where data is stored

All paths are relative to the project root unless noted.

| Path                        | Contents                                                      |
|-----------------------------|---------------------------------------------------------------|
| `sentinel.db`               | SQLite database: scans, hosts, ports and CVE alerts.          |
| `reports/`                  | One timestamped JSON file per scan, for portability.          |
| `nvd_cache/`                | Cached NVD responses (24-hour lifetime).                      |
| `exploitdb_cache/`          | Exploit-DB catalogue for Hunter (revalidated weekly).         |
| `logs/droidnet.log`         | Rotating log file (overridable with `DROIDNET_LOG_DIR`).      |
| `config.json`               | Optional configuration (see [Configuration](#9-configuration)). |
| `~/.sentinel/credentials`   | Auto-generated dashboard password (mode 0600), in your home.  |

The database tables are:

```
scans       id, network, scan_time, total_devices, created_at
hosts       id, scan_id, ip, risk
ports       id, host_id, port_entry
cve_alerts  id, cve_id, severity, score, service, ip, summary,
            impact, network, scan_id, created_at, match_type, notified_key
```

The JSON reports are written in parallel with the database so you can move
or archive individual scans without the database.

---

## 15. Running with and without root

Most of the tool works without root, but some capabilities need it.

| Feature                         | Without root                                   | With root            |
|---------------------------------|------------------------------------------------|----------------------|
| Discovery and port scanning     | Works (uses TCP-based probes)                  | Works (can use ARP/ICMP) |
| Hostname and MAC/vendor columns | Usually empty (MAC needs privileged probes)    | Populated            |
| CVE Watcher, Hunter, dashboard  | Works                                          | Works                |
| Spoofer (ARP cut)               | Not available                                  | Required             |
| Deauther (802.11 deauth)        | Not available                                  | Required             |

Running an unprivileged scan is the normal mode and is enough for auditing
exposure. Root only becomes necessary for the active-response modules and
for the richer discovery data.

---

## 16. Troubleshooting

**"nmap not found" or scanning does nothing.**
Install nmap (`apt install nmap`, or `pkg install nmap` on Termux) and run
again. nmap is required for all scanning.

**Every network is saved as "Wired Network" or "Unknown Wi-Fi".**
The tool could not read the Wi-Fi name. Install `iw` (`apt install iw`) or
make sure `nmcli` is available. On Termux, install the Termux:API app.
Scheduled tasks (cron, systemd) often start with a minimal `PATH`; Sentinel
also looks in `/usr/sbin` and `/sbin`, where `iw` lives, so it is found even
when those directories are absent from the service's `PATH`.

**A host shows as UNKNOWN or "Scan error".**
The host did not respond consistently during the scan, often because it went
to sleep (common for phones with Wi-Fi power saving). Sentinel already
scans such a host a second time at the end of the scan, so UNKNOWN means it
failed both attempts and could not be assessed at that moment. Re-scan
later, or wake the device first, to try again.

**The dashboard login always fails with an error.**
If `SENTINEL_PASS` contains bytes that are not valid UTF-8, it cannot be
typed into the login form. The startup banner warns about this. Set
`SENTINEL_PASS` to a normal text value.

**I did not set a password; where is it?**
It was generated and saved to `~/.sentinel/credentials`. Read it with
`cat ~/.sentinel/credentials`, or set `SENTINEL_PASS` yourself.

**Telegram alerts are not arriving.**
Check that both `TELEGRAM_TOKEN` and `TELEGRAM_CHAT_ID` are set and correct.
A delivery failure is reported on screen and in the log with Telegram's own
reason. If you previously saw the token in an error message or screenshot,
revoke it in `@BotFather` and use a new one.

**CVE Watcher reports nothing for old software.**
The default watch only looks at the last 120 days. Run
`python main.py cve --all-time` for a full audit of all dates; that is the
mode that reports long-known vulnerabilities.

**The Deauther has no effect.**
Modern networks using WPA3 with Management Frame Protection (802.11w) are
immune to deauthentication by design. Also confirm the interface is in
monitor mode and the chipset can inject (the module tests this when
`aireplay-ng` is available).

**NVD requests are slow.**
Without an API key the public NVD rate limit is low. Set `NVD_API_KEY` to
raise it. Repeated runs on the same day are served from the local cache.

---

## 17. Frequently asked questions

**Does scanning change anything on the other devices?**
No. Discovery, port scanning, Hunter, CVE Watcher and the dashboard only
read. Only the Spoofer, the Deauther and `scan --auto-cut` interfere with
other devices, and they do so only when you explicitly ask.

**Can I run it continuously?**
Yes. Daemon mode (`python main.py daemon`) scans on a loop and re-scans when
the network changes. Combine it with Telegram alerts to be notified of
changes.

**Does it need an internet connection?**
Scanning and the dashboard work offline. CVE Watcher needs internet to
reach the NVD. Hunter works offline with `searchsploit`, or with the
Exploit-DB catalogue once it has been downloaded; the Vulners source needs
internet.

**Where does the vulnerability data come from?**
CVE Watcher queries the NIST NVD. Hunter searches Exploit-DB: locally via
`searchsploit`, through the Vulners API when a key is set, or in the
downloaded Exploit-DB catalogue.

**Is the CVE match guaranteed to be exploitable?**
No. A CVE match means the detected version falls within an affected range.
Candidate matches are inferred from CVE descriptions and are labelled as
such. Vendors sometimes ship security updates without changing the version
string, so confirm against the actual firmware or package version.

---

## 18. Development and testing

Install the development dependencies and run the checks:

```bash
pip install -r requirements-dev.txt
python -m pytest -q
python -m ruff check droidnet main.py tests --select F,E9,B
python -m vulture droidnet main.py --min-confidence 80
```

The test suite simulates scanning, packet transmission, interface changes
and external API requests; it does not touch the real network, the real
database or the real log. Database tests use temporary files, and the log
directory is redirected for the duration of the suite. Real Wi-Fi hardware
and live external services require separate, manual validation. `scapy` may
be unavailable in restricted environments; the modules that use it report
this without breaking unrelated imports or tests.

The same checks run automatically in GitHub Actions
(`.github/workflows/ci.yml`) on every push to `main` and every pull request:
the test suite on Python 3.10, 3.11, 3.12, 3.13 and 3.14, then `ruff` and
`vulture`. A pull request shows the result of each job before it is merged.

---

## 19. Glossary

- **ARP cut / ARP spoofing.** Poisoning the ARP tables of two devices so
  that traffic between them stops flowing, cutting one host off the network.
- **BSSID.** The MAC address of a Wi-Fi access point.
- **CPE.** Common Platform Enumeration, a standardized identifier for a
  product and version, used to query the NVD precisely.
- **CVE.** Common Vulnerabilities and Exposures, a public identifier for a
  known vulnerability.
- **CVSS.** The scoring system that assigns a severity (0–10) to a CVE.
- **Deauthentication.** An 802.11 management frame that disconnects a client
  from an access point.
- **Monitor mode.** A Wi-Fi interface mode that can observe and inject raw
  802.11 frames; required by the Deauther.
- **NVD.** The NIST National Vulnerability Database, the source of CVE data.
- **SSID.** The human-readable name of a Wi-Fi network.
- **sweep / ping sweep.** Probing every address in a subnet to find the live
  hosts.

---

Released under the MIT License. For a concise overview, see the
[README](../README.md).
