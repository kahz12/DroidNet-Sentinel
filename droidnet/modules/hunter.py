"""
Exploit Lookup Module — cross-references scan results with Exploit-DB.

Takes the most recent scan with detected services from the history database
(the same scan CVE Watcher analyses) and searches each service against the
local Exploit-DB via searchsploit. If searchsploit is unavailable, it falls
back to the public Vulners API.

Requires:
    searchsploit — part of the exploitdb project (recommended)
    Linux: sudo apt install exploitdb
    Termux: exploitdb is NOT available as a Termux package.
            Clone the repository manually:
              git clone https://gitlab.com/exploit-database/exploitdb.git
              ln -s $PWD/exploitdb/searchsploit $PREFIX/bin/searchsploit
    Update DB: searchsploit -u

Online fallback: if searchsploit is not found in PATH, the public Vulners
API is used (rate-limited, no API key).
"""

import json
import shutil
import subprocess

import requests
from rich           import print as rprint
from rich.console   import Console
from rich.table     import Table

from droidnet.core.database import init_db, get_latest_scan_with_services
from droidnet.core.markup import esc
from droidnet.core.risk import is_port_line
from droidnet.modules.cve_watcher import parse_service_info

console = Console()

def _searchsploit_path() -> str | None:
    """
    Locate the searchsploit binary. Probed lazily on each call so a long-lived
    daemon picks up an `apt install exploitdb` performed after start-up.
    """
    return shutil.which("searchsploit")

# Query cache to avoid N identical lookups when the same service appears on
# N hosts. Lives for the duration of the module run.
_EXPLOIT_CACHE: dict[str, list[dict]] = {}


def clean_service_name(raw_service: str) -> str | None:
    """
    Extract the software name from an nmap port line for use as a
    searchsploit query.

    Input : "80/tcp   open  http    Apache httpd 2.4.29 ((Ubuntu))"
    Output: "Apache httpd 2.4.29"

    Uses CVE Watcher's parser, so both modules read banners the same way
    (MariaDB's real version, no wildcard ranges in product names).
    Returns None for markers and port lines without a banner.
    """
    info = parse_service_info(raw_service)
    return info["raw"] if info else None


def _hunt_exploits_local(query: str) -> list[dict] | None:
    """Query the local searchsploit binary. Returns a list of exploit dicts."""
    try:
        proc = subprocess.run(
            ["searchsploit", query, "--disable-colour", "-j"],
            capture_output=True,
            text=True,
            timeout=30,
        )
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as exc:
        rprint(f"[red]Error querying local Exploit-DB: {esc(exc)}[/red]")
        return None

    if proc.returncode != 0 or not proc.stdout:
        return None

    try:
        data = json.loads(proc.stdout)
    except json.JSONDecodeError as exc:
        rprint(f"[yellow]searchsploit returned non-JSON output for '{esc(query)}': {esc(exc)}[/yellow]")
        return None

    results = data.get("RESULTS_EXPLOIT") if isinstance(data, dict) else None
    return results if isinstance(results, list) and all(isinstance(item, dict) for item in results) else None


def _hunt_exploits_online(query: str) -> list[dict] | None:
    """
    Online fallback via the public Vulners API (no API key, rate-limited).

    Normalises the response to the same shape as local searchsploit:
    [{"Title": ..., "Path": ..., "Date_Published": ...}]
    """
    try:
        resp = requests.get(
            "https://vulners.com/api/v3/search/lucene/",
            params={"query": f"type:exploitdb AND {query}", "size": 10},
            timeout=10,
            headers={"User-Agent": "DroidNet-Sentinel"},
        )
        resp.raise_for_status()
        payload = resp.json()
    except (requests.RequestException, ValueError) as exc:
        rprint(f"[yellow]Online fallback failed for '{esc(query)}': {esc(exc)}[/yellow]")
        return None

    data = payload.get("data") if isinstance(payload, dict) else None
    if not isinstance(data, dict) or not isinstance(data.get("search"), list):
        return None

    results: list[dict] = []
    for item in data["search"]:
        if not isinstance(item, dict) or not isinstance(item.get("_source"), dict):
            return None
        src = item.get("_source", {})
        published = (src.get("published") or "")[:10]
        results.append({
            "Title":          src.get("title", "Unknown"),
            "Path":           src.get("href") or src.get("id", ""),
            "Date_Published": published,
        })
    return results


def hunt_exploits(query: str) -> list[dict] | None:
    """
    Run an exploit search for *query* and return results ordered
    by descending publication date (most recent first).

    Uses local searchsploit if available, otherwise falls back to
    online search (Vulners). Memoises by query to avoid duplicate requests.
    """
    if query in _EXPLOIT_CACHE:
        return _EXPLOIT_CACHE[query]

    if _searchsploit_path():
        results = _hunt_exploits_local(query)
    else:
        results = _hunt_exploits_online(query)

    if results is None:
        return None  # Transient failures must be retried, never cached.
    # Descending order by Date_Published; entries without a date go last.
    results.sort(key=lambda ex: ex.get("Date_Published") or "", reverse=True)

    _EXPLOIT_CACHE[query] = results
    return results


def run_hunter() -> None:
    """
    Main Hunter entry point.

    Loads the newest scan with detected services, iterates over each scanned
    host and service, queries Exploit-DB, and prints results to the terminal.

    The scan comes from the history database, not from the JSON files under
    reports/, so Hunter and CVE Watcher always analyse the same scan. The
    newest JSON file by modification time is not a reliable "latest scan":
    copying or touching an old report changes it, and the newest scan may
    have found no service to look up at all.
    """
    _EXPLOIT_CACHE.clear()
    rprint("[bold red][☠][/bold red] Starting DroidNet Hunter module...")

    if not _searchsploit_path():
        rprint(
            "[yellow][!] searchsploit not found in PATH; "
            "using online fallback (Vulners, rate-limited).[/yellow]"
        )

    # Hunter may be the first thing run on a fresh install, before any scan
    # has created the schema (idempotent).
    init_db()
    scan = get_latest_scan_with_services()
    if not scan:
        rprint("[yellow][-] No scans with detected services found. Run Sentinel first.[/yellow]")
        return

    # The network name is the SSID, which any nearby access point can choose.
    rprint(f"[*] Analysing scan from [bold white]{esc(scan['network'])}[/bold white] "
           f"(ID: {scan['id']}, {esc(scan['scan_time'])})")

    for ip, services in scan["targets"].items():
        # Hosts holding only markers ("Shield intact", "Error: ...") have no
        # service to look up.
        if not any(is_port_line(s) for s in services):
            continue

        rprint(f"\n[bold green][+][/bold green] Analysing: [bold cyan]{esc(ip)}[/bold cyan]")

        for raw in services:
            query = clean_service_name(raw)
            if not query or len(query) < 4:
                continue

            rprint(f"  [*] Query: [yellow]{esc(query)}[/yellow]")
            exploits = hunt_exploits(query)

            if exploits:
                table = Table(show_header=True, header_style="bold red")
                table.add_column("Date",          style="cyan",  width=12)
                table.add_column("Exploit Title", style="white")
                table.add_column("Path / EDB-ID", style="dim",   justify="right")

                # Exploit-DB / Vulners fields are external data, and table
                # cells are parsed as markup. A null field from the API
                # falls back to a label instead of rendering "None".
                for ex in exploits[:5]:
                    table.add_row(
                        esc(ex.get("Date_Published") or "—"),
                        esc(ex.get("Title") or "Unknown"),
                        esc(ex.get("Path") or ""),
                    )

                console.print(table)

                if len(exploits) > 5:
                    rprint(f"  [dim]... and {len(exploits) - 5} more exploits hidden.[/dim]")
            elif exploits is None:
                rprint("[yellow]Exploit lookup failed; result unknown.[/yellow]")
            else:
                rprint("  [dim][-] No verified public exploits.[/dim]")


if __name__ == "__main__":
    run_hunter()
