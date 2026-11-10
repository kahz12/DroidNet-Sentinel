"""
Exploit Lookup Module — cross-references scan results with Exploit-DB.

Takes the most recent scan with detected services from the history database
(the same scan CVE Watcher analyses) and looks each service up in Exploit-DB.

Sources, in order of preference:
    1. searchsploit — the local Exploit-DB (recommended, fully offline).
         Kali: sudo apt install exploitdb        (update with: searchsploit -u)
         Ubuntu, Debian and others have no package. Clone the repository
         into /opt/exploitdb, the path its bundled .searchsploit_rc points
         at, and link the script into PATH:
           sudo git clone --depth 1 https://gitlab.com/exploit-database/exploitdb.git /opt/exploitdb
           sudo ln -sf /opt/exploitdb/searchsploit /usr/local/bin/searchsploit
         Termux has no /opt: clone anywhere, then copy .searchsploit_rc to
         ~/.searchsploit_rc and change its path_array entries to the clone.
    2. Vulners — when VULNERS_API_KEY is set. Its API refuses keyless
       clients (they get a Cloudflare challenge, HTTP 403).
    3. The Exploit-DB catalogue — downloaded once and searched offline
       (see droidnet.modules.exploitdb). Also used when a Vulners lookup
       fails, so a wrong key or an outage still yields an answer.
"""

import json
import shutil
import subprocess

import requests
from rich           import print as rprint
from rich.console   import Console
from rich.table     import Table

from droidnet import config
from droidnet.core.database import init_db, get_latest_scan_with_services
from droidnet.core.markup import esc
from droidnet.modules import exploitdb
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


_VULNERS_URL = "https://vulners.com/api/v3/search/lucene/"


def _redact(text: str, secret: str) -> str:
    return text.replace(secret, "<redacted>") if secret else text


def _hunt_exploits_vulners(query: str, api_key: str) -> list[dict] | None:
    """
    Search Vulners' copy of Exploit-DB with an API key.

    The key travels in the X-Api-Key header and the query in a POST body, so
    neither can appear in a URL that an exception message would print; any
    error text is still scrubbed of the key before it is shown. Normalises
    hits to searchsploit's shape: [{"Title", "Path", "Date_Published"}].
    Returns None when the lookup fails, so the caller can try the catalogue.
    """
    def failed(reason) -> None:
        rprint(f"[yellow]Vulners lookup failed for '{esc(query)}': "
               f"{esc(_redact(str(reason), api_key))}[/yellow]")

    try:
        resp = requests.post(
            _VULNERS_URL,
            json={"query": f"type:exploitdb AND {query}", "size": 10},
            headers={"X-Api-Key": api_key, "User-Agent": "DroidNet-Sentinel"},
            timeout=15,
        )
    except requests.RequestException as exc:
        return failed(exc)
    try:
        payload = resp.json()
    except ValueError:            # e.g. a Cloudflare challenge page
        return failed(f"HTTP {resp.status_code}")

    data = payload.get("data") if isinstance(payload, dict) else None
    if not isinstance(payload, dict) or payload.get("result") != "OK":
        # Vulners explains a refusal ("Unknown api key") in data.error.
        reason = data.get("error") if isinstance(data, dict) else None
        return failed(reason or f"HTTP {resp.status_code}")
    if not isinstance(data, dict) or not isinstance(data.get("search"), list):
        return failed("unexpected response")

    results: list[dict] = []
    for item in data["search"]:
        src = item.get("_source") if isinstance(item, dict) else None
        if not isinstance(src, dict):
            return failed("unexpected response")
        results.append({
            "Title":          src.get("title") or "Unknown",
            "Path":           src.get("href") or src.get("id") or "",
            "Date_Published": (src.get("published") or "")[:10],
        })
    return results


def hunt_exploits(query: str) -> list[dict] | None:
    """
    Run an exploit search for *query* and return results ordered
    by descending publication date (most recent first).

    Source order: searchsploit when installed; otherwise Vulners when
    VULNERS_API_KEY is set, then the offline Exploit-DB catalogue (also when
    Vulners fails). Memoises by query to avoid duplicate requests.
    """
    if query in _EXPLOIT_CACHE:
        return _EXPLOIT_CACHE[query]

    if _searchsploit_path():
        results = _hunt_exploits_local(query)
    else:
        results = None
        if config.VULNERS_API_KEY:
            results = _hunt_exploits_vulners(query, config.VULNERS_API_KEY)
        if results is None:
            results = exploitdb.search(query)

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
        source = ("the Vulners API (VULNERS_API_KEY)" if config.VULNERS_API_KEY else
                  "the Exploit-DB catalogue (downloaded once, then searched offline)")
        rprint(f"[yellow][!] searchsploit not found in PATH; using {source}.[/yellow]")

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
        # Markers ("Shield intact", "Error: ...") and port lines without a
        # product banner ("8008/tcp open http") give nothing to look up; a
        # host with only those is skipped rather than listed with no queries.
        # The same product on two ports is looked up once.
        queries = [q for q in dict.fromkeys(clean_service_name(raw) for raw in services)
                   if q and len(q) >= 4]
        if not queries:
            continue

        rprint(f"\n[bold green][+][/bold green] Analysing: [bold cyan]{esc(ip)}[/bold cyan]")

        for query in queries:
            rprint(f"  [*] Query: [yellow]{esc(query)}[/yellow]")
            exploits = hunt_exploits(query)

            if exploits:
                table = Table(show_header=True, header_style="bold red")
                table.add_column("Date",          style="cyan",  width=12)
                table.add_column("Exploit Title", style="white")
                table.add_column("Path / EDB-ID", style="dim",   justify="right")

                # Exploit-DB, Vulners and catalogue fields are external data,
                # and table cells are parsed as markup. A null field from an
                # API falls back to a label instead of rendering "None".
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
