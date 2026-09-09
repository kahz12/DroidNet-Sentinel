"""
Exploit Lookup Module — cross-references scan results with Exploit-DB.

Takes the most recent Sentinel JSON report and searches each detected
service against the local Exploit-DB via searchsploit. If searchsploit
is unavailable, it falls back to the public Vulners API.

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
import os
import shutil
import subprocess

import requests
from rich           import print as rprint
from rich.console   import Console
from rich.table     import Table

from droidnet.config import REPORTS_DIR

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


def get_latest_report() -> str | None:
    """
    Return the path of the most recently modified report JSON file.

    Returns None if the reports directory is empty or does not exist.
    """
    files = list(REPORTS_DIR.glob("*.json"))
    if not files:
        return None
    return str(max(files, key=os.path.getmtime))


def clean_service_name(raw_service: str) -> str | None:
    """
    Extract the software name from an nmap port line for use as a
    searchsploit query.

    Input : "80/tcp   open  http    Apache httpd 2.4.29 ((Ubuntu))"
    Output: "Apache httpd 2.4.29"

    Returns None for lines that cannot be parsed (markers, errors).
    """
    parts = raw_service.split()
    if len(parts) < 4 or "Shield" in raw_service or "Error" in raw_service:
        return None

    query = " ".join(parts[3:])
    query = query.split("(")[0].strip()
    return query or None


def _hunt_exploits_local(query: str) -> list[dict] | None:
    """Consulta searchsploit local. Devuelve lista de dicts de exploits."""
    try:
        proc = subprocess.run(
            ["searchsploit", query, "--disable-colour", "-j"],
            capture_output=True,
            text=True,
            timeout=30,
        )
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as exc:
        rprint(f"[red]Error querying local Exploit-DB: {exc}[/red]")
        return None

    if proc.returncode != 0 or not proc.stdout:
        return None

    try:
        data = json.loads(proc.stdout)
    except json.JSONDecodeError as exc:
        rprint(f"[yellow]searchsploit returned non-JSON output for '{query}': {exc}[/yellow]")
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
        rprint(f"[yellow]Online fallback failed for '{query}': {exc}[/yellow]")
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

    Loads the latest Sentinel report, iterates over each scanned host
    and service, queries Exploit-DB, and prints results to the terminal.
    """
    _EXPLOIT_CACHE.clear()
    rprint("[bold red][☠][/bold red] Starting DroidNet Hunter module...")

    if not _searchsploit_path():
        rprint(
            "[yellow][!] searchsploit not found in PATH; "
            "using online fallback (Vulners, rate-limited).[/yellow]"
        )

    latest = get_latest_report()
    if not latest:
        rprint("[yellow][-] No Sentinel reports found. Run a scan first.[/yellow]")
        return

    rprint(f"[*] Loading latest scan: [bold white]{latest}[/bold white]")

    try:
        with open(latest) as fh:
            data = json.load(fh)
        if not isinstance(data, dict) or not isinstance(data.get("targets"), dict):
            raise ValueError("invalid report structure")
    except (OSError, ValueError) as exc:
        rprint(f"[yellow]Could not load report: {exc}[/yellow]")
        return

    for ip, services in data.get("targets", {}).items():
        if "Shield intact" in services or (services and "Error" in services[0]):
            continue

        rprint(f"\n[bold green][+][/bold green] Analysing: [bold cyan]{ip}[/bold cyan]")

        for raw in services:
            query = clean_service_name(raw)
            if not query or len(query) < 4:
                continue

            rprint(f"  [*] Query: [yellow]{query}[/yellow]")
            exploits = hunt_exploits(query)

            if exploits:
                table = Table(show_header=True, header_style="bold red")
                table.add_column("Date",          style="cyan",  width=12)
                table.add_column("Exploit Title", style="white")
                table.add_column("Path / EDB-ID", style="dim",   justify="right")

                for ex in exploits[:5]:
                    table.add_row(
                        ex.get("Date_Published", "") or "—",
                        ex.get("Title", "Unknown"),
                        ex.get("Path", ""),
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
