"""
Exploit Lookup Module — cross-references scan results with Exploit-DB.

Takes the most recent Sentinel JSON report and searches each detected
service against the local Exploit-DB via searchsploit.

Requires:
    searchsploit — part of the exploitdb project
    Linux: sudo apt install exploitdb
    Termux: exploitdb is NOT available as a Termux package.
            Clone the repository manually:
              git clone https://gitlab.com/exploit-database/exploitdb.git
              ln -s $PWD/exploitdb/searchsploit $PREFIX/bin/searchsploit
    Update DB: searchsploit -u
"""

import json
import os
import subprocess

from rich           import print as rprint
from rich.console   import Console
from rich.table     import Table

from droidnet.config import REPORTS_DIR

console = Console()


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
    if len(parts) < 4 or "Escudo" in raw_service or "Error" in raw_service:
        return None

    query = " ".join(parts[3:])
    query = query.split("(")[0].strip()
    return query or None


def hunt_exploits(query: str) -> list[dict]:
    """
    Run searchsploit and return matching exploits for *query*.

    Uses -j for JSON output and --disable-colour to avoid ANSI codes
    that break JSON parsing.

    Returns:
        List of exploit dicts, each with at least "Title" and "Path".
    """
    try:
        proc = subprocess.run(
            ["searchsploit", query, "--disable-colour", "-j"],
            capture_output=True,
            text=True,
            timeout=30,
        )
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as exc:
        rprint(f"[red]Error consultando Exploit-DB: {exc}[/red]")
        return []

    if proc.returncode != 0 or not proc.stdout:
        return []

    try:
        data = json.loads(proc.stdout)
    except json.JSONDecodeError as exc:
        # searchsploit antiguo o stderr mezclado en stdout: salida no-JSON.
        rprint(f"[yellow]searchsploit devolvió salida no-JSON para '{query}': {exc}[/yellow]")
        return []

    return data.get("RESULTS_EXPLOIT", [])


def run_hunter() -> None:
    """
    Main Hunter entry point.

    Loads the latest Sentinel report, iterates over each scanned host
    and service, queries Exploit-DB, and prints results to the terminal.
    """
    rprint("[bold red][☠][/bold red] Iniciando módulo DroidNet Hunter...")

    latest = get_latest_report()
    if not latest:
        rprint("[yellow][-] No hay reportes de Sentinel. Ejecuta un escaneo primero.[/yellow]")
        return

    rprint(f"[*] Cargando último escaneo: [bold white]{latest}[/bold white]")

    with open(latest) as fh:
        data = json.load(fh)

    for ip, services in data.get("targets", {}).items():
        if "Escudo intacto" in services or (services and "Error" in services[0]):
            continue

        rprint(f"\n[bold green][+][/bold green] Analizando: [bold cyan]{ip}[/bold cyan]")

        for raw in services:
            query = clean_service_name(raw)
            if not query or len(query) < 4:
                continue

            rprint(f"  [*] Query: [yellow]{query}[/yellow]")
            exploits = hunt_exploits(query)

            if exploits:
                table = Table(show_header=True, header_style="bold red")
                table.add_column("Exploit Title", style="white")
                table.add_column("Path / EDB-ID", style="dim", justify="right")

                for ex in exploits[:5]:
                    table.add_row(ex.get("Title", "Desconocido"), ex.get("Path", ""))

                console.print(table)

                if len(exploits) > 5:
                    rprint(f"  [dim]... y {len(exploits) - 5} exploits más ocultos.[/dim]")
            else:
                rprint("  [dim][-] Sin exploits públicos verificados.[/dim]")


if __name__ == "__main__":
    run_hunter()
