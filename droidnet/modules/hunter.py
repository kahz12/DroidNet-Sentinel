"""
Exploit Lookup Module — cross-references scan results with Exploit-DB.

Takes the most recent Sentinel JSON report and searches each detected
service against the local Exploit-DB via searchsploit. If searchsploit
no está disponible, hace fallback a la API pública de Vulners.

Requires:
    searchsploit — part of the exploitdb project (recomendado)
    Linux: sudo apt install exploitdb
    Termux: exploitdb is NOT available as a Termux package.
            Clone the repository manually:
              git clone https://gitlab.com/exploit-database/exploitdb.git
              ln -s $PWD/exploitdb/searchsploit $PREFIX/bin/searchsploit
    Update DB: searchsploit -u

Fallback online: si searchsploit no se encuentra en PATH, se usa la API
pública de Vulners (rate-limited, sin API key).
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

# Detect searchsploit una sola vez al cargar el módulo.
_SEARCHSPLOIT_PATH: str | None = shutil.which("searchsploit")

# Cache de queries para evitar N consultas idénticas cuando el mismo
# servicio aparece en N hosts. Vive durante la ejecución del módulo.
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
    if len(parts) < 4 or "Escudo" in raw_service or "Error" in raw_service:
        return None

    query = " ".join(parts[3:])
    query = query.split("(")[0].strip()
    return query or None


def _hunt_exploits_local(query: str) -> list[dict]:
    """Consulta searchsploit local. Devuelve lista de dicts de exploits."""
    try:
        proc = subprocess.run(
            ["searchsploit", query, "--disable-colour", "-j"],
            capture_output=True,
            text=True,
            timeout=30,
        )
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as exc:
        rprint(f"[red]Error consultando Exploit-DB local: {exc}[/red]")
        return []

    if proc.returncode != 0 or not proc.stdout:
        return []

    try:
        data = json.loads(proc.stdout)
    except json.JSONDecodeError as exc:
        rprint(f"[yellow]searchsploit devolvió salida no-JSON para '{query}': {exc}[/yellow]")
        return []

    return data.get("RESULTS_EXPLOIT", [])


def _hunt_exploits_online(query: str) -> list[dict]:
    """
    Fallback online vía API pública de Vulners (sin API key, rate-limited).

    Normaliza la respuesta al mismo shape que searchsploit local:
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
        rprint(f"[yellow]Fallback online falló para '{query}': {exc}[/yellow]")
        return []

    results: list[dict] = []
    for item in payload.get("data", {}).get("search", []):
        src = item.get("_source", {})
        published = (src.get("published") or "")[:10]
        results.append({
            "Title":          src.get("title", "Desconocido"),
            "Path":           src.get("href") or src.get("id", ""),
            "Date_Published": published,
        })
    return results


def hunt_exploits(query: str) -> list[dict]:
    """
    Run an exploit search for *query* and return results ordered
    by descending publication date (most recent first).

    Uses local searchsploit if available, otherwise falls back to
    online search (Vulners). Memoises by query to avoid duplicate requests.
    """
    if query in _EXPLOIT_CACHE:
        return _EXPLOIT_CACHE[query]

    if _SEARCHSPLOIT_PATH:
        results = _hunt_exploits_local(query)
    else:
        results = _hunt_exploits_online(query)

    # Orden descendente por Date_Published; entradas sin fecha al final.
    results.sort(key=lambda ex: ex.get("Date_Published") or "", reverse=True)

    _EXPLOIT_CACHE[query] = results
    return results


def run_hunter() -> None:
    """
    Main Hunter entry point.

    Loads the latest Sentinel report, iterates over each scanned host
    and service, queries Exploit-DB, and prints results to the terminal.
    """
    rprint("[bold red][☠][/bold red] Iniciando módulo DroidNet Hunter...")

    if not _SEARCHSPLOIT_PATH:
        rprint(
            "[yellow][!] searchsploit no encontrado en PATH; "
            "usando fallback online (Vulners, rate-limited).[/yellow]"
        )

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
                table.add_column("Fecha",         style="cyan",  width=12)
                table.add_column("Exploit Title", style="white")
                table.add_column("Path / EDB-ID", style="dim",   justify="right")

                for ex in exploits[:5]:
                    table.add_row(
                        ex.get("Date_Published", "") or "—",
                        ex.get("Title", "Desconocido"),
                        ex.get("Path", ""),
                    )

                console.print(table)

                if len(exploits) > 5:
                    rprint(f"  [dim]... y {len(exploits) - 5} exploits más ocultos.[/dim]")
            else:
                rprint("  [dim][-] Sin exploits públicos verificados.[/dim]")


if __name__ == "__main__":
    run_hunter()
