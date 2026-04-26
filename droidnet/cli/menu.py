"""
Interactive CLI menu for DroidNet Sentinel.

Provides the banner, the main menu loop, and all action wrappers
that bridge user input to the feature modules.
"""

import json
import os
import threading
import time

from rich           import print as rprint
from rich.console   import Console
from rich.panel     import Panel
from rich.prompt    import Prompt
from rich.table     import Table

from droidnet           import __version__
from droidnet.config    import REPORTS_DIR
from droidnet.platform.utils import check_root, get_default_iface

console = Console()


# ══════════════════════════════════════════════════════════════════
#  Banner
# ══════════════════════════════════════════════════════════════════

def print_banner() -> None:
    """Print the ASCII banner and system capability summary."""
    banner = """
[bold cyan]
██████╗ ██████╗  ██████╗ ██╗██████╗ ███╗   ██╗███████╗████████╗
██╔══██╗██╔══██╗██╔═══██╗██║██╔══██╗████╗  ██║██╔════╝╚══██╔══╝
██║  ██║██████╔╝██║   ██║██║██║  ██║██╔██╗ ██║█████╗     ██║
██║  ██║██╔══██╗██║   ██║██║██║  ██║██║╚██╗██║██╔══╝     ██║
██████╔╝██║  ██║╚██████╔╝██║██████╔╝██║ ╚████║███████╗   ██║
╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚═╝╚═════╝ ╚═╝  ╚═══╝╚══════╝   ╚═╝
[/bold cyan][bold red]
███████╗███████╗███╗   ██╗████████╗██╗███╗   ██╗███████╗██╗
██╔════╝██╔════╝████╗  ██║╚══██╔══╝██║████╗  ██║██╔════╝██║
███████╗█████╗  ██╔██╗ ██║   ██║   ██║██╔██╗ ██║█████╗  ██║
╚════██║██╔══╝  ██║╚██╗██║   ██║   ██║██║╚██╗██║██╔══╝  ██║
███████║███████╗██║ ╚████║   ██║   ██║██║ ╚████║███████╗███████╗
╚══════╝╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚═╝╚═╝  ╚═══╝╚══════╝╚══════╝
[/bold red]"""

    console.print(banner)
    console.print(
        Panel(
            f"[bold white]v{__version__}[/bold white] · "
            "[dim]Solo para uso en redes propias o con autorización explícita.[/dim]",
            style="dim cyan",
            expand=False,
        )
    )
    console.print()

    try:
        from droidnet.core.env import evaluate_system, display_capabilities
        display_capabilities(evaluate_system())
        console.print()
    except Exception:
        pass


# ══════════════════════════════════════════════════════════════════
#  Menu rendering
# ══════════════════════════════════════════════════════════════════

def print_menu() -> None:
    """Render the main menu table."""
    table = Table(show_header=False, box=None, padding=(0, 2))
    table.add_column(style="bold cyan",  width=4)
    table.add_column(style="bold white", width=28)
    table.add_column(style="dim")

    table.add_row("[1]", "Sentinel — Escaneo rápido",  "Escanea la red y muestra resultados")
    table.add_row("[2]", "Sentinel — Modo daemon",      "Escaneo continuo en background")
    table.add_row("[3]", "Hunter — Buscar exploits",    "Analiza el último reporte vs Exploit-DB")
    table.add_row("[4]", "Dashboard — Command Center",  "Levanta servidor web en :5000")
    table.add_row("[5]", "Spoofer — Corte ARP manual",  "Cortar acceso a una IP específica")
    table.add_row("[6]", "Deauther — Deauth 802.11",    "Desconectar dispositivo del AP")
    table.add_row("[7]", "Ver reportes guardados",      "Listar auditorías anteriores")
    table.add_row("[8]", "CVE-Watcher — Alertas CVE",   "Cruzar red escaneada con CVEs recientes")
    table.add_row("[dim]─[/dim]", "[dim]──────────────────────────[/dim]", "")
    table.add_row("[0]", "[red]Salir[/red]", "")

    console.print(Panel(table, title="[bold cyan]⚡ MENÚ PRINCIPAL[/bold cyan]", border_style="cyan"))


# ══════════════════════════════════════════════════════════════════
#  Action wrappers
# ══════════════════════════════════════════════════════════════════

def _ask_auto_cut() -> bool:
    """Ask whether to activate automatic ARP cutting. Default is NO (destructive)."""
    answer = Prompt.ask(
        "[bold]¿Corte ARP automático a hosts no fiables?[/bold]",
        choices=["s", "n"],
        default="n",
        show_choices=True,
    )
    return answer.lower() == "s"


def _run_sentinel_interactive() -> None:
    from droidnet.modules.sentinel import run_sentinel
    auto_cut = _ask_auto_cut()
    run_sentinel(interactive=True, auto_cut=auto_cut)


def _run_sentinel_daemon() -> None:
    from droidnet.modules.sentinel import run_sentinel
    auto_cut = _ask_auto_cut()
    rprint("[bold yellow][!][/bold yellow] Iniciando Sentinel en modo daemon...")
    rprint("[dim]Ctrl+C para detener.[/dim]\n")
    t = threading.Thread(
        target=run_sentinel,
        kwargs={"interactive": False, "auto_cut": auto_cut},
        daemon=True,
    )
    t.start()
    try:
        while t.is_alive():
            time.sleep(1)
    except KeyboardInterrupt:
        rprint("\n[bold yellow][!][/bold yellow] Daemon detenido.")


def _run_hunter() -> None:
    from droidnet.modules.hunter import run_hunter
    run_hunter()


def _run_dashboard() -> None:
    from droidnet.web.dashboard import app, _print_startup_banner
    # From the interactive menu, the bind is always loopback. To
    # expose to LAN, use the CLI: `python main.py --dashboard --expose`.
    _print_startup_banner(host="127.0.0.1")
    rprint("[dim]Ctrl+C para detener.[/dim]\n")
    try:
        app.run(host="127.0.0.1", port=5000, debug=False, use_reloader=False)
    except KeyboardInterrupt:
        rprint("\n[bold yellow][!][/bold yellow] Dashboard detenido.")


def _run_spoofer_interactive() -> None:
    from droidnet.modules.spoofer import poison

    if not check_root():
        rprint("[red][✗] Necesitas root para el spoofer.[/red]")
        return

    console.print("\n[bold cyan]── ARP Spoofer ──[/bold cyan]")
    target_ip  = Prompt.ask("  IP víctima")
    gateway_ip = Prompt.ask("  IP gateway", default="192.168.1.1")
    iface      = Prompt.ask("  Interfaz",   default=get_default_iface())
    console.print()
    poison(target_ip, gateway_ip, iface)


def _run_cve_watcher() -> None:
    from droidnet.modules.cve_watcher import run_cve_watcher
    run_cve_watcher(show_history=True)


def _run_deauther_interactive() -> None:
    from droidnet.modules.deauther import deauth_target, BROADCAST

    if not check_root():
        rprint("[red][✗] Necesitas root para el deauther.[/red]")
        return

    console.print("\n[bold cyan]── 802.11 Deauther ──[/bold cyan]")
    rprint("[dim]Escribe 'broadcast' como MAC para expulsar a todos los clientes del AP.[/dim]")

    raw_target = Prompt.ask("  MAC víctima (o 'broadcast')")
    bssid      = Prompt.ask("  BSSID del AP")
    iface      = Prompt.ask("  Interfaz (monitor mode)", default="wlan0mon")

    target = BROADCAST if raw_target.lower() == "broadcast" else raw_target
    console.print()
    deauth_target(target, bssid, iface)


def list_reports() -> None:
    """List all saved reports with basic metadata."""
    from datetime import datetime

    files = sorted(REPORTS_DIR.glob("*.json"), key=os.path.getmtime, reverse=True)
    if not files:
        rprint("[yellow][-] No hay reportes guardados. Ejecuta un escaneo primero.[/yellow]")
        return

    table = Table(
        title        = "[bold cyan]Reportes guardados[/bold cyan]",
        show_header  = True,
        header_style = "bold magenta",
    )
    table.add_column("#",       style="dim",   width=4)
    table.add_column("Red",     style="white", width=20)
    table.add_column("Fecha",   style="cyan")
    table.add_column("Hosts",   justify="center")
    table.add_column("Archivo", style="dim")

    for i, path in enumerate(files, 1):
        try:
            with path.open() as fh:
                data = json.load(fh)
            ts = data.get("time", "")
            try:
                ts = datetime.strptime(ts, "%Y%m%d_%H%M%S").strftime("%d/%m/%Y %H:%M")
            except Exception:
                pass
            hosts = str(len(data.get("targets", {})))
            table.add_row(str(i), data.get("network", "?"), ts, hosts, path.name)
        except Exception:
            table.add_row(str(i), "?", "?", "?", path.name)

    console.print("\n", table, "\n")


# ══════════════════════════════════════════════════════════════════
#  Main interactive loop
# ══════════════════════════════════════════════════════════════════

def interactive_menu() -> None:
    """
    Main menu loop — reads the user's choice and dispatches it.
    Runs until the user chooses option 0 or presses Ctrl+C.
    """
    actions = {
        "1": _run_sentinel_interactive,
        "2": _run_sentinel_daemon,
        "3": _run_hunter,
        "4": _run_dashboard,
        "5": _run_spoofer_interactive,
        "6": _run_deauther_interactive,
        "7": list_reports,
        "8": _run_cve_watcher,
    }

    while True:
        print_menu()

        try:
            choice = Prompt.ask(
                "[bold cyan]droidnet[/bold cyan][white]>[/white]",
                choices=["0", "1", "2", "3", "4", "5", "6", "7", "8"],
                show_choices=False,
            )
        except KeyboardInterrupt:
            rprint("\n[bold yellow][!][/bold yellow] Saliendo...")
            break

        if choice == "0":
            rprint("\n[bold cyan][*][/bold cyan] DroidNet Sentinel cerrado. Stay safe.\n")
            break

        console.print()
        actions[choice]()
        console.print()

        try:
            console.input("[dim]  Presiona Enter para volver al menú...[/dim]")
        except KeyboardInterrupt:
            break

        console.clear()
        print_banner()
