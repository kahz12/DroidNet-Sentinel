"""
╔══════════════════════════════════════════════════════════════════╗
║              DroidNet Sentinel — Interactive CLI                 ║
║──────────────────────────────────────────────────────────────────║
║  Descripción:                                                    ║
║  Punto de entrada unificado para todos los módulos del toolkit.  ║
║  Expone un menú interactivo y soporte de flags CLI para          ║
║  uso tanto manual como automatizado (scripts, cron, etc).        ║
║                                                                  ║
║  Módulos integrados:                                             ║
║  · sentinel.py  → Escaneo de red + corte ARP                     ║
║  · hunter.py    → Búsqueda de exploits en Exploit-DB             ║
║  · dashboard.py → Servidor web Flask                             ║
║  · spoofer.py   → ARP Spoofing manual                            ║
║  · deauther.py  → Deauth 802.11 (requiere monitor mode)          ║
╚══════════════════════════════════════════════════════════════════╝
"""

# ── Stdlib ────────────────────────────────────────────────────────
import os
import sys
import argparse
import subprocess
import threading
import time

# ── Terceros ──────────────────────────────────────────────────────
from rich.console import Console
from rich.panel   import Panel
from rich.table   import Table
from rich.prompt  import Prompt, Confirm
from rich         import print as rprint

console = Console()

# ── Versión del toolkit ───────────────────────────────────────────
VERSION = "1.0.0"


# ══════════════════════════════════════════════════════════════════
#  UI: Banner de inicio
# ══════════════════════════════════════════════════════════════════

def print_banner():
    """Imprime el banner ASCII del toolkit al iniciar."""
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
            f"[bold white]v{VERSION}[/bold white] · "
            "[dim]Solo para uso en redes propias o con autorización explícita.[/dim]",
            style="dim cyan",
            expand=False
        )
    )
    console.print()


# ══════════════════════════════════════════════════════════════════
#  UI: Menú principal
# ══════════════════════════════════════════════════════════════════

def print_menu():
    """Renderiza el menú principal con Rich."""
    table = Table(
        show_header  = False,
        box          = None,
        padding      = (0, 2)
    )
    table.add_column(style="bold cyan",   width=4)
    table.add_column(style="bold white",  width=28)
    table.add_column(style="dim")

    table.add_row("[ 1 ]", "Sentinel — Escaneo rápido",    "Escanea la red y muestra resultados")
    table.add_row("[ 2 ]", "Sentinel — Modo daemon",        "Escaneo continuo en background")
    table.add_row("[ 3 ]", "Hunter — Buscar exploits",      "Analiza el último reporte vs Exploit-DB")
    table.add_row("[ 4 ]", "Dashboard — Command Center",    "Levanta servidor web en :5000")
    table.add_row("[ 5 ]", "Spoofer — Corte ARP manual",    "Cortar acceso a una IP específica")
    table.add_row("[ 6 ]", "Deauther — Deauth 802.11",      "Desconectar dispositivo del AP")
    table.add_row("[ 7 ]", "Ver reportes guardados",        "Listar auditorías anteriores")
    table.add_row("[dim]─[/dim]", "[dim]──────────────────────────[/dim]", "")
    table.add_row("[ 0 ]", "[red]Salir[/red]",              "")

    console.print(
        Panel(table, title="[bold cyan]⚡ MENÚ PRINCIPAL[/bold cyan]", border_style="cyan")
    )


# ══════════════════════════════════════════════════════════════════
#  ACCIONES: Wrappers de cada módulo
# ══════════════════════════════════════════════════════════════════

def run_sentinel_interactive():
    """Ejecuta sentinel.py en modo interactivo (un solo ciclo)."""
    try:
        from sentinel import run_sentinel
        run_sentinel(interactive=True)
    except ImportError:
        rprint("[red][✗] sentinel.py no encontrado en el directorio actual.[/red]")


def run_sentinel_daemon():
    """
    Lanza sentinel.py en modo daemon dentro de un hilo separado.
    El hilo es daemon=True → muere cuando el proceso principal termina.
    """
    try:
        from sentinel import run_sentinel
        rprint("[bold yellow][!][/bold yellow] Iniciando Sentinel en modo daemon...")
        rprint("[dim]Escanea cada 5 minutos o al cambiar de red. Ctrl+C para detener.[/dim]\n")
        t = threading.Thread(target=run_sentinel, kwargs={"interactive": False}, daemon=True)
        t.start()
        # Mantenemos el hilo vivo hasta Ctrl+C
        while t.is_alive():
            time.sleep(1)
    except KeyboardInterrupt:
        rprint("\n[bold yellow][!][/bold yellow] Daemon detenido.")
    except ImportError:
        rprint("[red][✗] sentinel.py no encontrado.[/red]")


def run_hunter():
    """Ejecuta hunter.py para analizar el último reporte."""
    try:
        from hunter import run_hunter
        run_hunter()
    except ImportError:
        rprint("[red][✗] hunter.py no encontrado.[/red]")


def run_dashboard():
    """
    Lanza dashboard.py (Flask) en un hilo separado.
    Flask bloquea el hilo principal, así que lo corremos aparte
    y le mostramos al usuario cómo detenerlo.
    """
    try:
        from dashboard import app
        rprint("[bold green][✓][/bold green] Dashboard levantado en [cyan]http://127.0.0.1:5000[/cyan]")
        rprint("[dim]Ábrelo en el navegador. Ctrl+C aquí para detenerlo.[/dim]\n")
        try:
            # use_reloader=False obligatorio al correr dentro de un hilo
            app.run(host="0.0.0.0", port=5000, debug=False, use_reloader=False)
        except KeyboardInterrupt:
            rprint("\n[bold yellow][!][/bold yellow] Dashboard detenido.")
    except ImportError:
        rprint("[red][✗] dashboard.py no encontrado.[/red]")


def run_spoofer_interactive():
    """
    Solicita los parámetros del ataque ARP por input interactivo
    y lanza spoofer.py con los valores ingresados.
    """
    try:
        from spoofer import poison
    except ImportError:
        rprint("[red][✗] spoofer.py no encontrado.[/red]")
        return

    # Verificar root antes de pedir datos
    if os.geteuid() != 0:
        rprint("[red][✗] Necesitas root para ejecutar el spoofer.[/red]")
        return

    console.print("\n[bold cyan]── ARP Spoofer ──[/bold cyan]")
    target_ip  = Prompt.ask("  IP víctima")
    gateway_ip = Prompt.ask("  IP gateway", default="192.168.1.1")
    iface      = Prompt.ask("  Interfaz",   default="wlan0")

    console.print()
    poison(target_ip, gateway_ip, iface)


def run_deauther_interactive():
    """
    Solicita los parámetros del ataque Deauth por input interactivo
    y lanza deauther.py con los valores ingresados.
    """
    try:
        from deauther import deauth_target, BROADCAST
    except ImportError:
        rprint("[red][✗] deauther.py no encontrado.[/red]")
        return

    if os.geteuid() != 0:
        rprint("[red][✗] Necesitas root para ejecutar el deauther.[/red]")
        return

    console.print("\n[bold cyan]── 802.11 Deauther ──[/bold cyan]")
    rprint("[dim]Introduce 'broadcast' como MAC para expulsar a todos los clientes del AP.[/dim]")

    raw_target = Prompt.ask("  MAC víctima (o 'broadcast')")
    bssid      = Prompt.ask("  BSSID del AP")
    iface      = Prompt.ask("  Interfaz (monitor mode)", default="wlan0mon")

    target = BROADCAST if raw_target.lower() == "broadcast" else raw_target

    console.print()
    deauth_target(target, bssid, iface)


def list_reports():
    """
    Lista todos los reportes guardados en reports/ con sus metadatos
    básicos (red, timestamp, cantidad de hosts).
    """
    import glob
    import json
    from datetime import datetime

    files = glob.glob("reports/*.json")
    if not files:
        rprint("[yellow][-] No hay reportes guardados. Ejecuta un escaneo primero.[/yellow]")
        return

    files.sort(key=os.path.getmtime, reverse=True)

    table = Table(
        title        = "[bold cyan]Reportes guardados[/bold cyan]",
        show_header  = True,
        header_style = "bold magenta"
    )
    table.add_column("#",        style="dim",   width=4)
    table.add_column("Red",      style="white", width=20)
    table.add_column("Fecha",    style="cyan")
    table.add_column("Hosts",    justify="center")
    table.add_column("Archivo",  style="dim")

    for i, f in enumerate(files, 1):
        try:
            with open(f) as fh:
                data = json.load(fh)
            ts = data.get("time", "")
            try:
                ts = datetime.strptime(ts, "%Y%m%d_%H%M%S").strftime("%d/%m/%Y %H:%M")
            except:
                pass
            hosts = str(len(data.get("targets", {})))
            table.add_row(str(i), data.get("network", "?"), ts, hosts, os.path.basename(f))
        except:
            table.add_row(str(i), "?", "?", "?", os.path.basename(f))

    console.print("\n", table, "\n")


# ══════════════════════════════════════════════════════════════════
#  CORE: Bucle principal del CLI
# ══════════════════════════════════════════════════════════════════

def interactive_menu():
    """
    Bucle principal del menú interactivo.
    Lee la opción del usuario y despacha a la función correspondiente.
    Continúa hasta que el usuario elija salir (opción 0).
    """
    actions = {
        "1": run_sentinel_interactive,
        "2": run_sentinel_daemon,
        "3": run_hunter,
        "4": run_dashboard,
        "5": run_spoofer_interactive,
        "6": run_deauther_interactive,
        "7": list_reports,
    }

    while True:
        print_menu()

        try:
            choice = Prompt.ask(
                "[bold cyan]droidnet[/bold cyan][white]>[/white]",
                choices=["0","1","2","3","4","5","6","7"],
                show_choices=False
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

        # Pausa antes de volver al menú para que el usuario lea el output
        try:
            input("[dim]  Presiona Enter para volver al menú...[/dim]")
        except KeyboardInterrupt:
            break

        console.clear()
        print_banner()


# ══════════════════════════════════════════════════════════════════
#  CLI FLAGS: Modo no interactivo para scripting/automatización
# ══════════════════════════════════════════════════════════════════

def parse_args():
    """
    Define los flags CLI para uso no interactivo.

    Permite invocar módulos directamente sin pasar por el menú:
        python main.py --scan
        python main.py --daemon
        python main.py --hunt
        python main.py --dashboard
        python main.py --spoof 192.168.1.105 192.168.1.1
        python main.py --deauth A1:B2:C3 AA:BB:CC wlan0mon
        python main.py --reports
    """
    parser = argparse.ArgumentParser(
        description="DroidNet Sentinel — Network Security Toolkit",
        formatter_class=argparse.RawTextHelpFormatter
    )

    parser.add_argument("--scan",      action="store_true",  help="Escaneo único de red")
    parser.add_argument("--daemon",    action="store_true",  help="Modo daemon (continuo)")
    parser.add_argument("--hunt",      action="store_true",  help="Buscar exploits en último reporte")
    parser.add_argument("--dashboard", action="store_true",  help="Levantar dashboard web")
    parser.add_argument("--reports",   action="store_true",  help="Listar reportes guardados")

    parser.add_argument(
        "--spoof",
        nargs  = "+",
        metavar= ("VICTIM_IP", "GATEWAY_IP"),
        help   = "ARP Spoof: --spoof <IP_VICTIMA> <IP_GATEWAY> [IFACE]"
    )

    parser.add_argument(
        "--deauth",
        nargs  = 3,
        metavar= ("TARGET_MAC", "BSSID", "IFACE"),
        help   = "Deauth: --deauth <MAC|broadcast> <BSSID> <IFACE>"
    )

    return parser.parse_args()


def handle_args(args):
    """
    Despacha la acción correspondiente según los flags recibidos.
    Devuelve True si se ejecutó algún flag, False si no había ninguno
    (en cuyo caso el caller lanza el menú interactivo).

    Args:
        args: Namespace de argparse con los flags parseados.

    Returns:
        bool: True si se procesó algún flag.
    """
    if args.scan:
        run_sentinel_interactive()
        return True

    if args.daemon:
        run_sentinel_daemon()
        return True

    if args.hunt:
        run_hunter()
        return True

    if args.dashboard:
        run_dashboard()
        return True

    if args.reports:
        list_reports()
        return True

    if args.spoof:
        try:
            from spoofer import poison
        except ImportError:
            rprint("[red][✗] spoofer.py no encontrado.[/red]")
            return True

        if os.geteuid() != 0:
            rprint("[red][✗] Necesitas root.[/red]")
            return True

        target  = args.spoof[0]
        gateway = args.spoof[1]
        iface   = args.spoof[2] if len(args.spoof) > 2 else "wlan0"
        poison(target, gateway, iface)
        return True

    if args.deauth:
        try:
            from deauther import deauth_target, BROADCAST
        except ImportError:
            rprint("[red][✗] deauther.py no encontrado.[/red]")
            return True

        if os.geteuid() != 0:
            rprint("[red][✗] Necesitas root.[/red]")
            return True

        target = BROADCAST if args.deauth[0].lower() == "broadcast" else args.deauth[0]
        deauth_target(target, args.deauth[1], args.deauth[2])
        return True

    return False


# ══════════════════════════════════════════════════════════════════
#  ENTRYPOINT
# ══════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    """
    Uso interactivo:
        python main.py

    Uso con flags (no interactivo):
        python main.py --scan
        python main.py --daemon
        python main.py --hunt
        python main.py --dashboard
        python main.py --reports
        python main.py --spoof 192.168.1.105 192.168.1.1 wlan0
        python main.py --deauth A1:B2:C3:D4:E5:F6 AA:BB:CC:DD:EE:FF wlan0mon
        python main.py --deauth broadcast AA:BB:CC:DD:EE:FF wlan0mon

    Todos los módulos deben estar en el mismo directorio que main.py.
    """
    print_banner()

    args = parse_args()

    # Si se pasaron flags, ejecutamos en modo no interactivo
    if not handle_args(args):
        # Sin flags → menú interactivo
        interactive_menu()
