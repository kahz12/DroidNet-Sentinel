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
from rich.align     import Align
from rich.console   import Console, Group
from rich.panel     import Panel
from rich.prompt    import Prompt
from rich.table     import Table
from rich.text      import Text

from droidnet           import __version__
from droidnet.config    import REPORTS_DIR
from droidnet.platform.utils import check_root, get_default_iface

console = Console()


# ══════════════════════════════════════════════════════════════════
#  Banner
# ══════════════════════════════════════════════════════════════════

_BANNER_ART = r"""
██████╗ ██████╗  ██████╗ ██╗██████╗ ███╗   ██╗███████╗████████╗
██╔══██╗██╔══██╗██╔═══██╗██║██╔══██╗████╗  ██║██╔════╝╚══██╔══╝
██║  ██║██████╔╝██║   ██║██║██║  ██║██╔██╗ ██║█████╗     ██║
██║  ██║██╔══██╗██║   ██║██║██║  ██║██║╚██╗██║██╔══╝     ██║
██████╔╝██║  ██║╚██████╔╝██║██████╔╝██║ ╚████║███████╗   ██║
╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚═╝╚═════╝ ╚═╝  ╚═══╝╚══════╝   ╚═╝
"""

_BANNER_SUB = r"""
███████╗███████╗███╗   ██╗████████╗██╗███╗   ██╗███████╗██╗
██╔════╝██╔════╝████╗  ██║╚══██╔══╝██║████╗  ██║██╔════╝██║
███████╗█████╗  ██╔██╗ ██║   ██║   ██║██╔██╗ ██║█████╗  ██║
╚════██║██╔══╝  ██║╚██╗██║   ██║   ██║██║╚██╗██║██╔══╝  ██║
███████║███████╗██║ ╚████║   ██║   ██║██║ ╚████║███████╗███████╗
╚══════╝╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚═╝╚═╝  ╚═══╝╚══════╝╚══════╝
"""


def print_banner() -> None:
    """Render the ASCII banner, version pill and capability summary."""
    console.print(Text(_BANNER_ART, style="bold cyan"))
    console.print(Text(_BANNER_SUB, style="bold red"))

    subtitle = Text.assemble(
        ("  v", "dim"),
        (__version__, "bold white"),
        ("  •  ",  "dim"),
        ("Network Security Toolkit", "bold cyan"),
        ("  •  ",  "dim"),
        ("Authorised use only", "italic dim"),
    )
    console.print(Panel(subtitle, style="cyan", expand=False, padding=(0, 2)))
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

# (key, label, description, accent_style)
_RECON_ITEMS = [
    ("1", "Sentinel — Quick scan",
        "Single-pass scan of the current network.",          "bold green"),
    ("2", "Sentinel — Daemon mode",
        "Continuous background scanning with alerts.",       "bold green"),
    ("3", "Hunter — Exploit lookup",
        "Match the latest report against Exploit-DB.",       "bold cyan"),
    ("4", "CVE Watcher",
        "Cross-check the network against recent CVEs.",      "bold cyan"),
]

_OPS_ITEMS = [
    ("5", "Dashboard — Command Center",
        "Launch the web UI on http://127.0.0.1:5000.",       "bold magenta"),
    ("6", "Spoofer — Manual ARP cut",
        "Cut a single host off the LAN. Requires root.",     "bold yellow"),
    ("7", "Deauther — 802.11 deauth",
        "Boot a client off the AP. Requires monitor mode.",  "bold red"),
]

_DATA_ITEMS = [
    ("8", "Saved reports",
        "Browse the reports written under reports/.",        "bold white"),
    ("9", "Help & user guide",
        "What every feature does and how to use it.",        "bold cyan"),
    ("0", "Exit",
        "Close DroidNet Sentinel.",                          "bold red"),
]

_VALID_CHOICES = [k for k, *_ in (_RECON_ITEMS + _OPS_ITEMS + _DATA_ITEMS)]


def _section_table(title: str, items: list[tuple[str, str, str, str]]) -> Panel:
    """Render one menu section as a borderless table inside a titled panel."""
    table = Table(show_header=False, box=None, padding=(0, 2), expand=True)
    table.add_column(width=4, justify="right")
    table.add_column(width=30)
    table.add_column(style="dim")

    for key, label, desc, style in items:
        table.add_row(
            f"[bold cyan][{key}][/bold cyan]",
            f"[{style}]{label}[/{style}]",
            desc,
        )
    return Panel(
        table,
        title=f"[bold cyan]{title}[/bold cyan]",
        border_style="cyan",
        padding=(0, 1),
    )


def print_menu() -> None:
    """Render the main menu — three sections inside one outer panel."""
    grouped = Group(
        _section_table("RECON & SCAN",   _RECON_ITEMS),
        _section_table("OPERATIONS",     _OPS_ITEMS),
        _section_table("REPORTS & HELP", _DATA_ITEMS),
    )
    console.print(
        Panel(
            grouped,
            title="[bold white]M A I N   M E N U[/bold white]",
            border_style="bright_cyan",
            padding=(1, 2),
        )
    )


# ══════════════════════════════════════════════════════════════════
#  Help screen
# ══════════════════════════════════════════════════════════════════

def _help_intro() -> Panel:
    body = Text.assemble(
        ("DroidNet Sentinel", "bold cyan"),
        " is a network-security toolkit that audits Wi-Fi networks you own "
        "or are explicitly authorised to test. It discovers live hosts, "
        "fingerprints services, classifies risk and tracks how the network "
        "changes between scans.\n\n",
        ("Typical workflow:\n", "bold white"),
        "  1. Connect to the target network.\n"
        "  2. Run option ",
        ("[1] Quick scan",     "bold green"),
        " or option ",
        ("[2] Daemon",         "bold green"),
        ".\n"
        "  3. Open option ",
        ("[5] Dashboard",      "bold magenta"),
        " to review findings in the web UI.\n"
        "  4. Run option ",
        ("[3] Hunter",         "bold cyan"),
        " or option ",
        ("[4] CVE Watcher",    "bold cyan"),
        " to look for known issues.\n",
    )
    return Panel(
        body,
        title="[bold cyan]Overview[/bold cyan]",
        border_style="cyan",
        padding=(1, 2),
    )


def _help_features() -> Panel:
    table = Table(show_header=True, header_style="bold cyan",
                  box=None, padding=(0, 2), expand=True)
    table.add_column("Feature",  style="bold white", width=22)
    table.add_column("Purpose",  style="dim",        width=44)
    table.add_column("Notes",    style="italic dim")

    table.add_row("Sentinel — scan",
                  "Discovers live hosts and open services on the LAN.",
                  "No root required.")
    table.add_row("Sentinel — daemon",
                  "Same as scan, repeated on a fixed cadence.",
                  "Sends Telegram alerts on changes.")
    table.add_row("Hunter",
                  "Matches the latest scan against the local Exploit-DB.",
                  "Requires `searchsploit`.")
    table.add_row("CVE Watcher",
                  "Queries the NVD for CVEs that match found services.",
                  "Needs internet access.")
    table.add_row("Dashboard",
                  "Web UI showing scan history, diffs and risk levels.",
                  "Loopback by default.")
    table.add_row("Spoofer",
                  "Manual ARP-poisoning cut against a single IP.",
                  "Authorised use only — root required.")
    table.add_row("Deauther",
                  "Sends 802.11 deauth frames at a target or broadcast.",
                  "Needs monitor mode + root.")
    table.add_row("Reports",
                  "Lists every JSON report written under reports/.",
                  "Read-only.")
    return Panel(
        table,
        title="[bold cyan]Features[/bold cyan]",
        border_style="cyan",
        padding=(0, 1),
    )


def _help_risk() -> Panel:
    table = Table(show_header=True, header_style="bold cyan",
                  box=None, padding=(0, 2), expand=True)
    table.add_column("Level",   width=12)
    table.add_column("Trigger", width=36)
    table.add_column("Meaning")

    table.add_row("[bold red]CRÍTICO[/bold red]",
                  "FTP / Telnet / SMB / NetBIOS / RDP",
                  "High-impact service that should not be exposed.")
    table.add_row("[bold yellow]MEDIO[/bold yellow]",
                  "HTTP / HTTP-alt / DNS / SSDP / NFS",
                  "LAN-exposed service. Worth a banner check.")
    table.add_row("[bold blue]BAJO[/bold blue]",
                  "Other open ports",
                  "Open service outside the higher tiers.")
    table.add_row("[bold green]MÍNIMO[/bold green]",
                  "No open ports",
                  "Reachable host with no services.")
    return Panel(
        table,
        title="[bold cyan]Risk levels[/bold cyan]",
        border_style="cyan",
        padding=(0, 1),
    )


def _help_safety() -> Panel:
    body = Text.assemble(
        ("Authorisation. ", "bold yellow"),
        "Spoofer and Deauther are offensive features. Run them only on "
        "networks you own or have written permission to test.\n",
        ("Credentials. ", "bold yellow"),
        "The dashboard auto-generates a password the first time it runs and "
        "saves it to ",
        ("~/.sentinel/credentials", "cyan"),
        " with mode 0600. Override with ",
        ("SENTINEL_PASS", "cyan"),
        ".\n",
        ("Exposure. ", "bold yellow"),
        "Bind the dashboard to LAN only behind a TLS proxy "
        "(nginx / caddy). HTTP credentials travel in plaintext otherwise.\n",
        ("Logs. ", "bold yellow"),
        "All actions are logged to ",
        ("logs/droidnet.log", "cyan"),
        ". Delete the file to reset history.",
    )
    return Panel(
        body,
        title="[bold cyan]Safety & ethics[/bold cyan]",
        border_style="cyan",
        padding=(1, 2),
    )


def _help_cli() -> Panel:
    body = Text.assemble(
        "Every menu option also has a non-interactive equivalent — useful "
        "for cron jobs and scripts:\n\n",
        ("  python main.py scan         ",  "cyan"), "Single scan\n",
        ("  python main.py daemon       ",  "cyan"), "Continuous scan\n",
        ("  python main.py hunt         ",  "cyan"), "Run Hunter\n",
        ("  python main.py cve          ",  "cyan"), "Run CVE Watcher\n",
        ("  python main.py dashboard    ",  "cyan"), "Start the web UI\n",
        ("  python main.py reports      ",  "cyan"), "List saved reports\n",
        ("  python main.py spoof IP GW  ",  "cyan"), "Manual ARP cut\n",
        ("  python main.py deauth ...   ",  "cyan"), "Manual deauth\n",
        ("  python main.py db purge     ",  "cyan"), "Prune old scans\n\n",
        "Add ",
        ("--help", "bold cyan"),
        " to any subcommand to see its flags.",
    )
    return Panel(
        body,
        title="[bold cyan]Command-line equivalents[/bold cyan]",
        border_style="cyan",
        padding=(1, 2),
    )


def _show_help() -> None:
    """Render the help screen as a stack of titled panels."""
    console.clear()
    console.print(
        Align.center(
            Text("DroidNet Sentinel — User Guide",
                 style="bold white on cyan"),
            width=console.size.width,
        )
    )
    console.print()
    console.print(_help_intro())
    console.print(_help_features())
    console.print(_help_risk())
    console.print(_help_safety())
    console.print(_help_cli())


# ══════════════════════════════════════════════════════════════════
#  Action wrappers
# ══════════════════════════════════════════════════════════════════

def _ask_auto_cut() -> bool:
    """Ask whether to enable automatic ARP cutting. Default is NO (destructive)."""
    answer = Prompt.ask(
        "[bold]Enable automatic ARP cut on untrusted hosts?[/bold]",
        choices=["y", "n"],
        default="n",
        show_choices=True,
    )
    return answer.lower() == "y"


def _run_sentinel_interactive() -> None:
    from droidnet.modules.sentinel import run_sentinel
    auto_cut = _ask_auto_cut()
    run_sentinel(interactive=True, auto_cut=auto_cut)


def _run_sentinel_daemon() -> None:
    from droidnet.modules.sentinel import run_sentinel
    auto_cut = _ask_auto_cut()
    rprint("[bold yellow][!][/bold yellow] Starting Sentinel in daemon mode...")
    rprint("[dim]Press Ctrl+C to stop.[/dim]\n")
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
        rprint("\n[bold yellow][!][/bold yellow] Daemon stopped.")


def _run_hunter() -> None:
    from droidnet.modules.hunter import run_hunter
    run_hunter()


def _run_dashboard() -> None:
    from droidnet.web.dashboard import app, _print_startup_banner
    # From the interactive menu, the bind is always loopback. To
    # expose to LAN, use the CLI: `python main.py --dashboard --expose`.
    _print_startup_banner(host="127.0.0.1")
    rprint("[dim]Press Ctrl+C to stop.[/dim]\n")
    try:
        app.run(host="127.0.0.1", port=5000, debug=False, use_reloader=False)
    except KeyboardInterrupt:
        rprint("\n[bold yellow][!][/bold yellow] Dashboard stopped.")


def _run_spoofer_interactive() -> None:
    from droidnet.modules.spoofer import poison

    if not check_root():
        rprint("[red][x] Root privileges required for the Spoofer.[/red]")
        return

    console.print("\n[bold cyan]── ARP Spoofer ──[/bold cyan]")
    target_ip  = Prompt.ask("  Victim IP")
    gateway_ip = Prompt.ask("  Gateway IP", default="192.168.1.1")
    iface      = Prompt.ask("  Interface",  default=get_default_iface())
    console.print()
    poison(target_ip, gateway_ip, iface)


def _run_cve_watcher() -> None:
    from droidnet.modules.cve_watcher import run_cve_watcher
    run_cve_watcher(show_history=True)


def _run_deauther_interactive() -> None:
    from droidnet.modules.deauther import deauth_target, BROADCAST

    if not check_root():
        rprint("[red][x] Root privileges required for the Deauther.[/red]")
        return

    console.print("\n[bold cyan]── 802.11 Deauther ──[/bold cyan]")
    rprint("[dim]Type 'broadcast' as MAC to kick every client off the AP.[/dim]")

    raw_target = Prompt.ask("  Victim MAC (or 'broadcast')")
    bssid      = Prompt.ask("  AP BSSID")
    iface      = Prompt.ask("  Interface (monitor mode)", default="wlan0mon")

    target = BROADCAST if raw_target.lower() == "broadcast" else raw_target
    console.print()
    deauth_target(target, bssid, iface)


def list_reports() -> None:
    """List all saved reports with basic metadata."""
    from datetime import datetime

    files = sorted(REPORTS_DIR.glob("*.json"), key=os.path.getmtime, reverse=True)
    if not files:
        rprint("[yellow][-] No saved reports yet. Run a scan first.[/yellow]")
        return

    table = Table(
        title        = "[bold cyan]Saved reports[/bold cyan]",
        show_header  = True,
        header_style = "bold magenta",
    )
    table.add_column("#",       style="dim",   width=4)
    table.add_column("Network", style="white", width=22)
    table.add_column("Date",    style="cyan")
    table.add_column("Hosts",   justify="center")
    table.add_column("File",    style="dim")

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
        "4": _run_cve_watcher,
        "5": _run_dashboard,
        "6": _run_spoofer_interactive,
        "7": _run_deauther_interactive,
        "8": list_reports,
        "9": _show_help,
    }

    while True:
        print_menu()

        try:
            choice = Prompt.ask(
                "[bold cyan]droidnet[/bold cyan][white] ›[/white]",
                choices=_VALID_CHOICES,
                show_choices=False,
            )
        except (KeyboardInterrupt, EOFError):
            rprint("\n[bold yellow][!][/bold yellow] Exiting...")
            break

        if choice == "0":
            rprint("\n[bold cyan][*][/bold cyan] DroidNet Sentinel closed. Stay safe.\n")
            break

        console.print()
        actions[choice]()
        console.print()

        try:
            console.input("[dim]  Press Enter to return to the menu...[/dim]")
        except (KeyboardInterrupt, EOFError):
            break

        console.clear()
