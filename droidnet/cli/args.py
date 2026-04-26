"""
CLI for DroidNet Sentinel.

Subcommands (preferred):
    python main.py scan [--auto-cut]
    python main.py daemon [--auto-cut]
    python main.py hunt
    python main.py dashboard [--expose]
    python main.py reports
    python main.py cve
    python main.py spoof <VICTIM_IP> <GATEWAY_IP> [--iface IFACE]
    python main.py deauth <TARGET_MAC|broadcast> <BSSID> --iface IFACE
                          [--channel N] [--count N]
    python main.py db purge [--days N]

Legacy flags (still accepted, deprecation notice printed):
    python main.py --scan | --daemon | --hunt | --dashboard | --reports
                   --cve-watch | --spoof ... | --deauth ...

Global flags:
    -v / --verbose   DEBUG-level logging on stdout.
    -q / --quiet     ERROR-level only on stdout.
"""

import argparse
import sys

from rich import print as rprint

from droidnet.core.logger import configure as _log_configure
from droidnet.platform.utils import check_root, get_default_iface

# Default retention window for the `db purge` subcommand.
_DEFAULT_RETENTION_DAYS = 90


# ══════════════════════════════════════════════════════════════════
#  Parser construction
# ══════════════════════════════════════════════════════════════════

def _add_global(parser: argparse.ArgumentParser) -> None:
    """Verbosity flags shared at the top level."""
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Logging DEBUG en stdout.")
    parser.add_argument("-q", "--quiet", action="store_true",
                        help="Sólo errores en stdout (logs completos siguen yendo a logs/).")


def _add_legacy_flags(parser: argparse.ArgumentParser) -> None:
    """Old flat flags kept for backward compatibility."""
    parser.add_argument("--scan",      action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--daemon",    action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--hunt",      action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--dashboard", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--reports",   action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--cve-watch", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--auto-cut",  action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--expose",    action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--spoof",  nargs="+", metavar=("VICTIM_IP", "GATEWAY_IP"),
                        help=argparse.SUPPRESS)
    parser.add_argument("--deauth", nargs=3,   metavar=("TARGET_MAC", "BSSID", "IFACE"),
                        help=argparse.SUPPRESS)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog        = "droidnet",
        description = "DroidNet Sentinel — Network Security Toolkit",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    _add_global(parser)
    _add_legacy_flags(parser)

    sub = parser.add_subparsers(dest="cmd", metavar="<comando>")

    p_scan = sub.add_parser("scan",   help="Escaneo único de red")
    p_scan.add_argument("--auto-cut", action="store_true",
                        help="Ejecuta corte ARP a hosts no fiables.")

    p_daemon = sub.add_parser("daemon", help="Modo daemon (escaneo continuo)")
    p_daemon.add_argument("--auto-cut", action="store_true",
                          help="Ejecuta corte ARP a hosts no fiables.")

    sub.add_parser("hunt", help="Buscar exploits del último reporte")

    p_dash = sub.add_parser("dashboard", help="Levantar dashboard web (Flask)")
    p_dash.add_argument("--expose", action="store_true",
                        help="Bind 0.0.0.0 (LAN) en vez de 127.0.0.1.")

    sub.add_parser("reports", help="Listar reportes guardados")
    sub.add_parser("cve",     aliases=["cve-watch"], help="Monitorear CVEs")

    p_spoof = sub.add_parser("spoof", help="ARP Spoof a una IP")
    p_spoof.add_argument("victim",  metavar="VICTIM_IP")
    p_spoof.add_argument("gateway", metavar="GATEWAY_IP")
    p_spoof.add_argument("--iface", default=None,
                         help=f"Interfaz (default: {get_default_iface()}).")

    p_deauth = sub.add_parser("deauth", help="Deauth 802.11")
    p_deauth.add_argument("target",  metavar="TARGET_MAC",
                          help="MAC víctima o 'broadcast'.")
    p_deauth.add_argument("bssid",   metavar="BSSID")
    p_deauth.add_argument("--iface", required=True, help="Interfaz en monitor mode.")
    p_deauth.add_argument("--channel", type=int, default=None,
                          help="Canal 802.11 fijo (default: hopping 1/6/11).")
    p_deauth.add_argument("--count",   type=int, default=0,
                          help="Frames a enviar (0 = infinito).")

    p_db = sub.add_parser("db", help="Mantenimiento de base de datos")
    sub_db = p_db.add_subparsers(dest="db_cmd", metavar="<acción>")
    p_purge = sub_db.add_parser("purge", help="Borrar scans antiguos.")
    p_purge.add_argument("--days", type=int, default=_DEFAULT_RETENTION_DAYS,
                         help=f"Retención en días (default {_DEFAULT_RETENTION_DAYS}).")

    return parser


def parse_args() -> argparse.Namespace:
    parser = _build_parser()
    args = parser.parse_args()
    _log_configure(verbose=args.verbose, quiet=args.quiet)
    return args


# ══════════════════════════════════════════════════════════════════
#  Dispatch
# ══════════════════════════════════════════════════════════════════

def _run_scan(auto_cut: bool) -> None:
    from droidnet.modules.sentinel import run_sentinel
    run_sentinel(interactive=True, auto_cut=auto_cut)


def _run_daemon(auto_cut: bool) -> None:
    from droidnet.modules.sentinel import run_sentinel
    run_sentinel(interactive=False, auto_cut=auto_cut)


def _run_hunt() -> None:
    from droidnet.modules.hunter import run_hunter
    run_hunter()


def _run_dashboard(expose: bool) -> None:
    from droidnet.web.dashboard import app, _print_startup_banner
    host = "0.0.0.0" if expose else "127.0.0.1"
    _print_startup_banner(host=host)
    app.run(host=host, port=5000, debug=False, use_reloader=False)


def _run_reports() -> None:
    from droidnet.cli.menu import list_reports
    list_reports()


def _run_cve() -> None:
    from droidnet.modules.cve_watcher import run_cve_watcher
    run_cve_watcher(show_history=True)


def _run_spoof(victim: str, gateway: str, iface: str | None) -> bool:
    if not check_root():
        rprint("[red][✗] Necesitas root.[/red]")
        return True
    from droidnet.modules.spoofer import poison
    poison(victim, gateway, iface or get_default_iface())
    return True


def _run_deauth(target: str, bssid: str, iface: str,
                channel: int | None, count: int) -> bool:
    if not check_root():
        rprint("[red][✗] Necesitas root.[/red]")
        return True
    from droidnet.modules.deauther import deauth_target, BROADCAST
    mac = BROADCAST if target.lower() == "broadcast" else target
    deauth_target(mac, bssid, iface, count=count, channel=channel)
    return True


def _run_db_purge(days: int) -> None:
    from droidnet.core.database import purge_old_scans
    deleted = purge_old_scans(days)
    rprint(f"[green][✓][/green] Purgados {deleted} scans con antigüedad > {days} días.")


def _legacy_warn(flag: str, replacement: str) -> None:
    rprint(f"[yellow][!][/yellow] {flag} está obsoleto; usa: [cyan]{replacement}[/cyan]")


def handle_args(args: argparse.Namespace) -> bool:
    """
    Dispatch the action that matches the subcommand or legacy flags.

    Returns True if anything was handled (caller should not start the menu).
    """
    # ── Subcommand path (preferred) ──────────────────────────────
    cmd = getattr(args, "cmd", None)
    if cmd == "scan":
        _run_scan(args.auto_cut)
        return True
    if cmd == "daemon":
        _run_daemon(args.auto_cut)
        return True
    if cmd == "hunt":
        _run_hunt()
        return True
    if cmd == "dashboard":
        _run_dashboard(args.expose)
        return True
    if cmd == "reports":
        _run_reports()
        return True
    if cmd in ("cve", "cve-watch"):
        _run_cve()
        return True
    if cmd == "spoof":
        return _run_spoof(args.victim, args.gateway, args.iface)
    if cmd == "deauth":
        return _run_deauth(args.target, args.bssid, args.iface,
                           args.channel, args.count)
    if cmd == "db":
        if getattr(args, "db_cmd", None) == "purge":
            _run_db_purge(args.days)
        else:
            rprint("[yellow]Uso: droidnet db purge [--days N][/yellow]")
        return True

    # ── Legacy flag path (back-compat) ───────────────────────────
    if args.scan:
        _legacy_warn("--scan", "droidnet scan [--auto-cut]")
        _run_scan(args.auto_cut)
        return True
    if args.daemon:
        _legacy_warn("--daemon", "droidnet daemon [--auto-cut]")
        _run_daemon(args.auto_cut)
        return True
    if args.hunt:
        _legacy_warn("--hunt", "droidnet hunt")
        _run_hunt()
        return True
    if args.dashboard:
        _legacy_warn("--dashboard", "droidnet dashboard [--expose]")
        _run_dashboard(args.expose)
        return True
    if args.reports:
        _legacy_warn("--reports", "droidnet reports")
        _run_reports()
        return True
    if args.cve_watch:
        _legacy_warn("--cve-watch", "droidnet cve")
        _run_cve()
        return True
    if args.spoof:
        _legacy_warn("--spoof",
                     "droidnet spoof <VICTIM> <GATEWAY> [--iface IFACE]")
        if len(args.spoof) < 2:
            rprint("[red][✗] --spoof requiere al menos <IP_VICTIMA> <IP_GATEWAY>.[/red]")
            return True
        iface = args.spoof[2] if len(args.spoof) > 2 else None
        return _run_spoof(args.spoof[0], args.spoof[1], iface)
    if args.deauth:
        _legacy_warn("--deauth",
                     "droidnet deauth <MAC|broadcast> <BSSID> --iface IFACE")
        return _run_deauth(args.deauth[0], args.deauth[1], args.deauth[2],
                           channel=None, count=0)

    return False
