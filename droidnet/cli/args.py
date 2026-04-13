"""
CLI argument parser for non-interactive / scripted usage.

Allows invoking any module directly without the interactive menu:
    python main.py --scan
    python main.py --daemon
    python main.py --hunt
    python main.py --dashboard
    python main.py --reports
    python main.py --spoof 192.168.1.105 192.168.1.1 [wlan0]
    python main.py --deauth A1:B2:C3 AA:BB:CC wlan0mon
"""

import argparse

from rich import print as rprint

from droidnet.platform.utils import check_root, get_default_iface


def parse_args() -> argparse.Namespace:
    """Define and parse CLI flags."""
    parser = argparse.ArgumentParser(
        description="DroidNet Sentinel — Network Security Toolkit",
        formatter_class=argparse.RawTextHelpFormatter,
    )

    parser.add_argument("--scan",      action="store_true", help="Escaneo único de red")
    parser.add_argument("--daemon",    action="store_true", help="Modo daemon (continuo)")
    parser.add_argument("--hunt",      action="store_true", help="Buscar exploits en último reporte")
    parser.add_argument("--dashboard", action="store_true", help="Levantar dashboard web")
    parser.add_argument("--reports",   action="store_true", help="Listar reportes guardados")
    parser.add_argument("--cve-watch", action="store_true", help="Monitorear CVEs vs red escaneada")

    parser.add_argument(
        "--spoof",
        nargs="+",
        metavar=("VICTIM_IP", "GATEWAY_IP"),
        help="ARP Spoof: --spoof <IP_VICTIMA> <IP_GATEWAY> [IFACE]",
    )
    parser.add_argument(
        "--deauth",
        nargs=3,
        metavar=("TARGET_MAC", "BSSID", "IFACE"),
        help="Deauth: --deauth <MAC|broadcast> <BSSID> <IFACE>",
    )

    return parser.parse_args()


def handle_args(args: argparse.Namespace) -> bool:
    """
    Dispatch the action that matches the supplied flags.

    Returns:
        True if a flag was processed (caller should not launch the menu).
        False if no flags were present (caller should launch the menu).
    """
    if args.scan:
        from droidnet.modules.sentinel import run_sentinel
        run_sentinel(interactive=True)
        return True

    if args.daemon:
        from droidnet.modules.sentinel import run_sentinel
        run_sentinel(interactive=False)
        return True

    if args.hunt:
        from droidnet.modules.hunter import run_hunter
        run_hunter()
        return True

    if args.dashboard:
        from droidnet.web.dashboard import app, _print_startup_banner
        _print_startup_banner()
        app.run(host="0.0.0.0", port=5000, debug=False, use_reloader=False)
        return True

    if args.reports:
        from droidnet.cli.menu import list_reports
        list_reports()
        return True

    if args.cve_watch:
        from droidnet.modules.cve_watcher import run_cve_watcher
        run_cve_watcher(show_history=True)
        return True

    if args.spoof:
        if not check_root():
            rprint("[red][✗] Necesitas root.[/red]")
            return True
        from droidnet.modules.spoofer import poison
        target  = args.spoof[0]
        gateway = args.spoof[1]
        iface   = args.spoof[2] if len(args.spoof) > 2 else get_default_iface()
        poison(target, gateway, iface)
        return True

    if args.deauth:
        if not check_root():
            rprint("[red][✗] Necesitas root.[/red]")
            return True
        from droidnet.modules.deauther import deauth_target, BROADCAST
        target = BROADCAST if args.deauth[0].lower() == "broadcast" else args.deauth[0]
        deauth_target(target, args.deauth[1], args.deauth[2])
        return True

    return False
