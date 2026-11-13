"""
DroidNet Sentinel — Entry Point

Usage (interactive menu):
    python main.py

Usage (non-interactive / scripted):
    python main.py scan [--auto-cut]
    python main.py daemon [--auto-cut]
    python main.py hunt
    python main.py cve [--all-time]
    python main.py dashboard [--expose]
    python main.py reports
    python main.py guard-log
    python main.py spoof <VICTIM_IP> <GATEWAY_IP> [--iface IFACE]
    python main.py deauth <TARGET_MAC|broadcast> <BSSID> --iface IFACE
    python main.py db purge [--days N]

Run any subcommand with --help for its flags. The flat flags (--scan,
--hunt, ...) still work for existing scripts; see droidnet/cli/args.py.
"""

from rich import print as rprint

from droidnet.cli import print_banner, parse_args, handle_args, interactive_menu

if __name__ == "__main__":
    # Parse before the banner: -h/--help and usage errors make argparse print
    # and exit here, so the banner and environment probe never land in front
    # of the help text. A normal run falls through and shows the banner.
    args = parse_args()
    print_banner()
    try:
        if not handle_args(args):
            interactive_menu()
    except KeyboardInterrupt:
        # Ctrl+C and, via core.guard, SIGTERM/SIGHUP all land here once the
        # scanner's own `finally` blocks have restored any ARP tables. Exit
        # quietly with status 0 so a service manager sees a clean stop rather
        # than a traceback.
        rprint("\n[dim]DroidNet Sentinel stopped.[/dim]")
