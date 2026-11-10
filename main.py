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
    python main.py spoof <VICTIM_IP> <GATEWAY_IP> [--iface IFACE]
    python main.py deauth <TARGET_MAC|broadcast> <BSSID> --iface IFACE
    python main.py db purge [--days N]

Run any subcommand with --help for its flags. The flat flags (--scan,
--hunt, ...) still work for existing scripts; see droidnet/cli/args.py.
"""

from droidnet.cli import print_banner, parse_args, handle_args, interactive_menu

if __name__ == "__main__":
    # Parse before the banner: -h/--help and usage errors make argparse print
    # and exit here, so the banner and environment probe never land in front
    # of the help text. A normal run falls through and shows the banner.
    args = parse_args()
    print_banner()
    if not handle_args(args):
        interactive_menu()
