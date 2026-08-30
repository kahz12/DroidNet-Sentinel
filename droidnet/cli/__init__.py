from droidnet.cli.menu import print_banner, interactive_menu
from droidnet.cli.args import parse_args, handle_args

__all__ = ["print_banner", "interactive_menu", "parse_args", "handle_args", "main"]


def main() -> None:
    """Console entry point: run scripted args, else drop into the menu."""
    print_banner()
    args = parse_args()
    if not handle_args(args):
        interactive_menu()
