"""
System capabilities analyser.

Evaluates the host environment to determine which modules and tools
are available. Works on both Android (Termux) and Linux PC.
"""

from rich.console import Console

from droidnet import config
from droidnet.platform.utils import (
    is_termux,
    get_platform_name,
    check_root,
    get_available_tools,
    get_default_iface,
    has_command,
)

console = Console()


def evaluate_system() -> dict:
    """
    Interrogate the host to determine tactical capabilities.

    Returns:
        dict with keys:
            platform_name        – "Android (Termux)" or "Linux"
            is_termux            – bool
            is_root              – bool
            raw_sockets_enabled  – bool (requires root)
            monitor_mode_capable – bool (requires root + iw or airmon-ng)
            default_iface        – str
            tools                – dict[str, bool]
    """
    is_root = check_root()

    return {
        "platform_name":        get_platform_name(),
        "is_termux":            is_termux(),
        "is_root":              is_root,
        "raw_sockets_enabled":  is_root,
        "monitor_mode_capable": is_root and (has_command("iw") or has_command("airmon-ng")),
        "default_iface":        get_default_iface(),
        "tools":                get_available_tools(),
    }


def display_capabilities(env_state: dict) -> None:
    """
    Render the system state to the terminal using Rich.

    Args:
        env_state: dict returned by evaluate_system().
    """
    console.print("\n[bold cyan][*] Probing operating environment...[/bold cyan]")
    console.print(f"  [+] Platform   : [bold green]{env_state['platform_name']}[/bold green]")
    console.print(f"  [+] Interface  : [cyan]{env_state['default_iface']}[/cyan]")

    if env_state["is_root"]:
        console.print("  [+] Privilege  : [bold red]ROOT[/bold red]")
    else:
        console.print("  [+] Privilege  : [bold yellow]Standard user (limited)[/bold yellow]")

    console.print("\n[bold white]  Modules:[/bold white]")

    # Each module reports one of three states:
    #   "ok"       — fully available, no note.
    #   "degraded" — runs in a reduced mode; the note says which.
    #   "missing"  — cannot run; the note says what it needs.
    # Hunter is the degraded case: without searchsploit it still works, through
    # Vulners when VULNERS_API_KEY is set or else the Exploit-DB catalogue it
    # downloads on first use. Flagging it as missing would send users after a
    # package they may not have (exploitdb has no Termux build).
    has = env_state["tools"].get
    hunter = "ok" if has("searchsploit", False) else "degraded"
    hunter_note = ("no searchsploit: Vulners API" if config.VULNERS_API_KEY else
                   "no searchsploit: Exploit-DB catalogue, downloaded on first use")

    def requires(*needs: tuple[str, bool]) -> str:
        """Name only the requirements still unmet, so an installed tool is not asked for."""
        return "Requires " + " + ".join(label for label, met in needs if not met)

    modules = [
        ("Sentinel (Network scan)",    "ok",     ""),
        ("Hunter (Exploit lookup)",    hunter,   hunter_note),
        ("Dashboard (Command Center)", "ok",     ""),
        ("Spoofer (ARP MitM)",
         "ok" if env_state["raw_sockets_enabled"] and has("arpspoof", False) else "missing",
         requires(("root", env_state["raw_sockets_enabled"]), ("arpspoof", has("arpspoof", False)))),
        # Monitor mode stays listed: the probe cannot tell whether the Wi-Fi
        # adapter supports it, only whether root and a tool to enable it exist.
        ("Deauther (802.11 DoS)",
         "ok" if env_state["monitor_mode_capable"] else "missing",
         requires(("root", env_state["is_root"]), ("iw", has("iw", False)), ("monitor mode", False))),
    ]

    marks = {"ok": "[green]+[/green]", "degraded": "[yellow]~[/yellow]", "missing": "[red]x[/red]"}
    for name, state, note in modules:
        suffix = f" [dim]({note})[/dim]" if state != "ok" else ""
        console.print(f"    {marks[state]} {name}{suffix}")

    console.print("\n[bold white]  Tools:[/bold white]")
    tools = env_state["tools"]
    # A missing tool whose job an installed one already does is not a gap.
    # nmcli and iw both read the Wi-Fi network name; iw also enables monitor
    # mode for the Deauther, so only nmcli can be covered this way.
    covered_by = {"nmcli": "iw"}
    for tool, available in tools.items():
        alternative = covered_by.get(tool)
        if available:
            console.print(f"    [green]+[/green] {tool}")
        elif alternative and tools.get(alternative):
            console.print(f"    [yellow]~[/yellow] {tool} [dim](not needed: {alternative} in use)[/dim]")
        else:
            console.print(f"    [red]x[/red] [dim]{tool}[/dim]")


if __name__ == "__main__":
    display_capabilities(evaluate_system())
