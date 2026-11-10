"""
System capabilities analyser.

Evaluates the host environment to determine which modules and tools
are available. Works on both Android (Termux) and Linux PC.
"""

from rich.console import Console

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
    # Hunter is the degraded case: without searchsploit it still works through
    # the online Vulners fallback, so flagging it as missing would send users
    # after a package they may not have (exploitdb has no Termux build).
    has = env_state["tools"].get
    hunter = "ok" if has("searchsploit", False) else "degraded"
    modules = [
        ("Sentinel (Network scan)",    "ok",     ""),
        ("Hunter (Exploit lookup)",    hunter,   "online fallback: Vulners, rate-limited"),
        ("Dashboard (Command Center)", "ok",     ""),
        ("Spoofer (ARP MitM)",
         "ok" if env_state["raw_sockets_enabled"] and has("arpspoof", False) else "missing",
         "Requires root + arpspoof"),
        ("Deauther (802.11 DoS)",
         "ok" if env_state["monitor_mode_capable"] else "missing",
         "Requires root + iw + monitor mode"),
    ]

    marks = {"ok": "[green]+[/green]", "degraded": "[yellow]~[/yellow]", "missing": "[red]x[/red]"}
    for name, state, note in modules:
        suffix = f" [dim]({note})[/dim]" if state != "ok" else ""
        console.print(f"    {marks[state]} {name}{suffix}")

    console.print("\n[bold white]  Tools:[/bold white]")
    for tool, available in env_state["tools"].items():
        if available:
            console.print(f"    [green]+[/green] {tool}")
        else:
            console.print(f"    [red]x[/red] [dim]{tool}[/dim]")


if __name__ == "__main__":
    display_capabilities(evaluate_system())
