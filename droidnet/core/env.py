"""
System capabilities analyser.

Evaluates the host environment to determine which modules and tools
are available. Works on both Android (Termux) and Linux PC.
"""

from rich.console import Console
from rich.table   import Table

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
    console.print("\n[bold cyan][*] Evaluando Entorno Operativo...[/bold cyan]")
    console.print(f"  [+] Plataforma  : [bold green]{env_state['platform_name']}[/bold green]")
    console.print(f"  [+] Interfaz    : [cyan]{env_state['default_iface']}[/cyan]")

    if env_state["is_root"]:
        console.print("  [+] Acceso      : [bold red]ROOT[/bold red]")
    else:
        console.print("  [+] Acceso      : [bold yellow]Usuario Estándar (Limitado)[/bold yellow]")

    console.print("\n[bold white]  Módulos:[/bold white]")

    modules = [
        ("Sentinel (Escaneo de Red)",  True,
         "Siempre disponible"),
        ("Hunter (Búsqueda Exploits)", env_state["tools"].get("searchsploit", False),
         "Requiere searchsploit"),
        ("Dashboard (Command Center)", True,
         "Siempre disponible"),
        ("Spoofer (ARP MitM)",
         env_state["raw_sockets_enabled"] and env_state["tools"].get("arpspoof", False),
         "Requiere root + arpspoof"),
        ("Deauther (802.11 DoS)",      env_state["monitor_mode_capable"],
         "Requiere root + iw + monitor mode"),
    ]

    for name, available, note in modules:
        if available:
            console.print(f"    [green]✓[/green] {name}")
        else:
            console.print(f"    [red]✗[/red] {name} [dim]({note})[/dim]")

    console.print("\n[bold white]  Herramientas:[/bold white]")
    for tool, available in env_state["tools"].items():
        if available:
            console.print(f"    [green]✓[/green] {tool}")
        else:
            console.print(f"    [red]✗[/red] [dim]{tool}[/dim]")


if __name__ == "__main__":
    display_capabilities(evaluate_system())
