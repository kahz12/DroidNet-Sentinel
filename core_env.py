"""
╔══════════════════════════════════════════════════════════════════╗
║          DroidNet Core Env — System Capabilities Analyzer        ║
║──────────────────────────────────────────────────────────────────║
║  Descripción:                                                    ║
║  Evalúa el entorno operativo del sistema para determinar qué     ║
║  módulos y capacidades están disponibles. Funciona tanto en      ║
║  Android (Termux) como en Linux PC.                              ║
║                                                                  ║
║  Capacidades detectadas:                                         ║
║  · Plataforma (Android/Termux vs Linux PC)                       ║
║  · Nivel de acceso (root vs usuario estándar)                    ║
║  · Herramientas disponibles (nmap, arpspoof, iw, etc.)           ║
║  · Interfaz de red activa                                        ║
╚══════════════════════════════════════════════════════════════════╝
"""

# ── Terceros ──────────────────────────────────────────────────────
from rich.console import Console
from rich.table   import Table

# ── Módulos internos ──────────────────────────────────────────────
from platform_utils import (
    is_termux,
    get_platform_name,
    check_root,
    get_available_tools,
    get_default_iface,
    has_command
)

console = Console()


def evaluate_system():
    """
    Interroga al sistema host para determinar capacidades tácticas.

    Evalúa:
    - Plataforma: Termux (Android) o Linux PC
    - Privilegios: root o usuario estándar
    - Raw sockets: necesario para ARP Spoofing
    - Monitor mode: necesario para Deauth (requiere iw o airmon-ng)
    - Herramientas: nmap, arpspoof, searchsploit, etc.
    - Interfaz activa: wlan0, wlp2s0, etc.

    Returns:
        dict: Estado completo del entorno con todas las capacidades.
    """
    is_root = check_root()

    env_state = {
        "platform_name":        get_platform_name(),
        "is_termux":            is_termux(),
        "is_root":              is_root,
        "raw_sockets_enabled":  is_root,
        "monitor_mode_capable": is_root and (has_command("iw") or has_command("airmon-ng")),
        "default_iface":        get_default_iface(),
        "tools":                get_available_tools(),
    }

    return env_state


def display_capabilities(env_state):
    """
    Renderiza el estado del sistema para el operador usando Rich.

    Muestra:
    1. Plataforma detectada
    2. Interfaz de red activa
    3. Nivel de acceso (root/usuario)
    4. Tabla de módulos con estado (activo/bloqueado)
    5. Tabla de herramientas con disponibilidad

    Args:
        env_state (dict): Estado del sistema de evaluate_system().
    """
    console.print("\n[bold cyan][*] Evaluando Entorno Operativo...[/bold cyan]")

    # ── Plataforma ────────────────────────────────────────────────
    platform_name = env_state["platform_name"]
    console.print(f"  [+] Plataforma  : [bold green]{platform_name}[/bold green]")
    console.print(f"  [+] Interfaz    : [cyan]{env_state['default_iface']}[/cyan]")

    # ── Nivel de acceso ───────────────────────────────────────────
    if env_state["is_root"]:
        console.print("  [+] Acceso      : [bold red]ROOT[/bold red]")
    else:
        console.print("  [+] Acceso      : [bold yellow]Usuario Estándar (Limitado)[/bold yellow]")

    # ── Módulos del toolkit ───────────────────────────────────────
    console.print("\n[bold white]  Módulos:[/bold white]")

    modules = [
        ("Sentinel (Escaneo de Red)",  True,
         "Siempre disponible"),
        ("Hunter (Búsqueda Exploits)", env_state["tools"].get("searchsploit", False),
         "Requiere searchsploit"),
        ("Dashboard (Command Center)", True,
         "Siempre disponible"),
        ("Spoofer (ARP MitM)",         env_state["raw_sockets_enabled"] and env_state["tools"].get("arpspoof", False),
         "Requiere root + arpspoof"),
        ("Deauther (802.11 DoS)",      env_state["monitor_mode_capable"],
         "Requiere root + iw + monitor mode"),
    ]

    for name, available, note in modules:
        if available:
            console.print(f"    [green]✓[/green] {name}")
        else:
            console.print(f"    [red]✗[/red] {name} [dim]({note})[/dim]")

    # ── Herramientas ──────────────────────────────────────────────
    tools = env_state["tools"]
    console.print("\n[bold white]  Herramientas:[/bold white]")

    for tool, available in tools.items():
        if available:
            console.print(f"    [green]✓[/green] {tool}")
        else:
            console.print(f"    [red]✗[/red] [dim]{tool}[/dim]")


if __name__ == "__main__":
    current_env = evaluate_system()
    display_capabilities(current_env)
"""
<parameter name="Description">Rewritten to use platform_utils abstractions, adding tool availability detection and better display.
"""