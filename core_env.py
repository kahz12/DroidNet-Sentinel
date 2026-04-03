import os
import platform
import subprocess
from rich.console import Console

console = Console()

def evaluate_system():
    """Interroga al sistema host para determinar capacidades tácticas."""
    
    env_state = {
        "os_name": platform.system(),
        "is_termux": "com.termux" in os.environ.get("PREFIX", ""),
        "is_root": False,
        "raw_sockets_enabled": False, # Necesario para ARP Spoofing
        "monitor_mode_capable": False # Necesario para Deauth
    }

    # 1. Verificación de privilegios
    if hasattr(os, 'geteuid'):
        env_state["is_root"] = (os.geteuid() == 0)

    # 2. Análisis de capacidades basadas en privilegios
    if env_state["is_root"]:
        env_state["raw_sockets_enabled"] = True
        
        # 3. Verificamos si existen herramientas de inyección Wi-Fi (como 'iw' o 'aircrack-ng')
        try:
            proc = subprocess.run(['which', 'iw'], capture_output=True, text=True)
            if proc.returncode == 0:
                env_state["monitor_mode_capable"] = True
        except Exception:
            pass

    return env_state

def display_capabilities(env_state):
    """Renderiza el estado del sistema para el operador."""
    console.print("\n[bold cyan][*] Evaluando Entorno Operativo...[/bold cyan]")
    
    # Detección de plataforma
    if env_state["is_termux"]:
        console.print("  [+] Plataforma detectada: [bold green]Android (Termux)[/bold green]")
    else:
        console.print(f"  [+] Plataforma detectada: [bold green]{env_state['os_name']}[/bold green]")

    # Nivel de acceso
    if env_state["is_root"]:
        console.print("  [+] Nivel de Acceso: [bold red]ROOT (God Mode)[/bold red]")
    else:
        console.print("  [+] Nivel de Acceso: [bold yellow]Usuario Estándar (Limitado)[/bold yellow]")

    # Capacidades Tácticas
    console.print("\n[bold white]Módulos Disponibles:[/bold white]")
    console.print("  [+] Sentinel (Reconocimiento Pasivo/Activo): [green]ACTIVO[/green]")
    console.print("  [+] Hunter (Búsqueda de Exploits): [green]ACTIVO[/green]")
    
    # Restricciones
    if env_state["raw_sockets_enabled"]:
         console.print("  [+] ARP Spoofing (MitM): [green]DISPONIBLE[/green]")
    else:
         console.print("  [-] ARP Spoofing (MitM): [red]BLOQUEADO[/red] (Requiere Root)")
         
    if env_state["monitor_mode_capable"]:
         console.print("  [+] Deauth Attack (DoS): [green]DISPONIBLE[/green]")
    else:
         console.print("  [-] Deauth Attack (DoS): [red]BLOQUEADO[/red] (Requiere Root + Interfaz Wi-Fi)")

if __name__ == "__main__":
    current_env = evaluate_system()
    display_capabilities(current_env)
