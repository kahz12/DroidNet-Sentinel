"""
╔══════════════════════════════════════════════════════════════════╗
║          DroidNet Platform Utils — Cross-Platform Layer          ║
║──────────────────────────────────────────────────────────────────║
║  Descripción:                                                    ║
║  Capa de abstracción que detecta automáticamente la plataforma   ║
║  (Android/Termux o Linux PC) y provee funciones unificadas       ║
║  para obtener info WiFi, enviar notificaciones y verificar       ║
║  privilegios root.                                               ║
║                                                                  ║
║  Plataformas soportadas:                                         ║
║  · Android (Termux)  → termux-wifi-connectioninfo, termux-notif  ║
║  · Linux PC          → nmcli, iwconfig, notify-send              ║
║                                                                  ║
║  Uso:                                                            ║
║    from platform_utils import get_wifi_info, send_notification   ║
║    info = get_wifi_info()   # Retorna dict unificado o None      ║
║    send_notification("Título", "Mensaje")                        ║
╚══════════════════════════════════════════════════════════════════╝
"""

# ── Stdlib ────────────────────────────────────────────────────────
import os
import re
import subprocess
import platform
import shutil

# ── Terceros ──────────────────────────────────────────────────────
from rich import print as rprint


# ══════════════════════════════════════════════════════════════════
#  DETECCIÓN DE PLATAFORMA
# ══════════════════════════════════════════════════════════════════

def is_termux():
    """
    Detecta si el script está corriendo dentro de Termux en Android.

    Termux establece la variable de entorno PREFIX con una ruta que
    contiene 'com.termux'. Este es el método más confiable para
    distinguir Termux de un Linux normal.

    Returns:
        bool: True si estamos en Termux, False en cualquier otro caso.
    """
    return "com.termux" in os.environ.get("PREFIX", "")


def get_platform_name():
    """
    Retorna un nombre legible de la plataforma actual.

    Returns:
        str: "Android (Termux)" o el nombre del OS (ej: "Linux").
    """
    if is_termux():
        return "Android (Termux)"
    return platform.system()


# ══════════════════════════════════════════════════════════════════
#  VERIFICACIÓN DE PRIVILEGIOS
# ══════════════════════════════════════════════════════════════════

def check_root():
    """
    Verifica si el proceso actual tiene privilegios root/superusuario.

    En Linux/Android usa os.geteuid() (effective UID).
    Si geteuid no está disponible (ej: Windows), retorna False.

    Returns:
        bool: True si root, False si usuario normal.
    """
    if hasattr(os, 'geteuid'):
        return os.geteuid() == 0
    return False


# ══════════════════════════════════════════════════════════════════
#  DETECCIÓN DE HERRAMIENTAS DISPONIBLES
# ══════════════════════════════════════════════════════════════════

def has_command(cmd):
    """
    Verifica si un comando está instalado y disponible en el PATH.

    Usa shutil.which() que es cross-platform (funciona en Linux,
    macOS y Windows) en lugar de subprocess + 'which'.

    Args:
        cmd (str): Nombre del comando a buscar (ej: "nmap", "nmcli").

    Returns:
        bool: True si el comando existe en el PATH.
    """
    return shutil.which(cmd) is not None


def get_available_tools():
    """
    Detecta qué herramientas del toolkit están disponibles en el sistema.

    Útil para mostrar al usuario qué módulos pueden funcionar
    y cuáles requieren instalación adicional.

    Returns:
        dict: {nombre_herramienta: bool} con disponibilidad de cada una.
    """
    tools = {
        "nmap":          has_command("nmap"),
        "arpspoof":      has_command("arpspoof"),
        "searchsploit":  has_command("searchsploit"),
        "iw":            has_command("iw"),
    }

    # Herramientas específicas de plataforma
    if is_termux():
        tools["termux-wifi-connectioninfo"] = has_command("termux-wifi-connectioninfo")
        tools["termux-notification"]        = has_command("termux-notification")
    else:
        tools["nmcli"]       = has_command("nmcli")
        tools["iwconfig"]    = has_command("iwconfig")
        tools["notify-send"] = has_command("notify-send")

    return tools


# ══════════════════════════════════════════════════════════════════
#  DETECCIÓN DE INTERFAZ WiFi ACTIVA
# ══════════════════════════════════════════════════════════════════

def get_default_iface():
    """
    Detecta la interfaz de red WiFi activa del sistema.

    Estrategia por plataforma:
    - Termux: siempre "wlan0" (Android solo expone esa interfaz)
    - Linux PC: parsea la tabla de rutas para encontrar la interfaz
      por defecto, o busca interfaces wireless en /sys/class/net/

    Returns:
        str: Nombre de la interfaz activa (ej: "wlan0", "wlp2s0")
             o "wlan0" como fallback seguro.
    """
    if is_termux():
        return "wlan0"

    # Linux PC: buscar interfaz por defecto en la tabla de rutas
    try:
        proc = subprocess.run(
            ['ip', 'route', 'show', 'default'],
            capture_output=True, text=True
        )
        # Formato: "default via 192.168.1.1 dev wlp2s0 proto dhcp ..."
        match = re.search(r'dev\s+(\S+)', proc.stdout)
        if match:
            return match.group(1)
    except Exception:
        pass

    # Fallback: buscar en /sys/class/net/ interfaces wireless
    try:
        for iface in os.listdir("/sys/class/net"):
            wireless_dir = f"/sys/class/net/{iface}/wireless"
            if os.path.isdir(wireless_dir):
                return iface
    except Exception:
        pass

    return "wlan0"


# ══════════════════════════════════════════════════════════════════
#  INFORMACIÓN WiFi — CROSS-PLATFORM
# ══════════════════════════════════════════════════════════════════

def _get_wifi_info_termux():
    """
    Obtiene info WiFi usando la API nativa de Termux.

    Ejecuta termux-wifi-connectioninfo que retorna un JSON con
    ssid, bssid, ip, supplicant_state, etc.

    Solo devuelve datos si supplicant_state == "COMPLETED"
    (conexión WiFi activa y autenticada).

    Returns:
        dict | None: Info WiFi o None si no hay conexión.
    """
    import json
    try:
        proc = subprocess.run(
            ['termux-wifi-connectioninfo'],
            capture_output=True, text=True
        )
        data = json.loads(proc.stdout)
        if data.get("supplicant_state") == "COMPLETED":
            return {
                "ssid":     data.get("ssid", "Desconocida"),
                "ip":       data.get("ip", None),
                "bssid":    data.get("bssid", "Unknown"),
                "platform": "termux"
            }
    except Exception:
        pass
    return None


def _get_wifi_info_nmcli():
    """
    Obtiene info WiFi usando nmcli (NetworkManager CLI).

    nmcli es la herramienta estándar de NetworkManager en la mayoría
    de distribuciones Linux modernas (Ubuntu, Fedora, Arch, etc.).

    Comandos usados:
    - nmcli -t -f active,ssid,bssid dev wifi → Lista redes WiFi
      filtrada por la activa (ACTIVE:yes/sí)
    - hostname -I → IP(s) asignada(s) al host

    Returns:
        dict | None: Info WiFi o None si no hay conexión.
    """
    try:
        # Obtener SSID y BSSID de la conexión WiFi activa
        proc = subprocess.run(
            ['nmcli', '-t', '-f', 'active,ssid,bssid', 'dev', 'wifi'],
            capture_output=True, text=True
        )

        if proc.returncode != 0:
            return None

        # Buscar la línea activa — nmcli usa "yes" o "sí" según locale
        active_line = None
        for line in proc.stdout.strip().split('\n'):
            # Formato: "yes:MiRed:AA\:BB\:CC\:DD\:EE\:FF"
            # o        "sí:MiRed:AA\:BB\:CC\:DD\:EE\:FF"
            if line.lower().startswith(('yes:', 'sí:')):
                active_line = line
                break

        if not active_line:
            return None

        # Parsear — nmcli escapa los ':' dentro de BSSID con '\'
        parts = active_line.split(':')
        ssid = parts[1] if len(parts) > 1 else "Desconocida"

        # El BSSID tiene ':' escapados, lo reconstruimos
        # Formato raw: "AA\:BB\:CC\:DD\:EE\:FF" → unimos todo después del SSID
        bssid_raw = ':'.join(parts[2:]) if len(parts) > 2 else "Unknown"
        bssid = bssid_raw.replace('\\', '')

        # Obtener IP local
        ip_addr = _get_local_ip()

        if ip_addr:
            return {
                "ssid":     ssid,
                "ip":       ip_addr,
                "bssid":    bssid,
                "platform": "linux"
            }

    except Exception:
        pass
    return None


def _get_wifi_info_iwconfig():
    """
    Fallback: obtiene info WiFi usando iwconfig + ip addr.

    Para sistemas Linux sin NetworkManager (servidores, distros
    minimalistas, algunas configuraciones de Kali).

    iwconfig muestra el ESSID y la calidad de señal de la
    interfaz WiFi activa.

    Returns:
        dict | None: Info WiFi o None si no hay conexión.
    """
    try:
        iface = get_default_iface()

        proc = subprocess.run(
            ['iwconfig', iface],
            capture_output=True, text=True
        )

        if proc.returncode != 0:
            return None

        # Extraer SSID: 'ESSID:"MiRed"'
        ssid_match = re.search(r'ESSID[:\s]*"([^"]+)"', proc.stdout)
        if not ssid_match:
            return None

        ssid = ssid_match.group(1)

        # Extraer BSSID: 'Access Point: AA:BB:CC:DD:EE:FF'
        bssid_match = re.search(
            r'Access Point[:\s]*([0-9A-Fa-f:]{17})', proc.stdout
        )
        bssid = bssid_match.group(1) if bssid_match else "Unknown"

        ip_addr = _get_local_ip()

        if ip_addr:
            return {
                "ssid":     ssid,
                "ip":       ip_addr,
                "bssid":    bssid,
                "platform": "linux"
            }

    except Exception:
        pass
    return None


def _get_local_ip():
    """
    Obtiene la IP local principal del host.

    Estrategia en orden de prioridad:
    1. hostname -I → retorna todas las IPs, tomamos la primera
    2. ip route get 1 → simula una ruta y extrae la IP source

    Returns:
        str | None: IP local (ej: "192.168.1.100") o None.
    """
    # Método 1: hostname -I
    try:
        proc = subprocess.run(
            ['hostname', '-I'],
            capture_output=True, text=True
        )
        ips = proc.stdout.strip().split()
        if ips:
            return ips[0]
    except Exception:
        pass

    # Método 2: ip route get
    try:
        proc = subprocess.run(
            ['ip', 'route', 'get', '1'],
            capture_output=True, text=True
        )
        match = re.search(r'src\s+(\S+)', proc.stdout)
        if match:
            return match.group(1)
    except Exception:
        pass

    return None


def get_wifi_info():
    """
    Función pública unificada para obtener información WiFi.

    Detecta la plataforma automáticamente y usa la implementación
    correspondiente. En Linux PC intenta nmcli primero y cae a
    iwconfig como fallback.

    Returns:
        dict | None: Dict con formato unificado:
            {
                "ssid":     str,  # Nombre de la red WiFi
                "ip":       str,  # IP local del dispositivo
                "bssid":    str,  # MAC del AP
                "platform": str   # "termux" o "linux"
            }
            None si no hay WiFi activa o no se pudo obtener info.
    """
    if is_termux():
        return _get_wifi_info_termux()

    # Linux PC: intentar nmcli primero (más confiable)
    if has_command("nmcli"):
        info = _get_wifi_info_nmcli()
        if info:
            return info

    # Fallback: iwconfig
    if has_command("iwconfig"):
        info = _get_wifi_info_iwconfig()
        if info:
            return info

    # Último recurso: solo IP sin WiFi info (conexión por cable)
    ip_addr = _get_local_ip()
    if ip_addr and ip_addr != "127.0.0.1":
        return {
            "ssid":     "Red Cableada",
            "ip":       ip_addr,
            "bssid":    "N/A",
            "platform": "linux"
        }

    return None


# ══════════════════════════════════════════════════════════════════
#  NOTIFICACIONES — CROSS-PLATFORM
# ══════════════════════════════════════════════════════════════════

def send_notification(title, message):
    """
    Envía una notificación nativa del sistema operativo.

    Plataformas:
    - Termux: termux-notification con -t (título) y -c (contenido)
    - Linux PC: notify-send con timeout de 5 segundos

    Si ningún método de notificación está disponible, solo
    muestra el mensaje en la consola Rich como fallback.

    Args:
        title   (str): Título de la notificación.
        message (str): Cuerpo/contenido de la notificación.
    """
    if is_termux():
        # Termux: usa la API de notificaciones de Android
        try:
            subprocess.run(
                ['termux-notification', '-t', title, '-c', message],
                capture_output=True
            )
            return
        except Exception:
            pass

    else:
        # Linux PC: usa libnotify (notify-send)
        if has_command("notify-send"):
            try:
                subprocess.run(
                    ['notify-send', '-t', '5000', title, message],
                    capture_output=True
                )
                return
            except Exception:
                pass

    # Fallback universal: log en consola
    rprint(f"[dim][🔔] {title}: {message}[/dim]")


# ══════════════════════════════════════════════════════════════════
#  ENTRYPOINT: Diagnóstico de plataforma
# ══════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    """
    Ejecutar standalone para diagnóstico rápido de la plataforma:
        python platform_utils.py
    """
    from rich.console import Console
    from rich.table import Table

    console = Console()

    console.print("\n[bold cyan]═══ DroidNet Platform Diagnostics ═══[/bold cyan]\n")

    console.print(f"  Plataforma : [bold]{get_platform_name()}[/bold]")
    console.print(f"  Root       : {'[green]Sí[/green]' if check_root() else '[yellow]No[/yellow]'}")
    console.print(f"  Interfaz   : [cyan]{get_default_iface()}[/cyan]")

    wifi = get_wifi_info()
    if wifi:
        console.print(f"  WiFi SSID  : [bold white]{wifi['ssid']}[/bold white]")
        console.print(f"  IP Local   : [cyan]{wifi['ip']}[/cyan]")
        console.print(f"  BSSID      : [dim]{wifi['bssid']}[/dim]")
    else:
        console.print("  WiFi       : [red]No detectada[/red]")

    console.print("\n[bold white]Herramientas:[/bold white]")
    tools = get_available_tools()

    table = Table(show_header=False, box=None, padding=(0, 2))
    table.add_column(style="white", width=30)
    table.add_column(width=12)

    for tool, available in tools.items():
        status = "[green]✓ Disponible[/green]" if available else "[red]✗ No encontrado[/red]"
        table.add_row(f"  {tool}", status)

    console.print(table)
    console.print()

