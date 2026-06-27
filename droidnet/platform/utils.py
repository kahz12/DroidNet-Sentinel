"""
Cross-platform abstraction layer.

Detects the host platform (Android/Termux vs Linux PC) and provides
unified functions for WiFi info, notifications and privilege checks.

Supported platforms:
    Android (Termux)  → termux-wifi-connectioninfo, termux-notification
    Linux PC          → nmcli / iwconfig, notify-send
"""

import functools
import os
import re
import platform
import shutil
import subprocess

from rich import print as rprint


# ══════════════════════════════════════════════════════════════════
#  Platform detection
# ══════════════════════════════════════════════════════════════════

@functools.cache
def is_termux() -> bool:
    """Return True when running inside Termux on Android."""
    return "com.termux" in os.environ.get("PREFIX", "")


def get_platform_name() -> str:
    """Return a human-readable platform label."""
    return "Android (Termux)" if is_termux() else platform.system()


# ══════════════════════════════════════════════════════════════════
#  Privilege check
# ══════════════════════════════════════════════════════════════════

@functools.cache
def check_root() -> bool:
    """Return True if the process is running as root/superuser."""
    if hasattr(os, "geteuid"):
        return os.geteuid() == 0
    return False


# ══════════════════════════════════════════════════════════════════
#  Tool availability
# ══════════════════════════════════════════════════════════════════

def has_command(cmd: str) -> bool:
    """Return True if *cmd* is available in PATH."""
    return shutil.which(cmd) is not None


def get_available_tools() -> dict[str, bool]:
    """
    Probe which toolkit dependencies are installed.

    Returns:
        dict: {tool_name: available} for every relevant binary.
    """
    tools: dict[str, bool] = {
        "nmap":         has_command("nmap"),
        "arpspoof":     has_command("arpspoof"),
        "searchsploit": has_command("searchsploit"),
        "iw":           has_command("iw"),
    }

    if is_termux():
        tools["termux-wifi-connectioninfo"] = has_command("termux-wifi-connectioninfo")
        tools["termux-notification"]        = has_command("termux-notification")
    else:
        tools["nmcli"]       = has_command("nmcli")
        tools["iwconfig"]    = has_command("iwconfig")
        tools["notify-send"] = has_command("notify-send")

    return tools


# ══════════════════════════════════════════════════════════════════
#  Network interface detection
# ══════════════════════════════════════════════════════════════════

def get_default_iface() -> str:
    """
    Return the name of the active network interface.

    Strategy:
        Termux  → always "wlan0"
        Linux   → parse default route; fall back to /sys/class/net scan
    """
    if is_termux():
        return "wlan0"

    try:
        proc = subprocess.run(
            ["ip", "route", "show", "default"],
            capture_output=True, text=True, stdin=subprocess.DEVNULL,
        )
        match = re.search(r"dev\s+(\S+)", proc.stdout)
        if match:
            return match.group(1)
    except Exception:
        pass

    try:
        for iface in os.listdir("/sys/class/net"):
            if os.path.isdir(f"/sys/class/net/{iface}/wireless"):
                return iface
    except Exception:
        pass

    return "wlan0"


def get_default_gateway(local_ip: str | None = None) -> str | None:
    """
    Return the LAN default-gateway IP.

    Strategy:
        Parse ``ip route show default`` for the ``via <addr>`` field. If that
        fails (no route, busybox without the field, etc.) and *local_ip* is a
        dotted IPv4 address, fall back to the conventional ``.1`` host of that
        /24. Returns None when neither path yields an address.
    """
    try:
        proc = subprocess.run(
            ["ip", "route", "show", "default"],
            capture_output=True, text=True, stdin=subprocess.DEVNULL,
        )
        match = re.search(r"via\s+(\S+)", proc.stdout)
        if match:
            return match.group(1)
    except Exception:
        pass

    if local_ip and local_ip.count(".") == 3:
        return ".".join(local_ip.split(".")[:-1]) + ".1"
    return None


# ══════════════════════════════════════════════════════════════════
#  WiFi info — cross-platform
# ══════════════════════════════════════════════════════════════════

def _get_local_ip() -> str | None:
    """Return the primary local IP address of the host."""
    # `ip route get` works on every Linux distro and on Termux/busybox;
    # `hostname -I` is a glibc-only extension, so it's only the fallback.
    try:
        proc = subprocess.run(
            ["ip", "route", "get", "1"],
            capture_output=True, text=True, stdin=subprocess.DEVNULL,
        )
        match = re.search(r"src\s+(\S+)", proc.stdout)
        if match:
            return match.group(1)
    except Exception:
        pass

    try:
        proc = subprocess.run(
            ["hostname", "-I"],
            capture_output=True, text=True, stdin=subprocess.DEVNULL,
        )
        ips = proc.stdout.strip().split()
        if ips:
            return ips[0]
    except Exception:
        pass

    return None


def _get_wifi_info_termux() -> dict | None:
    import json as _json
    try:
        proc = subprocess.run(
            ["termux-wifi-connectioninfo"],
            capture_output=True, text=True, stdin=subprocess.DEVNULL,
        )
        data = _json.loads(proc.stdout)
        if data.get("supplicant_state") == "COMPLETED":
            return {
                "ssid":     data.get("ssid", "Unknown"),
                "ip":       data.get("ip"),
                "bssid":    data.get("bssid", "Unknown"),
                "platform": "termux",
            }
    except Exception:
        pass
    return None


def _get_wifi_info_nmcli() -> dict | None:
    try:
        proc = subprocess.run(
            ["nmcli", "-t", "-f", "active,ssid,bssid", "dev", "wifi"],
            capture_output=True, text=True, stdin=subprocess.DEVNULL,
            # Force the C locale so the "active" field is always "yes"/"no",
            # not a locale-translated value.
            env={**os.environ, "LC_ALL": "C"},
        )
        if proc.returncode != 0:
            return None

        for line in proc.stdout.strip().split("\n"):
            if line.lower().startswith("yes:"):
                parts = line.split(":")
                ssid      = parts[1] if len(parts) > 1 else "Unknown"
                bssid_raw = ":".join(parts[2:]) if len(parts) > 2 else "Unknown"
                bssid     = bssid_raw.replace("\\", "")
                ip_addr   = _get_local_ip()
                if ip_addr:
                    return {"ssid": ssid, "ip": ip_addr, "bssid": bssid, "platform": "linux"}
    except Exception:
        pass
    return None


def _get_wifi_info_iwconfig() -> dict | None:
    try:
        iface = get_default_iface()
        proc  = subprocess.run(
            ["iwconfig", iface],
            capture_output=True, text=True, stdin=subprocess.DEVNULL,
        )
        if proc.returncode != 0:
            return None

        ssid_match = re.search(r'ESSID[:\s]*"([^"]+)"', proc.stdout)
        if not ssid_match:
            return None

        ssid        = ssid_match.group(1)
        bssid_match = re.search(r"Access Point[:\s]*([0-9A-Fa-f:]{17})", proc.stdout)
        bssid       = bssid_match.group(1) if bssid_match else "Unknown"
        ip_addr     = _get_local_ip()

        if ip_addr:
            return {"ssid": ssid, "ip": ip_addr, "bssid": bssid, "platform": "linux"}
    except Exception:
        pass
    return None


def get_wifi_info() -> dict | None:
    """
    Return active WiFi connection info in a unified format:
        {"ssid": str, "ip": str, "bssid": str, "platform": str}

    Returns None if no active WiFi connection is detected.
    """
    if is_termux():
        return _get_wifi_info_termux()

    if has_command("nmcli"):
        info = _get_wifi_info_nmcli()
        if info:
            return info

    if has_command("iwconfig"):
        info = _get_wifi_info_iwconfig()
        if info:
            return info

    ip_addr = _get_local_ip()
    if ip_addr and ip_addr != "127.0.0.1":
        return {"ssid": "Wired Network", "ip": ip_addr, "bssid": "N/A", "platform": "linux"}

    return None


# ══════════════════════════════════════════════════════════════════
#  Notifications — cross-platform
# ══════════════════════════════════════════════════════════════════

def send_notification(title: str, message: str) -> None:
    """
    Send a native OS notification.

    Termux → termux-notification
    Linux  → notify-send (libnotify)
    Fallback → print to console
    """
    if is_termux():
        try:
            subprocess.run(
                ["termux-notification", "-t", title, "-c", message],
                capture_output=True, stdin=subprocess.DEVNULL, timeout=5,
            )
            return
        except Exception:
            pass
    else:
        if has_command("notify-send"):
            try:
                subprocess.run(
                    ["notify-send", "-t", "5000", title, message],
                    capture_output=True, stdin=subprocess.DEVNULL, timeout=5,
                )
                return
            except Exception:
                pass

    rprint(f"[dim][🔔] {title}: {message}[/dim]")


# ══════════════════════════════════════════════════════════════════
#  Standalone diagnostics
# ══════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    from rich.console import Console
    from rich.table   import Table

    console = Console()
    console.print("\n[bold cyan]═══ DroidNet Platform Diagnostics ═══[/bold cyan]\n")
    console.print(f"  Platform   : [bold]{get_platform_name()}[/bold]")
    console.print(f"  Root       : {'[green]Yes[/green]' if check_root() else '[yellow]No[/yellow]'}")
    console.print(f"  Interface  : [cyan]{get_default_iface()}[/cyan]")

    wifi = get_wifi_info()
    if wifi:
        console.print(f"  WiFi SSID  : [bold white]{wifi['ssid']}[/bold white]")
        console.print(f"  Local IP   : [cyan]{wifi['ip']}[/cyan]")
        console.print(f"  BSSID      : [dim]{wifi['bssid']}[/dim]")
    else:
        console.print("  WiFi       : [red]Not detected[/red]")

    console.print("\n[bold white]Tools:[/bold white]")
    table = Table(show_header=False, box=None, padding=(0, 2))
    table.add_column(style="white", width=30)
    table.add_column(width=20)

    for tool, available in get_available_tools().items():
        status = "[green]✓ Available[/green]" if available else "[red]✗ Not found[/red]"
        table.add_row(f"  {tool}", status)

    console.print(table)
    console.print()
