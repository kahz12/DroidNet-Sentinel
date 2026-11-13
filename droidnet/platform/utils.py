"""
Cross-platform abstraction layer.

Detects the host platform (Android/Termux vs Linux PC) and provides
unified functions for WiFi info, notifications and privilege checks.

Supported platforms:
    Android (Termux)  → termux-wifi-connectioninfo, termux-notification
    Linux PC          → nmcli / iw, notify-send
"""

import functools
import os
import re
import platform
import shutil
import subprocess
from contextlib import contextmanager
from pathlib import Path

from rich import print as rprint
# rich's escape directly, not droidnet.core.markup.esc: importing droidnet.core
# runs its __init__, which imports notifier → this module (circular import).
from rich.markup import escape

_COMMAND_TIMEOUT = 10


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

# Network admin tools (iw, arpspoof) install under sbin, which cron and
# systemd routinely drop from PATH (often just /usr/bin:/bin). Search these
# alongside PATH so a reduced environment still finds them.
_SBIN_DIRS = ("/usr/sbin", "/sbin", "/usr/local/sbin")


def resolve_command(cmd: str) -> str | None:
    """Full path to *cmd*, searching PATH and then the standard sbin directories.

    Returns None when the tool is nowhere to be found. Resolving to an absolute
    path also lets callers exec the tool without relying on the child's PATH,
    which matters when the daemon runs under cron or systemd with a trimmed PATH.
    """
    found = shutil.which(cmd)
    if found:
        return found
    return shutil.which(cmd, path=os.pathsep.join(_SBIN_DIRS))


def has_command(cmd: str) -> bool:
    """Return True if *cmd* is available in PATH or the standard sbin directories."""
    return resolve_command(cmd) is not None


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
            capture_output=True, text=True, stdin=subprocess.DEVNULL, timeout=_COMMAND_TIMEOUT,
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
            capture_output=True, text=True, stdin=subprocess.DEVNULL, timeout=_COMMAND_TIMEOUT,
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
            capture_output=True, text=True, stdin=subprocess.DEVNULL, timeout=_COMMAND_TIMEOUT,
        )
        match = re.search(r"src\s+(\S+)", proc.stdout)
        if match:
            return match.group(1)
    except Exception:
        pass

    try:
        proc = subprocess.run(
            ["hostname", "-I"],
            capture_output=True, text=True, stdin=subprocess.DEVNULL, timeout=_COMMAND_TIMEOUT,
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
            capture_output=True, text=True, stdin=subprocess.DEVNULL, timeout=_COMMAND_TIMEOUT,
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


def _split_nmcli_fields(line: str) -> list[str]:
    """Decode nmcli terse fields, respecting escaped colons and backslashes."""
    fields, current = [], []
    escaped = False
    for char in line:
        if escaped:
            current.append(char)
            escaped = False
        elif char == "\\":
            escaped = True
        elif char == ":":
            fields.append("".join(current))
            current = []
        else:
            current.append(char)
    if escaped:
        current.append("\\")
    fields.append("".join(current))
    return fields


def _get_wifi_info_nmcli() -> dict | None:
    try:
        proc = subprocess.run(
            ["nmcli", "-t", "-f", "active,ssid,bssid", "dev", "wifi"],
            capture_output=True, text=True, stdin=subprocess.DEVNULL, timeout=_COMMAND_TIMEOUT,
            # Force the C locale so the "active" field is always "yes"/"no",
            # not a locale-translated value.
            env={**os.environ, "LC_ALL": "C"},
        )
        if proc.returncode != 0:
            return None

        for line in proc.stdout.strip().split("\n"):
            if line.lower().startswith("yes:"):
                parts = _split_nmcli_fields(line)
                ssid      = parts[1] if len(parts) > 1 else "Unknown"
                bssid = parts[2] if len(parts) > 2 else "Unknown"
                ip_addr   = _get_local_ip()
                if ip_addr:
                    return {"ssid": ssid, "ip": ip_addr, "bssid": bssid, "platform": "linux"}
    except Exception:
        pass
    return None


_IW_CONNECTED = re.compile(r"^Connected to ([0-9A-Fa-f:]{17})\b", re.M)
_IW_SSID      = re.compile(r"^\s*SSID: (.*)$", re.M)
_IW_ESCAPE    = re.compile(rb"\\x([0-9A-Fa-f]{2})")


def _unescape_iw_ssid(printed: str) -> str:
    """Recover the SSID that ``iw`` printed through print_ssid_escaped().

    iw writes printable ASCII and inner spaces as-is and every other byte
    (non-ASCII, a backslash, a leading or trailing space) as \\xNN. Undo the
    escapes byte by byte, then decode as UTF-8 — the usual SSID encoding —
    replacing invalid sequences rather than failing on an odd network name.
    """
    raw = _IW_ESCAPE.sub(lambda m: bytes([int(m.group(1), 16)]),
                         printed.encode("ascii", "backslashreplace"))
    return raw.decode("utf-8", "replace")


def _get_wifi_info_iw() -> dict | None:
    """SSID and BSSID from ``iw dev <iface> link``; None when not associated.

    iw replaces the retired wireless-tools (iwconfig) and needs no root to
    read the current link. Its output is not localised, so no locale override
    is needed.
    """
    try:
        # Resolved to an absolute path so the call works under a trimmed PATH.
        # When iw cannot be resolved the bare name is still tried: a missing
        # binary then raises FileNotFoundError, handled below like any failure.
        iw = resolve_command("iw") or "iw"
        proc = subprocess.run(
            [iw, "dev", get_default_iface(), "link"],
            capture_output=True, text=True, stdin=subprocess.DEVNULL, timeout=_COMMAND_TIMEOUT,
        )
        if proc.returncode != 0:
            return None
        bssid = _IW_CONNECTED.search(proc.stdout)
        ssid  = _IW_SSID.search(proc.stdout)
        ip_addr = _get_local_ip()
        if bssid and ssid and ip_addr:
            return {"ssid": _unescape_iw_ssid(ssid.group(1)), "ip": ip_addr,
                    "bssid": bssid.group(1).upper(), "platform": "linux"}
    except Exception:
        pass
    return None


_SYS_NET = Path("/sys/class/net")


def _is_wireless(iface: str) -> bool:
    """True when *iface* is a Wi-Fi device (cfg80211 links it to a phy80211)."""
    return (_SYS_NET / iface / "phy80211").exists()


def get_wifi_info() -> dict | None:
    """
    Return active network info in a unified format:
        {"ssid": str, "ip": str, "bssid": str, "platform": str}

    On Linux the SSID comes from nmcli, or from iw when NetworkManager is not
    in use (netplan + systemd-networkd, for example). Without either tool the
    connection is still returned under a generic label so scans keep working;
    the label says Wi-Fi or wired from the kernel's own view of the interface.

    Returns None if there is no usable network connection.
    """
    if is_termux():
        return _get_wifi_info_termux()

    if has_command("nmcli"):
        info = _get_wifi_info_nmcli()
        if info:
            return info

    if has_command("iw"):
        info = _get_wifi_info_iw()
        if info:
            return info

    ip_addr = _get_local_ip()
    if ip_addr and ip_addr != "127.0.0.1":
        # Without an SSID every network shares this label in the history;
        # installing iw (or nmcli) restores the real network name.
        label = "Unknown Wi-Fi" if _is_wireless(get_default_iface()) else "Wired Network"
        return {"ssid": label, "ip": ip_addr, "bssid": "N/A", "platform": "linux"}

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

    # message carries the SSID ("N hosts analysed on <SSID>"): escape it.
    rprint(f"[dim][🔔] {escape(str(title))}: {escape(str(message))}[/dim]")


# ══════════════════════════════════════════════════════════════════
#  Power management (Termux)
# ══════════════════════════════════════════════════════════════════

@contextmanager
def wake_lock():
    """Hold a Termux CPU wake lock for the duration of the block.

    Android's Doze mode freezes background processes once the screen is off,
    which would pause a long-running daemon between scans. `termux-wake-lock`
    (from termux-api) keeps the CPU awake; the lock is released on exit even
    if the block raises. Outside Termux, or without termux-api installed,
    this is a no-op — it keeps nothing awake and the daemon still runs.

    Note: a wake lock does not stop Android from *killing* the process (the
    low-memory and phantom-process killers still can); it only keeps a living
    process from being frozen.
    """
    held = False
    if is_termux() and has_command("termux-wake-lock"):
        try:
            subprocess.run(["termux-wake-lock"], capture_output=True,
                           stdin=subprocess.DEVNULL, timeout=5)
            held = True
        except Exception:
            pass
    try:
        yield held
    finally:
        if held:
            try:
                subprocess.run(["termux-wake-unlock"], capture_output=True,
                               stdin=subprocess.DEVNULL, timeout=5)
            except Exception:
                pass


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
        console.print(f"  WiFi SSID  : [bold white]{escape(str(wifi['ssid']))}[/bold white]")
        console.print(f"  Local IP   : [cyan]{escape(str(wifi['ip']))}[/cyan]")
        console.print(f"  BSSID      : [dim]{escape(str(wifi['bssid']))}[/dim]")
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
