"""
Core Scanner Module — network discovery, port scanning and ARP response.

Flow per cycle:
    get_wifi_info → ping_sweep → deep_scan → evaluate_risk
                 → save_report → display_table → cut_unknowns
                 → send_alert
"""

import json
import re
import subprocess
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta
from pathlib import Path

from rich           import print as rprint
from rich.console   import Console
from rich.table     import Table

from droidnet.config       import (
    CHECK_INTERVAL,
    RESCAN_HOURS,
    REPORTS_DIR,
    load_user_config,
)
from droidnet.core.database  import init_db, save_scan, purge_old_scans
from droidnet.core.logger    import get_logger
from droidnet.core.risk      import classify_risk
from droidnet.core.notifier  import send_alert, escape_markdown
from droidnet.platform.utils import get_default_iface, get_default_gateway, get_wifi_info

log = get_logger(__name__)

console = Console()


# ══════════════════════════════════════════════════════════════════
#  Risk evaluation
# ══════════════════════════════════════════════════════════════════
# Single source of truth for the port→risk mapping lives in core.database
# (classify_risk). Here we only decorate it with Rich markup for the TUI.

_RISK_MARKUP = {
    "MINIMAL":  "[bold green]MINIMAL[/bold green]",
    "LOW":      "[bold blue]LOW[/bold blue]",   # blue — matches README + dashboard
    "MEDIUM":   "[bold yellow]MEDIUM[/bold yellow]",
    "CRITICAL": "[bold red]CRITICAL[/bold red]",
}


def evaluate_risk(ports: list[str]) -> str:
    """Return the Rich-markup version of classify_risk(ports)."""
    label = classify_risk(ports)
    return _RISK_MARKUP.get(label, label)


# ══════════════════════════════════════════════════════════════════
#  Display
# ══════════════════════════════════════════════════════════════════

def display_results_table(
    ssid: str,
    scan_data: dict,
    metadata: dict[str, dict] | None = None,
) -> None:
    """
    Render a Rich table with scan results.

    Args:
        ssid      : Network name shown in the title.
        scan_data : {ip: [port_entries]} from deep_scan.
        metadata  : Optional {ip: {hostname, mac, vendor}} from ping_sweep
                    to enrich the table with extra columns.
    """
    metadata = metadata or {}

    table = Table(
        title        = f"[bold cyan]Sentinel audit: {ssid}[/bold cyan]",
        show_header  = True,
        header_style = "bold magenta",
    )
    table.add_column("Target (IP)",       style="dim",   width=15)
    table.add_column("Hostname",          style="white", width=18, overflow="fold")
    table.add_column("Vendor",            style="dim",   width=18, overflow="fold")
    table.add_column("Risk",              justify="center")
    table.add_column("Ports/Versions",    style="green")
    table.add_column("Services",          style="yellow")

    for ip, results in scan_data.items():
        meta     = metadata.get(ip, {})
        hostname = meta.get("hostname") or "—"
        vendor   = meta.get("vendor")   or "—"
        risk     = evaluate_risk(results)

        if results == ["Shield intact"]:
            table.add_row(
                ip, hostname, vendor, risk,
                "[blue]Closed[/blue]", "Protected device",
            )
        elif results and "Error" in results[0]:
            table.add_row(
                ip, hostname, vendor, "[white]???[/white]",
                "[red]Failed[/red]", "Scan error",
            )
        else:
            ports    = "\n".join(p.split()[0]           for p in results)
            services = "\n".join(" ".join(p.split()[2:]) for p in results)
            table.add_row(ip, hostname, vendor, risk, ports, services)

    console.print("\n", table, "\n")


# ══════════════════════════════════════════════════════════════════
#  Discovery
# ══════════════════════════════════════════════════════════════════

def _parse_nmap_sn(output: str) -> dict[str, dict]:
    """
    Parse `nmap -sn` output extracting IP, hostname, MAC and vendor.

    Returns:
        {ip: {"hostname": str|None, "mac": str|None, "vendor": str|None}}
    """
    hosts: dict[str, dict] = {}
    blocks = re.split(r"(?=Nmap scan report for )", output)

    for block in blocks:
        if not block.startswith("Nmap scan report for "):
            continue

        first_line = block.split("\n", 1)[0]
        m = re.match(
            r"Nmap scan report for (\S+) \((\d+\.\d+\.\d+\.\d+)\)", first_line
        )
        if m:
            hostname, ip = m.group(1), m.group(2)
        else:
            m = re.match(r"Nmap scan report for (\d+\.\d+\.\d+\.\d+)", first_line)
            if not m:
                continue
            hostname, ip = None, m.group(1)

        mac_match = re.search(
            r"MAC Address: ([0-9A-Fa-f:]{17})(?:\s+\(([^)]*)\))?", block
        )
        mac = mac_match.group(1) if mac_match else None
        vendor = (
            mac_match.group(2).strip() if mac_match and mac_match.group(2) else None
        )

        hosts[ip] = {"hostname": hostname, "mac": mac, "vendor": vendor}

    return hosts


def _run_nmap_sn(args: list[str]) -> tuple[int, str]:
    """Run an nmap discovery command. Returns (returncode, stdout)."""
    try:
        proc = subprocess.run(
            args, capture_output=True, text=True, timeout=180,
            stdin=subprocess.DEVNULL,
        )
        return proc.returncode, proc.stdout
    except subprocess.TimeoutExpired:
        rprint("[yellow][-] ping_sweep timed out (180 s). Slow or very crowded network.[/yellow]")
        return 124, ""
    except Exception:
        return 1, ""


def ping_sweep(ip_address: str, excluded: list[str]) -> dict[str, dict]:
    """
    Host discovery on the /24 subnet of *ip_address*.

    Primary:  nmap -sn (default probes — ICMP+ARP under root, TCP otherwise).
    Fallback: nmap -PE -PA80 -PS22,80,443 -sn  (more explicit probes
              when the network filters ICMP or ARP isn't visible without root).

    Args:
        ip_address : Local IP of this device (e.g. 192.168.1.100).
        excluded   : IPs to skip (at minimum: our own IP).

    Returns:
        {ip: {"hostname": ..., "mac": ..., "vendor": ...}}
    """
    subnet      = ".".join(ip_address.split(".")[:-1]) + ".0/24"
    exclude_arg = ["--exclude", ",".join(excluded)] if excluded else []

    rc, out = _run_nmap_sn(["nmap", "-sn", subnet] + exclude_arg)
    hosts = _parse_nmap_sn(out) if rc == 0 else {}

    if not hosts:
        rprint("[dim][-] -sn returned nothing. Trying -PE -PA -PS fallback...[/dim]")
        rc, out = _run_nmap_sn(
            ["nmap", "-sn", "-PE", "-PA80", "-PS22,80,443", subnet] + exclude_arg
        )
        if rc == 0:
            hosts = _parse_nmap_sn(out)

    return hosts


_DEEP_SCAN_WORKERS = 16


def _scan_one(ip: str) -> tuple[str, list[str]]:
    """Run nmap -F -sV -T4 on a single IP. Returns (ip, ports_or_marker)."""
    try:
        proc = subprocess.run(
            ["nmap", "-F", "-sV", "-T4", ip],
            capture_output=True, text=True, timeout=120,
            stdin=subprocess.DEVNULL,
        )
        ports = re.findall(r"(\d+/tcp\s+open\s+.*)", proc.stdout)
        return ip, ([p.strip() for p in ports] if ports else ["Shield intact"])
    except subprocess.TimeoutExpired:
        return ip, ["Error: timeout"]
    except Exception:
        return ip, ["Error"]


def deep_scan(live_ips: list[str]) -> dict:
    """
    Fast port and version scan on each live IP, in parallel.

    Flags: -F (top 100 ports), -sV (version detection), -T4 (aggressive timing).
    Up to 8 hosts in parallel (I/O-bound: the GIL is released during subprocess).

    Returns:
        {ip: [open port lines]} or {ip: ["Shield intact"]} for closed hosts.
    """
    if not live_ips:
        return {}

    workers = min(_DEEP_SCAN_WORKERS, len(live_ips))
    results: dict = {}
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = [pool.submit(_scan_one, ip) for ip in live_ips]
        for fut in as_completed(futures):
            ip, ports = fut.result()
            results[ip] = ports
    return results


# ══════════════════════════════════════════════════════════════════
#  Active response
# ══════════════════════════════════════════════════════════════════

def cut_unknowns(targets: list[str], my_ip: str, config: dict) -> None:
    """
    Launch ARP spoofing threads against every IP not in trusted_ips.

    The local host and the default gateway are always protected, even when
    absent from trusted_ips — cutting them would ARP-poison the operator and
    knock every device on the LAN off the internet. The gateway is detected
    from the routing table (not hard-assumed to be .1).
    Each poisoning thread is daemonised and dies when main exits.

    Args:
        targets : Active IPs found by ping_sweep.
        my_ip   : Local IP of this device.
        config  : Loaded user config dict (needs "trusted_ips" key).
    """
    try:
        from droidnet.modules.spoofer import poison
    except ImportError:
        rprint("[yellow][-] spoofer unavailable. Skipping ARP cut.[/yellow]")
        return

    gateway = get_default_gateway(my_ip)
    if not gateway:
        rprint("[yellow][-] Could not determine the gateway. Skipping ARP cut.[/yellow]")
        return

    # Always protect the local host and gateway, independent of trusted_ips.
    protected = set(config.get("trusted_ips", [])) | {my_ip, gateway}
    unknown = [ip for ip in targets if ip not in protected]

    if not unknown:
        rprint("[dim][-] No unknown hosts. Network is clean.[/dim]")
        return

    iface = get_default_iface()
    for ip in unknown:
        rprint(f"[bold red][☠][/bold red] Unknown: [cyan]{ip}[/cyan] — running ARP cut.")
        t = threading.Thread(target=poison, args=(ip, gateway, iface), daemon=True)
        t.start()


# ══════════════════════════════════════════════════════════════════
#  Persistence
# ══════════════════════════════════════════════════════════════════

def _sanitize_ssid(ssid: str) -> str:
    """Strip everything except word chars and hyphens to prevent path traversal."""
    return re.sub(r'[^\w\-]', '_', ssid) or "unknown"


def save_report(ssid: str, scan_data: dict) -> Path:
    """
    Save *scan_data* to reports/<SSID>_<timestamp>.json.

    Returns:
        Path to the created file.
    """
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    ts        = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_ssid = _sanitize_ssid(ssid)
    filename  = REPORTS_DIR / f"{safe_ssid}_{ts}.json"

    # Final guard: ensure resolved path is inside REPORTS_DIR.
    if filename.resolve().parent != REPORTS_DIR.resolve():
        raise ValueError(f"Report path escapes REPORTS_DIR: {filename}")

    with filename.open("w") as fh:
        json.dump({"network": ssid, "time": ts, "targets": scan_data}, fh, indent=4)

    return filename


# ══════════════════════════════════════════════════════════════════
#  Main scan loop
# ══════════════════════════════════════════════════════════════════

def run_sentinel(interactive: bool = True, auto_cut: bool = False) -> None:
    """
    Main Sentinel loop.

    Modes:
        interactive=True  → single scan cycle, then return.
        interactive=False → daemon: loops every CHECK_INTERVAL seconds,
                            re-scans when the SSID changes or RESCAN_HOURS pass.

    Args:
        interactive : True for one-shot scan, False for daemon mode.
        auto_cut    : If True, executes cut_unknowns automatically on
                      hosts not listed in trusted_ips. Default is False
                      (opt-in) — ARP cutting is destructive.
    """
    # Ensure the schema exists before any scan writes (idempotent). Done here
    # rather than at import so merely importing the module never touches the DB.
    init_db()

    last_ssid       = None
    last_scan_time  = datetime.min
    last_purge_time = datetime.min  # daily DB retention sweep

    rprint("[bold yellow][!][/bold yellow] DroidNet Sentinel ready.")

    while True:
        info   = get_wifi_info()
        config = load_user_config()

        # ── Daily DB retention sweep ─────────────────────────────
        # Opt-out by setting db_retention_days <= 0 in config.json.
        retention_days = int(config.get("db_retention_days", 90))
        now_for_purge  = datetime.now()
        if retention_days > 0 and (now_for_purge - last_purge_time) > timedelta(days=1):
            try:
                deleted = purge_old_scans(retention_days)
                if deleted:
                    log.info("db purge deleted=%d retention_days=%d",
                             deleted, retention_days)
            except Exception as exc:
                log.warning("db purge failed: %s", exc)
            last_purge_time = now_for_purge

        if info:
            current_ssid = info.get("ssid", "Desconocida")
            my_ip        = info.get("ip")
            now          = datetime.now()

            should_scan = (
                interactive
                or current_ssid != last_ssid
                or (now - last_scan_time) > timedelta(hours=RESCAN_HOURS)
            )

            if should_scan and my_ip and my_ip != "0.0.0.0":
                rprint(f"\n[bold green][*][/bold green] Scan en curso: [bold white]{current_ssid}[/bold white]")
                log.info("scan started network=%s my_ip=%s auto_cut=%s",
                         current_ssid, my_ip, auto_cut)

                excluded = config.get("excluded_ips", [])
                if my_ip not in excluded:
                    excluded.append(my_ip)

                metadata = ping_sweep(my_ip, excluded)
                live_ips = list(metadata.keys())

                if live_ips:
                    results = deep_scan(live_ips)
                    ts      = datetime.now().strftime("%Y%m%d_%H%M%S")
                    save_report(current_ssid, results)
                    save_scan(current_ssid, ts, results)
                    display_results_table(current_ssid, results, metadata)
                    log.info("scan finished network=%s hosts=%d",
                             current_ssid, len(live_ips))
                    if auto_cut:
                        cut_unknowns(live_ips, my_ip, config)
                    else:
                        rprint("[dim][-] auto-cut disabled. Use --auto-cut for ARP cut.[/dim]")
                else:
                    rprint("[yellow][-] No hosts detected on the network.[/yellow]")
                    log.warning("scan empty network=%s (no hosts detected)",
                                current_ssid)

                ssid_md = escape_markdown(current_ssid)
                send_alert(
                    title       = "Sentinel Alert",
                    local_msg   = f"{len(live_ips)} hosts analysed on {current_ssid}",
                    telegram_msg= (
                        f"🛡️ *DroidNet Sentinel Report*\n\n"
                        f"📡 *Network:* `{ssid_md}`\n"
                        f"🎯 *Live targets:* {len(live_ips)}\n"
                        f"⚠️ *Check the Command Center for details.*"
                    ),
                )

                last_ssid, last_scan_time = current_ssid, now

        if interactive:
            break

        time.sleep(CHECK_INTERVAL)


if __name__ == "__main__":
    import sys
    run_sentinel(
        interactive="--daemon" not in sys.argv,
        auto_cut="--auto-cut" in sys.argv,
    )
