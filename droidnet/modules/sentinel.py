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
from datetime import datetime, timedelta
from pathlib import Path

import requests
from rich           import print as rprint
from rich.console   import Console
from rich.table     import Table

from droidnet.config       import (
    CHECK_INTERVAL,
    RESCAN_HOURS,
    REPORTS_DIR,
    load_user_config,
)
from droidnet.core.database  import init_db, save_scan
from droidnet.core.notifier  import send_alert
from droidnet.platform.utils import get_wifi_info

# Ensure the database schema exists before any scan runs.
init_db()

console = Console()


# ══════════════════════════════════════════════════════════════════
#  Risk evaluation
# ══════════════════════════════════════════════════════════════════

_CRITICAL_PORTS = {"21/tcp", "23/tcp", "445/tcp", "139/tcp", "3389/tcp"}
_MEDIUM_PORTS   = {"80/tcp", "8080/tcp", "53/tcp", "1900/tcp", "2049/tcp"}


def evaluate_risk(ports: list[str]) -> str:
    """
    Classify the threat level for a host based on its open ports.

    Returns a Rich-markup string: MÍNIMO / BAJO / MEDIO / CRÍTICO.
    """
    if not ports or "Escudo intacto" in ports:
        return "[bold green]MÍNIMO[/bold green]"

    level = "[bold green]BAJO[/bold green]"
    for entry in ports:
        port_id = entry.split()[0]
        if port_id in _CRITICAL_PORTS:
            return "[bold red]CRÍTICO[/bold red]"
        if port_id in _MEDIUM_PORTS:
            level = "[bold yellow]MEDIO[/bold yellow]"
    return level


# ══════════════════════════════════════════════════════════════════
#  Display
# ══════════════════════════════════════════════════════════════════

def display_results_table(ssid: str, scan_data: dict) -> None:
    """Render a Rich table with the scan results for *ssid*."""
    table = Table(
        title        = f"[bold cyan]Auditoría Sentinel: {ssid}[/bold cyan]",
        show_header  = True,
        header_style = "bold magenta",
    )
    table.add_column("Objetivo (IP)", style="dim",  width=15)
    table.add_column("Riesgo",        justify="center")
    table.add_column("Puertos/Versiones", style="green")
    table.add_column("Servicios",     style="yellow")

    for ip, results in scan_data.items():
        risk = evaluate_risk(results)

        if results == ["Escudo intacto"]:
            table.add_row(ip, risk, "[blue]Cerrado[/blue]", "Dispositivo Protegido")

        elif results and "Error" in results[0]:
            table.add_row(ip, "[white]???[/white]", "[red]Falla[/red]", "Error de escaneo")

        else:
            ports    = "\n".join(p.split()[0]           for p in results)
            services = "\n".join(" ".join(p.split()[2:]) for p in results)
            table.add_row(ip, risk, ports, services)

    console.print("\n", table, "\n")


# ══════════════════════════════════════════════════════════════════
#  Discovery
# ══════════════════════════════════════════════════════════════════

def ping_sweep(ip_address: str, excluded: list[str]) -> list[str]:
    """
    ARP-based host discovery on the /24 subnet of *ip_address*.

    Uses nmap -sn (ping scan, no port scan) — fast and silent on LAN.

    Args:
        ip_address : Local IP of this device (e.g. 192.168.1.100).
        excluded   : IPs to skip (at minimum: our own IP).

    Returns:
        List of active IPs found.
    """
    subnet      = ".".join(ip_address.split(".")[:-1]) + ".0/24"
    exclude_arg = ["--exclude", ",".join(excluded)] if excluded else []

    try:
        proc = subprocess.run(
            ["nmap", "-sn", subnet] + exclude_arg,
            capture_output=True, text=True,
        )
        return re.findall(r"Nmap scan report for (\d+\.\d+\.\d+\.\d+)", proc.stdout)
    except Exception:
        return []


def deep_scan(live_ips: list[str]) -> dict:
    """
    Fast port and version scan on each live IP.

    Flags: -F (top 100 ports), -sV (version detection), -T4 (aggressive timing).

    Returns:
        {ip: [open port lines]} or {ip: ["Escudo intacto"]} for closed hosts.
    """
    results: dict = {}
    for ip in live_ips:
        try:
            proc = subprocess.run(
                ["nmap", "-F", "-sV", "-T4", ip],
                capture_output=True, text=True,
            )
            ports = re.findall(r"(\d+/tcp\s+open\s+.*)", proc.stdout)
            results[ip] = [p.strip() for p in ports] if ports else ["Escudo intacto"]
        except Exception:
            results[ip] = ["Error"]
    return results


# ══════════════════════════════════════════════════════════════════
#  Active response
# ══════════════════════════════════════════════════════════════════

def cut_unknowns(targets: list[str], my_ip: str, config: dict) -> None:
    """
    Launch ARP spoofing threads against every IP not in trusted_ips.

    Gateway is inferred as the .1 address of the local subnet.
    Each poisoning thread is daemonised and dies when main exits.

    Args:
        targets : Active IPs found by ping_sweep.
        my_ip   : Local IP of this device.
        config  : Loaded user config dict (needs "trusted_ips" key).
    """
    try:
        from droidnet.modules.spoofer import poison
    except ImportError:
        rprint("[yellow][-] spoofer no disponible. Saltando corte ARP.[/yellow]")
        return

    gateway = ".".join(my_ip.split(".")[:-1]) + ".1"
    trusted = config.get("trusted_ips", [])
    unknown = [ip for ip in targets if ip not in trusted]

    if not unknown:
        rprint("[dim][-] Sin desconocidos. Red limpia.[/dim]")
        return

    for ip in unknown:
        rprint(f"[bold red][☠][/bold red] Desconocido: [cyan]{ip}[/cyan] — ejecutando corte ARP.")
        t = threading.Thread(target=poison, args=(ip, gateway), daemon=True)
        t.start()


# ══════════════════════════════════════════════════════════════════
#  Persistence
# ══════════════════════════════════════════════════════════════════

def save_report(ssid: str, scan_data: dict) -> Path:
    """
    Save *scan_data* to reports/<SSID>_<timestamp>.json.

    Returns:
        Path to the created file.
    """
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    ts       = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = REPORTS_DIR / f"{ssid.replace(' ', '_')}_{ts}.json"

    with filename.open("w") as fh:
        json.dump({"network": ssid, "time": ts, "targets": scan_data}, fh, indent=4)

    return filename


# ══════════════════════════════════════════════════════════════════
#  Main scan loop
# ══════════════════════════════════════════════════════════════════

def run_sentinel(interactive: bool = True) -> None:
    """
    Main Sentinel loop.

    Modes:
        interactive=True  → single scan cycle, then return.
        interactive=False → daemon: loops every CHECK_INTERVAL seconds,
                            re-scans when the SSID changes or RESCAN_HOURS pass.

    Args:
        interactive: True for one-shot scan, False for daemon mode.
    """
    last_ssid      = None
    last_scan_time = datetime.min

    rprint("[bold yellow][!][/bold yellow] DroidNet Sentinel listo.")

    while True:
        info   = get_wifi_info()
        config = load_user_config()

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

                excluded = config.get("excluded_ips", [])
                if my_ip not in excluded:
                    excluded.append(my_ip)

                targets = ping_sweep(my_ip, excluded)

                if targets:
                    results   = deep_scan(targets)
                    ts        = datetime.now().strftime("%Y%m%d_%H%M%S")
                    save_report(current_ssid, results)
                    save_scan(current_ssid, ts, results)
                    display_results_table(current_ssid, results)
                    cut_unknowns(targets, my_ip, config)
                else:
                    rprint("[yellow][-] Sin hosts detectados en la red.[/yellow]")

                send_alert(
                    title       = "Sentinel Alert",
                    local_msg   = f"{len(targets)} hosts analizados en {current_ssid}",
                    telegram_msg= (
                        f"🛡️ *DroidNet Sentinel Report*\n\n"
                        f"📡 *Red:* `{current_ssid}`\n"
                        f"🎯 *Objetivos vivos:* {len(targets)}\n"
                        f"⚠️ *Revisa el Command Center para detalles.*"
                    ),
                )

                last_ssid, last_scan_time = current_ssid, now

        if interactive:
            break

        time.sleep(CHECK_INTERVAL)


if __name__ == "__main__":
    import sys
    run_sentinel(interactive="--daemon" not in sys.argv)
