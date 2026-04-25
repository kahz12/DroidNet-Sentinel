"""
CVE-Watcher Module — monitors recent CVEs and cross-references with scanned network.

Flow:
    1. Load latest scan from DB (services + versions per host)
    2. Extract software keywords (CPE-like) from nmap service banners
    3. Query NIST NVD API for recent CVEs matching each keyword
    4. Score matches, generate human-readable impact summary
    5. Persist alerts to DB + notify via Telegram / local

Requires:
    Internet access for NVD API queries (no API key needed for basic use,
    but rate-limited to ~5 requests per 30 seconds without a key).

Optional:
    Set NVD_API_KEY env var for higher rate limits.
"""

import os
import re
import time
from datetime import datetime, timedelta, timezone

import requests
from rich import print as rprint
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from droidnet.core.database import (
    init_db,
    get_latest_scan_with_services,
    save_cve_alert,
    get_cve_alerts,
)
from droidnet.core.notifier import send_alert

console = Console()

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_API_KEY = os.environ.get("NVD_API_KEY", "")

# Delay between NVD requests to respect rate limits
_REQUEST_DELAY = 6.5 if not NVD_API_KEY else 1.0


# ══════════════════════════════════════════════════════════════════
#  Service banner parsing
# ══════════════════════════════════════════════════════════════════

def parse_service_info(port_entry: str) -> dict | None:
    """
    Extract structured service info from an nmap port line.

    Input:  "80/tcp   open  http    Apache httpd 2.4.29 ((Ubuntu))"
    Output: {"port": "80/tcp", "proto": "http", "product": "Apache httpd",
             "version": "2.4.29", "raw": "Apache httpd 2.4.29"}

    Returns None for unparseable entries.
    """
    if "Escudo" in port_entry or "Error" in port_entry:
        return None

    parts = port_entry.split()
    if len(parts) < 4:
        return None

    port_id = parts[0]       # 80/tcp
    proto = parts[2]         # http
    remainder = " ".join(parts[3:])

    # Strip trailing parenthesized info like ((Ubuntu))
    remainder = re.sub(r"\(.*?\)", "", remainder).strip()

    # Try to split product from version
    version_match = re.search(r"(\d+\.\d[\w.]*)", remainder)
    if version_match:
        version = version_match.group(1)
        product = remainder[:version_match.start()].strip()
    else:
        version = ""
        product = remainder

    if not product or len(product) < 2:
        return None

    return {
        "port": port_id,
        "proto": proto,
        "product": product,
        "version": version,
        "raw": f"{product} {version}".strip(),
    }


def build_search_keywords(targets: dict) -> list[dict]:
    """
    From scan targets, build a list of unique service queries.

    Returns list of dicts with keys: keyword, ips (list), port, version.
    """
    seen: dict[str, dict] = {}

    for ip, port_entries in targets.items():
        for entry in port_entries:
            info = parse_service_info(entry)
            if not info:
                continue

            key = info["raw"].lower()
            if key not in seen:
                seen[key] = {
                    "keyword": info["raw"],
                    "product": info["product"],
                    "version": info["version"],
                    "port": info["port"],
                    "ips": [],
                }
            if ip not in seen[key]["ips"]:
                seen[key]["ips"].append(ip)

    return list(seen.values())


# ══════════════════════════════════════════════════════════════════
#  NVD API queries
# ══════════════════════════════════════════════════════════════════

def query_nvd(keyword: str, days_back: int = 120) -> list[dict]:
    """
    Query NIST NVD for CVEs matching *keyword* published in the last *days_back* days.

    Returns a list of simplified CVE dicts.
    """
    now_utc = datetime.now(timezone.utc)
    pub_start = (now_utc - timedelta(days=days_back)).strftime("%Y-%m-%dT00:00:00.000")
    pub_end = now_utc.strftime("%Y-%m-%dT23:59:59.999")

    params = {
        "keywordSearch": keyword,
        "pubStartDate": pub_start,
        "pubEndDate": pub_end,
        "resultsPerPage": 10,
    }

    headers = {}
    if NVD_API_KEY:
        headers["apiKey"] = NVD_API_KEY

    try:
        resp = requests.get(NVD_API_URL, params=params, headers=headers, timeout=30)
        if resp.status_code == 403:
            rprint("[yellow]  [-] NVD rate limit alcanzado. Esperando...[/yellow]")
            time.sleep(30)
            resp = requests.get(NVD_API_URL, params=params, headers=headers, timeout=30)

        if resp.status_code != 200:
            rprint(f"[dim]  [-] NVD respondió {resp.status_code} para '{keyword}'[/dim]")
            return []

        data = resp.json()
    except Exception as exc:
        rprint(f"[red]  [✗] Error consultando NVD: {exc}[/red]")
        return []

    results = []
    for item in data.get("vulnerabilities", []):
        cve = item.get("cve", {})
        cve_id = cve.get("id", "?")

        # Extract description (prefer English)
        desc = ""
        for d in cve.get("descriptions", []):
            if d.get("lang") == "en":
                desc = d.get("value", "")
                break
        if not desc:
            descs = cve.get("descriptions", [])
            desc = descs[0].get("value", "") if descs else ""

        # Extract CVSS score and severity
        score, severity = _extract_cvss(cve)

        results.append({
            "cve_id": cve_id,
            "description": desc,
            "score": score,
            "severity": severity,
            "published": cve.get("published", ""),
        })

    return results


def _extract_cvss(cve: dict) -> tuple[float | None, str]:
    """Extract the best available CVSS score and severity from a CVE entry."""
    metrics = cve.get("metrics", {})

    # Try CVSS 3.1 first, then 3.0, then 2.0
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        metric_list = metrics.get(key, [])
        if metric_list:
            cvss_data = metric_list[0].get("cvssData", {})
            score = cvss_data.get("baseScore")
            severity = cvss_data.get("baseSeverity", "UNKNOWN")
            if score is not None:
                return score, severity.upper()

    return None, "UNKNOWN"


# ══════════════════════════════════════════════════════════════════
#  Impact analysis (AI-style summary)
# ══════════════════════════════════════════════════════════════════

_SEVERITY_ICONS = {
    "CRITICAL": "[bold red]CRITICAL[/bold red]",
    "HIGH":     "[red]HIGH[/red]",
    "MEDIUM":   "[yellow]MEDIUM[/yellow]",
    "LOW":      "[green]LOW[/green]",
    "UNKNOWN":  "[dim]UNKNOWN[/dim]",
}

_SEVERITY_EMOJI = {
    "CRITICAL": "\U0001f534",  # red circle
    "HIGH":     "\U0001f7e0",  # orange circle
    "MEDIUM":   "\U0001f7e1",  # yellow circle
    "LOW":      "\U0001f7e2",  # green circle
    "UNKNOWN":  "\u26aa",       # white circle
}


def generate_impact_summary(cve: dict, service_info: dict, affected_ips: list[str]) -> str:
    """
    Generate a human-readable impact assessment.

    Analyzes the CVE description and context to produce actionable insight.
    """
    desc = cve["description"]
    severity = cve["severity"]
    score = cve["score"]
    product = service_info["product"]
    version = service_info.get("version", "")
    ip_count = len(affected_ips)

    # Classify attack vector from description keywords
    attack_hints = []
    desc_lower = desc.lower()
    if any(w in desc_lower for w in ("remote", "remotely", "unauthenticated", "network")):
        attack_hints.append("explotable remotamente")
    if any(w in desc_lower for w in ("code execution", "rce", "command injection", "arbitrary code")):
        attack_hints.append("permite ejecucion de codigo")
    if any(w in desc_lower for w in ("denial of service", "dos", "crash", "hang")):
        attack_hints.append("puede causar denegacion de servicio")
    if any(w in desc_lower for w in ("privilege", "escalat", "root", "admin")):
        attack_hints.append("escalacion de privilegios")
    if any(w in desc_lower for w in ("information disclosure", "leak", "exfiltrat", "sensitive")):
        attack_hints.append("fuga de informacion")
    if any(w in desc_lower for w in ("authentication bypass", "auth bypass")):
        attack_hints.append("bypass de autenticacion")

    lines = []
    lines.append(f"Servicio afectado: {product} {version} en {ip_count} host(s)")

    if attack_hints:
        lines.append(f"Vector de ataque: {', '.join(attack_hints)}")

    if severity == "CRITICAL" or (score and score >= 9.0):
        lines.append("ACCION REQUERIDA: Actualizar o aislar este servicio inmediatamente")
    elif severity == "HIGH" or (score and score >= 7.0):
        lines.append("Recomendacion: Priorizar actualizacion de este servicio")
    elif severity == "MEDIUM" or (score and score >= 4.0):
        lines.append("Recomendacion: Planificar actualizacion en el proximo ciclo")
    else:
        lines.append("Riesgo bajo — monitorear")

    return " | ".join(lines)


# ══════════════════════════════════════════════════════════════════
#  Display
# ══════════════════════════════════════════════════════════════════

def display_cve_table(matches: list[dict]) -> None:
    """Render a Rich table with CVE matches."""
    if not matches:
        rprint("[green][✓] Sin CVEs relevantes encontrados para los servicios detectados.[/green]")
        return

    table = Table(
        title="[bold red]CVE-Watcher — Vulnerabilidades detectadas[/bold red]",
        show_header=True,
        header_style="bold red",
    )
    table.add_column("CVE",       style="bold white", width=18)
    table.add_column("Severidad", justify="center",   width=10)
    table.add_column("Score",     justify="center",   width=6)
    table.add_column("Servicio",  style="cyan",       width=22)
    table.add_column("IPs",       style="dim",        width=15)
    table.add_column("Impacto",   style="yellow")

    for m in matches:
        sev_display = _SEVERITY_ICONS.get(m["severity"], m["severity"])
        score_str = f"{m['score']:.1f}" if m["score"] else "—"
        ips_str = ", ".join(m["ips"][:3])
        if len(m["ips"]) > 3:
            ips_str += f" +{len(m['ips']) - 3}"

        table.add_row(
            m["cve_id"],
            sev_display,
            score_str,
            m["service"],
            ips_str,
            m["impact"],
        )

    console.print("\n", table, "\n")


def display_alerts_history(alerts: list[dict]) -> None:
    """Show previously saved CVE alerts from the database."""
    if not alerts:
        rprint("[dim][-] Sin alertas CVE almacenadas.[/dim]")
        return

    table = Table(
        title="[bold cyan]Historial de alertas CVE[/bold cyan]",
        show_header=True,
        header_style="bold magenta",
    )
    table.add_column("CVE",       style="bold white", width=18)
    table.add_column("Severidad", justify="center",   width=10)
    table.add_column("Servicio",  style="cyan",       width=20)
    table.add_column("IP",        style="dim",        width=15)
    table.add_column("Red",       style="white",      width=15)
    table.add_column("Fecha",     style="dim")

    for a in alerts:
        sev = _SEVERITY_ICONS.get(a["severity"], a["severity"])
        table.add_row(a["cve_id"], sev, a["service"], a["ip"], a["network"], a["created_at"])

    console.print("\n", table, "\n")


# ══════════════════════════════════════════════════════════════════
#  Notification
# ══════════════════════════════════════════════════════════════════

def _build_telegram_report(matches: list[dict], network: str) -> str:
    """Build a Markdown-formatted Telegram message for CVE alerts."""
    lines = [
        "\U0001f6a8 *CVE-Watcher Alert*\n",
        f"\U0001f4e1 *Red:* `{network}`",
        f"\u26a0\ufe0f *Vulnerabilidades:* {len(matches)}\n",
    ]

    for m in matches[:5]:
        emoji = _SEVERITY_EMOJI.get(m["severity"], "\u26aa")
        score_str = f"{m['score']:.1f}" if m["score"] else "?"
        lines.append(
            f"{emoji} `{m['cve_id']}` — *{m['severity']}* ({score_str})\n"
            f"   {m['service']} \u2192 {', '.join(m['ips'][:3])}\n"
            f"   _{m['impact'][:100]}_\n"
        )

    if len(matches) > 5:
        lines.append(f"\n_... y {len(matches) - 5} mas. Revisa el Command Center._")

    return "\n".join(lines)


# ══════════════════════════════════════════════════════════════════
#  Main entry point
# ══════════════════════════════════════════════════════════════════

def run_cve_watcher(days_back: int = 120, show_history: bool = False) -> list[dict]:
    """
    Main CVE-Watcher flow.

    1. Load latest scan with services from DB
    2. Extract service keywords
    3. Query NVD for each keyword
    4. Cross-reference, score, and summarize
    5. Persist + alert

    Args:
        days_back    : How many days back to search for CVEs.
        show_history : If True, also display stored CVE alerts.

    Returns:
        List of matched CVE dicts.
    """
    init_db()

    rprint(
        Panel(
            "[bold red]CVE-Watcher[/bold red] — Monitoreo de vulnerabilidades",
            subtitle=f"[dim]Buscando CVEs de los ultimos {days_back} dias[/dim]",
            style="red",
        )
    )

    # Step 1: Load scan data
    scan = get_latest_scan_with_services()
    if not scan:
        rprint("[yellow][-] No hay escaneos con servicios detectados. Ejecuta Sentinel primero.[/yellow]")
        if show_history:
            display_alerts_history(get_cve_alerts())
        return []

    network = scan["network"]
    scan_id = scan["id"]
    rprint(f"[*] Analizando scan de [bold white]{network}[/bold white] (ID: {scan_id})")

    # Step 2: Extract keywords
    keywords = build_search_keywords(scan["targets"])
    if not keywords:
        rprint("[yellow][-] No se encontraron servicios con version identificable.[/yellow]")
        return []

    rprint(f"[*] {len(keywords)} servicio(s) unico(s) detectados:\n")
    for kw in keywords:
        rprint(f"    [cyan]\u2022[/cyan] {kw['keyword']} ({kw['port']}) — {', '.join(kw['ips'])}")
    rprint()

    # Step 3: Query NVD
    all_matches: list[dict] = []

    for i, kw in enumerate(keywords):
        rprint(f"[bold cyan][\u2026][/bold cyan] Consultando NVD: [yellow]{kw['keyword']}[/yellow]")

        cves = query_nvd(kw["keyword"], days_back=days_back)

        if not cves:
            # Try with just the product name (without version)
            if kw["version"]:
                rprint(f"  [dim]Reintentando con: {kw['product']}[/dim]")
                time.sleep(_REQUEST_DELAY)
                cves = query_nvd(kw["product"], days_back=days_back)

        for cve in cves:
            impact = generate_impact_summary(cve, kw, kw["ips"])

            match = {
                "cve_id":   cve["cve_id"],
                "severity": cve["severity"],
                "score":    cve["score"],
                "service":  kw["keyword"],
                "ips":      kw["ips"],
                "impact":   impact,
                "description": cve["description"],
            }
            all_matches.append(match)

            # Persist each alert
            for ip in kw["ips"]:
                save_cve_alert(
                    cve_id=cve["cve_id"],
                    severity=cve["severity"],
                    score=cve["score"],
                    service=kw["keyword"],
                    ip=ip,
                    summary=cve["description"][:500],
                    impact=impact,
                    network=network,
                    scan_id=scan_id,
                )

        if i < len(keywords) - 1:
            time.sleep(_REQUEST_DELAY)

    # Step 4: Sort by severity/score (critical first)
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4}
    all_matches.sort(key=lambda m: (severity_order.get(m["severity"], 5), -(m["score"] or 0)))

    # Step 5: Display + notify
    display_cve_table(all_matches)

    if all_matches:
        critical_count = sum(1 for m in all_matches if m["severity"] in ("CRITICAL", "HIGH"))
        send_alert(
            title="CVE-Watcher Alert",
            local_msg=f"{len(all_matches)} CVEs encontrados ({critical_count} criticos/altos) en {network}",
            telegram_msg=_build_telegram_report(all_matches, network),
        )

    if show_history:
        rprint("\n[bold cyan]--- Historial de alertas ---[/bold cyan]")
        display_alerts_history(get_cve_alerts(network=network))

    return all_matches


if __name__ == "__main__":
    run_cve_watcher()
