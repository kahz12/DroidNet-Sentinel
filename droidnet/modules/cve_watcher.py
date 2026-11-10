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

import hashlib
import json
import os
import re
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import requests
from rich import print as rprint
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from droidnet.config import NVD_CACHE_DIR
from droidnet.core.database import (
    init_db,
    get_latest_scan_with_services,
    save_cve_alert,
    get_cve_alerts,
)
from droidnet.core.logger import get_logger
from droidnet.core.markup import esc
from droidnet.core.notifier import send_alert, escape_markdown

log = get_logger(__name__)

console = Console()

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_API_KEY = os.environ.get("NVD_API_KEY", "")

# Delay between NVD requests to respect rate limits
_REQUEST_DELAY = 6.5 if not NVD_API_KEY else 1.0

# Exponential backoff for 429/403 — base 1s, up to ~30s, max 5 retries.
_BACKOFF_MAX_RETRIES = 5
_BACKOFF_BASE        = 1.0
_BACKOFF_CAP         = 30.0

# Local NVD response cache: JSON file per (query, UTC day).
# Implicit 24h TTL: the key includes YYYYMMDD, so once the day passes,
# the file is no longer considered for the new day's query.
_CACHE_TTL_SECONDS = 24 * 3600


# ══════════════════════════════════════════════════════════════════
#  CPE mapping (heuristic vendor:product → cpeName)
# ══════════════════════════════════════════════════════════════════

# Static map for the most common services appearing in nmap banners.
# Key = normalized product string (lowercase). Value = "vendor:product"
# in CPE 2.3 format. Queried before falling back to generic keywordSearch.
_PRODUCT_TO_CPE: dict[str, str] = {
    "apache httpd":         "apache:http_server",
    "apache":               "apache:http_server",
    "nginx":                "nginx:nginx",
    "openssh":              "openbsd:openssh",
    "microsoft iis":        "microsoft:internet_information_services",
    "iis":                  "microsoft:internet_information_services",
    # NVD files MySQL under Oracle (oracle:mysql:8.0.36 has 73 CVEs,
    # mysql:mysql:8.0.36 has 2 and no dictionary entry).
    "mysql":                "oracle:mysql",
    "mariadb":              "mariadb:mariadb",
    "postgresql":           "postgresql:postgresql",
    "vsftpd":               "vsftpd_project:vsftpd",
    "proftpd":              "proftpd:proftpd",
    "pure-ftpd":            "pureftpd:pure-ftpd",
    "exim":                 "exim:exim",
    "postfix":              "postfix:postfix",
    "dovecot":              "dovecot:dovecot",
    "samba smbd":           "samba:samba",
    "samba":                "samba:samba",
    "isc bind":             "isc:bind",
    "bind":                 "isc:bind",
    "dnsmasq":              "thekelleys:dnsmasq",
    "lighttpd":             "lighttpd:lighttpd",
    "redis":                "redis:redis",
    "memcached":            "memcached:memcached",
    "mongodb":              "mongodb:mongodb",
    "elasticsearch":        "elastic:elasticsearch",
}

# Generic role words nmap appends to product names ("PostgreSQL DB",
# "Microsoft IIS httpd", "Redis key-value store"). One trailing word is
# stripped to retry the exact lookup. Never prefix-match instead: "Apache
# Tomcat", "Elasticsearch Kibana" or "Dovecot Pigeonhole sieve" are other
# products and would silently borrow the wrong CPE.
_NMAP_ROLE_SUFFIXES = (
    "key-value store", "rest api",
    "httpd", "smtpd", "imapd", "pop3d", "ftpd", "sshd", "smbd", "db",
)

# Products whose NVD CPE names keep the release suffix in the *update*
# field (dictionary: openssh 9.6:p1, proftpd 1.3.5:a). Sending "8.2p1" as
# the version misses every CVE that lists the exact version (e.g.
# CVE-2020-12062 → openssh:8.2:*), keeping only range-based matches.
_UPDATE_SUFFIX_PRODUCTS = {"openbsd:openssh", "proftpd:proftpd"}
_VERSION_UPDATE_RE = re.compile(r"(\d+(?:\.\d+)+)([a-z]+\d*)", re.IGNORECASE)


def _lookup_vendor_product(product: str) -> str | None:
    """Map an nmap product string to "vendor:product", or None if unknown."""
    key = " ".join(product.lower().split())
    if key in _PRODUCT_TO_CPE:
        return _PRODUCT_TO_CPE[key]
    for suffix in _NMAP_ROLE_SUFFIXES:
        if key.endswith(" " + suffix):
            return _PRODUCT_TO_CPE.get(key[: -len(suffix) - 1])
    return None


def build_cpe_name(product: str, version: str) -> str | None:
    """
    Builds a cpeName 2.3 from (product, version) using the static map.
    Returns None if vendor is unknown or version is missing.

    NVD requires the exact version for cpeName; without it, the endpoint
    rejects the query, so we only emit CPE if we have both.
    """
    if not version:
        return None

    vendor_product = _lookup_vendor_product(product)
    if not vendor_product:
        return None

    update = "*"
    if vendor_product in _UPDATE_SUFFIX_PRODUCTS:
        split = _VERSION_UPDATE_RE.fullmatch(version)
        if split:
            version, update = split.group(1), split.group(2).lower()

    return f"cpe:2.3:a:{vendor_product}:{version}:{update}:*:*:*:*:*:*"


# ══════════════════════════════════════════════════════════════════
#  NVD response cache (JSON per query + UTC day)
# ══════════════════════════════════════════════════════════════════

def _cache_path(query_id: str) -> Path:
    """Cache file path for a specific query + day."""
    day = datetime.now(timezone.utc).strftime("%Y%m%d")
    digest = hashlib.sha1(query_id.encode("utf-8")).hexdigest()[:16]
    return NVD_CACHE_DIR / f"{digest}_{day}.json"


def _cache_load(query_id: str) -> list[dict] | None:
    """Returns the cached result if it exists and is fresh (<24h)."""
    path = _cache_path(query_id)
    try:
        if (time.time() - path.stat().st_mtime) > _CACHE_TTL_SECONDS:
            return None
        with path.open() as fh:
            cached = json.load(fh)
        # Older caches may contain only the first page; never reuse them.
        if isinstance(cached, dict) and cached.get("schema") == 2 and isinstance(cached.get("results"), list):
            return cached["results"]
        return None
    except (json.JSONDecodeError, OSError):
        return None


def _cache_store(query_id: str, results: list[dict]) -> None:
    """Persists *results* for *query_id* (best-effort, ignores I/O errors)."""
    try:
        NVD_CACHE_DIR.mkdir(parents=True, exist_ok=True)
        with _cache_path(query_id).open("w") as fh:
            json.dump({"schema": 2, "results": results}, fh)
    except OSError:
        pass


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
    if "Shield" in port_entry or "Error" in port_entry:
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

def _nvd_get(params: dict, query_label: str) -> dict | None:
    """
    GET with exponential backoff against 429/403.

    Returns parsed JSON or None if all retries fail / network error occurs.
    Respects Retry-After if NVD sends it.
    """
    headers = {"apiKey": NVD_API_KEY} if NVD_API_KEY else {}

    for attempt in range(_BACKOFF_MAX_RETRIES):
        try:
            resp = requests.get(NVD_API_URL, params=params, headers=headers, timeout=30)
        except requests.RequestException as exc:
            rprint(f"[red]  [✗] NVD network error ({esc(query_label)}): {esc(exc)}[/red]")
            return None

        if resp.status_code == 200:
            try:
                return resp.json()
            except ValueError as exc:
                rprint(f"[red]  [✗] NVD returned invalid JSON ({esc(query_label)}): {esc(exc)}[/red]")
                return None

        if resp.status_code in (429, 403):
            retry_after = resp.headers.get("Retry-After")
            if retry_after and retry_after.isdigit():
                delay = min(float(retry_after), _BACKOFF_CAP)
            else:
                delay = min(_BACKOFF_BASE * (2 ** attempt), _BACKOFF_CAP)
            rprint(
                f"[yellow]  [-] NVD {resp.status_code} ({esc(query_label)}); "
                f"backoff {delay:.1f}s (attempt {attempt + 1}/{_BACKOFF_MAX_RETRIES})[/yellow]"
            )
            log.warning("nvd backoff status=%s query=%s delay=%.1fs attempt=%d",
                        resp.status_code, query_label, delay, attempt + 1)
            time.sleep(delay)
            continue

        # Other codes: do not retry.
        rprint(f"[dim]  [-] NVD responded {resp.status_code} for '{esc(query_label)}'[/dim]")
        return None

    rprint(f"[red]  [✗] NVD: retries exhausted for '{esc(query_label)}'[/red]")
    return None


def _extract_cwes(cve: dict) -> list[str]:
    """Return the CWE identifiers listed in the CVE's weaknesses block."""
    cwes: list[str] = []
    for weakness in cve.get("weaknesses", []):
        if not isinstance(weakness, dict):
            continue
        for d in weakness.get("description", []):
            if isinstance(d, dict):
                value = d.get("value", "")
                if value.startswith("CWE-") and value not in cwes:
                    cwes.append(value)
    return cwes


def _parse_nvd_payload(data: dict) -> list[dict]:
    """Normalizes the NVD response into a simplified CVE list."""
    results: list[dict] = []
    for item in data.get("vulnerabilities", []):
        cve = item.get("cve", {})
        cve_id = cve.get("id", "?")

        # Extract description (prefer English). Guard against malformed NVD
        # payloads where a description entry is not a dict.
        desc = ""
        descs = cve.get("descriptions", [])
        for d in descs:
            if isinstance(d, dict) and d.get("lang") == "en":
                desc = d.get("value", "")
                break
        if not desc:
            first = descs[0] if descs else None
            desc = first.get("value", "") if isinstance(first, dict) else ""

        score, severity = _extract_cvss(cve)

        results.append({
            "cve_id":      cve_id,
            "description": desc,
            "score":       score,
            "severity":    severity,
            "published":   cve.get("published", ""),
            "cwes":        _extract_cwes(cve),
            # Present in the NVD record only when CISA lists the CVE as a Known
            # Exploited Vulnerability (actively exploited in the wild).
            "kev":         bool(cve.get("cisaExploitAdd")),
        })
    return results


def query_nvd(
    keyword: str,
    days_back: int = 120,
    cpe_name: str | None = None,
) -> list[dict] | None:
    """
    Query NIST NVD for CVEs published in the last *days_back* days.

    If *cpe_name* is provided, `cpeName` parameter is used (CPE-search,
    much more precise). Otherwise falls back to `keywordSearch`.

    Results are cached to disk by (query, UTC day) for 24h to avoid
    re-querying NVD for the same day's repetitions.
    Returns None on failed/incomplete queries; [] means a completed search
    with no matches. Only complete result sets are cached.
    """
    if isinstance(days_back, bool) or not isinstance(days_back, int) or not 1 <= days_back <= 120:
        raise ValueError("days_back must be an integer between 1 and 120")
    now_utc = datetime.now(timezone.utc).replace(microsecond=0)
    pub_start = (now_utc - timedelta(days=days_back)).isoformat(timespec="milliseconds")
    pub_end = now_utc.isoformat(timespec="milliseconds")

    if cpe_name:
        params = {
            "cpeName":        cpe_name,
            "isVulnerable":   "",
            "pubStartDate":   pub_start,
            "pubEndDate":     pub_end,
            "resultsPerPage": 2000,
        }
        cache_key   = f"cpe:{cpe_name}:{days_back}"
        query_label = cpe_name
    else:
        params = {
            "keywordSearch":  keyword,
            "pubStartDate":   pub_start,
            "pubEndDate":     pub_end,
            "resultsPerPage": 2000,
        }
        cache_key   = f"kw:{keyword.lower()}:{days_back}"
        query_label = keyword

    cached = _cache_load(cache_key)
    if cached is not None:
        rprint(f"[dim]  \\[cache] {esc(query_label)}[/dim]")
        log.debug("nvd cache hit query=%s", query_label)
        return cached
    log.debug("nvd cache miss query=%s", query_label)

    results = []
    start = 0
    while True:
        data = _nvd_get({**params, "startIndex": start}, query_label)
        if not isinstance(data, dict):
            return None
        items = data.get("vulnerabilities")
        total = data.get("totalResults")
        if (not isinstance(items, list) or not isinstance(total, int)
                or total < 0 or data.get("startIndex") != start
                or any(not isinstance(item, dict) or not isinstance(item.get("cve"), dict) for item in items)):
            log.warning("invalid NVD page query=%s", query_label)
            return None
        if not items and start < total:
            log.warning("incomplete NVD pagination query=%s", query_label)
            return None
        results.extend(_parse_nvd_payload(data))
        start += len(items)
        if start >= total:
            break
        time.sleep(_REQUEST_DELAY)
    _cache_store(cache_key, results)
    return results


# Metric blocks in order of preference. CVSS 3.x stays first so scores of
# CVEs that have it do not change; CVSS 4.0 is often the only score a CNA
# supplies on a fresh CVE (~10% of new CVEs), and v2 is legacy.
_CVSS_METRIC_KEYS = ("cvssMetricV31", "cvssMetricV30", "cvssMetricV40", "cvssMetricV2")
_CVSS_SEVERITIES = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE"}


def _severity_from_score(score: float, legacy_v2: bool) -> str:
    """Qualitative band for *score* when NVD omits baseSeverity."""
    if legacy_v2:  # CVSS v2 has no CRITICAL or NONE bands.
        return "HIGH" if score >= 7.0 else "MEDIUM" if score >= 4.0 else "LOW"
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    return "LOW" if score > 0 else "NONE"


def _metric_score(entry, legacy_v2: bool) -> tuple[float | None, str]:
    """Score and severity of one metric entry; (None, ...) if unusable."""
    data = entry.get("cvssData") if isinstance(entry, dict) else None
    if not isinstance(data, dict):
        return None, "UNKNOWN"
    score = data.get("baseScore")
    if isinstance(score, bool) or not isinstance(score, (int, float)) or not 0 <= score <= 10:
        return None, "UNKNOWN"
    # v3.x / v4.0 keep baseSeverity inside cvssData; v2 keeps it beside it.
    severity = (entry if legacy_v2 else data).get("baseSeverity")
    if isinstance(severity, str) and severity.upper() in _CVSS_SEVERITIES:
        return float(score), severity.upper()
    return float(score), _severity_from_score(score, legacy_v2)


def _extract_cvss(cve: dict) -> tuple[float | None, str]:
    """Extract the best available CVSS score and severity from a CVE entry.

    Malformed blocks are skipped rather than raising, so one bad record
    cannot abort the whole run.
    """
    metrics = cve.get("metrics")
    if not isinstance(metrics, dict):
        return None, "UNKNOWN"

    for key in _CVSS_METRIC_KEYS:
        entries = metrics.get(key)
        if not isinstance(entries, list):
            continue
        # NVD's own analysis ("Primary") beats a CNA's ("Secondary");
        # sorted() is stable, so the original order breaks ties.
        entries = sorted(entries, key=lambda e: not (isinstance(e, dict) and e.get("type") == "Primary"))
        for entry in entries:
            score, severity = _metric_score(entry, legacy_v2=(key == "cvssMetricV2"))
            if score is not None:
                return score, severity

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
        attack_hints.append("remotely exploitable")
    if any(w in desc_lower for w in ("code execution", "rce", "command injection", "arbitrary code")):
        attack_hints.append("allows code execution")
    if any(w in desc_lower for w in ("denial of service", "dos", "crash", "hang")):
        attack_hints.append("can cause denial of service")
    if any(w in desc_lower for w in ("privilege", "escalat", "root", "admin")):
        attack_hints.append("privilege escalation")
    if any(w in desc_lower for w in ("information disclosure", "leak", "exfiltrat", "sensitive")):
        attack_hints.append("information leak")
    if any(w in desc_lower for w in ("authentication bypass", "auth bypass")):
        attack_hints.append("authentication bypass")

    lines = []
    candidate = service_info.get("match_type") == "candidate"
    if candidate:
        lines.append(f"Candidate match: {product} {version} on {ip_count} host(s); version applicability unverified")
    else:
        lines.append(f"Affected service: {product} {version} on {ip_count} host(s)")

    if cve.get("kev"):
        lines.append("CISA KEV: known exploited in the wild")

    if attack_hints:
        lines.append(f"Attack vector: {', '.join(attack_hints)}")

    cwes = cve.get("cwes") or []
    if cwes:
        lines.append(f"Weakness: {', '.join(cwes)}")

    if candidate:
        lines.append("Verify the affected versions before remediation")
    elif cve.get("kev") or severity == "CRITICAL" or (score and score >= 9.0):
        lines.append("ACTION REQUIRED: Update or isolate this service immediately")
    elif severity == "HIGH" or (score and score >= 7.0):
        lines.append("Recommendation: Prioritise updating this service")
    elif severity == "MEDIUM" or (score and score >= 4.0):
        lines.append("Recommendation: Plan update in the next cycle")
    else:
        lines.append("Low risk — monitor")

    return " | ".join(lines)


# ══════════════════════════════════════════════════════════════════
#  Display
# ══════════════════════════════════════════════════════════════════

def display_cve_table(matches: list[dict], complete: bool = True) -> None:
    """Render a Rich table with CVE matches."""
    if not matches:
        if complete:
            rprint("[green][✓] No matching CVEs found in the queried publication window.[/green]")
        else:
            rprint("[yellow]CVE analysis incomplete: queries failed; absence of vulnerabilities is unknown.[/yellow]")
        return

    table = Table(
        title="[bold red]CVE-Watcher — CVE matches[/bold red]",
        show_header=True,
        header_style="bold red",
    )
    table.add_column("CVE",       style="bold white", width=18)
    table.add_column("Match",     style="white")
    table.add_column("Severity",  justify="center",   width=10)
    table.add_column("Score",     justify="center",   width=6)
    table.add_column("Service",   style="cyan",       width=22)
    table.add_column("IPs",       style="dim",        width=15)
    table.add_column("Impact",    style="yellow")

    for m in matches:
        sev_display = _SEVERITY_ICONS.get(m["severity"], esc(m["severity"]))
        score_str = f"{m['score']:.1f}" if m["score"] else "—"
        ips_str = ", ".join(m["ips"][:3])
        if len(m["ips"]) > 3:
            ips_str += f" +{len(m['ips']) - 3}"

        # Table cells are parsed as markup too: escape every external field.
        table.add_row(
            esc(m["cve_id"]),
            "Candidate" if m.get("match_type") == "candidate" else "CPE",
            sev_display,
            score_str,
            esc(m["service"]),
            esc(ips_str),
            esc(m["impact"]),
        )

    console.print("\n", table, "\n")


def display_alerts_history(alerts: list[dict]) -> None:
    """Show previously saved CVE alerts from the database."""
    if not alerts:
        rprint("[dim][-] No stored CVE alerts.[/dim]")
        return

    table = Table(
        title="[bold cyan]CVE alerts history[/bold cyan]",
        show_header=True,
        header_style="bold magenta",
    )
    table.add_column("CVE",       style="bold white", width=18)
    table.add_column("Severity",  justify="center",   width=10)
    table.add_column("Service",   style="cyan",       width=20)
    table.add_column("IP",        style="dim",        width=15)
    table.add_column("Network",   style="white",      width=15)
    table.add_column("Date",      style="dim")

    for a in alerts:
        sev = _SEVERITY_ICONS.get(a["severity"], esc(a["severity"]))
        table.add_row(esc(a["cve_id"]), sev, esc(a["service"]), esc(a["ip"]),
                      esc(a["network"]), esc(a["created_at"]))

    console.print("\n", table, "\n")


# ══════════════════════════════════════════════════════════════════
#  Notification
# ══════════════════════════════════════════════════════════════════

def _build_telegram_report(matches: list[dict], network: str) -> str:
    """Build a Markdown-formatted Telegram message for CVE alerts."""
    lines = [
        "\U0001f6a8 *CVE-Watcher Alert*\n",
        f"\U0001f4e1 *Network:* `{escape_markdown(network)}`",
        f"\u26a0\ufe0f *CVE matches:* {len(matches)}\n",
    ]

    for m in matches[:5]:
        emoji = _SEVERITY_EMOJI.get(m["severity"], "\u26aa")
        score_str = f"{m['score']:.1f}" if m["score"] else "?"
        service_md = escape_markdown(m["service"])
        impact_md  = escape_markdown(m["impact"][:100])
        lines.append(
            f"{emoji} `{m['cve_id']}` — *{m['severity']}* ({score_str}) "
            f"({'candidate' if m.get('match_type') == 'candidate' else 'CPE match'})\n"
            f"   {service_md} \u2192 {', '.join(m['ips'][:3])}\n"
            f"   _{impact_md}_\n"
        )

    if len(matches) > 5:
        lines.append(f"\n_... and {len(matches) - 5} more. Check the Command Center._")

    return "\n".join(lines)


# ══════════════════════════════════════════════════════════════════
#  Main entry point
# ══════════════════════════════════════════════════════════════════

class CVEWatchResult(list):
    """List-compatible matches with explicit query completion status."""

    def __init__(self):
        super().__init__()
        self.failed_queries: list[str] = []

    @property
    def complete(self) -> bool:
        return not self.failed_queries


def run_cve_watcher(days_back: int = 120, show_history: bool = False) -> CVEWatchResult:
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
    if isinstance(days_back, bool) or not isinstance(days_back, int) or not 1 <= days_back <= 120:
        raise ValueError("days_back must be an integer between 1 and 120")
    init_db()
    all_matches = CVEWatchResult()

    rprint(
        Panel(
            "[bold red]CVE-Watcher[/bold red] — Vulnerability monitoring",
            subtitle=f"[dim]Searching CVEs from the last {days_back} days[/dim]",
            style="red",
        )
    )

    # Load the newest persisted scan that contains service banners.
    scan = get_latest_scan_with_services()
    if not scan:
        rprint("[yellow][-] No scans with detected services found. Run Sentinel first.[/yellow]")
        if show_history:
            display_alerts_history(get_cve_alerts())
        return all_matches

    network = scan["network"]
    scan_id = scan["id"]
    rprint(f"[*] Analysing scan from [bold white]{esc(network)}[/bold white] (ID: {scan_id})")

    # Normalize banners into deduplicated service queries.
    keywords = build_search_keywords(scan["targets"])
    if not keywords:
        rprint("[yellow][-] No services with identifiable version found.[/yellow]")
        return all_matches

    rprint(f"[*] {len(keywords)} unique service(s) detected:\n")
    for kw in keywords:
        rprint(f"    [cyan]\u2022[/cyan] {esc(kw['keyword'])} ({esc(kw['port'])}) — "
               f"{esc(', '.join(kw['ips']))}")
    rprint()

    # Query NVD and retain whether each match is version-qualified.
    for i, kw in enumerate(keywords):
        cpe_name = build_cpe_name(kw["product"], kw["version"])
        kw["match_type"] = "cpe" if cpe_name else "candidate"
        mode_tag = "CPE" if cpe_name else "keyword"
        rprint(
            f"[bold cyan][\u2026][/bold cyan] Querying NVD ({mode_tag}): "
            f"[yellow]{esc(cpe_name or kw['keyword'])}[/yellow]"
        )

        cves = query_nvd(kw["keyword"], days_back=days_back, cpe_name=cpe_name)

        if cves == []:
            # Try with just the product name (without version, via keyword)
            if kw["version"]:
                rprint(f"  [dim]Retrying with keyword: {esc(kw['product'])}[/dim]")
                time.sleep(_REQUEST_DELAY)
                cves = query_nvd(kw["product"], days_back=days_back)
                kw["match_type"] = "candidate"

        if cves is None:
            all_matches.failed_queries.append(kw["keyword"])
            if i < len(keywords) - 1:
                time.sleep(_REQUEST_DELAY)
            continue

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
                "match_type": kw["match_type"],
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

    # Present the most urgent matches first.
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4}
    all_matches.sort(key=lambda m: (severity_order.get(m["severity"], 5), -(m["score"] or 0)))

    # Render the result and notify configured channels.
    display_cve_table(all_matches, complete=all_matches.complete)
    if not all_matches.complete:
        rprint(f"[yellow]Incomplete analysis: {len(all_matches.failed_queries)} service query/queries failed.[/yellow]")

    if all_matches:
        critical_count = sum(1 for m in all_matches if m["severity"] in ("CRITICAL", "HIGH"))
        send_alert(
            title="CVE-Watcher Alert",
            local_msg=f"{len(all_matches)} CVE matches ({critical_count} critical/high) on {network}; "
                      f"{'complete' if all_matches.complete else 'incomplete'} analysis",
            telegram_msg=_build_telegram_report(all_matches, network),
        )

    if show_history:
        rprint("\n[bold cyan]--- Alert history ---[/bold cyan]")
        display_alerts_history(get_cve_alerts(network=network))

    return all_matches


if __name__ == "__main__":
    run_cve_watcher()
