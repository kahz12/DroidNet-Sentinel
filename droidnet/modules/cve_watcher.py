"""
CVE Watcher — matches the software found by the last scan against NVD.

Flow:
    1. Load the newest scan in the history DB that detected services.
    2. Turn each nmap banner into one query per (product, version).
    3. Ask the NIST NVD API for that version's CVEs: a cpeName query (NVD's
       own version match, for products in the CPE map) plus a description
       search, which also reaches CVEs NVD has not analysed yet. By default
       only CVEs published in the last 120 days count; a full audit drops
       the publication-date filter.
    4. Score each match and write a short impact summary for it.
    5. Store the alerts and announce only the new or changed ones, over
       Telegram and a local notification.

Requires:
    Internet access to the NVD API. No key is needed, but keyless clients
    are limited to 5 requests per 30 seconds; NVD_API_KEY raises that to 50.
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
    mark_cve_alerts_notified,
    get_cve_alerts,
)
from droidnet.core.logger import get_logger
from droidnet.core.markup import esc
from droidnet.core.notifier import send_alert, escape_html
from droidnet.core.risk import is_port_line

log = get_logger(__name__)

console = Console()

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_API_KEY = os.environ.get("NVD_API_KEY", "")

# Minimum spacing between real NVD requests. The public API allows 5
# requests per 30 s without a key and 50 with one. Enforced only in
# _throttle(), right before each HTTP request, so results served from the
# local cache never wait.
_REQUEST_DELAY = 6.5 if not NVD_API_KEY else 1.0
_last_request_at: float | None = None   # time.monotonic() of the last real request

# Attempts per request for transient failures, with exponential backoff from
# 1 s capped at 30 s (or NVD's Retry-After). Transient means: rate limiting
# (429, and the 403 NVD answers keyless clients over quota), server errors,
# timeouts and dropped connections.
_BACKOFF_MAX_RETRIES = 5
_BACKOFF_BASE        = 1.0
_BACKOFF_CAP         = 30.0
_RETRY_STATUSES      = {403, 429, 500, 502, 503, 504}

# Local NVD response cache: JSON file per (query, UTC day).
# Implicit 24h TTL: the key includes YYYYMMDD, so a file written on an
# earlier day never matches today's key and is not reused.
_CACHE_TTL_SECONDS = 24 * 3600
_CACHE_SCHEMA      = 3  # bump whenever the shape of a parsed CVE changes


# ══════════════════════════════════════════════════════════════════
#  CPE mapping (heuristic vendor:product → cpeName)
# ══════════════════════════════════════════════════════════════════

# Static map for the most common services appearing in nmap banners.
# Key = normalized product string (lowercase). Value = "vendor:product" in
# CPE 2.3 format, or a tuple of them when NVD files the product's CVEs under
# more than one vendor name; every CPE is queried and the results merged.
# Products not listed here are matched only through the description search.
_PRODUCT_TO_CPE: dict[str, str | tuple[str, ...]] = {
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
    # libupnp, common in routers' UPnP services. NVD splits its CVEs across
    # the old and the current project name with no overlap (1.6.19: three
    # under libupnp_project, seven more under pupnp_project).
    "portable sdk for upnp devices": ("libupnp_project:libupnp", "pupnp_project:pupnp"),
    "portable sdk for upnp":         ("libupnp_project:libupnp", "pupnp_project:pupnp"),
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


def _lookup_vendor_products(product: str) -> tuple[str, ...]:
    """Map an nmap product string to its "vendor:product" names; () if unknown."""
    key = " ".join(product.lower().split())
    found = _PRODUCT_TO_CPE.get(key)
    if found is None:
        for suffix in _NMAP_ROLE_SUFFIXES:
            if key.endswith(" " + suffix):
                found = _PRODUCT_TO_CPE.get(key[: -len(suffix) - 1])
                break
    if found is None:
        return ()
    return (found,) if isinstance(found, str) else found


def build_cpe_names(product: str, version: str) -> list[str]:
    """
    Build every cpeName 2.3 for (product, version) from the static map.
    Returns [] if the product is unknown or the version is missing.

    NVD requires the exact version for cpeName; without it, the endpoint
    rejects the query, so we only emit CPEs when we have both.
    """
    if not version:
        return []

    names = []
    for vendor_product in _lookup_vendor_products(product):
        cpe_version, update = version, "*"
        if vendor_product in _UPDATE_SUFFIX_PRODUCTS:
            split = _VERSION_UPDATE_RE.fullmatch(version)
            if split:
                cpe_version, update = split.group(1), split.group(2).lower()
        names.append(f"cpe:2.3:a:{vendor_product}:{cpe_version}:{update}:*:*:*:*:*:*")
    return names


def build_cpe_name(product: str, version: str) -> str | None:
    """The first CPE of build_cpe_names(), or None; for single-CPE callers."""
    names = build_cpe_names(product, version)
    return names[0] if names else None


# ══════════════════════════════════════════════════════════════════
#  Description-based candidates
# ══════════════════════════════════════════════════════════════════
# keywordSearch returns every CVE whose description mentions a word, and most
# of those are about other software: on real NVD data (120-day window)
# "nginx" gave 112 hits and "PostgreSQL" 162, none about the product itself
# ("Nginx UI", "PostgreSQL Anonymizer", plugins "served by nginx"). A CVE
# counts only when its description names the product immediately followed
# by affected versions — "OpenSSH through 10.6", "Redis before 8.8.0",
# "Apache Tomcat: from 9.0.0.M1 through 9.0.119" — and the detected version
# falls inside one of them.

# Products whose CVE descriptions use another name than nmap's banner.
_DESCRIPTION_NAMES = {"apache:http_server": "Apache HTTP Server"}

_V = r"(?:versions?\s+)?v?(\d+(?:\.\d+)*)[\w.+-]*"   # group 1: numeric part
# (clause, has lower bound, upper bound inclusive)
_RANGE_CLAUSES = (
    (re.compile(rf"from\s+{_V}\s+(?:before|until)\s+{_V}", re.I), True, False),
    (re.compile(rf"(?:from\s+)?{_V}\s+(?:through|to)\s+{_V}", re.I), True, True),
    (re.compile(rf"(?:before|prior\s+to|<)\s*{_V}", re.I), False, False),
    (re.compile(rf"(?:through|up\s+to(?:\s+and\s+including)?|<=)\s*{_V}", re.I), False, True),
    (re.compile(rf"{_V}\s+and\s+(?:earlier|prior|below|older)", re.I), False, True),
)
_RANGE_LEAD = re.compile(r"[\s:,]*")
_RANGE_SEP  = re.compile(r"\s*(?:,|;|\band\b|\bor\b)?\s*", re.I)


def _description_name(product: str) -> str:
    """How CVE descriptions name *product*: nmap's string minus a role word."""
    for vendor_product in _lookup_vendor_products(product):
        if vendor_product in _DESCRIPTION_NAMES:
            return _DESCRIPTION_NAMES[vendor_product]
    name = " ".join(product.split())
    for suffix in _NMAP_ROLE_SUFFIXES:
        if name.lower().endswith(" " + suffix):
            return name[: -len(suffix) - 1]
    return name


def _version_key(version) -> tuple[int, ...] | None:
    """Numeric part of a version for comparison: "9.6p1" → (9, 6), "2.4.0" → (2, 4)."""
    m = re.match(r"\s*v?(\d+(?:\.\d+)*)", str(version or ""))
    if not m:
        return None
    parts = [int(p) for p in m.group(1).split(".")]
    while len(parts) > 1 and parts[-1] == 0:   # 2.4.0 == 2.4
        parts.pop()
    return tuple(parts)


def _match_range_clause(text: str, pos: int):
    """The first _RANGE_CLAUSES entry matching at *pos*: (match, has_lower, inclusive) or None."""
    for clause_re, has_lower, inclusive in _RANGE_CLAUSES:
        clause = clause_re.match(text, pos)
        if clause:
            return clause, has_lower, inclusive
    return None


def _described_ranges(description: str, name_re: re.Pattern) -> list[tuple]:
    """(low, high, high_inclusive) ranges stated right after the product name.

    After each mention of the product, clauses are read one after another
    ("from 9.0.0.M1 through 9.0.119, from 10.1.0-M1 through 10.1.56") until
    the text stops describing versions.
    """
    text = " ".join(description.split())   # also folds \n and \xa0
    ranges = []
    for m in name_re.finditer(text):
        pos = _RANGE_LEAD.match(text, m.end()).end()
        while (found := _match_range_clause(text, pos)) is not None:
            clause, has_lower, inclusive = found
            bounds = [_version_key(v) for v in clause.groups()]
            low, high = bounds if has_lower else (None, bounds[0])
            ranges.append((low, high, inclusive))
            pos = _RANGE_SEP.match(text, clause.end()).end()
    return ranges


def _version_in_ranges(version: str, ranges: list[tuple]) -> bool:
    key = _version_key(version)
    if key is None:
        # Without a version no range can be checked. Keeping the CVE would
        # turn a version-less service into its product's whole history
        # (live NVD, full audit: 55 for Samba, 32 for Dovecot).
        return False
    return any((low is None or key >= low) and (key < high or (inclusive and key == high))
               for low, high, inclusive in ranges)


def _keyword_candidates(cves: list[dict], name: str, version: str,
                        cpe_checked: bool, exclude: set[str]) -> list[dict]:
    """CVEs from a description search that are about *name* and affect *version*.

    cpe_checked: the service also had a cpeName query. NVD already matched
    its analysed CVEs against CPEs, so only unanalysed ones can add anything.
    exclude: CVE IDs that query already confirmed.
    """
    name_re = re.compile(r"(?<![\w-])" + r"\s+".join(map(re.escape, name.split()))
                         + r"(?![\w-])", re.I)
    found = []
    for cve in cves:
        if cve.get("cve_id") in exclude or (cpe_checked and cve.get("analysed")):
            continue
        ranges = _described_ranges(cve.get("description") or "", name_re)
        if ranges and _version_in_ranges(version, ranges):
            found.append(cve)
    return found


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
        # Older caches may contain only the first page (schema 1) or lack the
        # analysed / attack_vector fields (schema 2); never reuse them.
        if (isinstance(cached, dict) and cached.get("schema") == _CACHE_SCHEMA
                and isinstance(cached.get("results"), list)):
            return cached["results"]
        return None
    except (json.JSONDecodeError, OSError):
        return None


def _cache_store(query_id: str, results: list[dict]) -> None:
    """Persists *results* for *query_id* (best-effort, ignores I/O errors)."""
    try:
        NVD_CACHE_DIR.mkdir(parents=True, exist_ok=True)
        with _cache_path(query_id).open("w") as fh:
            json.dump({"schema": _CACHE_SCHEMA, "results": results}, fh)
    except OSError:
        pass


# ══════════════════════════════════════════════════════════════════
#  Service banner parsing
# ══════════════════════════════════════════════════════════════════

# nmap prints a version it could only narrow down as a wildcard range
# ("Samba smbd 3.X - 4.X"). That is no version at all, and left in place it
# would become part of the product name.
_WILDCARD_VERSION = re.compile(r"\s*\b\d+\.[xX](?:\s*-\s*\d+\.[xX])?\s*$")

# MariaDB 10+ answers MySQL clients as "5.5.5-<real version>" so that old
# clients accept it, and nmap passes the prefix through: "MariaDB 5.5.5-10.3.34"
# today, "MySQL 5.5.5-10.3.34-MariaDB-..." from older nmap releases.
_MARIADB_COMPAT = re.compile(r"\b5\.5\.5-(\d+\.\d+[\w.]*)")


def parse_service_info(port_entry: str) -> dict | None:
    """
    Extract structured service info from an nmap port line.

    Input:  "80/tcp   open  http    Apache httpd 2.4.29 ((Ubuntu))"
    Output: {"port": "80/tcp", "proto": "http", "product": "Apache httpd",
             "version": "2.4.29", "raw": "Apache httpd 2.4.29"}

    version is "" when nmap did not determine one. Returns None for markers
    ("Shield intact", "Error: ...") and port lines without a banner.
    """
    if not is_port_line(port_entry):
        return None

    parts = port_entry.split()
    if len(parts) < 4:
        return None

    port_id = parts[0]       # 80/tcp
    proto = parts[2]         # http
    remainder = " ".join(parts[3:])

    # nmap's extra info sits in parentheses: "((Ubuntu))", "(workgroup: X)".
    remainder = re.sub(r"\(.*?\)", "", remainder).strip()
    remainder = _WILDCARD_VERSION.sub("", remainder)

    # The product is what precedes the first dotted number.
    version_match = re.search(r"(\d+\.\d[\w.]*)", remainder)
    if version_match:
        version = version_match.group(1)
        product = remainder[:version_match.start()].strip()
    else:
        version = ""
        product = remainder

    mariadb = _MARIADB_COMPAT.search(remainder) if "mariadb" in remainder.lower() else None
    if mariadb:
        product, version = "MariaDB", mariadb.group(1)

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

    Returns list of dicts with keys: keyword (product and version as one
    string), product, version ("" when unknown), port, ips (list).
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

def _throttle() -> None:
    """Wait until _REQUEST_DELAY has passed since the previous real NVD request.

    Time already spent elsewhere (parsing, rendering, a backoff sleep) counts
    towards the delay, so only the remainder is slept.
    """
    global _last_request_at
    if _last_request_at is not None:
        remaining = _REQUEST_DELAY - (time.monotonic() - _last_request_at)
        if remaining > 0:
            time.sleep(remaining)
    _last_request_at = time.monotonic()


def _nvd_get(params: dict, query_label: str) -> dict | None:
    """
    GET one NVD page, retrying transient failures with exponential backoff.

    Retried: _RETRY_STATUSES, timeouts and connection errors, honouring
    Retry-After when NVD sends it. Any other status (404, a malformed
    request) fails at once: the same request would get the same answer.
    There is no sleep after the final attempt. Every attempt passes through
    _throttle(), the only place that spaces requests for NVD's rate limit.

    Returns the parsed JSON, or None when the request fails or attempts run out.
    """
    headers = {"apiKey": NVD_API_KEY} if NVD_API_KEY else {}
    reason = ""

    for attempt in range(1, _BACKOFF_MAX_RETRIES + 1):
        _throttle()
        retry_after = None
        try:
            resp = requests.get(NVD_API_URL, params=params, headers=headers, timeout=30)
        except (requests.Timeout, requests.ConnectionError) as exc:
            reason = f"network error: {exc}"
        except requests.RequestException as exc:
            rprint(f"[red]  [✗] NVD request error ({esc(query_label)}): {esc(exc)}[/red]")
            return None
        else:
            if resp.status_code == 200:
                try:
                    return resp.json()
                except ValueError as exc:
                    rprint(f"[red]  [✗] NVD returned invalid JSON ({esc(query_label)}): {esc(exc)}[/red]")
                    return None
            if resp.status_code not in _RETRY_STATUSES:
                rprint(f"[dim]  [-] NVD responded {resp.status_code} for '{esc(query_label)}'[/dim]")
                return None
            reason = f"HTTP {resp.status_code}"
            retry_after = resp.headers.get("Retry-After")

        if attempt == _BACKOFF_MAX_RETRIES:
            break
        if retry_after and retry_after.isdigit():
            delay = min(float(retry_after), _BACKOFF_CAP)
        else:
            delay = min(_BACKOFF_BASE * (2 ** (attempt - 1)), _BACKOFF_CAP)
        rprint(
            f"[yellow]  [-] NVD {esc(reason)} ({esc(query_label)}); retrying in "
            f"{delay:.1f}s (attempt {attempt}/{_BACKOFF_MAX_RETRIES})[/yellow]"
        )
        log.warning("nvd retry reason=%s query=%s delay=%.1fs attempt=%d",
                    reason, query_label, delay, attempt)
        time.sleep(delay)

    rprint(f"[red]  [✗] NVD: retries exhausted for '{esc(query_label)}' ({esc(reason)})[/red]")
    log.warning("nvd retries exhausted query=%s last=%s", query_label, reason)
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
            "attack_vector": _extract_attack_vector(cve),
            "published":   cve.get("published", ""),
            "cwes":        _extract_cwes(cve),
            # Present in the NVD record only when CISA lists the CVE as a Known
            # Exploited Vulnerability (actively exploited in the wild).
            "kev":         bool(cve.get("cisaExploitAdd")),
            # NVD has matched the CVE against CPEs (it has configurations).
            # Unanalysed CVEs are invisible to cpeName searches.
            "analysed":    bool(cve.get("configurations")),
        })
    return results


def _check_days_back(days_back) -> None:
    """Accept None (any publication date) or an int in 1..120.

    NVD rejects publication-date ranges longer than 120 days, so a wider
    window is expressed by omitting the dates altogether (None).
    """
    if days_back is None:
        return
    if isinstance(days_back, bool) or not isinstance(days_back, int) or not 1 <= days_back <= 120:
        raise ValueError("days_back must be None or an integer between 1 and 120")


def query_nvd(
    keyword: str,
    days_back: int | None = 120,
    cpe_name: str | None = None,
) -> list[dict] | None:
    """
    Query NIST NVD for CVEs published in the last *days_back* days, or of
    any publication date when *days_back* is None (full audit).

    With *cpe_name* the `cpeName` parameter is used: NVD's own match of the
    exact version against each CVE's configurations. Otherwise a
    `keywordSearch` over CVE descriptions runs, whose hits the caller must
    filter (see _keyword_candidates).

    Results are cached to disk by (query, window, UTC day) for 24h, so a
    windowed result is never served as a full-audit one or vice versa.
    Returns None on failed/incomplete queries; [] means a completed search
    with no matches. Only complete result sets are cached.
    """
    _check_days_back(days_back)
    window: dict[str, str] = {}
    if days_back is not None:
        now_utc = datetime.now(timezone.utc).replace(microsecond=0)
        window = {
            "pubStartDate": (now_utc - timedelta(days=days_back)).isoformat(timespec="milliseconds"),
            "pubEndDate":   now_utc.isoformat(timespec="milliseconds"),
        }
    window_tag = "all" if days_back is None else days_back

    if cpe_name:
        params = {"cpeName": cpe_name, "isVulnerable": "", **window, "resultsPerPage": 2000}
        cache_key   = f"cpe:{cpe_name}:{window_tag}"
        query_label = cpe_name
    else:
        params = {"keywordSearch": keyword, **window, "resultsPerPage": 2000}
        cache_key   = f"kw:{keyword.lower()}:{window_tag}"
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
    _cache_store(cache_key, results)
    return results


# Metric blocks in order of preference. CVSS 3.x comes first: almost every
# analysed CVE carries it, so alerts scored with it stay comparable with one
# another. CVSS 4.0 is used when it is the only score, which is common on
# fresh CVEs whose CNA supplies nothing else (~10% of new CVEs). v2 is the
# last resort, for old CVEs scored before 3.0 existed.
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


def _best_metric(cve: dict) -> tuple[float, str, dict, bool] | None:
    """The preferred usable CVSS metric: (score, severity, cvssData, legacy_v2).

    Malformed blocks are skipped rather than raising, so one bad record
    cannot abort the whole run.
    """
    metrics = cve.get("metrics")
    if not isinstance(metrics, dict):
        return None

    for key in _CVSS_METRIC_KEYS:
        entries = metrics.get(key)
        if not isinstance(entries, list):
            continue
        # NVD's own analysis ("Primary") beats a CNA's ("Secondary");
        # sorted() is stable, so the original order breaks ties.
        entries = sorted(entries, key=lambda e: not (isinstance(e, dict) and e.get("type") == "Primary"))
        legacy_v2 = key == "cvssMetricV2"
        for entry in entries:
            score, severity = _metric_score(entry, legacy_v2=legacy_v2)
            if score is not None:
                return score, severity, entry["cvssData"], legacy_v2

    return None


def _extract_cvss(cve: dict) -> tuple[float | None, str]:
    """Extract the best available CVSS score and severity from a CVE entry."""
    best = _best_metric(cve)
    return (best[0], best[1]) if best else (None, "UNKNOWN")


def _extract_attack_vector(cve: dict) -> str | None:
    """Attack vector of the scoring metric: NETWORK, ADJACENT[_NETWORK], LOCAL..."""
    best = _best_metric(cve)
    if not best:
        return None
    vector = best[2].get("accessVector" if best[3] else "attackVector")  # v2 name differs
    return vector.upper() if isinstance(vector, str) else None


# ══════════════════════════════════════════════════════════════════
#  Impact analysis (heuristic summary)
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


# Description cues for the impact summary, matched as whole words or
# phrases. Plain substring checks read "rce" in "resource", "hang" in
# "change", "root" in "chroot" and "sensitive" in "case-sensitive".
_ATTACK_HINTS = (
    ("allows code execution", re.compile(
        r"\bcode execution\b|\brce\b|\bcommand injection\b|\barbitrary (?:code|commands?)\b", re.I)),
    ("can cause denial of service", re.compile(
        r"\bdenial[- ]of[- ]service\b|\bdos\b|\bcrash(?:es|ed|ing)?\b|\bhang(?:s|ing)?\b"
        r"|\bresource exhaustion\b|\buncontrolled resource consumption\b", re.I)),
    ("privilege escalation", re.compile(
        r"\bprivilege escalation\b|\bescalat(?:e|es|ed|ing|ion)\b|\belevation of privileges?\b"
        # The verb only: "elevated privileges" alone is context ("the server
        # runs with elevated privileges"), not an escalation.
        r"|\belevat(?:e|es|ing) (?:\w+ ){0,2}privileges?\b"
        r"|\bexecut\w* (?:\w+ ){0,3}with (?:elevated|higher|root|system|administrator) privileges\b"
        r"|\bgain(?:s|ed|ing)? (?:\w+ )?privileges?\b|\b(?:as|to|gain|obtain) root\b"
        r"|\broot (?:privileges?|access|shell)\b", re.I)),
    ("information leak", re.compile(
        r"\binformation disclosure\b|\bleak(?:s|ed|ing|age)?\b|\bexfiltrat\w*"
        r"|\bsensitive (?:information|data)\b", re.I)),
    ("authentication bypass", re.compile(
        r"\b(?:authentication|auth) bypass\b|\bbypass(?:es|ing)? (?:the )?authentication\b", re.I)),
)
# Only used without a CVSS attack vector; "network" alone is not a cue
# ("X is a network traffic analysis tool").
_REMOTE_HINT = re.compile(r"\bremote(?:ly)?\b", re.I)


def generate_impact_summary(cve: dict, service_info: dict, affected_ips: list[str]) -> str:
    """
    One-line impact summary for an alert, with " | " between its parts.

    It names the affected service and how many hosts run it (flagging a
    candidate match whose versions come from the description), whether CISA
    lists the CVE as exploited in the wild, how it can be attacked (remote
    per the CVSS attack vector, plus whole-word cues from the description),
    its CWE weaknesses, and a recommendation scaled to KEV status, severity
    and score.
    """
    desc = cve["description"]
    severity = cve["severity"]
    score = cve["score"]
    product = service_info["product"]
    version = service_info.get("version", "")
    ip_count = len(affected_ips)

    # Remote exploitability: the CVSS attack vector is authoritative; the
    # description is only a fallback when NVD has no CVSS metric.
    vector = cve.get("attack_vector")
    remote = vector == "NETWORK" if vector else bool(_REMOTE_HINT.search(desc))
    attack_hints = ["remotely exploitable"] if remote else []
    attack_hints += [hint for hint, cue in _ATTACK_HINTS if cue.search(desc)]

    lines = []
    candidate = service_info.get("match_type") == "candidate"
    if candidate:
        lines.append(f"Candidate match: {product} {version} on {ip_count} host(s); affected "
                     f"versions taken from the CVE description, not yet confirmed by NVD")
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
    """Show the CVE alerts stored in the database by earlier runs."""
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
    """Build an HTML-mode Telegram message for new or changed CVE alerts.

    Every external value goes through escape_html(); see notifier for why
    Telegram's legacy Markdown mode cannot carry them safely.
    """
    lines = [
        "\U0001f6a8 <b>CVE-Watcher Alert</b>\n",
        f"\U0001f4e1 <b>Network:</b> <code>{escape_html(network)}</code>",
        f"\u26a0\ufe0f <b>New or changed CVE matches:</b> {len(matches)}\n",
    ]

    for m in matches[:5]:
        emoji = _SEVERITY_EMOJI.get(m["severity"], "\u26aa")
        score_str = f"{m['score']:.1f}" if m["score"] else "?"
        kind = "candidate" if m.get("match_type") == "candidate" else "CPE match"
        lines.append(
            f"{emoji} <code>{escape_html(m['cve_id'])}</code> — "
            f"<b>{escape_html(m['severity'])}</b> ({score_str}) ({kind})\n"
            f"   {escape_html(m['service'])}\u2192 {escape_html(', '.join(m['ips'][:3]))}\n"
            # Truncate before escaping: the reverse could cut "&amp;" in half.
            f"   <i>{escape_html(m['impact'][:100])}</i>\n"
        )

    if len(matches) > 5:
        lines.append(f"\n<i>... and {len(matches) - 5} more. Check the Command Center.</i>")

    return "\n".join(lines)


# ══════════════════════════════════════════════════════════════════
#  Main entry point
# ══════════════════════════════════════════════════════════════════

class CVEWatchResult(list):
    """List-compatible matches with explicit query completion status.

    failed_queries: services whose NVD query failed (analysis incomplete).
    unversioned:    services nmap reported without a version; they cannot be
                    matched against any affected range, so they are listed
                    as not checked rather than queried.
    """

    def __init__(self):
        super().__init__()
        self.failed_queries: list[str] = []
        self.unversioned: list[str] = []

    @property
    def complete(self) -> bool:
        return not self.failed_queries


def run_cve_watcher(days_back: int | None = 120, show_history: bool = False) -> CVEWatchResult:
    """
    Main CVE-Watcher flow.

    1. Load the latest scan with service banners from the DB.
    2. Turn banners into one query per (product, version).
    3. Per service: every mapped CPE (NVD's version match) plus a description
       search for CVEs NVD has not analysed yet.
    4. Score the matches and write an impact summary for each.
    5. Persist them and announce only the new or changed ones.

    Args:
        days_back    : Publication window in days (1–120) to watch for new
                       disclosures, or None for a full audit of the detected
                       versions against CVEs of any date.
        show_history : If True, also display stored CVE alerts.

    Returns:
        CVEWatchResult: the matches (a list of dicts) plus failed_queries /
        complete, so an empty result can be told apart from a failed one.
    """
    _check_days_back(days_back)
    init_db()
    all_matches = CVEWatchResult()

    window = ("CVEs of any publication date (full audit)" if days_back is None
              else f"CVEs from the last {days_back} days")
    rprint(
        Panel(
            "[bold red]CVE-Watcher[/bold red] — Vulnerability monitoring",
            subtitle=f"[dim]Searching {window}[/dim]",
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
        rprint("[yellow][-] No services with an identifiable product found.[/yellow]")
        if show_history:
            rprint("\n[bold cyan]--- Alert history ---[/bold cyan]")
            display_alerts_history(get_cve_alerts(network=network))
        return all_matches

    rprint(f"[*] {len(keywords)} unique service(s) detected:\n")
    for kw in keywords:
        rprint(f"    [cyan]\u2022[/cyan] {esc(kw['keyword'])} ({esc(kw['port'])}) — "
               f"{esc(', '.join(kw['ips']))}")
    rprint()

    # Per service: a CPE query confirms CVEs NVD has analysed for this exact
    # version; a description search adds those NVD has not analysed yet
    # (invisible to CPE search), kept only when their text names the product
    # with a version range that covers the detected version.
    for kw in keywords:
        if not kw["version"]:
            all_matches.unversioned.append(kw["keyword"])
            continue
        cpe_names = build_cpe_names(kw["product"], kw["version"])
        confirmed: list[dict] = []
        cpe_failed = False
        for cpe_name in cpe_names:
            rprint(f"[bold cyan][\u2026][/bold cyan] Querying NVD (CPE): [yellow]{esc(cpe_name)}[/yellow]")
            found = query_nvd(kw["keyword"], days_back=days_back, cpe_name=cpe_name)
            if found is None:
                cpe_failed = True
                break
            # A product filed under several vendor names can share CVEs
            # between them; keep each CVE once.
            known = {c["cve_id"] for c in confirmed}
            confirmed += [c for c in found if c["cve_id"] not in known]
        if cpe_failed:
            # No broader search either: an HTTP error says nothing about the
            # product, so the service is reported as not analysed rather than
            # with a partial set of its CVEs.
            all_matches.failed_queries.append(kw["keyword"])
            continue

        name = _description_name(kw["product"])
        rprint(f"[bold cyan][\u2026][/bold cyan] Searching NVD descriptions: [yellow]{esc(name)}[/yellow]")
        described = query_nvd(name, days_back=days_back)
        if described is None:
            # The service is reported as incompletely analysed, but the CPE
            # matches found above are real and are kept.
            all_matches.failed_queries.append(kw["keyword"])
            described = []
        candidates = _keyword_candidates(
            described, name, kw["version"], cpe_checked=bool(cpe_names),
            exclude={c["cve_id"] for c in confirmed},
        )

        for cve, match_type in [(c, "cpe") for c in confirmed] + [(c, "candidate") for c in candidates]:
            impact = generate_impact_summary(cve, {**kw, "match_type": match_type}, kw["ips"])

            match = {
                "cve_id":   cve["cve_id"],
                "severity": cve["severity"],
                "score":    cve["score"],
                "service":  kw["keyword"],
                "ips":      kw["ips"],
                "impact":   impact,
                "description": cve["description"],
                "match_type": match_type,
                "notify":   False,
            }
            all_matches.append(match)

            # Persist (or refresh) each alert; only new or changed ones are
            # announced, instead of re-sending every match on every run.
            for ip in kw["ips"]:
                if save_cve_alert(
                    cve_id=cve["cve_id"],
                    severity=cve["severity"],
                    score=cve["score"],
                    service=kw["keyword"],
                    ip=ip,
                    summary=cve["description"][:500],
                    impact=impact,
                    network=network,
                    scan_id=scan_id,
                    match_type=match_type,
                ):
                    match["notify"] = True

    # Present the most urgent matches first.
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4}
    all_matches.sort(key=lambda m: (severity_order.get(m["severity"], 5), -(m["score"] or 0)))

    # Render the result and notify configured channels.
    display_cve_table(all_matches, complete=all_matches.complete)
    if not all_matches.complete:
        rprint(f"[yellow]Incomplete analysis: {len(all_matches.failed_queries)} service query/queries failed.[/yellow]")
    if all_matches.unversioned:
        # Said explicitly so a "no matches" result is not read as clean for them.
        rprint(f"[yellow][-] Not checked, version not detected: "
               f"{esc(', '.join(all_matches.unversioned))}[/yellow]")

    to_notify = [m for m in all_matches if m["notify"]]
    if to_notify:
        critical_count = sum(1 for m in to_notify if m["severity"] in ("CRITICAL", "HIGH"))
        delivered = send_alert(
            title="CVE-Watcher Alert",
            local_msg=f"{len(to_notify)} new or changed CVE matches ({critical_count} critical/high) "
                      f"on {network}; {'complete' if all_matches.complete else 'incomplete'} analysis",
            telegram_msg=_build_telegram_report(to_notify, network),
        )
        # False: Telegram failed — keep the alerts pending so the next run
        # retries them. None: Telegram is not configured, so the local
        # notification was the announcement.
        if delivered is False:
            rprint("[yellow][-] Telegram delivery failed; these alerts will be "
                   "re-sent on the next run.[/yellow]")
        else:
            mark_cve_alerts_notified(
                (m["cve_id"], ip, m["service"], network) for m in to_notify for ip in m["ips"]
            )
    elif all_matches:
        rprint(f"[dim][-] No new or changed CVE alerts since the last notification "
               f"({len(all_matches)} already reported).[/dim]")

    if show_history:
        rprint("\n[bold cyan]--- Alert history ---[/bold cyan]")
        display_alerts_history(get_cve_alerts(network=network))

    return all_matches


if __name__ == "__main__":
    run_cve_watcher()
