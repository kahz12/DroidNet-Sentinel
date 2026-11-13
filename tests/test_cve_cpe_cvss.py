"""CPE names and CVSS extraction, checked against real NVD / nmap data.

Fixtures mirror what the live services return:
* nmap product strings come from nmap-service-probes ("PostgreSQL DB",
  "Microsoft IIS httpd", "Redis key-value store", ...).
* CPE names come from the NVD CPE dictionary: OpenSSH portable releases are
  version "9.6" + update "p1"; ProFTPD "1.3.5" + update "a"; MySQL is
  filed under oracle:mysql.
* CVSS blocks follow the NVD 2.0 schema: v3.x / v4.0 keep baseSeverity
  inside cvssData, v2 keeps it beside cvssData.
"""
import pytest

from droidnet.modules.cve_watcher import _parse_nvd_payload, build_cpe_name


def cpe(vendor_product: str, version: str, update: str = "*") -> str:
    return f"cpe:2.3:a:{vendor_product}:{version}:{update}:*:*:*:*:*:*"


# ── version / update split and MySQL vendor ─────────────────────────

@pytest.mark.parametrize("product, version, expected", [
    # The release suffix goes in the update field, as in the dictionary.
    ("OpenSSH", "8.2p1",    cpe("openbsd:openssh", "8.2", "p1")),
    ("OpenSSH", "9.6",      cpe("openbsd:openssh", "9.6")),
    ("ProFTPD", "1.3.5e",   cpe("proftpd:proftpd", "1.3.5", "e")),
    ("ProFTPD", "1.3.6rc4", cpe("proftpd:proftpd", "1.3.6", "rc4")),
    # Oracle owns MySQL; mysql:mysql has no recent dictionary entries.
    ("MySQL",   "8.0.36",   cpe("oracle:mysql", "8.0.36")),
    # A plain version has no release suffix, so the update field stays "*".
    ("Apache httpd", "2.4.29", cpe("apache:http_server", "2.4.29")),
    ("nginx",        "1.18.0", cpe("nginx:nginx", "1.18.0")),
    ("MariaDB",      "10.3.34", cpe("mariadb:mariadb", "10.3.34")),
])
def test_cpe_version_and_vendor(product, version, expected):
    assert build_cpe_name(product, version) == expected


# ── real nmap product strings reach the map ─────────────────────────

@pytest.mark.parametrize("product, vendor_product", [
    ("PostgreSQL DB",          "postgresql:postgresql"),
    ("Microsoft IIS httpd",    "microsoft:internet_information_services"),
    ("Microsoft IIS ftpd",     "microsoft:internet_information_services"),
    ("Postfix smtpd",          "postfix:postfix"),
    ("Exim smtpd",             "exim:exim"),
    ("Dovecot imapd",          "dovecot:dovecot"),
    ("Dovecot pop3d",          "dovecot:dovecot"),
    ("Redis key-value store",  "redis:redis"),
    ("Elasticsearch REST API", "elastic:elasticsearch"),
    ("Samba smbd",             "samba:samba"),
    ("ISC BIND",               "isc:bind"),
])
def test_nmap_product_strings_map_to_cpe(product, vendor_product):
    assert build_cpe_name(product, "1.2.3") == cpe(vendor_product, "1.2.3")


@pytest.mark.parametrize("product", [
    # Different products that share a vendor word: they must never borrow
    # another product's CPE (that would be a confident false match).
    "Apache Tomcat",
    "Apache Tomcat httpd",
    "Apache ActiveMQ",
    "Apache Stronghold httpd",
    "Elasticsearch Kibana",
    "Dovecot Pigeonhole sieve",
    "Postfix Greylist Daemon",
    "MySQL cluster management server",
    "Dropbear sshd",
])
def test_other_products_are_not_mapped(product):
    assert build_cpe_name(product, "1.2.3") is None


def test_missing_version_has_no_cpe():
    assert build_cpe_name("OpenSSH", "") is None


# ── CVSS extraction ─────────────────────────────────────────────────

def parse_metrics(metrics) -> tuple:
    out = _parse_nvd_payload({"vulnerabilities": [
        {"cve": {"id": "CVE-2026-0001", "descriptions": [], "metrics": metrics}}]})
    return out[0]["score"], out[0]["severity"]


def v3(score, severity=None, kind="Primary", version="3.1"):
    data = {"version": version, "baseScore": score}
    if severity:
        data["baseSeverity"] = severity
    return {"source": "nvd@nist.gov", "type": kind, "cvssData": data}


def v4(score, severity, kind="Secondary"):
    return {"source": "cna@example", "type": kind,
            "cvssData": {"version": "4.0", "baseScore": score, "baseSeverity": severity}}


def v2(score, severity=None):
    entry = {"source": "nvd@nist.gov", "type": "Primary",
             "cvssData": {"version": "2.0", "baseScore": score}}
    if severity:
        entry["baseSeverity"] = severity  # v2: beside cvssData, not inside
    return entry


def test_cvss_v4_only_is_scored():
    # ~10% of new CVEs carry only a CNA-supplied CVSS 4.0 score.
    assert parse_metrics({"cvssMetricV40": [v4(9.3, "CRITICAL")],
                          "ssvcV203": [{}]}) == (9.3, "CRITICAL")


def test_cvss_v2_severity_read_beside_cvss_data():
    # Shape of CVE-2020-12062 as served by NVD.
    assert parse_metrics({"cvssMetricV2": [v2(5.0, "MEDIUM")]}) == (5.0, "MEDIUM")


def test_cvss_v3_still_preferred_over_v4():
    metrics = {"cvssMetricV31": [v3(7.5, "HIGH")], "cvssMetricV40": [v4(9.3, "CRITICAL")]}
    assert parse_metrics(metrics) == (7.5, "HIGH")


def test_cvss_v4_preferred_over_legacy_v2():
    metrics = {"cvssMetricV2": [v2(10.0, "HIGH")], "cvssMetricV40": [v4(6.8, "MEDIUM")]}
    assert parse_metrics(metrics) == (6.8, "MEDIUM")


def test_cvss_primary_entry_preferred_over_secondary():
    metrics = {"cvssMetricV31": [v3(5.0, "MEDIUM", kind="Secondary"), v3(9.8, "CRITICAL")]}
    assert parse_metrics(metrics) == (9.8, "CRITICAL")


@pytest.mark.parametrize("metrics, expected", [
    ({"cvssMetricV31": [v3(9.1)]}, (9.1, "CRITICAL")),
    ({"cvssMetricV31": [v3(0.0)]}, (0.0, "NONE")),
    # CVSS v2 has no CRITICAL band.
    ({"cvssMetricV2":  [v2(9.1)]}, (9.1, "HIGH")),
])
def test_cvss_missing_severity_derived_from_score(metrics, expected):
    assert parse_metrics(metrics) == expected


@pytest.mark.parametrize("metrics, expected", [
    ("not-a-dict",                                (None, "UNKNOWN")),
    ({"cvssMetricV31": {"not": "a list"}},        (None, "UNKNOWN")),
    ({"cvssMetricV31": [None]},                   (None, "UNKNOWN")),
    # Bad entries are skipped, the next usable block still counts.
    ({"cvssMetricV31": [None, "x", {"cvssData": None}, v3("9.8"), v3(True), v3(11.0)],
      "cvssMetricV40": [v4(6.1, "MEDIUM")]},      (6.1, "MEDIUM")),
])
def test_cvss_malformed_metrics_do_not_crash(metrics, expected):
    assert parse_metrics(metrics) == expected
