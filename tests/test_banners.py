"""Reading nmap port lines: markers by exact form, versions as nmap prints them.

deep_scan writes either port lines ("80/tcp open http nginx 1.18.0") or a
marker in their place ("Shield intact", "Error", "Error: <why>"). A port
line's banner is free text and can itself contain "Error" or "Shield"
("Apache httpd 2.4.29 (Error page)"), so markers are recognised only by
their exact form — never by searching for the word.

nmap versions need normalising before they can be matched:
* MariaDB 10+ answers MySQL clients as "5.5.5-<real version>"; current nmap
  prints "MariaDB 5.5.5-10.3.34", older releases "MySQL 5.5.5-10.3.34-MariaDB".
* When nmap can only narrow a version down it prints a wildcard range
  ("Samba smbd 3.X - 4.X"): that is no version, not part of the product name.

A service without a version cannot be checked against any affected range,
so CVE Watcher lists it as not checked instead of guessing: on live NVD data
a version-less Samba would otherwise get 55 "candidates" in a full audit
(Dovecot 32) while a current install is affected by none of them.
"""
import io
from unittest.mock import Mock

import pytest
from rich.console import Console

from droidnet.core import database as db
from droidnet.core.risk import classify_risk, is_port_line, is_scan_error
from droidnet.modules import cve_watcher as cve
from droidnet.modules import hunter, sentinel
from droidnet.modules.cve_watcher import build_cpe_names, parse_service_info

ERROR_PAGE = "80/tcp open http Apache httpd 2.4.29 (Error page)"
SAMBA = "445/tcp open netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)"
MARIADB = "3306/tcp open mysql MariaDB 5.5.5-10.3.34"
MARIADB_OLD_NMAP = "3306/tcp open mysql MySQL 5.5.5-10.3.34-MariaDB-0ubuntu0.20.04.1"


# ── markers ────────────────────────────────────────────────────────

@pytest.mark.parametrize("entry", ["Shield intact", "Error", "Error: timeout",
                                   "Error: inconclusive port states", "", None])
def test_markers_are_not_port_lines(entry):
    assert not is_port_line(entry)


@pytest.mark.parametrize("entry", [ERROR_PAGE, "443/tcp open https ShieldOS httpd 1.2",
                                   "53/udp open domain dnsmasq 2.85"])
def test_port_lines_are_recognised_whatever_their_banner_says(entry):
    assert is_port_line(entry) and not is_scan_error(entry)


@pytest.mark.parametrize("entry, expected", [
    ("Error", True), ("Error: timeout", True), ("Errors in config", False),
    (ERROR_PAGE, False), ("Shield intact", False),
])
def test_scan_error_markers(entry, expected):
    assert is_scan_error(entry) is expected


def test_error_page_banner_is_assessed_not_unknown():
    assert classify_risk([ERROR_PAGE]) == "MEDIUM"


# ── version normalisation ──────────────────────────────────────────

@pytest.mark.parametrize("line, product, version", [
    (MARIADB,                                   "MariaDB", "10.3.34"),
    (MARIADB_OLD_NMAP,                          "MariaDB", "10.3.34"),
    ("3306/tcp open mysql MariaDB 11.4.2",      "MariaDB", "11.4.2"),
    # Real MySQL keeps its name and version, including a genuine 5.5.5.
    ("3306/tcp open mysql MySQL 5.7.33-0ubuntu0.18.04.1", "MySQL", "5.7.33"),
    ("3306/tcp open mysql MySQL 5.5.5",         "MySQL",   "5.5.5"),
    (SAMBA,                                     "Samba smbd", ""),
    ("139/tcp open netbios-ssn Samba smbd 4.X", "Samba smbd", ""),
    (ERROR_PAGE,                                "Apache httpd", "2.4.29"),
])
def test_product_and_version(line, product, version):
    info = parse_service_info(line)
    assert (info["product"], info["version"]) == (product, version)
    assert info["raw"] == f"{product} {version}".strip()


def test_mariadb_is_queried_with_its_real_version():
    info = parse_service_info(MARIADB_OLD_NMAP)
    assert build_cpe_names(info["product"], info["version"]) == [
        "cpe:2.3:a:mariadb:mariadb:10.3.34:*:*:*:*:*:*:*"]


@pytest.mark.parametrize("entry", ["Shield intact", "Error: timeout", "80/tcp open http"])
def test_markers_and_bare_ports_are_not_parsed(entry):
    assert parse_service_info(entry) is None


# ── Hunter uses the same reading ───────────────────────────────────

@pytest.mark.parametrize("line, query", [
    (ERROR_PAGE,       "Apache httpd 2.4.29"),
    (MARIADB_OLD_NMAP, "MariaDB 10.3.34"),
    (SAMBA,            "Samba smbd"),
    ("Error: timeout", None),
])
def test_hunter_query(line, query):
    assert hunter.clean_service_name(line) == query


def test_hunter_does_not_skip_a_host_whose_banner_says_error(monkeypatch):
    db.save_scan("lab", "20261110_120000", {"192.0.2.5": [ERROR_PAGE],
                                            "192.0.2.6": ["Error: timeout"]})
    monkeypatch.setattr(hunter, "_searchsploit_path", lambda: "/usr/bin/searchsploit")
    monkeypatch.setattr(hunter, "rprint", Console(file=io.StringIO()).print)
    monkeypatch.setattr(hunter, "console", Console(file=io.StringIO()))
    lookup = Mock(return_value=[])
    monkeypatch.setattr(hunter, "hunt_exploits", lookup)
    hunter.run_hunter()
    assert [c.args[0] for c in lookup.call_args_list] == ["Apache httpd 2.4.29"]


# ── Sentinel's scan table ──────────────────────────────────────────

def test_sentinel_table_shows_ports_of_a_host_whose_banner_says_error(monkeypatch):
    rec = Console(file=io.StringIO(), record=True, width=200, color_system=None)
    monkeypatch.setattr(sentinel, "console", rec)
    sentinel.display_results_table("lab", {"192.0.2.5": [ERROR_PAGE],
                                           "192.0.2.6": ["Error: timeout"]})
    rows = {line.split("│")[1].strip(): line for line in rec.export_text().splitlines()
            if line.count("│") > 2 and "192.0.2." in line}
    assert "80/tcp" in rows["192.0.2.5"] and "Scan error" not in rows["192.0.2.5"]
    assert "Scan error" in rows["192.0.2.6"]


# ── CVE Watcher: services without a version ────────────────────────

@pytest.fixture
def watcher(monkeypatch):
    """Record NVD queries; silence output except what the test reads."""
    rec = Console(file=io.StringIO(), record=True, width=200, color_system=None)
    monkeypatch.setattr(cve, "rprint", rec.print)
    monkeypatch.setattr(cve, "console", rec)
    monkeypatch.setattr(cve.time, "sleep", lambda _: None)
    monkeypatch.setattr(cve, "send_alert", lambda **_: None)
    queries = []
    monkeypatch.setattr(cve, "query_nvd",
                        lambda keyword, days_back=120, cpe_name=None: queries.append(cpe_name or keyword) or [])
    return queries, rec.export_text


@pytest.mark.parametrize("days_back", [120, None])
def test_services_without_a_version_are_listed_not_queried(watcher, days_back):
    queries, text = watcher
    db.save_scan("lab", "20261110_120000", {"192.0.2.5": [SAMBA, "53/tcp open domain dnsmasq 2.85"]})
    result = cve.run_cve_watcher(days_back=days_back)
    assert result.unversioned == ["Samba smbd"]
    assert not any("Samba" in q for q in queries)          # no NVD request for it
    assert any("dnsmasq" in q for q in queries)             # versioned service still checked
    out = text()
    assert "Samba smbd" in out and "version not detected" in out


def test_unknown_version_never_yields_candidates():
    # Real NVD text (CVE-2021-44142): the range parses, so only the missing
    # version can rule the CVE out.
    described = [{"cve_id": "CVE-2021-44142", "analysed": True,
                  "description": "All versions of Samba prior to 4.13.17 are vulnerable to an "
                                 "out-of-bounds heap read write vulnerability."}]
    assert cve._keyword_candidates(described, "Samba", "4.13.16", cpe_checked=False, exclude=set())
    assert cve._keyword_candidates(described, "Samba", "", cpe_checked=False, exclude=set()) == []


def test_history_is_shown_even_without_analysable_services(watcher):
    _, text = watcher
    db.save_scan("lab", "20261110_120000", {"192.0.2.5": ["80/tcp open http"]})
    db.save_cve_alert(cve_id="CVE-2016-8863", severity="CRITICAL", score=9.8, service="x 1",
                      ip="192.0.2.5", summary="s", impact=None, network="lab")
    cve.run_cve_watcher(show_history=True)
    out = text()
    assert "No services with an identifiable product" in out
    assert "Alert history" in out and "CVE-2016-8863" in out
