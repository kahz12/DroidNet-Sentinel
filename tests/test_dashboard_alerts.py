"""CVE alerts in the web dashboard: the /alerts page, the summary tile, the
per-host badge on scan cards and the /api/alerts JSON endpoint.

Alerts are written by CVE Watcher; the dashboard only reads them. Every
field shown comes from NVD or from a device banner, so the page must escape
it, and the NVD link is built only from a well-formed CVE identifier.
"""
import os
import re

import pytest

pytest.importorskip("flask")

from droidnet.core import database as db

os.environ.setdefault("SENTINEL_PASS", "test-import-only")
from droidnet.web import dashboard as dash  # noqa: E402

HOME, OFFICE = "Home Wi-Fi", "Office"
ROUTER, PRINTER = "192.0.2.1", "198.51.100.30"


def alert(cve_id, severity, score, ip=ROUTER, network=HOME, service="dnsmasq 2.85",
          match_type="cpe", impact="Affected service: dnsmasq 2.85 on 1 host(s) | "
                                   "Attack vector: remotely exploitable"):
    db.save_cve_alert(cve_id=cve_id, severity=severity, score=score, service=service,
                      ip=ip, summary=f"Description of {cve_id}", impact=impact,
                      network=network, match_type=match_type)


@pytest.fixture
def alerts():
    """A realistic mix: a home router's CVEs plus a printer on another network."""
    alert("CVE-2023-28450", "HIGH", 7.5)
    alert("CVE-2016-8863", "CRITICAL", 9.8, service="Portable SDK for UPnP devices 1.6.19")
    alert("CVE-2026-12969", "MEDIUM", 5.3)
    alert("CVE-2021-29462", "CRITICAL", 9.1, service="Portable SDK for UPnP devices 1.6.19")
    alert("CVE-2026-00001", "UNKNOWN", None, ip=PRINTER, network=OFFICE,
          service="lighttpd 1.4.55", match_type="candidate")
    alert("CVE-2019-11072", "LOW", 3.1, ip=PRINTER, network=OFFICE, service="lighttpd 1.4.55")


@pytest.fixture
def client():
    c = dash.app.test_client()
    with c.session_transaction() as sess:
        sess["authenticated"] = True
    return c


def page(client, path, **query):
    resp = client.get(path, query_string=query)
    assert resp.status_code == 200
    return resp.get_data(as_text=True)


def cve_order(html):
    """CVE ids in table order: the first id of each main row (an id also
    appears in its NVD link and in the expandable description)."""
    rows = html.split('<tr class="main">')[1:]
    return [re.search(r"CVE-\d{4}-\d+", row).group(0) for row in rows]


# ── database helpers ───────────────────────────────────────────────

def test_list_orders_by_severity_then_score(alerts):
    ids = [a["cve_id"] for a in db.list_cve_alerts()]
    assert ids == ["CVE-2016-8863", "CVE-2021-29462", "CVE-2023-28450",
                   "CVE-2026-12969", "CVE-2019-11072", "CVE-2026-00001"]


@pytest.mark.parametrize("filters, expected", [
    ({"network": OFFICE},                 {"CVE-2026-00001", "CVE-2019-11072"}),
    ({"ip": ROUTER, "severity": "CRITICAL"}, {"CVE-2016-8863", "CVE-2021-29462"}),
    ({"network": "Nowhere"},              set()),
])
def test_list_filters(alerts, filters, expected):
    assert {a["cve_id"] for a in db.list_cve_alerts(**filters)} == expected


def test_summary_counts_per_severity_and_host(alerts):
    summary = db.summarize_cve_alerts()
    assert summary["total"] == 6
    assert summary["by_severity"]["CRITICAL"] == 2 and summary["by_severity"]["HIGH"] == 1
    assert summary["by_host"][(HOME, ROUTER)] == {"count": 4, "worst": "CRITICAL"}
    assert summary["by_host"][(OFFICE, PRINTER)] == {"count": 2, "worst": "LOW"}
    assert summary["networks"] == [HOME, OFFICE]


# ── /alerts page ───────────────────────────────────────────────────

def test_alerts_page_requires_login():
    resp = dash.app.test_client().get("/alerts")
    assert resp.status_code == 302 and "/login" in resp.headers["Location"]


def test_alerts_page_lists_most_urgent_first(client, alerts):
    html = page(client, "/alerts")
    assert cve_order(html) == ["CVE-2016-8863", "CVE-2021-29462", "CVE-2023-28450",
                               "CVE-2026-12969", "CVE-2019-11072", "CVE-2026-00001"]


@pytest.mark.parametrize("query, expected", [
    ({"network": OFFICE},                     ["CVE-2019-11072", "CVE-2026-00001"]),
    ({"ip": ROUTER, "network": HOME},         ["CVE-2016-8863", "CVE-2021-29462",
                                               "CVE-2023-28450", "CVE-2026-12969"]),
    ({"severity": "critical"},                ["CVE-2016-8863", "CVE-2021-29462"]),
    ({"severity": "bogus"},                   ["CVE-2016-8863", "CVE-2021-29462", "CVE-2023-28450",
                                               "CVE-2026-12969", "CVE-2019-11072", "CVE-2026-00001"]),
])
def test_alerts_page_filters(client, alerts, query, expected):
    assert cve_order(page(client, "/alerts", **query)) == expected


def test_each_alert_shows_severity_score_match_and_impact(client, alerts):
    html = page(client, "/alerts")
    assert 'class="pill r-critical">CRITICAL<' in html
    assert 'class="pill r-high">HIGH<' in html
    assert ">9.8<" in html and ">—<" in html                     # score, and none for UNKNOWN
    assert ">Candidate<" in html and ">CPE<" in html
    assert "<li>Attack vector: remotely exploitable</li>" in html  # impact split into lines
    assert "Description of CVE-2016-8863" in html


def test_nvd_link_only_for_well_formed_ids(client):
    alert("CVE-2016-8863", "CRITICAL", 9.8)
    alert('CVE-1"><a href=x>', "HIGH", 7.0)
    html = page(client, "/alerts")
    assert 'href="https://nvd.nist.gov/vuln/detail/CVE-2016-8863"' in html
    assert 'rel="noopener noreferrer"' in html
    assert "nvd.nist.gov/vuln/detail/CVE-1" not in html
    assert "<a href=x>" not in html and "CVE-1&#34;&gt;&lt;a href=x&gt;" in html


def test_banner_text_is_escaped(client):
    alert("CVE-2020-0001", "HIGH", 7.5, service="<script>alert(1)</script>",
          impact="Affected service: <b>x</b> | Attack vector: <i>y</i>")
    html = page(client, "/alerts")
    assert "<script>alert(1)</script>" not in html and "<b>x</b>" not in html
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html


def test_empty_and_filtered_empty_states(client, alerts):
    assert "No alerts match these filters" in page(client, "/alerts", network="Nowhere")


def test_no_alerts_yet_explains_how_to_get_them(client):
    html = page(client, "/alerts")
    assert "No CVE alerts yet" in html and "python main.py cve" in html


# ── main dashboard: summary tile and host badge ────────────────────

def test_dashboard_tile_counts_alerts_and_links_to_page(client, alerts):
    html = page(client, "/")
    tile = re.search(r'<a class="stat[^"]*" href="/alerts">(.*?)</a>', html, re.S)
    assert tile, "CVE alerts tile missing"
    assert ">6<" in tile.group(1) and "2 critical" in tile.group(1) and "1 high" in tile.group(1)


def test_host_badge_links_to_its_filtered_alerts(client, alerts):
    db.save_scan(HOME, "20261109_120000", {ROUTER: ["53/tcp open domain dnsmasq 2.85"],
                                           "192.0.2.7": []})
    html = page(client, "/")
    badge = re.search(r'<a class="badge badge-cve (r-[a-z]+)" href="([^"]+)"[^>]*>(\d+) CVEs?</a>', html)
    assert badge, "host badge missing"
    css, href, count = badge.groups()
    assert (css, count) == ("r-critical", "4")              # worst severity colours it
    assert "ip=192.0.2.1" in href and "network=Home+Wi-Fi" in href
    assert html.count("CVEs</a>") + html.count("CVE</a>") == 1   # host without alerts: none


def test_every_page_links_to_alerts(client):
    for path in ("/", "/help", "/alerts"):
        assert 'href="/alerts"' in page(client, path), path


# ── JSON API ───────────────────────────────────────────────────────

def test_api_alerts_returns_filtered_json(client, alerts):
    data = client.get("/api/alerts", query_string={"network": OFFICE}).get_json()
    assert [a["cve_id"] for a in data] == ["CVE-2019-11072", "CVE-2026-00001"]
    assert "notified_key" not in data[0]   # internal notification state stays private


def test_api_alerts_requires_login():
    assert dash.app.test_client().get("/api/alerts").status_code == 302
