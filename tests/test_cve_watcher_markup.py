"""Untrusted text must never be parsed as Rich markup.

Banners come from devices on the scanned LAN, network names can be SSIDs,
and NVD / database fields are external data. A stray closing tag such as
"[/x]" in any of them would raise MarkupError and abort the whole run, and
a valid tag such as "[link=...]" would turn into a terminal hyperlink, so
every interpolated value is escaped at the boundary.
"""
import io
from unittest.mock import Mock

import pytest
import requests
from rich.console import Console

from droidnet.modules import cve_watcher as cve

PRODUCT = "Evil[/x] [link=https://evil.example]srv"
BANNER = f"80/tcp open http {PRODUCT} 1.0"
NETWORK = "Lab[/net]"


@pytest.fixture
def out(monkeypatch):
    """Send all module output to one plain recording console; return its text getter."""
    rec = Console(file=io.StringIO(), record=True, width=240, color_system=None)
    monkeypatch.setattr(cve, "console", rec)
    monkeypatch.setattr(cve, "rprint", rec.print)
    monkeypatch.setattr(cve.time, "sleep", lambda _: None)
    return rec.export_text


def test_run_survives_hostile_banner_and_network(out, monkeypatch):
    # Description names the product with a range covering the banner's 1.0,
    # so the CVE is kept as a candidate.
    hostile_cve = {"cve_id": "CVE-2026-0001", "severity": "[/sev]", "score": 5.0,
                   "description": f"{PRODUCT} before 2.0 lets [/d] in", "cwes": [],
                   "kev": False}
    alert = {"cve_id": "CVE-2026-0001", "severity": "[/sev]", "service": "svc[/s]",
             "ip": "192.0.2.5", "network": NETWORK, "created_at": "2026-11-09"}
    monkeypatch.setattr(cve, "init_db", lambda: None)
    monkeypatch.setattr(cve, "get_latest_scan_with_services",
                        lambda: {"network": NETWORK, "id": 1,
                                 "targets": {"192.0.2.5": [BANNER]}})
    monkeypatch.setattr(cve, "build_cpe_name", lambda *_: None)
    monkeypatch.setattr(cve, "query_nvd", lambda *_, **__: [hostile_cve])
    monkeypatch.setattr(cve, "save_cve_alert", Mock())
    monkeypatch.setattr(cve, "send_alert", Mock())
    monkeypatch.setattr(cve, "get_cve_alerts", lambda **_: [alert])

    result = cve.run_cve_watcher(show_history=True)

    assert len(result) == 1
    text = out()
    # Printed literally: nothing swallowed as a tag, no hyperlink created.
    assert PRODUCT in text
    assert NETWORK in text
    assert "[/sev]" in text
    assert "svc[/s]" in text


def test_tables_render_cells_literally_but_keep_own_styles(out):
    cve.display_cve_table([{
        "cve_id": "CVE-[/a]", "severity": "HIGH", "score": 7.5, "service": "s[/b]",
        "ips": ["192.0.2.1"], "impact": "i[/c] [red]x", "match_type": "cpe",
    }])
    cve.display_alerts_history([{
        "cve_id": "CVE-[/d]", "severity": "[/e]", "service": "s[/f]",
        "ip": "ip[/g]", "network": "n[/h]", "created_at": "t[/i]",
    }])
    text = out()
    for token in ("CVE-[/a]", "s[/b]", "i[/c] [red]x",
                  "CVE-[/d]", "[/e]", "s[/f]", "ip[/g]", "n[/h]", "t[/i]"):
        assert token in text, token
    # The module's own severity markup is still interpreted, not escaped.
    assert "HIGH" in text and "[red]HIGH" not in text


@pytest.mark.parametrize("outcome", ["network_error", "bad_json", "backoff", "other_status"])
def test_nvd_messages_escape_label_and_error(out, monkeypatch, outcome):
    label = "q[/x]"
    if outcome == "network_error":
        get = Mock(side_effect=requests.ConnectionError("boom [/y]"))
    else:
        status = {"bad_json": 200, "backoff": 429, "other_status": 503}[outcome]
        resp = Mock(status_code=status, headers={})
        resp.json.side_effect = ValueError("bad [/y]")
        get = Mock(return_value=resp)
    monkeypatch.setattr(cve.requests, "get", get)

    assert cve._nvd_get({}, query_label=label) is None
    assert label in out()


def test_cache_hit_message_is_literal(out, monkeypatch, tmp_path):
    monkeypatch.setattr(cve, "NVD_CACHE_DIR", tmp_path)
    empty = {"startIndex": 0, "resultsPerPage": 0, "totalResults": 0, "vulnerabilities": []}
    monkeypatch.setattr(cve, "_nvd_get", Mock(return_value=empty))
    cve.query_nvd("k[/x]")
    cve.query_nvd("k[/x]")  # served from cache
    # The literal "[cache]" label must survive: Rich would read it as a style tag.
    assert "[cache] k[/x]" in out()
