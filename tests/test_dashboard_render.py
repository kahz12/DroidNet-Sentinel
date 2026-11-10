"""Rendering tests for the dashboard host cards, focused on UNKNOWN hosts."""
import os
import re

import pytest

pytest.importorskip("flask")

from droidnet.core import database as db

os.environ.setdefault("SENTINEL_PASS", "test-import-only")
from droidnet.web import dashboard as dash  # noqa: E402

UNKNOWN_IP = "192.0.2.10"
MINIMAL_IP = "192.0.2.20"
CRITICAL_IP = "192.0.2.30"


@pytest.fixture
def html(monkeypatch, tmp_path):
    """Render the dashboard for a scan with one UNKNOWN, MINIMAL and CRITICAL host."""
    monkeypatch.setattr(db, "DB_PATH", tmp_path / "history.db")
    db.init_db()
    targets = {
        UNKNOWN_IP: ["Error: timeout", "Error: host unreachable"],
        MINIMAL_IP: [],
        CRITICAL_IP: ["23/tcp open telnet"],
    }
    # Two identical scans so the newest has no "new" hosts — the "new"
    # accent would otherwise mask the risk-based border.
    db.save_scan("test", "a", targets)
    db.save_scan("test", "b", targets)

    client = dash.app.test_client()
    with client.session_transaction() as sess:
        sess["authenticated"] = True
    resp = client.get("/")
    assert resp.status_code == 200
    return resp.get_data(as_text=True)


def _host_classes(html: str, ip: str) -> set[str]:
    m = re.search(
        r'<div class="(host[^"]*)">\s*<div class="host-head">\s*'
        r'<span class="ip">' + re.escape(ip) + r"</span>",
        html,
    )
    assert m, f"host card for {ip} not rendered"
    return set(m.group(1).split())


def _risk_badge_classes(html: str, ip: str) -> set[str]:
    m = re.search(
        r'<span class="ip">' + re.escape(ip) + r'</span>.*?<span class="(risk[^"]*)"',
        html,
        re.S,
    )
    assert m, f"risk badge for {ip} not rendered"
    return set(m.group(1).split())


def test_unknown_host_is_not_styled_as_healthy(html):
    # Bare "host" falls back to the green --ok border; UNKNOWN must not.
    assert _host_classes(html, UNKNOWN_IP) == {"host", "unknown"}
    assert _host_classes(html, MINIMAL_IP) == {"host"}
    assert _host_classes(html, CRITICAL_IP) == {"host", "vuln"}


def test_unknown_host_has_own_border_style(html):
    assert re.search(r"\.host\.unknown\s*\{[^}]*border-left", html)


def test_unknown_badge_is_distinct_from_medium(html):
    assert "r-unknown" in _risk_badge_classes(html, UNKNOWN_IP)
    assert "r-medium" not in _risk_badge_classes(html, UNKNOWN_IP)


def test_unknown_port_lines_render_as_block_lines(html):
    assert '<span class="unknown-line">? Error: timeout</span>' in html
    assert '<span class="unknown-line">? Error: host unreachable</span>' in html
    assert re.search(r"\.ports \.unknown-line\s*\{[^}]*display:\s*block", html)


@pytest.mark.parametrize("path", ["/", "/help", "/alerts"])
def test_every_risk_class_used_is_styled(path):
    # Each page carries its own <style>; a class used without a rule renders
    # as plain uncoloured text, so every r-* class a page uses must be defined
    # in that page (the risk colours live in the shared CSS for this reason).
    # One alert per severity, so the alert pill and badge classes are in use.
    for i, severity in enumerate(("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN")):
        db.save_cve_alert(cve_id=f"CVE-2026-{i:04}", severity=severity, score=None,
                          service="svc 1.0", ip=f"192.0.2.{i + 1}", summary="s",
                          impact=None, network="lab")
    db.save_scan("lab", "20261109_120000", {"192.0.2.1": ["80/tcp open http"]})
    client = dash.app.test_client()
    with client.session_transaction() as sess:
        sess["authenticated"] = True
    resp = client.get(path)
    # An error page uses no r-* classes and would pass vacuously.
    assert resp.status_code == 200
    page = resp.get_data(as_text=True)
    assert "r-unknown" in page
    for cls in ("r-critical", "r-high", "r-medium", "r-low", "r-minimal", "r-unknown"):
        if re.search(r'class="[^"]*\b' + cls + r'\b', page):
            assert re.search(r"(?m)^\s*\." + cls + r"\s*\{[^}]*color:", page), \
                f"{path} uses .{cls} but defines no colour for it"


def test_legend_explains_unknown(html):
    legend = re.search(r'<div class="legend">(.*?)</div>', html, re.S)
    assert legend, "legend not rendered"
    assert 'class="dot r-unknown"' in legend.group(1)
    assert "Unknown" in legend.group(1)
