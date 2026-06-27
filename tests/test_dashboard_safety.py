"""Tests for the dashboard redirect normaliser and login rate-limit cleanup."""

import os

import pytest

# Skip cleanly where Flask is not installed.
pytest.importorskip("flask")

# Importing dashboard runs module-level credential init. Set SENTINEL_PASS so
# the credential auto-gen branch does not touch ~/.sentinel on import.
os.environ.setdefault("SENTINEL_PASS", "test-import-only")

from droidnet.web import dashboard as dash  # noqa: E402


# ── _safe_next rejects off-site redirect targets ────────────────────

@pytest.mark.parametrize("good", [
    "/",
    "/dashboard",
    "/host/192.168.1.1?network=home",
    "/a/b/c#frag",
])
def test_safe_next_allows_same_site_paths(good):
    assert dash._safe_next(good) == good


@pytest.mark.parametrize("bad", [
    "//evil.com",
    "//evil.com/path",
    "http://evil.com",
    "https://evil.com/x",
    "javascript:alert(1)",
    "evil.com",
    "",
    None,
])
def test_safe_next_rejects_offsite(bad):
    # Anything that could leave the origin collapses to "/".
    assert dash._safe_next(bad) == "/"


# ── stale login buckets get swept; limiter still works ─────────────

def test_sweep_drops_expired_and_empty_keeps_fresh():
    dash._login_attempts.clear()
    try:
        now = 1000.0
        # Fully-expired bucket.
        dash._login_attempts["1.1.1.1"].append(now - dash._LOGIN_WINDOW_SEC - 5)
        # Empty bucket (defaultdict access leaves a dangling key).
        _ = dash._login_attempts["2.2.2.2"]
        # Fresh bucket inside the window.
        dash._login_attempts["3.3.3.3"].append(now - 1)

        dash._sweep_login_attempts(now)

        assert "1.1.1.1" not in dash._login_attempts
        assert "2.2.2.2" not in dash._login_attempts
        assert "3.3.3.3" in dash._login_attempts
    finally:
        dash._login_attempts.clear()


def test_rate_limiter_blocks_after_max_then_records():
    dash._login_attempts.clear()
    try:
        ip = "9.9.9.9"
        # First _LOGIN_MAX_TRIES attempts are allowed.
        assert all(not dash._login_rate_limited(ip)
                   for _ in range(dash._LOGIN_MAX_TRIES))
        # The next one is blocked.
        assert dash._login_rate_limited(ip) is True
    finally:
        dash._login_attempts.clear()


# ── DB init happens at serve-time, not on import ───────────────────

def test_startup_banner_initialises_db(monkeypatch, capsys):
    called = []
    monkeypatch.setattr(dash, "init_db", lambda: called.append(True))
    dash._print_startup_banner(host="127.0.0.1")
    assert called == [True]


# ── security headers on every response ──────────────────────────────

def test_security_headers_present():
    resp = dash.app.test_client().get("/login")
    assert resp.headers.get("X-Content-Type-Options") == "nosniff"
    assert resp.headers.get("X-Frame-Options") == "DENY"
    assert resp.headers.get("Referrer-Policy") == "same-origin"
    assert "default-src 'self'" in resp.headers.get("Content-Security-Policy", "")
