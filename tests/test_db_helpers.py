"""Unit tests for database helpers (_compute_diff + purge_old_scans + _has_open_ports)."""

import sqlite3
from pathlib import Path

import pytest

from droidnet.core.database import _compute_diff, _has_open_ports


# ── _compute_diff ────────────────────────────────────────────────

def test_diff_no_changes():
    a = {"1.1.1.1": ["80/tcp open http"]}
    new, gone, changes = _compute_diff(a, a)
    assert (new, gone, changes) == ([], [], {})


def test_diff_new_ip():
    curr = {"1.1.1.1": ["80/tcp open http"], "2.2.2.2": ["22/tcp open ssh"]}
    prev = {"1.1.1.1": ["80/tcp open http"]}
    new, gone, changes = _compute_diff(curr, prev)
    assert new == ["2.2.2.2"]
    assert gone == []
    assert changes == {}


def test_diff_gone_ip():
    curr = {"1.1.1.1": ["80/tcp open http"]}
    prev = {"1.1.1.1": ["80/tcp open http"], "9.9.9.9": ["22/tcp open ssh"]}
    new, gone, changes = _compute_diff(curr, prev)
    assert new == []
    assert gone == ["9.9.9.9"]
    assert changes == {}


def test_diff_port_added_and_removed():
    curr = {"1.1.1.1": ["80/tcp open http", "443/tcp open https"]}
    prev = {"1.1.1.1": ["80/tcp open http", "21/tcp open ftp"]}
    new, gone, changes = _compute_diff(curr, prev)
    assert new == [] and gone == []
    assert changes == {"1.1.1.1": {
        "added":   ["443/tcp open https"],
        "removed": ["21/tcp open ftp"],
    }}


def test_diff_results_are_sorted():
    curr = {"3.3.3.3": [], "1.1.1.1": [], "2.2.2.2": []}
    prev = {}
    new, _, _ = _compute_diff(curr, prev)
    assert new == ["1.1.1.1", "2.2.2.2", "3.3.3.3"]


# ── purge_old_scans (uses temp DB) ───────────────────────────────

def test_purge_deletes_old_scans(tmp_path: Path, monkeypatch):
    """Insert two scans, purge with retention=1 day, expect only the recent one to survive."""
    db = tmp_path / "test.db"
    monkeypatch.setattr("droidnet.core.database.DB_PATH", db)

    # Reimport to pick up the patched DB_PATH inside the connection helper.
    from droidnet.core import database as dbmod
    dbmod.init_db()

    conn = sqlite3.connect(db)
    # One old (10 days ago), one fresh (now).
    conn.execute(
        "INSERT INTO scans (network, scan_time, total_devices, created_at) "
        "VALUES ('old', '20260101_000000', 0, datetime('now', '-10 days'))"
    )
    conn.execute(
        "INSERT INTO scans (network, scan_time, total_devices, created_at) "
        "VALUES ('new', '20260420_000000', 0, datetime('now'))"
    )
    conn.commit()
    conn.close()

    deleted = dbmod.purge_old_scans(days=1)
    assert deleted == 1

    conn = sqlite3.connect(db)
    rows = conn.execute("SELECT network FROM scans").fetchall()
    conn.close()
    assert [r[0] for r in rows] == ["new"]


def test_purge_rejects_zero_or_negative():
    from droidnet.core.database import purge_old_scans
    with pytest.raises(ValueError):
        purge_old_scans(0)
    with pytest.raises(ValueError):
        purge_old_scans(-5)


# ── _has_open_ports (bug 3 fix) ──────────────────────────────────

def test_has_open_ports_real_tcp():
    assert _has_open_ports(["80/tcp open http"]) is True


def test_has_open_ports_multiple_real():
    assert _has_open_ports(["22/tcp open ssh", "443/tcp open https"]) is True


def test_has_open_ports_real_udp():
    # The regex covers udp too; if the scanner ever emits udp lines
    # we want them recognised as services.
    assert _has_open_ports(["53/udp open domain"]) is True


def test_has_open_ports_closed_marker():
    assert _has_open_ports(["Escudo intacto"]) is False


def test_has_open_ports_error_marker():
    assert _has_open_ports(["Error"]) is False


def test_has_open_ports_error_with_message():
    assert _has_open_ports(["Error: timeout"]) is False


def test_has_open_ports_empty_list():
    assert _has_open_ports([]) is False


def test_has_open_ports_empty_string_entry():
    # Defensive: a stray empty string should not match nor crash.
    assert _has_open_ports([""]) is False


def test_has_open_ports_mixed_real_and_error_real_wins():
    # If even one entry is a real port line, the host has services.
    assert _has_open_ports(["Error: partial", "8080/tcp open http"]) is True


def test_has_open_ports_banner_containing_word_error_still_real():
    # A real port whose banner happens to say "Error" — must count as a service.
    assert _has_open_ports(["80/tcp open http Some Error Page"]) is True


def test_has_open_ports_rejects_filtered_state():
    # Only "open" qualifies — "filtered" or "closed" do not.
    assert _has_open_ports(["80/tcp filtered http"]) is False
    assert _has_open_ports(["80/tcp closed http"]) is False


# ── get_latest_scan_with_services (integration with bug 3 fix) ───

def test_get_latest_skips_error_only_scans(tmp_path: Path, monkeypatch):
    """A scan whose only host has ['Error'] must not be returned."""
    db = tmp_path / "test.db"
    monkeypatch.setattr("droidnet.core.database.DB_PATH", db)

    from droidnet.core import database as dbmod
    dbmod.init_db()

    # Scan A: only errors → skip.
    dbmod.save_scan("net-A", "20260101_000000", {"10.0.0.1": ["Error"]})
    # Scan B: only closed → skip.
    dbmod.save_scan("net-B", "20260101_000100", {"10.0.0.2": ["Escudo intacto"]})
    # Scan C: real services → return.
    dbmod.save_scan("net-C", "20260101_000200",
                    {"10.0.0.3": ["22/tcp open ssh OpenSSH"]})

    result = dbmod.get_latest_scan_with_services()
    assert result is not None
    assert result["network"] == "net-C"
    assert result["targets"]["10.0.0.3"] == ["22/tcp open ssh OpenSSH"]


def test_get_latest_returns_none_when_all_scans_marker_only(tmp_path: Path, monkeypatch):
    db = tmp_path / "test.db"
    monkeypatch.setattr("droidnet.core.database.DB_PATH", db)

    from droidnet.core import database as dbmod
    dbmod.init_db()

    dbmod.save_scan("net-A", "20260101_000000", {"10.0.0.1": ["Error: timeout"]})
    dbmod.save_scan("net-B", "20260101_000100", {"10.0.0.2": ["Escudo intacto"]})

    assert dbmod.get_latest_scan_with_services() is None
