"""Unit tests for database helpers (_compute_diff + purge_old_scans)."""

import sqlite3
from pathlib import Path

import pytest

from droidnet.core.database import _compute_diff


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
