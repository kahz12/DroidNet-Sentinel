"""Unit tests for database helpers (_compute_diff + purge_old_scans + _has_open_ports)."""

import sqlite3
from pathlib import Path


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


def test_purge_zero_or_negative_is_optout():
    # Non-positive retention is an opt-out: returns 0 without deleting.
    from droidnet.core.database import purge_old_scans
    assert purge_old_scans(0) == 0
    assert purge_old_scans(-5) == 0


# ── cve_alerts dedup includes network ────────────────────────────

def test_cve_alert_dedup_includes_network(tmp_path: Path, monkeypatch):
    """Same CVE/ip/service under different SSIDs must both register; an exact
    repeat on the same network is deduped."""
    db = tmp_path / "cve.db"
    monkeypatch.setattr("droidnet.core.database.DB_PATH", db)
    from droidnet.core import database as dbmod
    dbmod.init_db()

    common = dict(cve_id="CVE-2024-0001", severity="HIGH", score=7.5,
                  service="http", ip="192.168.1.10", summary="x", impact=None)

    id_home   = dbmod.save_cve_alert(network="home",   **common)
    id_office = dbmod.save_cve_alert(network="office", **common)
    id_dup    = dbmod.save_cve_alert(network="home",   **common)  # exact repeat

    assert id_home is not None
    assert id_office is not None      # different network → new alert
    assert id_dup is None             # same network → deduped


# ── legacy Spanish → English data migration (init_db) ─────────────

def test_init_db_migrates_legacy_spanish_values(tmp_path: Path, monkeypatch):
    """An older DB holding Spanish risk labels / markers is rewritten to
    English on the next init_db() call."""
    db = tmp_path / "legacy.db"
    monkeypatch.setattr("droidnet.core.database.DB_PATH", db)
    from droidnet.core import database as dbmod
    dbmod.init_db()

    conn = sqlite3.connect(db)
    conn.execute("INSERT INTO scans (id, network, scan_time) VALUES (1, 'n', 't')")
    conn.execute("INSERT INTO hosts (scan_id, ip, risk) VALUES (1, '10.0.0.5', 'CRÍTICO')")
    conn.execute("INSERT INTO hosts (scan_id, ip, risk) VALUES (1, '10.0.0.6', 'MÍNIMO')")
    host_id = conn.execute("SELECT id FROM hosts WHERE ip = '10.0.0.6'").fetchone()[0]
    conn.execute("INSERT INTO ports (host_id, port_entry) VALUES (?, 'Escudo intacto')", (host_id,))
    conn.commit()
    conn.close()

    dbmod.init_db()  # idempotent re-init triggers the migration

    conn = sqlite3.connect(db)
    risks = {r[0] for r in conn.execute("SELECT risk FROM hosts").fetchall()}
    ports = {r[0] for r in conn.execute("SELECT port_entry FROM ports").fetchall()}
    conn.close()
    assert risks == {"CRITICAL", "MINIMAL"}
    assert ports == {"Shield intact"}


# ── cve_alerts UNIQUE key schema migration (init_db) ──────────────

def test_init_db_migrates_cve_alerts_unique_key(tmp_path: Path, monkeypatch):
    """An older cve_alerts keyed on (cve_id, ip, service) is rebuilt to include
    `network`, preserving existing rows."""
    db = tmp_path / "legacy_cve.db"
    monkeypatch.setattr("droidnet.core.database.DB_PATH", db)
    from droidnet.core import database as dbmod
    dbmod.init_db()

    # Recreate cve_alerts with the pre-network UNIQUE key and seed one row.
    conn = sqlite3.connect(db)
    conn.executescript("""
        DROP TABLE cve_alerts;
        CREATE TABLE cve_alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            cve_id TEXT NOT NULL, severity TEXT NOT NULL DEFAULT 'UNKNOWN',
            score REAL, service TEXT NOT NULL, ip TEXT NOT NULL,
            summary TEXT NOT NULL, impact TEXT, network TEXT NOT NULL,
            scan_id INTEGER, created_at TEXT NOT NULL DEFAULT (datetime('now')),
            UNIQUE(cve_id, ip, service)
        );
        INSERT INTO cve_alerts (cve_id, severity, score, service, ip, summary, impact, network)
            VALUES ('CVE-2024-1', 'HIGH', 7.5, 'http', '10.0.0.9', 's', NULL, 'home');
    """)
    conn.commit()
    conn.close()

    dbmod.init_db()  # triggers the cve_alerts rebuild

    # The seeded row survives the rebuild.
    rows = dbmod.get_cve_alerts()
    assert any(r["cve_id"] == "CVE-2024-1" and r["network"] == "home" for r in rows)

    # The same CVE/ip/service now registers under a different network.
    new_id = dbmod.save_cve_alert(cve_id="CVE-2024-1", severity="HIGH", score=7.5,
                                  service="http", ip="10.0.0.9", summary="s",
                                  impact=None, network="office")
    assert new_id is not None

    conn = sqlite3.connect(db)
    sql = conn.execute(
        "SELECT sql FROM sqlite_master WHERE name = 'cve_alerts'").fetchone()[0]
    conn.close()
    assert "service, network)" in sql


# ── _has_open_ports ──────────────────────────────────────────────

def test_has_open_ports_real_tcp():
    assert _has_open_ports(["80/tcp open http"]) is True


def test_has_open_ports_multiple_real():
    assert _has_open_ports(["22/tcp open ssh", "443/tcp open https"]) is True


def test_has_open_ports_real_udp():
    # The regex covers udp too; if the scanner ever emits udp lines
    # we want them recognised as services.
    assert _has_open_ports(["53/udp open domain"]) is True


def test_has_open_ports_closed_marker():
    assert _has_open_ports(["Shield intact"]) is False


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


# ── get_latest_scan_with_services (integration) ──────────────────

def test_get_latest_skips_error_only_scans(tmp_path: Path, monkeypatch):
    """A scan whose only host has ['Error'] must not be returned."""
    db = tmp_path / "test.db"
    monkeypatch.setattr("droidnet.core.database.DB_PATH", db)

    from droidnet.core import database as dbmod
    dbmod.init_db()

    # Scan A: only errors → skip.
    dbmod.save_scan("net-A", "20260101_000000", {"10.0.0.1": ["Error"]})
    # Scan B: only closed → skip.
    dbmod.save_scan("net-B", "20260101_000100", {"10.0.0.2": ["Shield intact"]})
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
    dbmod.save_scan("net-B", "20260101_000100", {"10.0.0.2": ["Shield intact"]})

    assert dbmod.get_latest_scan_with_services() is None
