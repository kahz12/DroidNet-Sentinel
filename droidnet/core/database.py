"""
SQLite persistence layer for DroidNet Sentinel.

Schema:
    scans  → one row per scan cycle  (network + timestamp)
    hosts  → one row per discovered IP per scan
    ports  → one row per open port per host

Public API:
    init_db()                   → create tables if absent (idempotent)
    save_scan(...)              → persist a complete scan result
    classify_risk(ports)        → plain-text risk label
    get_all_scans()             → all scans + targets, newest first
    get_all_scans_with_diffs()  → same, plus diff vs previous scan
    get_scan_diff(scan_id)      → single scan + diff data
    get_known_ips(network)      → all IPs ever seen on a network
"""

import sqlite3
from contextlib import contextmanager

from droidnet.config import DB_PATH
from droidnet.core.risk import classify_risk  # re-exported below for back-compat


# ══════════════════════════════════════════════════════════════════
#  Connection helper
# ══════════════════════════════════════════════════════════════════

@contextmanager
def _conn():
    """Yield a connected, row-factory-enabled SQLite connection."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


# ══════════════════════════════════════════════════════════════════
#  Schema
# ══════════════════════════════════════════════════════════════════

def init_db() -> None:
    """Create all tables if they do not exist. Safe to call repeatedly."""
    with _conn() as c:
        c.executescript("""
            CREATE TABLE IF NOT EXISTS scans (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                network       TEXT    NOT NULL,
                scan_time     TEXT    NOT NULL,
                total_devices INTEGER NOT NULL DEFAULT 0,
                created_at    TEXT    NOT NULL DEFAULT (datetime('now'))
            );

            CREATE TABLE IF NOT EXISTS hosts (
                id      INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
                ip      TEXT    NOT NULL,
                risk    TEXT    NOT NULL DEFAULT 'MÍNIMO',
                UNIQUE(scan_id, ip)
            );

            CREATE TABLE IF NOT EXISTS ports (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                host_id    INTEGER NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
                port_entry TEXT    NOT NULL
            );

            CREATE TABLE IF NOT EXISTS cve_alerts (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                cve_id      TEXT    NOT NULL,
                severity    TEXT    NOT NULL DEFAULT 'UNKNOWN',
                score       REAL,
                service     TEXT    NOT NULL,
                ip          TEXT    NOT NULL,
                summary     TEXT    NOT NULL,
                impact      TEXT,
                network     TEXT    NOT NULL,
                scan_id     INTEGER REFERENCES scans(id) ON DELETE SET NULL,
                created_at  TEXT    NOT NULL DEFAULT (datetime('now')),
                UNIQUE(cve_id, ip, service)
            );

            -- Indexes for frequent dashboard queries.
            CREATE INDEX IF NOT EXISTS idx_scans_network_id
                ON scans(network, id DESC);
            CREATE INDEX IF NOT EXISTS idx_hosts_scan_ip
                ON hosts(scan_id, ip);
            CREATE INDEX IF NOT EXISTS idx_ports_host
                ON ports(host_id);
            CREATE INDEX IF NOT EXISTS idx_cve_network_created
                ON cve_alerts(network, created_at DESC);
        """)


# ══════════════════════════════════════════════════════════════════
#  Internal helpers
# ══════════════════════════════════════════════════════════════════

def _hosts_for_scan(c: sqlite3.Connection, scan_id: int) -> dict[str, list[str]]:
    """Return {ip: [port_entries]} for a given scan_id (reuses open connection)."""
    rows = c.execute(
        "SELECT id, ip FROM hosts WHERE scan_id = ?", (scan_id,)
    ).fetchall()
    result: dict[str, list[str]] = {}
    for row in rows:
        ports = c.execute(
            "SELECT port_entry FROM ports WHERE host_id = ?", (row["id"],)
        ).fetchall()
        result[row["ip"]] = [p["port_entry"] for p in ports]
    return result


def _compute_diff(
    curr_targets: dict[str, list[str]],
    prev_targets: dict[str, list[str]],
) -> tuple[list[str], list[str], dict[str, dict]]:
    """
    Compare two target dicts and return (new_ips, gone_ips, port_changes).

    port_changes: {ip: {"added": [...], "removed": [...]}}
    """
    curr_ips = set(curr_targets)
    prev_ips = set(prev_targets)

    new_ips  = sorted(curr_ips - prev_ips)
    gone_ips = sorted(prev_ips - curr_ips)

    port_changes: dict[str, dict] = {}
    for ip in curr_ips & prev_ips:
        added   = sorted(set(curr_targets[ip]) - set(prev_targets[ip]))
        removed = sorted(set(prev_targets[ip]) - set(curr_targets[ip]))
        if added or removed:
            port_changes[ip] = {"added": added, "removed": removed}

    return new_ips, gone_ips, port_changes


# ══════════════════════════════════════════════════════════════════
#  Write
# ══════════════════════════════════════════════════════════════════

def save_scan(network: str, scan_time: str, targets: dict) -> int:
    """
    Persist a complete scan result to the database.

    Args:
        network   : SSID name.
        scan_time : Timestamp string (YYYYmmdd_HHMMSS).
        targets   : {ip: [port_entry, ...]} dict from deep_scan().

    Returns:
        The auto-generated scan ID.
    """
    with _conn() as c:
        cur = c.execute(
            "INSERT INTO scans (network, scan_time, total_devices) VALUES (?, ?, ?)",
            (network, scan_time, len(targets)),
        )
        scan_id = cur.lastrowid

        for ip, ports in targets.items():
            cur = c.execute(
                "INSERT OR IGNORE INTO hosts (scan_id, ip, risk) VALUES (?, ?, ?)",
                (scan_id, ip, classify_risk(ports)),
            )
            host_id = cur.lastrowid
            if host_id:
                c.executemany(
                    "INSERT INTO ports (host_id, port_entry) VALUES (?, ?)",
                    [(host_id, p) for p in ports],
                )

    return scan_id


# ══════════════════════════════════════════════════════════════════
#  Read
# ══════════════════════════════════════════════════════════════════

def get_all_scans() -> list[dict]:
    """Return all scans with their targets populated, newest first."""
    with _conn() as c:
        scans = c.execute("SELECT * FROM scans ORDER BY id DESC").fetchall()
        result = []
        for scan in scans:
            d = dict(scan)
            d["targets"] = _hosts_for_scan(c, d["id"])
            result.append(d)
    return result


def count_scans() -> int:
    """Total number of scans stored. Useful for pagination in the dashboard."""
    with _conn() as c:
        row = c.execute("SELECT COUNT(*) AS n FROM scans").fetchone()
    return int(row["n"]) if row else 0


def get_all_scans_with_diffs(
    limit: int | None = None,
    offset: int = 0,
) -> list[dict]:
    """
    Return scans (newest first) with targets and diff vs the previous
    scan on the same network.

    Args:
        limit  : maximum number of scans to return. None = no limit (legacy).
        offset : number of scans to skip (pagination).

    Extra keys per scan:
        new_ips      : IPs not present in the previous scan
        gone_ips     : IPs that disappeared since the previous scan
        port_changes : {ip: {"added": [...], "removed": [...]}}
        risks        : {ip: plain-text risk label}
    """
    with _conn() as c:
        if limit is None:
            scans = c.execute("SELECT * FROM scans ORDER BY id DESC").fetchall()
        else:
            scans = c.execute(
                "SELECT * FROM scans ORDER BY id DESC LIMIT ? OFFSET ?",
                (int(limit), int(offset)),
            ).fetchall()
        result = []

        for scan in scans:
            d = dict(scan)
            d["targets"] = _hosts_for_scan(c, d["id"])
            d["risks"]   = {ip: classify_risk(p) for ip, p in d["targets"].items()}

            prev = c.execute("""
                SELECT id FROM scans
                WHERE network = ? AND id < ?
                ORDER BY id DESC LIMIT 1
            """, (d["network"], d["id"])).fetchone()

            if prev:
                prev_targets = _hosts_for_scan(c, prev["id"])
                d["new_ips"], d["gone_ips"], d["port_changes"] = _compute_diff(
                    d["targets"], prev_targets
                )
            else:
                d["new_ips"]      = []
                d["gone_ips"]     = []
                d["port_changes"] = {}

            result.append(d)

    return result


def get_scan_diff(scan_id: int) -> dict:
    """
    Return a single scan dict with diff data vs the previous scan on the same network.

    Returns {} if scan_id does not exist.
    """
    with _conn() as c:
        row = c.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
        if not row:
            return {}

        d = dict(row)
        d["targets"] = _hosts_for_scan(c, scan_id)
        d["risks"]   = {ip: classify_risk(p) for ip, p in d["targets"].items()}

        prev = c.execute("""
            SELECT id FROM scans
            WHERE network = ? AND id < ?
            ORDER BY id DESC LIMIT 1
        """, (d["network"], scan_id)).fetchone()

        if prev:
            prev_targets = _hosts_for_scan(c, prev["id"])
            d["new_ips"], d["gone_ips"], d["port_changes"] = _compute_diff(
                d["targets"], prev_targets
            )
        else:
            d["new_ips"]      = []
            d["gone_ips"]     = []
            d["port_changes"] = {}

    return d


def get_known_ips(network: str) -> set[str]:
    """Return every IP ever seen on *network* across all historical scans."""
    with _conn() as c:
        rows = c.execute("""
            SELECT DISTINCT h.ip
              FROM hosts h
              JOIN scans s ON s.id = h.scan_id
             WHERE s.network = ?
        """, (network,)).fetchall()
    return {r["ip"] for r in rows}


# ══════════════════════════════════════════════════════════════════
#  CVE alerts
# ══════════════════════════════════════════════════════════════════

def save_cve_alert(
    cve_id: str,
    severity: str,
    score: float | None,
    service: str,
    ip: str,
    summary: str,
    impact: str | None,
    network: str,
    scan_id: int | None = None,
) -> int | None:
    """
    Persist a CVE alert. Returns the row ID, or None if it already exists.
    """
    with _conn() as c:
        try:
            cur = c.execute(
                """INSERT INTO cve_alerts
                   (cve_id, severity, score, service, ip, summary, impact, network, scan_id)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (cve_id, severity, score, service, ip, summary, impact, network, scan_id),
            )
            return cur.lastrowid
        except sqlite3.IntegrityError:
            return None


def get_cve_alerts(network: str | None = None, limit: int = 50) -> list[dict]:
    """Return recent CVE alerts, optionally filtered by network."""
    with _conn() as c:
        if network:
            rows = c.execute(
                "SELECT * FROM cve_alerts WHERE network = ? ORDER BY created_at DESC LIMIT ?",
                (network, limit),
            ).fetchall()
        else:
            rows = c.execute(
                "SELECT * FROM cve_alerts ORDER BY created_at DESC LIMIT ?",
                (limit,),
            ).fetchall()
    return [dict(r) for r in rows]


def purge_old_scans(days: int) -> int:
    """
    Delete scans older than *days*. CASCADE removes their hosts/ports;
    cve_alerts.scan_id flips to NULL (alerts are preserved).

    Returns the number of scan rows deleted.
    """
    if days <= 0:
        raise ValueError("days must be > 0")

    with _conn() as c:
        cur = c.execute(
            "DELETE FROM scans WHERE created_at < datetime('now', ?)",
            (f"-{int(days)} days",),
        )
        return cur.rowcount or 0


def get_latest_scan_with_services() -> dict | None:
    """
    Return the most recent scan that has hosts with open ports (not just 'Escudo intacto').

    Returns dict with keys: id, network, scan_time, targets {ip: [port_entries]}.
    """
    with _conn() as c:
        scans = c.execute("SELECT * FROM scans ORDER BY id DESC LIMIT 10").fetchall()
        for scan in scans:
            targets = _hosts_for_scan(c, scan["id"])
            has_services = any(
                ports and ports != ["Escudo intacto"] and not (ports and "Error" in ports[0])
                for ports in targets.values()
            )
            if has_services:
                d = dict(scan)
                d["targets"] = targets
                return d
    return None
