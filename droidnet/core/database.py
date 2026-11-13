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
from droidnet.core.logger import get_logger
# classify_risk labels every stored host; callers may also import it from here.
from droidnet.core.risk import classify_risk, is_port_line

log = get_logger(__name__)


def _has_open_ports(ports: list[str]) -> bool:
    """True iff *ports* contains at least one real open-port line.

    Markers ("Shield intact", "Error: timeout") are not services; see
    core.risk.is_port_line for how the two are told apart.
    """
    return any(is_port_line(entry) for entry in ports)


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
        # WAL lets the dashboard read while the daemon writes, without blocking.
        # The mode persists in the database file, so setting it once is enough.
        c.execute("PRAGMA journal_mode=WAL")
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
                risk    TEXT    NOT NULL DEFAULT 'MINIMAL',
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
                match_type   TEXT,  -- 'cpe' (version-confirmed) or 'candidate'
                notified_key TEXT,  -- "SEVERITY|match_type" last announced; NULL = pending
                UNIQUE(cve_id, ip, service, network)
            );

            -- Audit journal for the ARP-cut guardian: one row per cut,
            -- restore, refusal and guardian start/stop. A security trail,
            -- kept independent of the scan history so purging old scans
            -- never erases it.
            CREATE TABLE IF NOT EXISTS guard_events (
                id      INTEGER PRIMARY KEY AUTOINCREMENT,
                ts      TEXT    NOT NULL DEFAULT (datetime('now')),
                action  TEXT    NOT NULL,
                ip      TEXT,
                network TEXT,
                reason  TEXT
            );

            -- get_guard_events reads `ORDER BY id DESC LIMIT ?`, already served
            -- by the implicit rowid B-tree (id is an INTEGER PRIMARY KEY alias),
            -- so a dedicated index only added write cost. Drop any left over
            -- from an earlier schema.
            DROP INDEX IF EXISTS idx_guard_ts;

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

        # One-time data migration: rename legacy Spanish risk labels and the
        # closed-host marker to their English equivalents. Idempotent — the
        # WHERE clauses only match rows written by older versions.
        c.execute("UPDATE hosts SET risk = 'MINIMAL'  WHERE risk = 'MÍNIMO'")
        c.execute("UPDATE hosts SET risk = 'LOW'      WHERE risk = 'BAJO'")
        c.execute("UPDATE hosts SET risk = 'MEDIUM'   WHERE risk = 'MEDIO'")
        c.execute("UPDATE hosts SET risk = 'CRITICAL' WHERE risk = 'CRÍTICO'")
        c.execute("UPDATE ports SET port_entry = 'Shield intact' "
                  "WHERE port_entry = 'Escudo intacto'")

        # Schema migration: an older cve_alerts table keyed on
        # UNIQUE(cve_id, ip, service) is rebuilt to include `network`, so the
        # same CVE/ip/service registers separately per network. CREATE TABLE
        # IF NOT EXISTS never alters an existing table, so this is explicit.
        existing = c.execute(
            "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'cve_alerts'"
        ).fetchone()
        if existing and existing["sql"] and "service, network)" not in existing["sql"]:
            c.execute("""
                CREATE TABLE cve_alerts_migrated (
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
                    UNIQUE(cve_id, ip, service, network)
                )
            """)
            c.execute("""
                INSERT INTO cve_alerts_migrated
                    (id, cve_id, severity, score, service, ip, summary,
                     impact, network, scan_id, created_at)
                SELECT id, cve_id, severity, score, service, ip, summary,
                       impact, network, scan_id, created_at
                FROM cve_alerts
            """)
            c.execute("DROP TABLE cve_alerts")
            c.execute("ALTER TABLE cve_alerts_migrated RENAME TO cve_alerts")
            c.execute("CREATE INDEX IF NOT EXISTS idx_cve_network_created "
                      "ON cve_alerts(network, created_at DESC)")

        # Schema migration: notification state for CVE alerts. Rows that
        # predate these columns are backfilled as already announced (not
        # pending), so adding the columns to a populated database does not
        # re-notify its whole history. Each backfill runs only with its ADD.
        columns = {r["name"] for r in c.execute("PRAGMA table_info(cve_alerts)")}
        if "match_type" not in columns:
            c.execute("ALTER TABLE cve_alerts ADD COLUMN match_type TEXT")
            c.execute("UPDATE cve_alerts SET match_type = CASE "
                      "WHEN impact LIKE 'Candidate match:%' THEN 'candidate' ELSE 'cpe' END")
        if "notified_key" not in columns:
            c.execute("ALTER TABLE cve_alerts ADD COLUMN notified_key TEXT")
            c.execute(f"UPDATE cve_alerts SET notified_key = {_NOTIFIED_KEY_SQL}")


# ══════════════════════════════════════════════════════════════════
#  Internal helpers
# ══════════════════════════════════════════════════════════════════

def _hosts_for_scan(c: sqlite3.Connection, scan_id: int) -> dict[str, list[str]]:
    """Return {ip: [port_entries]} for a given scan_id (reuses open connection)."""
    return _hosts_for_scans(c, [scan_id])[scan_id]


def _hosts_for_scans(c: sqlite3.Connection, scan_ids) -> dict[int, dict[str, list[str]]]:
    """Batch-load snapshots, including hosts without ports, in bounded chunks."""
    ids = list(dict.fromkeys(scan_ids))
    result = {scan_id: {} for scan_id in ids}
    for start in range(0, len(ids), 400):
        chunk = ids[start:start + 400]
        placeholders = ",".join("?" for _ in chunk)
        rows = c.execute(f"""
            SELECT h.scan_id, h.ip, p.port_entry
            FROM hosts h LEFT JOIN ports p ON p.host_id = h.id
            WHERE h.scan_id IN ({placeholders}) ORDER BY h.id, p.id
        """, chunk)
        for row in rows:
            ports = result[row["scan_id"]].setdefault(row["ip"], [])
            if row["port_entry"] is not None:
                ports.append(row["port_entry"])
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

def get_all_scans(limit: int | None = None, offset: int = 0) -> list[dict]:
    """Return scans with targets, newest first; optionally paginate."""
    with _conn() as c:
        c.execute("BEGIN")
        scans = c.execute("SELECT * FROM scans ORDER BY id DESC LIMIT ? OFFSET ?",
                          (-1 if limit is None else int(limit), max(0, int(offset)))).fetchall()
        targets = _hosts_for_scans(c, [scan["id"] for scan in scans])
        result = []
        for scan in scans:
            d = dict(scan)
            d["targets"] = targets[d["id"]]
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
        limit  : maximum number of scans to return; None returns every scan.
        offset : number of scans to skip (pagination).

    Extra keys per scan:
        new_ips      : IPs not present in the previous scan
        gone_ips     : IPs that disappeared since the previous scan
        port_changes : {ip: {"added": [...], "removed": [...]}}
        risks        : {ip: plain-text risk label}
    """
    with _conn() as c:
        c.execute("BEGIN")
        scans = c.execute("""
            SELECT s.*, (SELECT p.id FROM scans p
                         WHERE p.network = s.network AND p.id < s.id
                         ORDER BY p.id DESC LIMIT 1) AS previous_id
            FROM scans s ORDER BY s.id DESC LIMIT ? OFFSET ?
        """, (-1 if limit is None else int(limit), max(0, int(offset)))).fetchall()
        ids = {row["id"] for row in scans} | {row["previous_id"] for row in scans if row["previous_id"] is not None}
        targets = _hosts_for_scans(c, ids)
        result = []

        for scan in scans:
            d = dict(scan)
            d["targets"] = targets[d["id"]]
            d["risks"]   = {ip: classify_risk(p) for ip, p in d["targets"].items()}

            prev_id = d.pop("previous_id")
            if prev_id is not None:
                prev_targets = targets[prev_id]
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

# What an announcement covered: "SEVERITY|match_type" (see _needs_notification).
_NOTIFIED_KEY_SQL = "severity || '|' || COALESCE(match_type, 'cpe')"
_ALERT_KEY_WHERE  = "cve_id = ? AND ip = ? AND service = ? AND network = ?"


def _needs_notification(notified_key: str | None, severity: str, match_type: str) -> bool:
    """New alerts, severity changes and candidate→CPE confirmations are announced.

    A score tweak within the same severity is not, and neither is a CPE match
    later found only by keyword (the CVE was already confirmed once).
    """
    if not notified_key:
        return True
    old_severity, _, old_type = notified_key.partition("|")
    return old_severity != severity or (old_type == "candidate" and match_type == "cpe")


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
    match_type: str = "cpe",
) -> bool:
    """
    Insert or refresh the alert keyed on (cve_id, ip, service, network).

    A re-detected alert takes the latest severity, score, texts, match type
    and scan, so a CVE first stored as UNKNOWN is updated once NVD scores it.

    Returns True when the alert should be announced: it was never announced,
    its severity changed, or a candidate match is now CPE-confirmed. Call
    mark_cve_alerts_notified() once the announcement has been delivered.
    """
    key = (cve_id, ip, service, network)
    with _conn() as c:
        c.execute(
            """INSERT INTO cve_alerts
               (cve_id, severity, score, service, ip, summary, impact, network,
                scan_id, match_type)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
               ON CONFLICT(cve_id, ip, service, network) DO UPDATE SET
                   severity   = excluded.severity,
                   score      = excluded.score,
                   summary    = excluded.summary,
                   impact     = excluded.impact,
                   scan_id    = excluded.scan_id,
                   match_type = excluded.match_type""",
            (cve_id, severity, score, service, ip, summary, impact, network,
             scan_id, match_type),
        )
        row = c.execute(
            f"SELECT notified_key FROM cve_alerts WHERE {_ALERT_KEY_WHERE}", key,
        ).fetchone()
    return _needs_notification(row["notified_key"] if row else None, severity, match_type)


def mark_cve_alerts_notified(keys) -> None:
    """Record that the (cve_id, ip, service, network) alerts were announced
    with their current severity and match type."""
    with _conn() as c:
        c.executemany(
            f"UPDATE cve_alerts SET notified_key = {_NOTIFIED_KEY_SQL} WHERE {_ALERT_KEY_WHERE}",
            list(keys),
        )


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


# Severity labels CVE Watcher stores, most urgent first. Anything else sorts
# after them. The SQL CASE is built from these literals only, never from input.
CVE_SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE", "UNKNOWN")
_SEVERITY_RANK_SQL = (
    "CASE severity "
    + " ".join(f"WHEN '{name}' THEN {rank}" for rank, name in enumerate(CVE_SEVERITIES))
    + f" ELSE {len(CVE_SEVERITIES)} END"
)


def _severity_rank(severity: str) -> int:
    return CVE_SEVERITIES.index(severity) if severity in CVE_SEVERITIES else len(CVE_SEVERITIES)


def list_cve_alerts(network: str | None = None, ip: str | None = None,
                    severity: str | None = None) -> list[dict]:
    """Every stored CVE alert matching the filters, most urgent first.

    Ordered by severity, then CVSS score (unscored last), then newest. A
    None filter is not applied. Unlike get_cve_alerts(), which serves the
    CLI's short recent-first history, this returns the full set: the
    dashboard needs every alert of a host, however old.
    """
    clauses, params = [], []
    for column, value in (("network", network), ("ip", ip), ("severity", severity)):
        if value is not None:
            clauses.append(f"{column} = ?")   # column names come from the tuple above, never from input
            params.append(value)
    where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    with _conn() as c:
        rows = c.execute(
            f"SELECT * FROM cve_alerts {where} ORDER BY {_SEVERITY_RANK_SQL}, "
            "score IS NULL, score DESC, created_at DESC, cve_id",
            params,
        ).fetchall()
    return [dict(r) for r in rows]


def summarize_cve_alerts() -> dict:
    """Alert counts for the dashboard's summary tile and per-host badges.

    Returns:
        total       : number of stored alerts.
        by_severity : {"CRITICAL": n, "HIGH": n, ...} for the labels present.
        by_host     : {(network, ip): {"count": n, "worst": severity}}; the
                      worst severity decides the badge colour.
        networks    : sorted networks that have at least one alert.
    """
    with _conn() as c:
        rows = c.execute(
            "SELECT network, ip, severity, COUNT(*) AS n FROM cve_alerts "
            "GROUP BY network, ip, severity"
        ).fetchall()
    by_severity: dict[str, int] = {}
    by_host: dict[tuple[str, str], dict] = {}
    for row in rows:
        by_severity[row["severity"]] = by_severity.get(row["severity"], 0) + row["n"]
        host = by_host.setdefault((row["network"], row["ip"]), {"count": 0, "worst": row["severity"]})
        host["count"] += row["n"]
        if _severity_rank(row["severity"]) < _severity_rank(host["worst"]):
            host["worst"] = row["severity"]
    return {
        "total":       sum(by_severity.values()),
        "by_severity": by_severity,
        "by_host":     by_host,
        "networks":    sorted({network for network, _ in by_host}),
    }


def purge_old_scans(days: int) -> int:
    """
    Delete scans older than *days*. CASCADE removes their hosts/ports;
    cve_alerts.scan_id flips to NULL (alerts are preserved).

    Returns the number of scan rows deleted. A non-positive *days* is treated
    as an opt-out (retention disabled) and returns 0 without deleting anything.
    """
    if days <= 0:
        return 0

    with _conn() as c:
        cur = c.execute(
            "DELETE FROM scans WHERE created_at < datetime('now', ?)",
            (f"-{int(days)} days",),
        )
        return cur.rowcount or 0


def get_latest_scan_with_services() -> dict | None:
    """
    Return the most recent scan that has at least one host with real open
    ports — not just closed-host markers ("Shield intact") or scan errors
    ("Error", "Error: timeout").

    Returns dict with keys: id, network, scan_time, targets {ip: [port_entries]}.
    """
    with _conn() as c:
        scans = c.execute("SELECT * FROM scans ORDER BY id DESC LIMIT 10").fetchall()
        for scan in scans:
            targets = _hosts_for_scan(c, scan["id"])
            if any(_has_open_ports(ports) for ports in targets.values()):
                d = dict(scan)
                d["targets"] = targets
                return d
    return None


# ══════════════════════════════════════════════════════════════════
#  Guard journal
# ══════════════════════════════════════════════════════════════════

# Actions recorded by the ARP-cut guardian. Anything else is rejected so a
# typo cannot quietly fill the journal with a bogus action.
_GUARD_ACTIONS = frozenset({"cut", "restore", "guard_start", "guard_stop", "refused"})


def record_guard_event(action: str, ip: str | None = None,
                       network: str | None = None, reason: str | None = None) -> None:
    """Append one event to the guard journal. Best-effort: never raises.

    The guardian calls this while cutting and restoring hosts, so a failure
    to write the journal (a locked or read-only database) must not stop it
    from sending the corrective ARP frames. The failure is logged instead.
    """
    if action not in _GUARD_ACTIONS:
        log.warning("guard journal: unknown action %r ignored", action)
        return
    try:
        with _conn() as c:
            c.execute(
                "INSERT INTO guard_events (action, ip, network, reason) "
                "VALUES (?, ?, ?, ?)",
                (action, ip, network, reason),
            )
    except sqlite3.Error as exc:
        log.warning("guard journal write failed (%s): %s", action, exc)


def get_guard_events(limit: int = 50) -> list[dict]:
    """Return the most recent guard-journal events, newest first."""
    with _conn() as c:
        rows = c.execute(
            "SELECT id, ts, action, ip, network, reason "
            "FROM guard_events ORDER BY id DESC LIMIT ?",
            (max(1, int(limit)),),
        ).fetchall()
    return [dict(row) for row in rows]
