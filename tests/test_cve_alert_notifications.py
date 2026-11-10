"""CVE alerts are refreshed on every run but announced once per change.

save_cve_alert upserts, so a re-detection updates the stored row (a CVE first
seen as UNKNOWN takes NVD's real severity once it is scored), and only a new
alert, a severity change or a candidate→CPE confirmation is announced — a
repeated, unchanged match is not re-sent to Telegram.
"""
import sqlite3

import pytest

from droidnet.core import database as db
from droidnet.modules import cve_watcher as cve

KEY = dict(cve_id="CVE-2026-0001", ip="192.0.2.5", service="nginx 1.18.0", network="lab")


def save(**over):
    fields = {**KEY, "severity": "UNKNOWN", "score": None, "summary": "s",
              "impact": "Affected service: nginx 1.18.0 on 1 host(s)", "match_type": "cpe"}
    return db.save_cve_alert(**{**fields, **over})


def mark():
    db.mark_cve_alerts_notified([(KEY["cve_id"], KEY["ip"], KEY["service"], KEY["network"])])


# ── storage: upsert + notification state ───────────────────────────

def test_new_alert_stays_pending_until_announced():
    assert save() is True
    assert save() is True     # never announced yet: still pending
    mark()
    assert save() is False    # announced and unchanged
    assert len(db.get_cve_alerts()) == 1


def test_redetection_refreshes_stored_fields_and_escalation_renotifies():
    save()
    mark()
    # NVD scored the CVE after it was first stored as UNKNOWN.
    assert save(severity="CRITICAL", score=9.8, impact="new impact", summary="s2") is True
    [row] = db.get_cve_alerts()
    assert (row["severity"], row["score"], row["impact"], row["summary"]) == \
        ("CRITICAL", 9.8, "new impact", "s2")


def test_score_change_alone_does_not_renotify():
    save(severity="HIGH", score=7.5)
    mark()
    assert save(severity="HIGH", score=7.8) is False
    assert db.get_cve_alerts()[0]["score"] == 7.8


def test_candidate_confirmed_by_cpe_renotifies_but_not_the_reverse():
    save(severity="HIGH", match_type="candidate")
    mark()
    assert save(severity="HIGH", match_type="cpe") is True
    mark()
    assert save(severity="HIGH", match_type="candidate") is False
    # The stored row still reflects how the latest run matched it.
    assert db.get_cve_alerts()[0]["match_type"] == "candidate"


def test_upgrade_adds_columns_and_does_not_resend_existing_alerts(tmp_path, monkeypatch):
    path = tmp_path / "before-upgrade.db"
    monkeypatch.setattr(db, "DB_PATH", path)
    conn = sqlite3.connect(path)
    conn.executescript("""
        CREATE TABLE cve_alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            cve_id TEXT NOT NULL, severity TEXT NOT NULL DEFAULT 'UNKNOWN',
            score REAL, service TEXT NOT NULL, ip TEXT NOT NULL,
            summary TEXT NOT NULL, impact TEXT, network TEXT NOT NULL,
            scan_id INTEGER, created_at TEXT NOT NULL DEFAULT (datetime('now')),
            UNIQUE(cve_id, ip, service, network)
        );
        INSERT INTO cve_alerts (cve_id, severity, score, service, ip, summary, impact, network)
        VALUES ('CVE-2026-0001', 'HIGH', 7.5, 'nginx 1.18.0', '192.0.2.5', 's',
                'Affected service: nginx 1.18.0 on 1 host(s)', 'lab'),
               ('CVE-2026-0002', 'HIGH', 7.5, 'nginx 1.18.0', '192.0.2.5', 's',
                'Candidate match: nginx 1.18.0 on 1 host(s); version applicability unverified', 'lab');
    """)
    conn.close()

    db.init_db()

    types = {r["cve_id"]: r["match_type"] for r in db.get_cve_alerts()}
    assert types == {"CVE-2026-0001": "cpe", "CVE-2026-0002": "candidate"}
    # Rows that predate the notification columns are backfilled as announced,
    # so re-detecting one on the first run after the upgrade stays quiet.
    assert save(severity="HIGH", score=7.5) is False

    # A genuinely new alert stays pending across later init_db() calls.
    assert save(cve_id="CVE-2026-0003", severity="HIGH") is True
    db.init_db()
    assert save(cve_id="CVE-2026-0003", severity="HIGH") is True


# ── run_cve_watcher: what reaches Telegram ─────────────────────────

def nvd(cve_id, severity="HIGH", score=7.5):
    return {"cve_id": cve_id, "severity": severity, "score": score,
            "description": "remote code execution", "cwes": [], "kev": False}


@pytest.fixture
def watcher(monkeypatch):
    """Real (isolated) DB and scan; NVD results and delivery outcome scripted."""
    db.save_scan("lab", "20261109_120000", {"192.0.2.5": ["80/tcp open http nginx 1.18.0"]})
    state = {"cves": [nvd("CVE-2026-0001")], "delivery": True, "sent": []}
    monkeypatch.setattr(cve.time, "sleep", lambda _: None)
    monkeypatch.setattr(cve, "query_nvd", lambda *_, **__: [dict(c) for c in state["cves"]])

    def send_alert(title, local_msg, telegram_msg):
        state["sent"].append(telegram_msg)
        return state["delivery"]

    monkeypatch.setattr(cve, "send_alert", send_alert)
    return state


def test_unchanged_findings_are_not_resent(watcher, capsys):
    cve.run_cve_watcher()
    result = cve.run_cve_watcher()
    assert len(watcher["sent"]) == 1
    assert len(result) == 1                       # still shown on the terminal
    assert "No new or changed CVE alerts" in capsys.readouterr().out


def test_only_the_escalated_cve_is_resent(watcher):
    watcher["cves"] = [nvd("CVE-2026-0001", "UNKNOWN", None), nvd("CVE-2026-0002")]
    cve.run_cve_watcher()
    watcher["cves"] = [nvd("CVE-2026-0001", "CRITICAL", 9.8), nvd("CVE-2026-0002")]
    cve.run_cve_watcher()
    first, second = watcher["sent"]
    assert "CVE-2026-0001" in first and "CVE-2026-0002" in first
    assert "CVE-2026-0001" in second and "CVE-2026-0002" not in second
    assert "CRITICAL" in second
    assert {r["cve_id"]: r["severity"] for r in db.get_cve_alerts()}["CVE-2026-0001"] == "CRITICAL"


def test_failed_delivery_is_retried_next_run(watcher):
    watcher["delivery"] = False      # Telegram rejected / unreachable
    cve.run_cve_watcher()
    watcher["delivery"] = True
    cve.run_cve_watcher()
    cve.run_cve_watcher()
    assert len(watcher["sent"]) == 2  # retried once, then settled


def test_unconfigured_telegram_counts_as_announced(watcher):
    watcher["delivery"] = None       # no bot configured: local notification only
    cve.run_cve_watcher()
    cve.run_cve_watcher()
    assert len(watcher["sent"]) == 1
