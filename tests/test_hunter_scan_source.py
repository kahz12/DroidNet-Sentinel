"""Hunter analyses the same scan as CVE Watcher: the newest one in the history
database that found at least one open service.

Both modules report on "the latest scan", so they must agree on which one that
is, or a single session lists exploits for one scan and CVEs for another. The
JSON files under reports/ cannot settle it: the newest file by modification
time may be a scan where every host was closed or failed (nothing to look up),
and copying or touching an old report makes it the "newest".
"""
import io
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
from rich.console import Console

from droidnet.core import database as db
from droidnet.modules import hunter


@pytest.fixture
def run(monkeypatch):
    """Run Hunter with exploit lookups stubbed; return its queries and output."""
    rec = Console(file=io.StringIO(), record=True, width=240, color_system=None)
    monkeypatch.setattr(hunter, "rprint", rec.print)
    monkeypatch.setattr(hunter, "console", rec)
    monkeypatch.setattr(hunter, "_searchsploit_path", lambda: "/usr/bin/searchsploit")
    lookup = Mock(return_value=[])
    monkeypatch.setattr(hunter, "hunt_exploits", lookup)

    def go():
        hunter.run_hunter()
        return SimpleNamespace(queries=[c.args[0] for c in lookup.call_args_list],
                               text=rec.export_text())
    return go


def test_hunter_reads_the_scan_cve_watcher_reads(run):
    db.save_scan("home", "20261110_090000", {"192.0.2.1": ["80/tcp open http nginx 1.18.0"]})
    with_services = db.save_scan("home", "20261110_100000",
                                 {"192.0.2.1": ["22/tcp open ssh OpenSSH 9.6p1"]})
    # Newest scan, but nothing to look up on it.
    db.save_scan("home", "20261110_110000", {"192.0.2.1": ["Shield intact"],
                                             "192.0.2.2": ["Error: host unreachable"]})
    out = run()
    assert out.queries == ["OpenSSH 9.6p1"]
    assert db.get_latest_scan_with_services()["id"] == with_services
    assert f"ID: {with_services}" in out.text


def test_no_scan_with_services(run):
    db.save_scan("home", "20261110_110000", {"192.0.2.1": ["Shield intact"]})
    out = run()
    assert out.queries == []
    assert "No scans with detected services found" in out.text


def test_first_run_without_a_history_database(run, monkeypatch, tmp_path):
    # Hunter run before any scan: the database file does not exist yet.
    monkeypatch.setattr(db, "DB_PATH", tmp_path / "never-scanned.db")
    out = run()
    assert out.queries == []
    assert "No scans with detected services found" in out.text
