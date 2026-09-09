"""Batch-query and API pagination regression tests using a temporary DB."""
import os
from contextlib import contextmanager

import pytest

from droidnet.core import database as db

os.environ.setdefault("SENTINEL_PASS", "test-import-only")
from droidnet.web import dashboard as dash  # noqa: E402


@pytest.fixture
def history(monkeypatch, tmp_path):
    monkeypatch.setattr(db, "DB_PATH", tmp_path / "history.db")
    db.init_db()
    for index in range(21):
        targets = {f"192.0.2.{i}": ["80/tcp open http"] for i in range(1, 100)}
        targets["192.0.2.100"] = []
        db.save_scan("test", str(index), targets)


def test_history_queries_do_not_grow_per_host(history, monkeypatch):
    connect = db._conn
    queries = []

    @contextmanager
    def traced():
        with connect() as c:
            c.set_trace_callback(queries.append)
            yield c

    monkeypatch.setattr(db, "_conn", traced)
    scans = db.get_all_scans_with_diffs(limit=20)
    assert len(scans) == 20
    assert scans[0]["targets"]["192.0.2.100"] == []
    assert all(not scan["port_changes"] for scan in scans)
    assert len(queries) <= 6


def test_diffs_find_previous_network_outside_page(history):
    db.save_scan("other", "new", {"198.51.100.1": []})
    db.save_scan("test", "empty", {})
    newest = db.get_all_scans_with_diffs(limit=1)[0]
    assert len(newest["gone_ips"]) == 100
    assert newest["new_ips"] == []


def test_api_pagination_preserves_array_and_bounds_work(history):
    client = dash.app.test_client()
    with client.session_transaction() as sess:
        sess["authenticated"] = True
    first = client.get("/api/reports?per_page=10")
    assert len(first.json) == 10
    assert first.headers["X-Total-Count"] == "21"
    assert 'rel="next"' in first.headers["Link"]
    second = client.get("/api/reports?page=2&per_page=10")
    assert {s["id"] for s in first.json}.isdisjoint(s["id"] for s in second.json)
    assert len(client.get("/api/reports?page=3&per_page=10").json) == 1
    assert client.get("/api/reports?page=99999999999999999999999999").json == []
    assert client.get("/api/reports?page=no").status_code == 400
    assert client.get("/api/reports?per_page=99999").headers["X-Per-Page"] == "100"
