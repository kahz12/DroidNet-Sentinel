"""Batched history queries and API pagination, against a temporary DB."""
import os
import re
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


def _auth(client):
    with client.session_transaction() as sess:
        sess["authenticated"] = True


def _page_label(html):
    m = re.search(r"Page (\d+) of (\d+) · (\d+) scans", html)
    return m.group(0) if m else None


def test_html_and_api_paginate_by_the_same_rules(history):
    # 21 scans. The HTML view and the JSON API share per_page clamping and the
    # page count, but differ by contract on bad input and out-of-range pages:
    # the browser view stays lenient and shows the nearest real page, the API
    # is strict and returns an empty array past the end.
    client = dash.app.test_client()
    _auth(client)

    # per_page over the cap is held at _MAX_PAGE_SIZE on both sides.
    assert client.get("/api/reports?per_page=99999").headers["X-Per-Page"] == "100"
    # Held at 100, all 21 scans fit on one page, so no pager is rendered.
    assert _page_label(client.get("/?per_page=99999").get_data(as_text=True)) is None

    # Same page count for the same window: 21 / 10 → 3 pages.
    assert "Page 1 of 3" in client.get("/?per_page=10").get_data(as_text=True)
    assert client.get("/api/reports?per_page=10").headers["X-Total-Count"] == "21"

    # Out-of-range page: HTML shows the last page, the API returns nothing.
    assert "Page 2 of 2" in client.get("/?page=99").get_data(as_text=True)
    assert client.get("/api/reports?page=99").json == []

    # Non-integer input: HTML falls back to page 1, the API rejects it.
    assert "Page 1 of 2" in client.get("/?page=abc").get_data(as_text=True)
    assert client.get("/api/reports?page=abc").status_code == 400


def test_next_page_link_is_absolute_and_follows_the_request_host(history):
    # RFC 8288 allows a relative Link target, but many HTTP clients only follow
    # an absolute URL. Build it from the request host so it is followable both
    # on loopback and when the dashboard is exposed on the LAN (--expose).
    host = "http://192.168.1.50:5000"
    client = dash.app.test_client()
    with client.session_transaction(base_url=host) as sess:
        sess["authenticated"] = True
    link = client.get("/api/reports?per_page=10", base_url=host).headers["Link"]
    assert link.startswith("<http://192.168.1.50:5000/api/reports?")
    assert 'page=2' in link and 'per_page=10' in link and link.endswith('>; rel="next"')


def test_api_without_params_returns_full_history(history):
    # Integrations that do not paginate: a bare GET returns every stored
    # scan, not just the first page.
    client = dash.app.test_client()
    with client.session_transaction() as sess:
        sess["authenticated"] = True
    resp = client.get("/api/reports")
    assert resp.status_code == 200
    assert len(resp.json) == 21
    assert resp.headers["X-Total-Count"] == "21"
    assert "Link" not in resp.headers
    # Supplying either parameter opts into pagination.
    assert len(client.get("/api/reports?page=1").json) == dash._DEFAULT_PAGE_SIZE
    assert len(client.get("/api/reports?per_page=5").json) == 5


def test_diff_queries_use_stored_host_risks_without_recomputing(history, monkeypatch):
    monkeypatch.setattr(
        db,
        "classify_risk",
        lambda _ports: pytest.fail("classify_risk should not be recomputed on read"),
    )
    scans = db.get_all_scans_with_diffs(limit=2)
    assert scans[0]["risks"]["192.0.2.1"] == "MEDIUM"
    assert scans[0]["risks"]["192.0.2.100"] == "MINIMAL"

    diff = db.get_scan_diff(scans[0]["id"])
    assert diff["risks"]["192.0.2.1"] == "MEDIUM"
    assert diff["risks"]["192.0.2.100"] == "MINIMAL"

