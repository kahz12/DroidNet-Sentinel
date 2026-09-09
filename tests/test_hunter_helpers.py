"""Unit tests for hunter's searchsploit path detection."""

import droidnet.modules.hunter as hunter
from unittest.mock import Mock


def test_searchsploit_path_probed_each_call(monkeypatch):
    # Binary present → path returned.
    monkeypatch.setattr(
        hunter.shutil, "which",
        lambda name: "/usr/bin/searchsploit" if name == "searchsploit" else None,
    )
    assert hunter._searchsploit_path() == "/usr/bin/searchsploit"

    # Binary later removed at runtime → re-probed, no import-time cache.
    monkeypatch.setattr(hunter.shutil, "which", lambda name: None)
    assert hunter._searchsploit_path() is None


def test_hunter_retries_errors_but_caches_successful_empty_results(monkeypatch):
    monkeypatch.setattr(hunter, "_EXPLOIT_CACHE", {})
    monkeypatch.setattr(hunter, "_searchsploit_path", lambda: "searchsploit")
    query = Mock(side_effect=[None, []])
    monkeypatch.setattr(hunter, "_hunt_exploits_local", query)
    assert hunter.hunt_exploits("nginx") is None
    assert hunter.hunt_exploits("nginx") == []
    assert hunter.hunt_exploits("nginx") == []
    assert query.call_count == 2


def test_each_hunter_run_refreshes_cache(monkeypatch):
    monkeypatch.setattr(hunter, "_EXPLOIT_CACHE", {"nginx": [{"Title": "stale"}]})
    monkeypatch.setattr(hunter, "_searchsploit_path", lambda: "searchsploit")
    monkeypatch.setattr(hunter, "get_latest_report", lambda: None)
    hunter.run_hunter()
    assert not hunter._EXPLOIT_CACHE
