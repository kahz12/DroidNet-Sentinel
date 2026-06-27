"""Unit tests for hunter's searchsploit path detection."""

import droidnet.modules.hunter as hunter


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
