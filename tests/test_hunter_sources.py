"""Where Hunter looks exploits up, in order of preference.

1. searchsploit, when installed: the local Exploit-DB, fully offline.
2. Vulners, when VULNERS_API_KEY is set. Without a key its API answers
   non-browser clients with a Cloudflare challenge (HTTP 403); with one the
   request reaches the API. The key travels in the X-Api-Key header only, so
   it never appears in a URL that an exception message could print.
3. The Exploit-DB catalogue (see test_exploitdb_catalogue.py), also used when
   a Vulners lookup fails, so a bad key or an outage still gives an answer.
"""
import io
from unittest.mock import Mock

import pytest
import requests
from rich.console import Console

from droidnet import config
from droidnet.core import database as db
from droidnet.modules import exploitdb, hunter

KEY = "0123456789ABCDEFtestkey"


@pytest.fixture
def out(monkeypatch):
    rec = Console(file=io.StringIO(), record=True, width=240, color_system=None)
    monkeypatch.setattr(hunter, "rprint", rec.print)
    monkeypatch.setattr(hunter, "console", rec)
    monkeypatch.setattr(hunter, "_EXPLOIT_CACHE", {})
    return rec.export_text


@pytest.fixture
def sources(monkeypatch):
    """Stub every backend; return the mocks so a test can see which ran."""
    mocks = {
        "local": Mock(return_value=[]),
        "vulners": Mock(return_value=[]),
        "catalogue": Mock(return_value=[]),
    }
    monkeypatch.setattr(hunter, "_hunt_exploits_local", mocks["local"])
    monkeypatch.setattr(hunter, "_hunt_exploits_vulners", mocks["vulners"])
    monkeypatch.setattr(exploitdb, "search", mocks["catalogue"])
    return mocks


# ── which source answers ───────────────────────────────────────────

def test_searchsploit_is_preferred(monkeypatch, sources, out):
    monkeypatch.setattr(hunter, "_searchsploit_path", lambda: "/usr/bin/searchsploit")
    monkeypatch.setattr(config, "VULNERS_API_KEY", KEY)
    hunter.hunt_exploits("vsftpd 2.3.4")
    assert sources["local"].called
    assert not sources["vulners"].called and not sources["catalogue"].called


def test_vulners_is_used_when_a_key_is_configured(monkeypatch, sources, out):
    monkeypatch.setattr(hunter, "_searchsploit_path", lambda: None)
    monkeypatch.setattr(config, "VULNERS_API_KEY", KEY)
    hunter.hunt_exploits("vsftpd 2.3.4")
    sources["vulners"].assert_called_once_with("vsftpd 2.3.4", KEY)
    assert not sources["catalogue"].called


def test_a_failed_vulners_lookup_falls_back_to_the_catalogue(monkeypatch, sources, out):
    monkeypatch.setattr(hunter, "_searchsploit_path", lambda: None)
    monkeypatch.setattr(config, "VULNERS_API_KEY", KEY)
    sources["vulners"].return_value = None
    sources["catalogue"].return_value = [{"Title": "t", "Path": "p", "Date_Published": "d"}]
    assert hunter.hunt_exploits("vsftpd 2.3.4") == sources["catalogue"].return_value


def test_without_searchsploit_or_key_the_catalogue_answers(monkeypatch, sources, out):
    monkeypatch.setattr(hunter, "_searchsploit_path", lambda: None)
    monkeypatch.setattr(config, "VULNERS_API_KEY", "")
    hunter.hunt_exploits("vsftpd 2.3.4")
    sources["catalogue"].assert_called_once_with("vsftpd 2.3.4")
    assert not sources["vulners"].called


@pytest.mark.parametrize("key, says", [
    ("", "Exploit-DB catalogue"),
    (KEY, "Vulners API"),
])
def test_run_announces_the_source_in_use(monkeypatch, sources, out, key, says):
    monkeypatch.setattr(hunter, "_searchsploit_path", lambda: None)
    monkeypatch.setattr(config, "VULNERS_API_KEY", key)
    hunter.run_hunter()
    assert says in out()
    assert KEY not in out()


def test_hosts_without_a_named_product_are_not_listed(monkeypatch, sources, out):
    # A port line with no banner gives nothing to look up; printing the host
    # heading anyway would leave an empty "Analysing" section.
    monkeypatch.setattr(hunter, "_searchsploit_path", lambda: "/usr/bin/searchsploit")
    db.save_scan("lab", "20261110_120000", {"192.0.2.3": ["8008/tcp open http"],
                                            "192.0.2.1": ["53/tcp open domain dnsmasq 2.85"]})
    hunter.run_hunter()
    text = out()
    assert "Analysing: 192.0.2.1" in text and "192.0.2.3" not in text


# ── the Vulners request ────────────────────────────────────────────

class Reply:
    def __init__(self, status, payload=None, text=""):
        self.status_code, self._payload, self.content = status, payload, (text or "x").encode()

    def json(self):
        if self._payload is None:
            raise ValueError("not JSON")
        return self._payload


def test_vulners_key_travels_in_a_header_only(monkeypatch, out):
    post = Mock(return_value=Reply(200, {"result": "OK", "data": {"search": [
        {"_source": {"title": "vsftpd 2.3.4 - Backdoor Command Execution",
                     "href": "https://vulners.com/exploitdb/EDB-ID:49757",
                     "published": "2021-04-12T00:00:00"}}]}}))
    monkeypatch.setattr(hunter.requests, "post", post)
    found = hunter._hunt_exploits_vulners("vsftpd 2.3.4", KEY)
    assert found == [{"Title": "vsftpd 2.3.4 - Backdoor Command Execution",
                      "Path": "https://vulners.com/exploitdb/EDB-ID:49757",
                      "Date_Published": "2021-04-12"}]
    (url,), kwargs = post.call_args
    assert kwargs["headers"]["X-Api-Key"] == KEY
    assert KEY not in url and KEY not in str(kwargs["json"])


@pytest.mark.parametrize("reply, reason", [
    (Reply(401, {"result": "error", "data": {"error": "Unknown api key", "errorCode": 157}}),
     "Unknown api key"),
    (Reply(403, None, "<html>Just a moment...</html>"), "HTTP 403"),
])
def test_vulners_errors_are_reported_and_fail_the_lookup(monkeypatch, out, reply, reason):
    monkeypatch.setattr(hunter.requests, "post", Mock(return_value=reply))
    assert hunter._hunt_exploits_vulners("vsftpd 2.3.4", KEY) is None
    assert reason in out()


def test_vulners_key_is_redacted_from_network_errors(monkeypatch, out):
    error = requests.ConnectionError(f"failed while sending X-Api-Key: {KEY}")
    monkeypatch.setattr(hunter.requests, "post", Mock(side_effect=error))
    assert hunter._hunt_exploits_vulners("vsftpd 2.3.4", KEY) is None
    text = out()
    assert KEY not in text and "<redacted>" in text
