"""NVD requests: transient failures are retried, and only real requests wait.

Retried with exponential backoff: rate limiting (429, and the 403 NVD sends
to keyless clients over quota), server errors (500/502/503/504), timeouts and
dropped connections. Anything else (404, a malformed request) fails at once,
since repeating it cannot help, and no time is spent sleeping after the last
attempt.

Rate-limit spacing lives in one place, right before each real HTTP request,
measured from the previous one. A result served from the local cache never
reaches it, so a re-run on the same day does not sleep at all.

Time is simulated: sleeping advances a fake clock instead of waiting.
"""
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
import requests

from droidnet.core import database as db
from droidnet.modules import cve_watcher as cve

PAGE = {"startIndex": 0, "resultsPerPage": 0, "totalResults": 0, "vulnerabilities": []}


@pytest.fixture
def net(monkeypatch, tmp_path):
    """Fake clock + scripted requests.get; records when each request was sent."""
    state = SimpleNamespace(now=1000.0, sleeps=[], sent_at=[], responses=[])

    def sleep(seconds):
        state.sleeps.append(seconds)
        state.now += seconds

    def get(*args, **kwargs):
        state.sent_at.append(state.now)
        outcome = state.responses.pop(0) if state.responses else response(200)
        if isinstance(outcome, BaseException):
            raise outcome
        return outcome

    monkeypatch.setattr(cve, "time", SimpleNamespace(
        monotonic=lambda: state.now, sleep=sleep, time=cve.time.time))
    monkeypatch.setattr(cve.requests, "get", get)
    monkeypatch.setattr(cve, "_REQUEST_DELAY", 6.5)
    monkeypatch.setattr(cve, "_last_request_at", None)
    monkeypatch.setattr(cve, "NVD_CACHE_DIR", tmp_path)
    monkeypatch.setattr(cve, "rprint", Mock())
    return state


def response(status, body=None, retry_after=None):
    resp = Mock(status_code=status, headers={"Retry-After": retry_after} if retry_after else {})
    resp.json.return_value = PAGE if body is None else body
    return resp


# ── retries ────────────────────────────────────────────────────────

@pytest.mark.parametrize("failures", [
    [response(500), response(502), response(503), response(504)],
    [requests.Timeout("read timed out"), requests.ConnectionError("connection reset")],
    [response(429), response(403)],
])
def test_transient_failures_are_retried_until_success(net, failures):
    net.responses = [*failures, response(200)]
    assert cve._nvd_get({}, "dnsmasq") == PAGE
    assert len(net.sent_at) == len(failures) + 1


@pytest.mark.parametrize("status", [400, 404])
def test_other_statuses_fail_at_once(net, status):
    net.responses = [response(status)]
    assert cve._nvd_get({}, "dnsmasq") is None
    assert len(net.sent_at) == 1 and net.sleeps == []


def test_non_network_request_errors_are_not_retried(net):
    net.responses = [requests.TooManyRedirects("loop")]
    assert cve._nvd_get({}, "dnsmasq") is None
    assert len(net.sent_at) == 1


def test_retry_after_is_honoured(net):
    net.responses = [response(503, retry_after="20"), response(200)]
    assert cve._nvd_get({}, "dnsmasq") == PAGE
    assert net.sent_at[1] - net.sent_at[0] == 20


def test_no_sleep_after_the_last_attempt(net):
    net.responses = [response(503)] * cve._BACKOFF_MAX_RETRIES
    assert cve._nvd_get({}, "dnsmasq") is None
    assert len(net.sent_at) == cve._BACKOFF_MAX_RETRIES
    assert net.now == net.sent_at[-1]   # gave up straight after the final request


# ── rate-limit spacing ─────────────────────────────────────────────

def test_real_requests_are_spaced_by_the_rate_limit_delay(net):
    cve._nvd_get({}, "a")
    cve._nvd_get({}, "b")
    assert net.sent_at[1] - net.sent_at[0] == 6.5


def test_time_already_elapsed_counts_towards_the_delay(net):
    cve._nvd_get({}, "a")
    net.now += 5          # e.g. parsing and rendering in between
    cve._nvd_get({}, "b")
    assert net.sleeps == [1.5]


def test_cache_hits_never_wait(net):
    cve.query_nvd("dnsmasq")
    net.sleeps.clear()
    for _ in range(3):
        cve.query_nvd("dnsmasq")
    assert net.sleeps == [] and len(net.sent_at) == 1


def test_a_rerun_served_from_cache_does_not_sleep(net, monkeypatch):
    db.save_scan("lab", "20261109_120000", {"192.0.2.1": [
        "53/tcp open domain dnsmasq 2.85",
        "1900/tcp open upnp Portable SDK for UPnP devices 1.6.19 (Linux 3.18.21; UPnP 1.0)"]})
    monkeypatch.setattr(cve, "send_alert", lambda **_: None)

    cve.run_cve_watcher()
    first_run_requests = len(net.sent_at)
    net.sleeps.clear()

    cve.run_cve_watcher()
    assert len(net.sent_at) == first_run_requests   # everything came from cache
    assert net.sleeps == []
