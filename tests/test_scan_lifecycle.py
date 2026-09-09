"""Regression tests with simulated processes; never send network packets."""
from threading import Event
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from droidnet.modules import sentinel, spoofer
from droidnet.core.risk import classify_risk


@pytest.mark.parametrize("rc,xml,expected", [
    (1, "", "Error: nmap failed"),
    (0, "broken", "Error"),
    (0, '<nmaprun><runstats><finished exit="success"/></runstats></nmaprun>', "Error: host unreachable"),
    (0, '<nmaprun><host><status state="up"/><ports><extraports state="filtered" count="100"/></ports></host><runstats><finished exit="success"/></runstats></nmaprun>', "Error: inconclusive port states"),
    (0, '<nmaprun><host><status state="up"/><ports><extraports state="closed" count="100"/></ports></host><runstats><finished exit="success"/></runstats></nmaprun>', "Shield intact"),
    (0, '<nmaprun><host><status state="up"/><ports><port protocol="tcp" portid="80"><state state="open"/><service name="http" product="nginx" version="1.18.0"/></port></ports></host><runstats><finished exit="success"/></runstats></nmaprun>', "80/tcp open http nginx 1.18.0"),
])
def test_nmap_states(monkeypatch, rc, xml, expected):
    monkeypatch.setattr(sentinel.subprocess, "run", lambda *a, **k: SimpleNamespace(returncode=rc, stdout=xml, stderr="failure"))
    _, ports = sentinel._scan_one("192.0.2.10")
    assert ports == [expected]
    if expected.startswith("Error"):
        assert classify_risk(ports) == "UNKNOWN"


def test_second_process_failure_reaps_first(monkeypatch):
    proc = Mock()
    proc.poll.return_value = None
    monkeypatch.setattr(spoofer, "_arpspoof_available", lambda: True)
    monkeypatch.setattr(spoofer.subprocess, "Popen", Mock(side_effect=[proc, OSError("failed")]))
    with pytest.raises(OSError):
        spoofer.poison("192.0.2.10", "192.0.2.1", "fake0")
    proc.terminate.assert_called_once()
    proc.wait.assert_called_once_with(timeout=5)


def test_response_jobs_deduplicate_cancel_and_join(monkeypatch):
    started, stopped = Event(), Event()

    def fake_poison(*args, stop_event):
        started.set()
        stop_event.wait(2)
        stopped.set()

    monkeypatch.setattr(spoofer, "poison", fake_poison)
    jobs = sentinel.AutoCutSession()
    key = ("192.0.2.10", "192.0.2.1", "fake0")
    try:
        jobs.update({key})
        assert started.wait(1)
        thread = jobs.jobs[key][1]
        jobs.update({key})
        assert jobs.jobs[key][1] is thread
        jobs.update(set())
        assert stopped.is_set()
        assert not thread.is_alive()
        assert not jobs.jobs
    finally:
        jobs.close()


def test_scanner_cleans_responses_on_interrupt(monkeypatch):
    jobs = Mock()
    monkeypatch.setattr(sentinel, "AutoCutSession", lambda: jobs)
    monkeypatch.setattr(sentinel, "_run_sentinel_loop", Mock(side_effect=KeyboardInterrupt))
    with pytest.raises(KeyboardInterrupt):
        sentinel.run_sentinel()
    jobs.close.assert_called_once()


def test_discovery_failure_differs_from_empty(monkeypatch):
    monkeypatch.setattr(sentinel, "_run_nmap_sn", lambda _: (1, ""))
    assert sentinel.ping_sweep("192.0.2.10", []) is None
    xml = '<nmaprun><runstats><finished exit="success"/></runstats></nmaprun>'
    monkeypatch.setattr(sentinel, "_run_nmap_sn", lambda _: (0, xml))
    assert sentinel.ping_sweep("192.0.2.10", []) == {}


def test_interrupt_cancels_queued_scans(monkeypatch):
    pool = Mock()
    monkeypatch.setattr(sentinel, "ThreadPoolExecutor", lambda **kwargs: pool)
    monkeypatch.setattr(sentinel, "as_completed", Mock(side_effect=KeyboardInterrupt))
    with pytest.raises(KeyboardInterrupt):
        sentinel.deep_scan(["192.0.2.10", "192.0.2.20"])
    pool.shutdown.assert_called_once_with(wait=True, cancel_futures=True)


def test_discovery_metadata(monkeypatch):
    xml = '<nmaprun><host><status state="up"/><address addr="192.0.2.20" addrtype="ipv4"/><address addr="AA:BB:CC:DD:EE:FF" addrtype="mac" vendor="Vendor"/><hostnames><hostname name="device"/></hostnames></host><runstats><finished exit="success"/></runstats></nmaprun>'
    monkeypatch.setattr(sentinel, "_run_nmap_sn", lambda _: (0, xml))
    assert sentinel.ping_sweep("192.0.2.10", []) == {
        "192.0.2.20": {"hostname": "device", "mac": "AA:BB:CC:DD:EE:FF", "vendor": "Vendor"}}


def test_failed_discovery_retries_and_empty_scan_records_disappearance(monkeypatch, tmp_path):
    from droidnet.core import database
    monkeypatch.setattr(database, "DB_PATH", tmp_path / "test.db")
    database.init_db()
    database.save_scan("test", "20260909_000000", {"192.0.2.20": ["80/tcp open http"]})
    monkeypatch.setattr(sentinel, "get_wifi_info", lambda: {"ssid": "test", "ip": "192.0.2.10"})
    monkeypatch.setattr(sentinel, "load_user_config", lambda: {"db_retention_days": 0})
    discover = Mock(side_effect=[None, {}])
    monkeypatch.setattr(sentinel, "ping_sweep", discover)
    monkeypatch.setattr(sentinel, "save_report", Mock())
    monkeypatch.setattr(sentinel, "display_results_table", Mock())
    alert = Mock()
    monkeypatch.setattr(sentinel, "send_alert", alert)
    monkeypatch.setattr(sentinel.time, "sleep", Mock(side_effect=[None, KeyboardInterrupt]))
    with pytest.raises(KeyboardInterrupt):
        sentinel.run_sentinel(interactive=False)
    assert discover.call_count == 2
    scans = database.get_all_scans_with_diffs()
    assert len(scans) == 2
    assert scans[0]["targets"] == {}
    assert scans[0]["gone_ips"] == ["192.0.2.20"]
    alert.assert_called_once()
