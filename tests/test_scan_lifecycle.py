"""Scan and response lifecycle with simulated processes; no network packets are sent."""
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
    # A firewall dropping every probe exposes nothing: same as all-closed.
    (0, '<nmaprun><host><status state="up"/><ports><extraports state="filtered" count="100"/></ports></host><runstats><finished exit="success"/></runstats></nmaprun>', "Shield intact"),
    (0, '<nmaprun><host><status state="up"/><ports/></host><runstats><finished exit="success"/></runstats></nmaprun>', "Error: inconclusive port states"),
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


def test_spoofer_logs_warning_when_backends_missing_or_arpspoof_exits_early(monkeypatch):
    warnings = []
    monkeypatch.setattr(spoofer.log, "warning", lambda msg, *args: warnings.append(msg % args if args else msg))
    monkeypatch.setattr(spoofer, "_arpspoof_available", lambda: False)
    monkeypatch.setattr(spoofer, "_SCAPY_OK", False)
    spoofer.poison("192.0.2.10", "192.0.2.1", "wlan0")
    assert any("neither arpspoof nor scapy available" in w for w in warnings)

    warnings.clear()
    proc = Mock()
    proc.poll.return_value = 1
    monkeypatch.setattr(spoofer, "_arpspoof_available", lambda: True)
    monkeypatch.setattr(spoofer.subprocess, "Popen", lambda *a, **k: proc)
    spoofer.poison("192.0.2.10", "192.0.2.1", "wlan0")
    assert any("arpspoof terminated unexpectedly" in w for w in warnings)


def test_nmap_discovery_and_host_scan_log_warnings_on_failure(monkeypatch):
    warnings = []
    monkeypatch.setattr(sentinel.log, "warning", lambda msg, *args: warnings.append(msg % args if args else msg))
    monkeypatch.setattr(
        sentinel.subprocess,
        "run",
        lambda *a, **k: SimpleNamespace(returncode=2, stdout="", stderr="failed to open raw socket"),
    )
    rc, _ = sentinel._run_nmap_sn(["nmap", "-sn", "192.0.2.0/24"])
    assert rc == 2
    assert any("failed to open raw socket" in w for w in warnings)

    warnings.clear()
    monkeypatch.setattr(sentinel, "_nmap_host", Mock(side_effect=RuntimeError("unexpected crash")))
    assert sentinel._scan_one("192.0.2.10") == ("192.0.2.10", ["Error"])
    assert any("unexpected crash" in w for w in warnings)


def test_print_banner_logs_debug_when_env_probe_raises(monkeypatch):
    from droidnet.cli import menu
    from droidnet.core import env

    debugs = []
    monkeypatch.setattr(menu.console, "print", lambda *a, **k: None)
    monkeypatch.setattr(env, "evaluate_system", Mock(side_effect=RuntimeError("probe boom")))
    monkeypatch.setattr(menu.log, "debug", lambda msg, *args: debugs.append(msg % args if args else msg))
    menu.print_banner()
    assert any("probe boom" in d for d in debugs)

