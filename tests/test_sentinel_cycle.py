"""Unit tests for the Sentinel discovery, ARP-cut, reporting and main loop cycle.

Every external side effect (subprocess, ARP spoofing, probes, alerts, Wi-Fi/route
lookups, sleep) is blocked by an autouse fixture; individual tests replace only
the collaborators they exercise.
"""

import io
import json
import subprocess
from datetime import datetime, timedelta
from types import SimpleNamespace
from unittest.mock import Mock, call

import pytest
from rich.console import Console

from droidnet.core.database import get_guard_events
from droidnet.modules import sentinel, spoofer


_EMPTY_NMAP_XML = '<nmaprun><runstats><finished exit="success"/></runstats></nmaprun>'
_ONE_HOST_XML = (
    '<nmaprun>'
    '<host><status state="up"/>'
    '<address addr="192.0.2.20" addrtype="ipv4"/>'
    '<address addr="AA:BB:CC:DD:EE:FF" addrtype="mac" vendor="Acme"/>'
    '<hostnames><hostname name="box.lan"/></hostnames>'
    '</host>'
    '<runstats><finished exit="success"/></runstats>'
    '</nmaprun>'
)


def _forbid(name: str):
    def _fail(*args, **kwargs):
        pytest.fail(f"Unexpected external effect: {name}")

    return _fail


def _forbid_sleep(seconds):
    raise AssertionError(f"Unexpected sentinel.time.sleep({seconds!r})")


@pytest.fixture(autouse=True)
def _block_external_effects(monkeypatch, tmp_path):
    """Fail immediately if a test leaks into subprocesses, probes, ARP or sleep."""
    monkeypatch.setattr(sentinel.subprocess, "run", _forbid("sentinel.subprocess.run"))
    monkeypatch.setattr(sentinel.subprocess, "Popen", _forbid("sentinel.subprocess.Popen"))
    monkeypatch.setattr(spoofer, "poison", _forbid("droidnet.modules.spoofer.poison"))
    monkeypatch.setattr(sentinel, "send_alert", _forbid("sentinel.send_alert"))
    monkeypatch.setattr(sentinel, "mdns_probe", _forbid("sentinel.mdns_probe"))
    monkeypatch.setattr(sentinel, "reverse_lookup", _forbid("sentinel.reverse_lookup"))
    monkeypatch.setattr(sentinel, "ssdp_probe", _forbid("sentinel.ssdp_probe"))
    monkeypatch.setattr(sentinel, "cast_probe", _forbid("sentinel.cast_probe"))
    monkeypatch.setattr(sentinel, "get_wifi_info", _forbid("sentinel.get_wifi_info"))
    monkeypatch.setattr(sentinel, "get_default_gateway", _forbid("sentinel.get_default_gateway"))
    monkeypatch.setattr(sentinel, "get_default_iface", _forbid("sentinel.get_default_iface"))
    monkeypatch.setattr(sentinel, "REPORTS_DIR", tmp_path / "reports")
    monkeypatch.setattr(sentinel.time, "sleep", _forbid_sleep)


def _record_output(monkeypatch):
    rec = Console(file=io.StringIO(), record=True, width=240, color_system=None)
    monkeypatch.setattr(sentinel, "rprint", rec.print)
    monkeypatch.setattr(sentinel, "console", rec)
    return rec.export_text


def _capture_log(monkeypatch, level: str) -> list[str]:
    messages: list[str] = []
    monkeypatch.setattr(
        sentinel.log,
        level,
        lambda msg, *args, **kwargs: messages.append(msg % args if args else str(msg)),
    )
    return messages


def _freeze_now(monkeypatch, get_now):
    class _FrozenDatetime(datetime):
        @classmethod
        def now(cls, tz=None):
            return get_now()

    monkeypatch.setattr(sentinel, "datetime", _FrozenDatetime)


def _fake_jobs():
    return SimpleNamespace(jobs={}, network=None, update=Mock(), wait=Mock(), close=Mock())


def _stub_scan_pipeline(monkeypatch, metadata, scan_results, order=None):
    """Replace the per-scan collaborators of _run_sentinel_loop with recorders."""
    def _wrap(name, fn):
        def _inner(*args, **kwargs):
            if order is not None:
                order.append(name)
            return fn(*args, **kwargs)

        return Mock(side_effect=_inner)

    stubs = SimpleNamespace(
        ping_sweep=_wrap("ping_sweep", lambda ip, ex: dict(metadata)),
        identify_devices=_wrap("identify_devices", lambda meta, ip: None),
        deep_scan=_wrap("deep_scan", lambda ips: dict(scan_results)),
        add_dhcp_fingerprints=_wrap("add_dhcp_fingerprints", lambda meta, dhcp: None),
        save_report=_wrap("save_report", lambda ssid, res: None),
        save_scan=_wrap("save_scan", lambda ssid, ts, res: 1),
        display_results_table=_wrap("display_results_table", lambda ssid, res, meta: None),
        cut_unknowns=_wrap("cut_unknowns", lambda *a, **k: None),
        send_alert=_wrap("send_alert", lambda **k: None),
    )
    for attr in vars(stubs):
        monkeypatch.setattr(sentinel, attr, getattr(stubs, attr))
    return stubs


# ── Discovery ──────────────────────────────────────────────────────


@pytest.mark.parametrize("xml", [
    "<nmaprun/>",
    "<nmaprun><runstats/></nmaprun>",
    "<nmaprun><runstats><finished/></runstats></nmaprun>",
    '<nmaprun><runstats><finished exit="error"/></runstats></nmaprun>',
], ids=["no-runstats", "no-finished", "missing-exit", "non-success-exit"])
def test_parse_nmap_sn_rejects_incomplete_or_failed_runstats(xml):
    with pytest.raises(ValueError, match="Incomplete Nmap discovery"):
        sentinel._parse_nmap_sn(xml)


def test_parse_nmap_sn_skips_non_up_or_non_ipv4_and_defaults_optional_fields():
    xml = (
        "<nmaprun>"
        # Down host: skipped.
        '<host><status state="down"/><address addr="192.0.2.1" addrtype="ipv4"/></host>'
        # Missing status element: skipped.
        '<host><address addr="192.0.2.2" addrtype="ipv4"/></host>'
        # Up host without IPv4 (IPv6 + MAC only): skipped.
        '<host><status state="up"/>'
        '<address addr="fe80::1" addrtype="ipv6"/>'
        '<address addr="AA:BB:CC:DD:EE:00" addrtype="mac"/></host>'
        # Up host with IPv4 only: hostname, mac and vendor are None.
        '<host><status state="up"/><address addr="192.0.2.20" addrtype="ipv4"/></host>'
        # Up host with MAC lacking vendor attribute.
        '<host><status state="up"/>'
        '<address addr="192.0.2.21" addrtype="ipv4"/>'
        '<address addr="AA:BB:CC:DD:EE:01" addrtype="mac"/></host>'
        # Up host with every field populated.
        '<host><status state="up"/>'
        '<address addr="192.0.2.22" addrtype="ipv4"/>'
        '<address addr="AA:BB:CC:DD:EE:02" addrtype="mac" vendor="Acme"/>'
        '<hostnames><hostname name="printer.lan"/></hostnames></host>'
        '<runstats><finished exit="success"/></runstats>'
        "</nmaprun>"
    )
    assert sentinel._parse_nmap_sn(xml) == {
        "192.0.2.20": {"hostname": None, "mac": None, "vendor": None},
        "192.0.2.21": {"hostname": None, "mac": "AA:BB:CC:DD:EE:01", "vendor": None},
        "192.0.2.22": {"hostname": "printer.lan", "mac": "AA:BB:CC:DD:EE:02", "vendor": "Acme"},
    }


def test_run_nmap_sn_forwards_argv_and_subprocess_options(monkeypatch):
    seen = []
    warnings = _capture_log(monkeypatch, "warning")

    def fake_run(argv, **kwargs):
        seen.append((argv, kwargs))
        return SimpleNamespace(returncode=0, stdout=_EMPTY_NMAP_XML, stderr="")

    monkeypatch.setattr(sentinel.subprocess, "run", fake_run)
    argv = ["nmap", "-sn", "-oX", "-", "192.0.2.0/24"]
    assert sentinel._run_nmap_sn(argv) == (0, _EMPTY_NMAP_XML)
    assert seen == [(
        argv,
        {"capture_output": True, "text": True, "timeout": 180, "stdin": subprocess.DEVNULL},
    )]
    assert warnings == []


def test_run_nmap_sn_nonzero_exit_returns_rc_and_stdout_and_logs_stderr(monkeypatch):
    warnings = _capture_log(monkeypatch, "warning")
    monkeypatch.setattr(
        sentinel.subprocess,
        "run",
        lambda *a, **k: SimpleNamespace(
            returncode=2, stdout="<partial/>", stderr="  permission denied \n",
        ),
    )
    assert sentinel._run_nmap_sn(["nmap", "-sn", "192.0.2.0/24"]) == (2, "<partial/>")
    assert warnings == ["nmap discovery failed exit=2 stderr=permission denied"]


def test_run_nmap_sn_timeout_returns_124_logs_warning_and_prints_message(monkeypatch):
    warnings = _capture_log(monkeypatch, "warning")
    text_of = _record_output(monkeypatch)
    monkeypatch.setattr(
        sentinel.subprocess,
        "run",
        Mock(side_effect=subprocess.TimeoutExpired(["nmap", "-sn"], 180)),
    )
    assert sentinel._run_nmap_sn(["nmap", "-sn", "192.0.2.0/24"]) == (124, "")
    assert warnings == ["nmap discovery timed out (180s)"]
    assert "timed out" in text_of()


def test_run_nmap_sn_unexpected_error_returns_1_and_logs_warning(monkeypatch):
    warnings = _capture_log(monkeypatch, "warning")
    text_of = _record_output(monkeypatch)
    monkeypatch.setattr(
        sentinel.subprocess,
        "run",
        Mock(side_effect=FileNotFoundError("nmap not installed")),
    )
    assert sentinel._run_nmap_sn(["nmap", "-sn", "192.0.2.0/24"]) == (1, "")
    assert warnings == ["nmap discovery failed: nmap not installed"]
    assert text_of() == ""


def test_ping_sweep_primary_argv_with_and_without_excludes(monkeypatch):
    calls = []

    def fake_run_sn(argv):
        calls.append(argv)
        return 0, _ONE_HOST_XML

    monkeypatch.setattr(sentinel, "_run_nmap_sn", fake_run_sn)
    expected_hosts = {
        "192.0.2.20": {"hostname": "box.lan", "mac": "AA:BB:CC:DD:EE:FF", "vendor": "Acme"},
    }

    assert sentinel.ping_sweep("192.0.2.10", ["192.0.2.10", "192.0.2.99"]) == expected_hosts
    assert calls == [
        ["nmap", "-sn", "-oX", "-", "192.0.2.0/24", "--exclude", "192.0.2.10,192.0.2.99"],
    ]

    calls.clear()
    assert sentinel.ping_sweep("192.0.2.10", []) == expected_hosts
    assert calls == [["nmap", "-sn", "-oX", "-", "192.0.2.0/24"]]


@pytest.mark.parametrize("bad_primary", [
    "<not-xml",
    '<nmaprun><runstats><finished exit="error"/></runstats></nmaprun>',
], ids=["unparseable-xml", "incomplete-xml"])
def test_ping_sweep_falls_back_on_unparseable_or_incomplete_primary(monkeypatch, bad_primary):
    calls = []
    responses = iter([(0, bad_primary), (0, _ONE_HOST_XML)])

    def fake_run_sn(argv):
        calls.append(argv)
        return next(responses)

    monkeypatch.setattr(sentinel, "_run_nmap_sn", fake_run_sn)
    hosts = sentinel.ping_sweep("192.0.2.10", [])
    assert hosts == {
        "192.0.2.20": {"hostname": "box.lan", "mac": "AA:BB:CC:DD:EE:FF", "vendor": "Acme"},
    }
    assert calls == [
        ["nmap", "-sn", "-oX", "-", "192.0.2.0/24"],
        ["nmap", "-sn", "-oX", "-", "-PE", "-PA80", "-PS22,80,443", "192.0.2.0/24"],
    ]


def test_ping_sweep_empty_complete_primary_with_failing_fallback_returns_empty(monkeypatch):
    calls = []
    responses = iter([(0, _EMPTY_NMAP_XML), (1, "")])

    def fake_run_sn(argv):
        calls.append(argv)
        return next(responses)

    monkeypatch.setattr(sentinel, "_run_nmap_sn", fake_run_sn)
    assert sentinel.ping_sweep("192.0.2.10", []) == {}
    assert len(calls) == 2


@pytest.mark.parametrize("pair", [
    [(0, "<broken"), (1, "")],
    [(1, ""), (0, "<nmaprun/>")],
], ids=["bad-primary-and-rc1-fallback", "rc1-primary-and-incomplete-fallback"])
def test_ping_sweep_both_passes_failing_returns_none(monkeypatch, pair):
    calls = []
    responses = iter(pair)

    def fake_run_sn(argv):
        calls.append(argv)
        return next(responses)

    monkeypatch.setattr(sentinel, "_run_nmap_sn", fake_run_sn)
    assert sentinel.ping_sweep("192.0.2.10", []) is None
    assert len(calls) == 2


# ── Automatic ARP cut ──────────────────────────────────────────────


def test_cut_event_triggers_on_active_only_on_first_wait():
    on_active = Mock()
    ev = sentinel._CutEvent(on_active)
    assert not ev.active
    assert not ev.ready.is_set()

    assert ev.wait(timeout=0) is False
    on_active.assert_called_once_with()
    assert ev.active is True
    assert ev.ready.is_set()

    assert ev.wait(timeout=0) is False
    assert on_active.call_count == 1

    ev.set()
    assert ev.wait(timeout=0) is True
    assert on_active.call_count == 1


def test_cut_event_already_set_before_first_wait_never_calls_on_active():
    on_active = Mock()
    ev = sentinel._CutEvent(on_active)
    ev.set()

    assert ev.wait(timeout=0) is True
    on_active.assert_not_called()
    assert ev.active is False
    assert not ev.ready.is_set()


def test_auto_cut_session_update_removes_job_when_thread_start_raises(monkeypatch):
    class _FailingThread:
        def __init__(self, target, args):
            self.target = target
            self.args = args

        def start(self):
            raise RuntimeError("cannot start thread")

    monkeypatch.setattr(sentinel.threading, "Thread", _FailingThread)
    jobs = sentinel.AutoCutSession()
    key = ("192.0.2.50", "192.0.2.1", "wlan0")

    with pytest.raises(RuntimeError, match="cannot start thread"):
        jobs.update({key})

    assert jobs.jobs == {}
    assert get_guard_events() == []


def test_auto_cut_session_run_logs_exception_and_sets_ready(monkeypatch):
    poison_mock = Mock(side_effect=RuntimeError("arpspoof failed"))
    monkeypatch.setattr(spoofer, "poison", poison_mock)
    exceptions = _capture_log(monkeypatch, "exception")

    on_active = Mock()
    stop = sentinel._CutEvent(on_active)
    key = ("192.0.2.50", "192.0.2.1", "wlan0")

    sentinel.AutoCutSession._run(key, stop)

    poison_mock.assert_called_once_with("192.0.2.50", "192.0.2.1", "wlan0", stop_event=stop)
    assert exceptions == ["ARP response failed for 192.0.2.50"]
    assert stop.ready.is_set()
    assert not stop.active
    on_active.assert_not_called()


def test_auto_cut_session_wait_polls_until_all_threads_exit(monkeypatch):
    sleeps = []
    monkeypatch.setattr(sentinel.time, "sleep", sleeps.append)

    jobs = sentinel.AutoCutSession()
    t1 = SimpleNamespace(is_alive=Mock(side_effect=[True, False, False]))
    t2 = SimpleNamespace(is_alive=Mock(side_effect=[True, False]))
    jobs.jobs[("192.0.2.50", "192.0.2.1", "wlan0")] = (Mock(), t1)
    jobs.jobs[("192.0.2.51", "192.0.2.1", "wlan0")] = (Mock(), t2)

    jobs.wait()
    assert sleeps == [0.2, 0.2]


def test_auto_cut_session_wait_returns_without_sleeping_when_no_live_jobs():
    # Relies on the autouse fixture's failing time.sleep to prove no sleep happens.
    jobs = sentinel.AutoCutSession()
    jobs.wait()

    dead = SimpleNamespace(is_alive=lambda: False)
    jobs.jobs[("192.0.2.50", "192.0.2.1", "wlan0")] = (Mock(), dead)
    jobs.wait()


@pytest.mark.parametrize("wait_exc", [None, KeyboardInterrupt], ids=["normal", "interrupt"])
def test_cut_unknowns_without_jobs_owns_session_and_always_closes(monkeypatch, wait_exc):
    events = []
    sessions = []
    real_unset = sentinel.AutoCutSession._UNSET

    class _RecordingSession:
        _UNSET = real_unset

        def __init__(self):
            self.jobs = {}
            self.network = None
            self._refused_network = self._UNSET
            sessions.append(self)

        def update(self, targets):
            events.append(("update", targets))

        def wait(self):
            events.append(("wait",))
            if wait_exc is not None:
                raise wait_exc

        def close(self):
            events.append(("close",))

    monkeypatch.setattr(sentinel, "AutoCutSession", _RecordingSession)
    monkeypatch.setattr(sentinel, "get_default_gateway", lambda _ip: "192.0.2.254")
    monkeypatch.setattr(sentinel, "get_default_iface", lambda: "wlan0")

    # 192.0.2.0/28 covers .0-.15; .16 is outside, while self (.100) and gateway (.254)
    # are outside the CIDR yet still protected.
    targets = ["192.0.2.254", "192.0.2.100", "192.0.2.15", "192.0.2.16"]
    cfg = {"trusted_ips": ["192.0.2.0/28"]}

    if wait_exc is not None:
        with pytest.raises(wait_exc):
            sentinel.cut_unknowns(targets, "192.0.2.100", cfg, network="Cafe")
    else:
        sentinel.cut_unknowns(targets, "192.0.2.100", cfg, network="Cafe")

    assert len(sessions) == 1
    assert sessions[0].network == "Cafe"
    assert events == [
        ("update", {("192.0.2.16", "192.0.2.254", "wlan0")}),
        ("wait",),
        ("close",),
    ]


def test_cut_unknowns_empty_trusted_ips_stops_running_jobs(monkeypatch):
    text_of = _record_output(monkeypatch)
    warnings = _capture_log(monkeypatch, "warning")

    jobs = SimpleNamespace(
        jobs={("192.0.2.99", "192.0.2.1", "wlan0"): (Mock(), Mock())},
        network=None,
        _refused_network=sentinel.AutoCutSession._UNSET,
        update=Mock(),
    )

    sentinel.cut_unknowns(["192.0.2.99"], "192.0.2.10", {"trusted_ips": []}, jobs, network="Home")

    jobs.update.assert_called_once_with(set())
    assert jobs.network == "Home"
    assert "trusted_ips" in text_of()
    assert warnings == ["auto-cut refused: trusted_ips is empty (network=Home)"]
    events = get_guard_events()
    assert len(events) == 1
    assert (events[0]["action"], events[0]["network"], events[0]["reason"]) == (
        "refused", "Home", "trusted_ips empty",
    )

    # Repeating the refusal on the same network does not append a duplicate journal row.
    sentinel.cut_unknowns(["192.0.2.99"], "192.0.2.10", {"trusted_ips": []}, jobs, network="Home")
    assert len(get_guard_events()) == 1


def test_cut_unknowns_all_hosts_protected_clears_jobs_and_prints_clean(monkeypatch):
    text_of = _record_output(monkeypatch)
    monkeypatch.setattr(sentinel, "get_default_gateway", lambda _ip: "192.0.2.254")
    # get_default_iface stays forbidden, proving we return before querying it.

    jobs = SimpleNamespace(
        jobs={},
        network=None,
        _refused_network=sentinel.AutoCutSession._UNSET,
        update=Mock(),
    )

    sentinel.cut_unknowns(
        ["192.0.2.254", "192.0.2.100", "192.0.2.1", "192.0.2.14"],
        "192.0.2.100",
        {"trusted_ips": ["192.0.2.0/28"]},
        jobs,
        network="Home",
    )

    jobs.update.assert_called_once_with(set())
    assert jobs.network == "Home"
    assert "No unknown hosts. Network is clean." in text_of()


# ── Reports ────────────────────────────────────────────────────────


def test_save_report_creates_reports_dir_and_writes_json(monkeypatch):
    _freeze_now(monkeypatch, lambda: datetime(2026, 11, 24, 9, 8, 7))
    assert not sentinel.REPORTS_DIR.exists()

    scan_data = {
        "192.0.2.5": ["80/tcp open http nginx 1.18.0"],
        "192.0.2.6": ["Shield intact"],
    }
    path = sentinel.save_report("My Cafe!", scan_data)

    assert sentinel.REPORTS_DIR.is_dir()
    assert path == sentinel.REPORTS_DIR / "My_Cafe__20261124_090807.json"
    assert json.loads(path.read_text(encoding="utf-8")) == {
        "network": "My Cafe!",
        "time": "20261124_090807",
        "targets": scan_data,
    }


def test_save_report_traversal_ssid_stays_inside_reports_dir(monkeypatch):
    _freeze_now(monkeypatch, lambda: datetime(2026, 11, 24, 9, 8, 7))

    path = sentinel.save_report("../../etc/x y", {"192.0.2.5": ["Shield intact"]})

    assert path.resolve().parent == sentinel.REPORTS_DIR.resolve()
    assert path.name == "______etc_x_y_20261124_090807.json"
    assert json.loads(path.read_text(encoding="utf-8")) == {
        "network": "../../etc/x y",
        "time": "20261124_090807",
        "targets": {"192.0.2.5": ["Shield intact"]},
    }


def test_save_report_rejects_escaped_path_and_writes_nothing(monkeypatch, tmp_path):
    _freeze_now(monkeypatch, lambda: datetime(2026, 11, 24, 9, 8, 7))
    monkeypatch.setattr(sentinel, "_sanitize_ssid", lambda _ssid: "../escape")

    with pytest.raises(ValueError, match="escapes REPORTS_DIR"):
        sentinel.save_report("evil", {"192.0.2.5": []})

    assert list(tmp_path.rglob("*.json")) == []


# ── Main loop (_run_sentinel_loop) ─────────────────────────────────


def test_loop_daily_retention_purge_runs_once_per_day(monkeypatch):
    t0 = datetime(2026, 6, 1, 12, 0, 0)
    clock = [t0]
    _freeze_now(monkeypatch, lambda: clock[0])
    _record_output(monkeypatch)
    infos = _capture_log(monkeypatch, "info")

    monkeypatch.setattr(sentinel, "get_wifi_info", lambda: None)
    monkeypatch.setattr(sentinel, "load_user_config", lambda: {"db_retention_days": 30})
    purge = Mock(side_effect=[4, 0])
    monkeypatch.setattr(sentinel, "purge_old_scans", purge)

    sleeps = []

    def fake_sleep(seconds):
        sleeps.append(seconds)
        if len(sleeps) == 1:
            clock[0] = t0 + timedelta(hours=12)          # same day -> skip purge
            return None
        if len(sleeps) == 2:
            clock[0] = t0 + timedelta(days=1, seconds=1)  # > 1 day -> purge again
            return None
        raise KeyboardInterrupt

    monkeypatch.setattr(sentinel.time, "sleep", fake_sleep)
    jobs = _fake_jobs()

    with pytest.raises(KeyboardInterrupt):
        sentinel._run_sentinel_loop(interactive=False, auto_cut=False, jobs=jobs, dhcp=None)

    assert purge.call_args_list == [call(30), call(30)]
    assert infos == ["db purge deleted=4 retention_days=30"]
    assert sleeps == [sentinel.CHECK_INTERVAL] * 3
    assert jobs.update.call_args_list == [call(set()), call(set()), call(set())]


@pytest.mark.parametrize("days", [0, -7])
def test_loop_retention_purge_skipped_when_non_positive(monkeypatch, days):
    _record_output(monkeypatch)
    monkeypatch.setattr(sentinel, "get_wifi_info", lambda: None)
    monkeypatch.setattr(sentinel, "load_user_config", lambda: {"db_retention_days": days})
    purge = Mock()
    monkeypatch.setattr(sentinel, "purge_old_scans", purge)

    sentinel._run_sentinel_loop(interactive=True, auto_cut=False, jobs=_fake_jobs(), dhcp=None)

    purge.assert_not_called()


def test_loop_retention_purge_error_logs_warning_and_continues(monkeypatch):
    t0 = datetime(2026, 6, 1, 12, 0, 0)
    _freeze_now(monkeypatch, lambda: t0)
    _record_output(monkeypatch)
    warnings = _capture_log(monkeypatch, "warning")

    monkeypatch.setattr(sentinel, "get_wifi_info", lambda: None)
    monkeypatch.setattr(sentinel, "load_user_config", lambda: {"db_retention_days": 14})
    purge = Mock(side_effect=RuntimeError("database is locked"))
    monkeypatch.setattr(sentinel, "purge_old_scans", purge)

    sleep = Mock(side_effect=[None, KeyboardInterrupt])
    monkeypatch.setattr(sentinel.time, "sleep", sleep)

    with pytest.raises(KeyboardInterrupt):
        sentinel._run_sentinel_loop(interactive=False, auto_cut=False, jobs=_fake_jobs(), dhcp=None)

    purge.assert_called_once_with(14)
    assert warnings == ["db purge failed: database is locked"]
    assert sleep.call_args_list == [call(sentinel.CHECK_INTERVAL), call(sentinel.CHECK_INTERVAL)]


def test_loop_reevaluates_trust_between_scans_without_rescanning(monkeypatch):
    t0 = datetime(2026, 6, 1, 12, 0, 0)
    clock = [t0]
    _freeze_now(monkeypatch, lambda: clock[0])
    _record_output(monkeypatch)

    my_ip = "192.0.2.10"
    cfg_first = {"db_retention_days": 0, "trusted_ips": ["192.0.2.1"]}
    cfg_second = {"db_retention_days": 0, "trusted_ips": ["192.0.2.1", "192.0.2.50"]}
    monkeypatch.setattr(sentinel, "get_wifi_info", lambda: {"ssid": "Home", "ip": my_ip})
    monkeypatch.setattr(sentinel, "load_user_config", Mock(side_effect=[cfg_first, cfg_second]))

    metadata = {
        "192.0.2.50": {"hostname": None, "mac": None, "vendor": None},
        "192.0.2.60": {"hostname": None, "mac": None, "vendor": None},
    }
    stubs = _stub_scan_pipeline(
        monkeypatch,
        metadata,
        {"192.0.2.50": ["Shield intact"], "192.0.2.60": ["Shield intact"]},
    )

    jobs = _fake_jobs()
    cut_calls = []

    def fake_cut(targets, ip, cfg, session, network=None):
        cut_calls.append((list(targets), ip, cfg, session, network))
        if len(cut_calls) == 1:
            session.jobs[("192.0.2.50", "192.0.2.1", "wlan0")] = (object(), object())
            session.jobs[("192.0.2.60", "192.0.2.1", "wlan0")] = (object(), object())

    monkeypatch.setattr(sentinel, "cut_unknowns", fake_cut)

    sleeps = []

    def fake_sleep(seconds):
        sleeps.append(seconds)
        if len(sleeps) == 1:
            clock[0] = t0 + timedelta(minutes=5)  # well within RESCAN_HOURS
            return None
        raise KeyboardInterrupt

    monkeypatch.setattr(sentinel.time, "sleep", fake_sleep)

    with pytest.raises(KeyboardInterrupt):
        sentinel._run_sentinel_loop(interactive=False, auto_cut=True, jobs=jobs, dhcp=None)

    assert stubs.ping_sweep.call_count == 1
    assert stubs.deep_scan.call_count == 1
    assert len(cut_calls) == 2
    assert cut_calls[0] == (["192.0.2.50", "192.0.2.60"], my_ip, cfg_first, jobs, "Home")
    assert cut_calls[1] == (["192.0.2.50", "192.0.2.60"], my_ip, cfg_second, jobs, "Home")
    assert cut_calls[1][3] is jobs


def test_loop_auto_cut_true_calls_cut_unknowns_after_scan(monkeypatch):
    _record_output(monkeypatch)
    my_ip = "192.0.2.10"
    cfg = {"db_retention_days": 0, "trusted_ips": ["192.0.2.1"]}
    monkeypatch.setattr(sentinel, "get_wifi_info", lambda: {"ssid": "Office", "ip": my_ip})
    monkeypatch.setattr(sentinel, "load_user_config", lambda: cfg)

    order = []
    metadata = {
        "192.0.2.20": {"hostname": "a", "mac": None, "vendor": None},
        "192.0.2.30": {"hostname": "b", "mac": None, "vendor": None},
    }
    stubs = _stub_scan_pipeline(
        monkeypatch,
        metadata,
        {"192.0.2.20": ["Shield intact"], "192.0.2.30": ["80/tcp open http"]},
        order=order,
    )
    monkeypatch.setattr(sentinel.time, "sleep", Mock(side_effect=KeyboardInterrupt))
    jobs = _fake_jobs()

    with pytest.raises(KeyboardInterrupt):
        sentinel._run_sentinel_loop(interactive=False, auto_cut=True, jobs=jobs, dhcp=None)

    stubs.cut_unknowns.assert_called_once_with(
        ["192.0.2.20", "192.0.2.30"], my_ip, cfg, jobs, network="Office",
    )
    assert order == [
        "ping_sweep",
        "identify_devices",
        "deep_scan",
        "add_dhcp_fingerprints",
        "save_report",
        "save_scan",
        "display_results_table",
        "cut_unknowns",
        "send_alert",
    ]


def test_loop_auto_cut_false_does_not_call_cut_unknowns(monkeypatch):
    _record_output(monkeypatch)
    cfg = {"db_retention_days": 0, "trusted_ips": ["192.0.2.1"]}
    monkeypatch.setattr(sentinel, "get_wifi_info", lambda: {"ssid": "Office", "ip": "192.0.2.10"})
    monkeypatch.setattr(sentinel, "load_user_config", lambda: cfg)

    stubs = _stub_scan_pipeline(
        monkeypatch,
        {"192.0.2.20": {"hostname": "a", "mac": None, "vendor": None}},
        {"192.0.2.20": ["Shield intact"]},
    )
    monkeypatch.setattr(sentinel.time, "sleep", Mock(side_effect=KeyboardInterrupt))

    with pytest.raises(KeyboardInterrupt):
        sentinel._run_sentinel_loop(interactive=False, auto_cut=False, jobs=_fake_jobs(), dhcp=None)

    stubs.cut_unknowns.assert_not_called()
    assert stubs.save_report.call_count == 1
    assert stubs.save_scan.call_count == 1
    assert stubs.display_results_table.call_count == 1
    assert stubs.send_alert.call_count == 1


def test_loop_interactive_auto_cut_prints_prompt_and_waits(monkeypatch):
    text_of = _record_output(monkeypatch)
    cfg = {"db_retention_days": 0, "trusted_ips": ["192.0.2.1"]}
    monkeypatch.setattr(sentinel, "get_wifi_info", lambda: {"ssid": "Lab", "ip": "192.0.2.10"})
    monkeypatch.setattr(sentinel, "load_user_config", lambda: cfg)

    order = []
    stubs = _stub_scan_pipeline(
        monkeypatch,
        {"192.0.2.20": {"hostname": None, "mac": None, "vendor": None}},
        {"192.0.2.20": ["Shield intact"]},
        order=order,
    )
    jobs = _fake_jobs()
    jobs.wait = Mock(side_effect=lambda: order.append("jobs.wait"))

    # Default forbidden sentinel.time.sleep proves interactive mode breaks without sleeping.
    sentinel._run_sentinel_loop(interactive=True, auto_cut=True, jobs=jobs, dhcp=None)

    assert stubs.ping_sweep.call_count == 1
    jobs.wait.assert_called_once_with()
    assert order[-3:] == ["cut_unknowns", "send_alert", "jobs.wait"]
    assert "Press Ctrl+C to stop active responses and restore ARP." in text_of()


def test_loop_interactive_without_auto_cut_returns_without_waiting(monkeypatch):
    text_of = _record_output(monkeypatch)
    cfg = {"db_retention_days": 0}
    monkeypatch.setattr(sentinel, "get_wifi_info", lambda: {"ssid": "Lab", "ip": "192.0.2.10"})
    monkeypatch.setattr(sentinel, "load_user_config", lambda: cfg)

    stubs = _stub_scan_pipeline(
        monkeypatch,
        {"192.0.2.20": {"hostname": None, "mac": None, "vendor": None}},
        {"192.0.2.20": ["Shield intact"]},
    )
    jobs = _fake_jobs()

    sentinel._run_sentinel_loop(interactive=True, auto_cut=False, jobs=jobs, dhcp=None)

    assert stubs.ping_sweep.call_count == 1
    stubs.cut_unknowns.assert_not_called()
    jobs.wait.assert_not_called()
    assert "Press Ctrl+C to stop active responses and restore ARP." not in text_of()
