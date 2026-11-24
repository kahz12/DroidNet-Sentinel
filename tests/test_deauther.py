"""Unit tests for 802.11 deauthentication (deauther.py) without real packets or hardware."""
import io
import subprocess
import threading
from types import SimpleNamespace

import pytest
from rich.console import Console

from droidnet.modules import deauther

TARGET_MAC = "aa:bb:cc:dd:ee:01"
BSSID = "11:22:33:44:55:66"
IFACE = "wlan0mon"


def _forbid(name: str):
    def _fail(*args, **kwargs):
        pytest.fail(f"unexpected call to {name}")
    return _fail


@pytest.fixture(autouse=True)
def _block_external_effects(monkeypatch):
    """Fail any test that attempts real commands, sysfs reads, root checks, or packet TX."""
    monkeypatch.setattr(deauther.subprocess, "run", _forbid("deauther.subprocess.run"))
    monkeypatch.setattr(deauther, "sendp", _forbid("deauther.sendp"), raising=False)
    monkeypatch.setattr(deauther, "check_root", _forbid("deauther.check_root"))
    monkeypatch.setattr(deauther, "resolve_command", _forbid("deauther.resolve_command"))
    monkeypatch.setattr(deauther, "open", _forbid("deauther.open"), raising=False)
    monkeypatch.setattr(deauther.time, "sleep", lambda _seconds: None)


@pytest.fixture
def output(monkeypatch):
    console = Console(file=io.StringIO(), record=True, width=240, color_system=None)
    monkeypatch.setattr(deauther, "rprint", console.print)
    return console


@pytest.fixture
def ready_monitor(monkeypatch):
    """Pre-configure deauth_target guards for an interface already in monitor mode."""
    monkeypatch.setattr(deauther, "_SCAPY_OK", True)
    monkeypatch.setattr(deauther, "check_root", lambda: True)
    monkeypatch.setattr(deauther, "_check_monitor_mode", lambda _iface: True)
    monkeypatch.setattr(deauther, "_injection_supported", lambda _iface: True)
    monkeypatch.setattr(deauther, "_set_channel", lambda _iface, _ch: True)


# ── _check_monitor_mode ────────────────────────────────────────────

@pytest.mark.parametrize(
    "content,expected",
    [
        ("803", True),
        ("803\n", True),
        ("1", False),
        ("1\n", False),
    ],
)
def test_check_monitor_mode_reads_sysfs_type(monkeypatch, content, expected):
    opened = []

    def fake_open(path, *args, **kwargs):
        opened.append(path)
        return io.StringIO(content)

    monkeypatch.setattr(deauther, "open", fake_open, raising=False)
    assert deauther._check_monitor_mode(IFACE) is expected
    assert opened == [f"/sys/class/net/{IFACE}/type"]


def test_check_monitor_mode_returns_false_when_sysfs_missing(monkeypatch):
    opened = []

    def fake_open(path, *args, **kwargs):
        opened.append(path)
        raise FileNotFoundError(path)

    monkeypatch.setattr(deauther, "open", fake_open, raising=False)
    assert deauther._check_monitor_mode("wlan9") is False
    assert opened == ["/sys/class/net/wlan9/type"]


# ── _enable_monitor ────────────────────────────────────────────────

@pytest.mark.parametrize("monitor_active", [True, False])
def test_enable_monitor_runs_ip_and_iw_commands_and_checks_mode(monkeypatch, monitor_active):
    calls = []
    sleeps = []
    checked = []

    monkeypatch.setattr(
        deauther,
        "resolve_command",
        lambda cmd: "/usr/sbin/iw" if cmd == "iw" else None,
    )
    monkeypatch.setattr(
        deauther.subprocess,
        "run",
        lambda argv, **kwargs: (calls.append((argv, kwargs)), SimpleNamespace(returncode=0))[1],
    )
    monkeypatch.setattr(deauther.time, "sleep", sleeps.append)
    monkeypatch.setattr(
        deauther,
        "_check_monitor_mode",
        lambda iface: (checked.append(iface), monitor_active)[1],
    )

    assert deauther._enable_monitor("wlan0") is monitor_active
    assert [argv for argv, _ in calls] == [
        ["ip", "link", "set", "wlan0", "down"],
        ["/usr/sbin/iw", "dev", "wlan0", "set", "type", "monitor"],
        ["ip", "link", "set", "wlan0", "up"],
    ]
    assert all(kwargs == {"capture_output": True, "timeout": 10, "check": True} for _, kwargs in calls)
    assert sleeps == [1]
    assert checked == ["wlan0"]


# ── _injection_supported ───────────────────────────────────────────

def test_injection_supported_returns_none_without_aireplay(monkeypatch):
    looked_up = []
    monkeypatch.setattr(
        deauther,
        "resolve_command",
        lambda cmd: (looked_up.append(cmd), None)[1],
    )
    # Autouse forbids subprocess.run, ensuring nothing is executed.
    assert deauther._injection_supported(IFACE) is None
    assert looked_up == ["aireplay-ng"]


@pytest.mark.parametrize(
    "stdout,stderr,expected",
    [
        ("12:00:00  Injection is working!\n", "", True),
        ("", "Notice: Injection is working", True),
        ("No Answer...", "timeout", False),
        (None, None, False),
    ],
)
def test_injection_supported_checks_stdout_and_stderr(monkeypatch, stdout, stderr, expected):
    calls = []
    monkeypatch.setattr(
        deauther,
        "resolve_command",
        lambda cmd: "/usr/sbin/aireplay-ng" if cmd == "aireplay-ng" else None,
    )
    monkeypatch.setattr(
        deauther.subprocess,
        "run",
        lambda argv, **kwargs: (
            calls.append((argv, kwargs)),
            SimpleNamespace(stdout=stdout, stderr=stderr),
        )[1],
    )

    assert deauther._injection_supported(IFACE) is expected
    assert calls == [
        (["/usr/sbin/aireplay-ng", "--test", IFACE], {"capture_output": True, "text": True, "timeout": 12}),
    ]


@pytest.mark.parametrize(
    "exc",
    [
        subprocess.TimeoutExpired(cmd="aireplay-ng", timeout=12),
        OSError("permission denied"),
    ],
)
def test_injection_supported_returns_none_on_timeout_or_oserror(monkeypatch, exc):
    calls = []
    monkeypatch.setattr(deauther, "resolve_command", lambda _cmd: "/usr/sbin/aireplay-ng")

    def boom(argv, **kwargs):
        calls.append(argv)
        raise exc

    monkeypatch.setattr(deauther.subprocess, "run", boom)
    assert deauther._injection_supported(IFACE) is None
    assert calls == [["/usr/sbin/aireplay-ng", "--test", IFACE]]


# ── _set_channel ───────────────────────────────────────────────────

@pytest.mark.parametrize("returncode,expected", [(0, True), (1, False)])
def test_set_channel_returns_bool_from_exit_code(monkeypatch, returncode, expected):
    calls = []
    monkeypatch.setattr(deauther, "resolve_command", lambda cmd: "/usr/sbin/iw" if cmd == "iw" else None)
    monkeypatch.setattr(
        deauther.subprocess,
        "run",
        lambda argv, **kwargs: (calls.append((argv, kwargs)), SimpleNamespace(returncode=returncode))[1],
    )

    assert deauther._set_channel(IFACE, 6) is expected
    assert calls == [
        (["/usr/sbin/iw", "dev", IFACE, "set", "channel", "6"], {"capture_output": True, "timeout": 2}),
    ]


@pytest.mark.parametrize(
    "exc",
    [
        OSError("iw missing"),
        subprocess.TimeoutExpired(cmd="iw", timeout=2),
    ],
)
def test_set_channel_returns_false_when_run_raises(monkeypatch, exc):
    calls = []
    monkeypatch.setattr(deauther, "resolve_command", lambda _cmd: None)

    def boom(argv, **kwargs):
        calls.append(argv)
        raise exc

    monkeypatch.setattr(deauther.subprocess, "run", boom)
    assert deauther._set_channel(IFACE, 6) is False
    assert calls == [["iw", "dev", IFACE, "set", "channel", "6"]]


# ── _ChannelHopper ─────────────────────────────────────────────────

def test_channel_hopper_visits_channels_in_order_and_wraps_around(monkeypatch):
    visited = []
    hopper = deauther._ChannelHopper(IFACE, interval=0.0)

    def fake_set_channel(iface, channel):
        visited.append((iface, channel))
        if len(visited) >= 5:
            hopper._stop.set()
        return True

    monkeypatch.setattr(deauther, "_set_channel", fake_set_channel)

    try:
        hopper.start()
        assert hopper._stop.wait(timeout=1.0)
    finally:
        hopper.stop()

    assert visited == [
        (IFACE, 1),
        (IFACE, 6),
        (IFACE, 11),
        (IFACE, 1),
        (IFACE, 6),
    ]
    assert hopper._thread is not None and not hopper._thread.is_alive()


def test_channel_hopper_start_is_idempotent_and_stop_ends_thread(monkeypatch):
    started = threading.Event()
    monkeypatch.setattr(
        deauther,
        "_set_channel",
        lambda _iface, _ch: (started.set(), True)[1],
    )
    hopper = deauther._ChannelHopper(IFACE, interval=60.0)

    try:
        hopper.start()
        assert started.wait(timeout=1.0)
        first_thread = hopper._thread
        assert first_thread is not None and first_thread.is_alive()
        hopper.start()
        assert hopper._thread is first_thread
    finally:
        hopper.stop()

    assert not first_thread.is_alive()


# ── _build_deauth ──────────────────────────────────────────────────

def test_build_deauth_frame_fields_and_reason():
    scapy = pytest.importorskip("scapy.all")

    frame = deauther._build_deauth(TARGET_MAC, BSSID)
    assert frame.haslayer(scapy.RadioTap)
    assert frame.haslayer(scapy.Dot11)
    assert frame.haslayer(scapy.Dot11Deauth)
    assert frame[scapy.Dot11].addr1 == TARGET_MAC
    assert frame[scapy.Dot11].addr2 == BSSID
    assert frame[scapy.Dot11].addr3 == BSSID
    assert frame[scapy.Dot11Deauth].reason == 7

    custom = deauther._build_deauth(TARGET_MAC, BSSID, reason=3)
    assert custom[scapy.Dot11Deauth].reason == 3


# ── deauth_target guards ───────────────────────────────────────────

def test_deauth_target_aborts_when_scapy_unavailable(monkeypatch, output):
    monkeypatch.setattr(deauther, "_SCAPY_OK", False)
    deauther.deauth_target(TARGET_MAC, BSSID, IFACE, count=1)
    assert "Scapy unavailable" in output.export_text()


def test_deauth_target_aborts_when_not_root(monkeypatch, output):
    monkeypatch.setattr(deauther, "_SCAPY_OK", True)
    monkeypatch.setattr(deauther, "check_root", lambda: False)
    deauther.deauth_target(TARGET_MAC, BSSID, IFACE, count=1)
    assert "Root required" in output.export_text()


def test_deauth_target_rejects_invalid_bssid(monkeypatch, output):
    monkeypatch.setattr(deauther, "_SCAPY_OK", True)
    monkeypatch.setattr(deauther, "check_root", lambda: True)
    deauther.deauth_target(TARGET_MAC, "not-a-bssid", IFACE, count=1)
    assert "Invalid BSSID: not-a-bssid" in output.export_text()


def test_deauth_target_rejects_invalid_target_mac(monkeypatch, output):
    monkeypatch.setattr(deauther, "_SCAPY_OK", True)
    monkeypatch.setattr(deauther, "check_root", lambda: True)
    deauther.deauth_target("bad-target", BSSID, IFACE, count=1)
    assert "Invalid target MAC: bad-target" in output.export_text()


def test_deauth_target_accepts_broadcast_target(monkeypatch, ready_monitor):
    scapy = pytest.importorskip("scapy.all")
    sent = []
    monkeypatch.setattr(deauther, "sendp", lambda frame, **kwargs: sent.append((frame, kwargs)), raising=False)

    deauther.deauth_target(deauther.BROADCAST, BSSID, IFACE, count=1, interval=0, channel=6)

    assert len(sent) == 1
    frame, kwargs = sent[0]
    assert frame[scapy.Dot11].addr1 == deauther.BROADCAST
    assert frame[scapy.Dot11].addr2 == BSSID
    assert frame[scapy.Dot11].addr3 == BSSID
    assert kwargs == {"iface": IFACE, "verbose": False}


@pytest.mark.parametrize(
    "bad_kwargs",
    [
        {"count": -1},
        {"interval": -0.1},
        {"channel": 0},
        {"channel": -6},
    ],
)
def test_deauth_target_rejects_invalid_numeric_arguments(monkeypatch, bad_kwargs):
    monkeypatch.setattr(deauther, "_SCAPY_OK", True)
    monkeypatch.setattr(deauther, "check_root", lambda: True)
    with pytest.raises(ValueError):
        deauther.deauth_target(TARGET_MAC, BSSID, IFACE, **bad_kwargs)


# ── deauth_target flow ─────────────────────────────────────────────

def test_deauth_target_stops_when_injection_test_fails(monkeypatch, ready_monitor, output):
    monkeypatch.setattr(deauther, "_injection_supported", lambda _iface: False)
    monkeypatch.setattr(deauther, "_ChannelHopper", _forbid("_ChannelHopper"))

    deauther.deauth_target(TARGET_MAC, BSSID, IFACE, count=1)

    assert "Injection test failed." in output.export_text()


def test_deauth_target_proceeds_when_injection_test_inconclusive(monkeypatch, ready_monitor):
    sent = []
    monkeypatch.setattr(deauther, "_injection_supported", lambda _iface: None)
    monkeypatch.setattr(deauther, "_build_deauth", lambda _t, _b: object())
    monkeypatch.setattr(deauther, "sendp", lambda frame, **kwargs: sent.append((frame, kwargs)), raising=False)

    deauther.deauth_target(TARGET_MAC, BSSID, IFACE, count=1, interval=0, channel=6)

    assert len(sent) == 1
    assert sent[0][1] == {"iface": IFACE, "verbose": False}


def test_deauth_target_fixed_channel_sets_channel_without_hopper(monkeypatch, ready_monitor):
    scapy = pytest.importorskip("scapy.all")
    channels_set = []
    sent = []

    monkeypatch.setattr(
        deauther,
        "_set_channel",
        lambda iface, ch: (channels_set.append((iface, ch)), True)[1],
    )
    monkeypatch.setattr(deauther, "_ChannelHopper", _forbid("_ChannelHopper"))
    monkeypatch.setattr(deauther, "sendp", lambda frame, **kwargs: sent.append((frame, kwargs)), raising=False)

    deauther.deauth_target(TARGET_MAC, BSSID, IFACE, count=1, interval=0, channel=11)

    assert channels_set == [(IFACE, 11)]
    assert len(sent) == 1
    assert sent[0][0][scapy.Dot11].addr1 == TARGET_MAC


def test_deauth_target_fixed_channel_failure_sends_nothing(monkeypatch, ready_monitor, output):
    channels_set = []
    monkeypatch.setattr(
        deauther,
        "_set_channel",
        lambda iface, ch: (channels_set.append((iface, ch)), False)[1],
    )
    monkeypatch.setattr(deauther, "_ChannelHopper", _forbid("_ChannelHopper"))

    deauther.deauth_target(TARGET_MAC, BSSID, IFACE, count=2, channel=11)

    assert channels_set == [(IFACE, 11)]
    assert "Could not set channel 11; stopping." in output.export_text()


def test_deauth_target_without_channel_starts_and_stops_hopper(monkeypatch, ready_monitor):
    events = []

    class _FakeHopper:
        def __init__(self, iface):
            events.append(("init", iface))

        def start(self):
            events.append("start")

        def stop(self):
            events.append("stop")

    monkeypatch.setattr(deauther, "_ChannelHopper", _FakeHopper)
    monkeypatch.setattr(deauther, "_build_deauth", lambda _t, _b: object())
    monkeypatch.setattr(deauther, "sendp", lambda _f, **k: events.append("sendp"), raising=False)

    deauther.deauth_target(TARGET_MAC, BSSID, IFACE, count=2, interval=0)

    assert events == [("init", IFACE), "start", "sendp", "sendp", "stop"]


def test_deauth_target_stops_hopper_after_send_error(monkeypatch, ready_monitor):
    events = []

    class _FakeHopper:
        def __init__(self, iface):
            events.append(("init", iface))

        def start(self):
            events.append("start")

        def stop(self):
            events.append("stop")

    def boom(_frame, **_kwargs):
        events.append("sendp")
        raise RuntimeError("tx error")

    monkeypatch.setattr(deauther, "_ChannelHopper", _FakeHopper)
    monkeypatch.setattr(deauther, "_build_deauth", lambda _t, _b: object())
    monkeypatch.setattr(deauther, "sendp", boom, raising=False)

    with pytest.raises(RuntimeError, match="tx error"):
        deauther.deauth_target(TARGET_MAC, BSSID, IFACE, count=2, interval=0)

    assert events == [("init", IFACE), "start", "sendp", "stop"]


def test_deauth_target_count_sends_exact_frames_and_sleeps_between_them(monkeypatch, ready_monitor, output):
    scapy = pytest.importorskip("scapy.all")
    events = []
    frames = []

    def fake_sendp(frame, **kwargs):
        frames.append(frame)
        events.append(("sendp", kwargs["iface"], kwargs["verbose"]))

    monkeypatch.setattr(deauther, "sendp", fake_sendp, raising=False)
    monkeypatch.setattr(deauther.time, "sleep", lambda secs: events.append(("sleep", secs)))

    deauther.deauth_target(TARGET_MAC, BSSID, IFACE, count=3, interval=0.25, channel=6)

    assert events == [
        ("sendp", IFACE, False),
        ("sleep", 0.25),
        ("sendp", IFACE, False),
        ("sleep", 0.25),
        ("sendp", IFACE, False),
        ("sleep", 0.25),
    ]
    assert len(frames) == 3
    for frame in frames:
        assert frame.haslayer(scapy.RadioTap)
        assert frame[scapy.Dot11].addr1 == TARGET_MAC
        assert frame[scapy.Dot11].addr2 == BSSID
        assert frame[scapy.Dot11].addr3 == BSSID
        assert frame[scapy.Dot11Deauth].reason == 7
    text = output.export_text()
    assert f"Deauth started on {IFACE}" in text
    assert "Frames sent: 3" in text


def test_deauth_target_keyboard_interrupt_reports_total_and_stops_hopper(monkeypatch, ready_monitor, output):
    events = []

    class _FakeHopper:
        def __init__(self, iface):
            events.append(("init", iface))

        def start(self):
            events.append("start")

        def stop(self):
            events.append("stop")

    sent_count = 0

    def fake_sendp(_frame, **_kwargs):
        nonlocal sent_count
        if sent_count == 2:
            events.append("interrupt")
            raise KeyboardInterrupt
        sent_count += 1
        events.append("sendp")

    monkeypatch.setattr(deauther, "_ChannelHopper", _FakeHopper)
    monkeypatch.setattr(deauther, "_build_deauth", lambda _t, _b: object())
    monkeypatch.setattr(deauther, "sendp", fake_sendp, raising=False)

    deauther.deauth_target(TARGET_MAC, BSSID, IFACE, count=0, interval=0.1)

    assert events == [("init", IFACE), "start", "sendp", "sendp", "interrupt", "stop"]
    assert "Stopped. 2 frames total." in output.export_text()
