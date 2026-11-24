"""Unit tests for ARP spoofing (spoofer.py) with all network and process calls mocked."""
import io
import subprocess
from threading import Event
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
from rich.console import Console

from droidnet.modules import spoofer

VICTIM_IP = "192.0.2.50"
GATEWAY_IP = "192.0.2.1"
IFACE = "eth0"
VICTIM_MAC = "aa:bb:cc:dd:ee:01"
GATEWAY_MAC = "aa:bb:cc:dd:ee:02"
OUR_MAC = "aa:bb:cc:dd:ee:03"


def _forbid(name: str):
    def _fail(*args, **kwargs):
        pytest.fail(f"unexpected call to {name}")
    return _fail


@pytest.fixture(autouse=True)
def _block_external_effects(monkeypatch):
    """Fail any test that lets a real packet, lookup, or subprocess escape."""
    monkeypatch.setattr(spoofer.subprocess, "Popen", _forbid("spoofer.subprocess.Popen"))
    monkeypatch.setattr(spoofer, "sendp", _forbid("spoofer.sendp"), raising=False)
    monkeypatch.setattr(spoofer, "srp", _forbid("spoofer.srp"), raising=False)
    monkeypatch.setattr(spoofer, "get_if_hwaddr", _forbid("spoofer.get_if_hwaddr"), raising=False)
    monkeypatch.setattr(spoofer, "resolve_command", _forbid("spoofer.resolve_command"))
    monkeypatch.setattr(spoofer.time, "sleep", lambda _seconds: None)


@pytest.fixture
def output(monkeypatch):
    console = Console(file=io.StringIO(), record=True, width=240, color_system=None)
    monkeypatch.setattr(spoofer, "rprint", console.print)
    return console


@pytest.fixture
def warnings(monkeypatch):
    records = []
    monkeypatch.setattr(
        spoofer.log,
        "warning",
        lambda msg, *args: records.append(msg % args if args else msg),
    )
    return records


def _assert_arp_reply(scapy, frame, *, dst_mac, psrc, hwsrc, pdst, hwdst):
    assert frame.haslayer(scapy.Ether) and frame.haslayer(scapy.ARP)
    assert frame[scapy.Ether].dst == dst_mac
    arp = frame[scapy.ARP]
    assert arp.op == 2
    assert arp.psrc == psrc
    assert arp.hwsrc == hwsrc
    assert arp.pdst == pdst
    assert arp.hwdst == hwdst


# ── _resolve_mac ───────────────────────────────────────────────────

def test_resolve_mac_sends_broadcast_arp_and_returns_first_hwsrc(monkeypatch):
    scapy = pytest.importorskip("scapy.all")
    calls = []

    def fake_srp(pkt, **kwargs):
        calls.append((pkt, kwargs))
        ans = [
            (None, SimpleNamespace(hwsrc=VICTIM_MAC)),
            (None, SimpleNamespace(hwsrc=GATEWAY_MAC)),
        ]
        return ans, []

    monkeypatch.setattr(spoofer, "srp", fake_srp, raising=False)
    assert spoofer._resolve_mac(VICTIM_IP, IFACE, timeout=1.5) == VICTIM_MAC
    assert len(calls) == 1
    pkt, kwargs = calls[0]
    assert pkt.haslayer(scapy.Ether) and pkt.haslayer(scapy.ARP)
    assert pkt[scapy.Ether].dst == "ff:ff:ff:ff:ff:ff"
    assert pkt[scapy.ARP].op == 1
    assert pkt[scapy.ARP].pdst == VICTIM_IP
    assert kwargs == {"iface": IFACE, "timeout": 1.5, "verbose": False}


def test_resolve_mac_returns_none_when_unanswered(monkeypatch):
    pytest.importorskip("scapy.all")
    monkeypatch.setattr(spoofer, "srp", lambda *a, **k: ([], []), raising=False)
    assert spoofer._resolve_mac(VICTIM_IP, IFACE) is None


def test_resolve_mac_logs_and_prints_when_srp_raises(monkeypatch, output, warnings):
    pytest.importorskip("scapy.all")

    def boom(*args, **kwargs):
        raise OSError("operation not permitted")

    monkeypatch.setattr(spoofer, "srp", boom, raising=False)
    assert spoofer._resolve_mac(VICTIM_IP, IFACE) is None
    assert any(VICTIM_IP in w and IFACE in w and "operation not permitted" in w for w in warnings)
    text = output.export_text()
    assert VICTIM_IP in text and "operation not permitted" in text


# ── _poison_scapy ──────────────────────────────────────────────────

@pytest.mark.parametrize(
    "resolved",
    [
        {VICTIM_IP: None, GATEWAY_IP: GATEWAY_MAC},
        {VICTIM_IP: VICTIM_MAC, GATEWAY_IP: None},
    ],
)
def test_poison_scapy_aborts_when_mac_resolution_fails(monkeypatch, output, warnings, resolved):
    monkeypatch.setattr(spoofer, "_resolve_mac", lambda ip, _iface: resolved[ip])
    spoofer._poison_scapy(VICTIM_IP, GATEWAY_IP, IFACE, interval=0)
    assert any("could not resolve MACs" in w and VICTIM_IP in w for w in warnings)
    assert "Could not resolve MACs" in output.export_text()


def test_poison_scapy_aborts_when_get_if_hwaddr_raises(monkeypatch, output, warnings):
    macs = {VICTIM_IP: VICTIM_MAC, GATEWAY_IP: GATEWAY_MAC}
    monkeypatch.setattr(spoofer, "_resolve_mac", lambda ip, _iface: macs[ip])
    monkeypatch.setattr(
        spoofer,
        "get_if_hwaddr",
        Mock(side_effect=OSError("no such device")),
        raising=False,
    )
    spoofer._poison_scapy(VICTIM_IP, GATEWAY_IP, IFACE, interval=0)
    assert any("could not read MAC" in w and IFACE in w and "no such device" in w for w in warnings)
    assert f"Could not read MAC from {IFACE}" in output.export_text()


def test_poison_scapy_sends_forged_replies_and_restores_on_stop(monkeypatch, output):
    scapy = pytest.importorskip("scapy.all")
    resolved_queries = []
    macs = {VICTIM_IP: VICTIM_MAC, GATEWAY_IP: GATEWAY_MAC}

    def fake_resolve(ip, iface):
        resolved_queries.append((ip, iface))
        return macs[ip]

    monkeypatch.setattr(spoofer, "_resolve_mac", fake_resolve)
    monkeypatch.setattr(spoofer, "get_if_hwaddr", lambda iface: OUR_MAC if iface == IFACE else "", raising=False)

    stop_event = Event()
    sent = []
    sleeps = []

    def fake_sendp(frame, **kwargs):
        sent.append((frame, kwargs))
        # Two rounds of two poison frames, then stop.
        if len(sent) == 4:
            stop_event.set()

    monkeypatch.setattr(spoofer, "sendp", fake_sendp, raising=False)
    monkeypatch.setattr(spoofer.time, "sleep", sleeps.append)

    spoofer._poison_scapy(VICTIM_IP, GATEWAY_IP, IFACE, interval=0, stop_event=stop_event)

    assert resolved_queries == [(VICTIM_IP, IFACE), (GATEWAY_IP, IFACE)]
    assert len(sent) == 14
    assert all(kwargs == {"iface": IFACE, "verbose": False} for _, kwargs in sent)

    # First 4 frames: 2 rounds of forged poison replies using our MAC.
    for offset in (0, 2):
        _assert_arp_reply(
            scapy, sent[offset][0],
            dst_mac=VICTIM_MAC, psrc=GATEWAY_IP, hwsrc=OUR_MAC,
            pdst=VICTIM_IP, hwdst=VICTIM_MAC,
        )
        _assert_arp_reply(
            scapy, sent[offset + 1][0],
            dst_mac=GATEWAY_MAC, psrc=VICTIM_IP, hwsrc=OUR_MAC,
            pdst=GATEWAY_IP, hwdst=GATEWAY_MAC,
        )

    # Final 10 frames: 5 restore bursts carrying the real MACs.
    for offset in range(4, 14, 2):
        _assert_arp_reply(
            scapy, sent[offset][0],
            dst_mac=VICTIM_MAC, psrc=GATEWAY_IP, hwsrc=GATEWAY_MAC,
            pdst=VICTIM_IP, hwdst=VICTIM_MAC,
        )
        _assert_arp_reply(
            scapy, sent[offset + 1][0],
            dst_mac=GATEWAY_MAC, psrc=VICTIM_IP, hwsrc=VICTIM_MAC,
            pdst=GATEWAY_IP, hwdst=GATEWAY_MAC,
        )

    assert sleeps == [0.2] * 5
    text = output.export_text()
    assert "Poisoned packets: 4" in text
    assert "ARP response stopped; restoration attempted." in text


def test_poison_scapy_restores_after_keyboard_interrupt(monkeypatch, output):
    scapy = pytest.importorskip("scapy.all")
    macs = {VICTIM_IP: VICTIM_MAC, GATEWAY_IP: GATEWAY_MAC}
    monkeypatch.setattr(spoofer, "_resolve_mac", lambda ip, _iface: macs[ip])
    monkeypatch.setattr(spoofer, "get_if_hwaddr", lambda _iface: OUR_MAC, raising=False)

    sent = []

    def fake_sendp(frame, **kwargs):
        sent.append((frame, kwargs))
        # Interrupt mid-poisoning on the second frame of round 1.
        if len(sent) == 2:
            raise KeyboardInterrupt

    monkeypatch.setattr(spoofer, "sendp", fake_sendp, raising=False)

    spoofer._poison_scapy(VICTIM_IP, GATEWAY_IP, IFACE, interval=0)

    # 2 poison attempts (second interrupted) + 10 restore frames.
    assert len(sent) == 12
    for offset in range(2, 12, 2):
        _assert_arp_reply(
            scapy, sent[offset][0],
            dst_mac=VICTIM_MAC, psrc=GATEWAY_IP, hwsrc=GATEWAY_MAC,
            pdst=VICTIM_IP, hwdst=VICTIM_MAC,
        )
        _assert_arp_reply(
            scapy, sent[offset + 1][0],
            dst_mac=GATEWAY_MAC, psrc=VICTIM_IP, hwsrc=VICTIM_MAC,
            pdst=GATEWAY_IP, hwdst=GATEWAY_MAC,
        )

    text = output.export_text()
    assert "Restoring ARP (5 bursts)" in text
    assert "ARP response stopped; restoration attempted." in text


def test_poison_scapy_attempts_all_restore_frames_when_some_fail(monkeypatch, output, warnings):
    scapy = pytest.importorskip("scapy.all")
    macs = {VICTIM_IP: VICTIM_MAC, GATEWAY_IP: GATEWAY_MAC}
    monkeypatch.setattr(spoofer, "_resolve_mac", lambda ip, _iface: macs[ip])
    monkeypatch.setattr(spoofer, "get_if_hwaddr", lambda _iface: OUR_MAC, raising=False)

    stop_event = Event()
    sent = []
    failing_restore_indices = {0, 3, 7}

    def fake_sendp(frame, **kwargs):
        idx = len(sent)
        sent.append(frame)
        if idx == 1:
            stop_event.set()
        elif idx >= 2 and (idx - 2) in failing_restore_indices:
            raise OSError("tx failed")

    monkeypatch.setattr(spoofer, "sendp", fake_sendp, raising=False)

    spoofer._poison_scapy(VICTIM_IP, GATEWAY_IP, IFACE, interval=0, stop_event=stop_event)

    # 2 poison frames + all 10 restore frames attempted despite 3 send errors.
    assert len(sent) == 12
    for offset in range(2, 12, 2):
        _assert_arp_reply(
            scapy, sent[offset],
            dst_mac=VICTIM_MAC, psrc=GATEWAY_IP, hwsrc=GATEWAY_MAC,
            pdst=VICTIM_IP, hwdst=VICTIM_MAC,
        )
        _assert_arp_reply(
            scapy, sent[offset + 1],
            dst_mac=GATEWAY_MAC, psrc=VICTIM_IP, hwsrc=VICTIM_MAC,
            pdst=GATEWAY_IP, hwdst=GATEWAY_MAC,
        )
    assert len(warnings) == 3
    assert all("ARP restoration failed" in w and "tx failed" in w for w in warnings)
    assert output.export_text().count("ARP restoration failed: tx failed") == 3


# ── poison ─────────────────────────────────────────────────────────

def test_poison_returns_immediately_when_stop_event_already_set():
    stop_event = Event()
    stop_event.set()
    # Autouse forbids resolve_command, Popen, and Scapy calls; none may run.
    spoofer.poison(VICTIM_IP, GATEWAY_IP, IFACE, stop_event=stop_event)


def test_poison_falls_back_to_scapy_when_arpspoof_missing(monkeypatch, output):
    monkeypatch.setattr(spoofer, "resolve_command", lambda _cmd: None)
    monkeypatch.setattr(spoofer, "_SCAPY_OK", True)
    delegated = []
    monkeypatch.setattr(
        spoofer,
        "_poison_scapy",
        lambda *args, **kwargs: delegated.append((args, kwargs)),
    )

    stop_event = Event()
    spoofer.poison(VICTIM_IP, GATEWAY_IP, IFACE, stop_event=stop_event)

    assert delegated == [((VICTIM_IP, GATEWAY_IP, IFACE), {"stop_event": stop_event})]
    text = output.export_text()
    assert "arpspoof not found; using Scapy fallback." in text
    assert VICTIM_IP in text and GATEWAY_IP in text and IFACE in text


def test_poison_arpspoof_starts_two_processes_and_stops_on_event(monkeypatch, output):
    monkeypatch.setattr(spoofer, "resolve_command", lambda cmd: "/usr/sbin/arpspoof" if cmd == "arpspoof" else None)
    spawned = []
    procs = [Mock(), Mock()]
    for proc in procs:
        proc.poll.return_value = None

    def fake_popen(argv, **kwargs):
        idx = len(spawned)
        spawned.append((argv, kwargs))
        return procs[idx]

    monkeypatch.setattr(spoofer.subprocess, "Popen", fake_popen)

    wait_calls = []
    wait_results = iter([False, True])
    stop_event = SimpleNamespace(
        is_set=lambda: False,
        wait=lambda timeout: (wait_calls.append(timeout), next(wait_results))[1],
    )

    spoofer.poison(VICTIM_IP, GATEWAY_IP, IFACE, stop_event=stop_event)

    assert spawned == [
        (["/usr/sbin/arpspoof", "-i", IFACE, "-t", VICTIM_IP, GATEWAY_IP],
         {"stdout": subprocess.DEVNULL, "stderr": subprocess.DEVNULL}),
        (["/usr/sbin/arpspoof", "-i", IFACE, "-t", GATEWAY_IP, VICTIM_IP],
         {"stdout": subprocess.DEVNULL, "stderr": subprocess.DEVNULL}),
    ]
    assert wait_calls == [0.5, 0.5]
    for proc in procs:
        proc.terminate.assert_called_once_with()
        proc.wait.assert_called_once_with(timeout=5)
    text = output.export_text()
    assert "Poisoning ARP..." in text
    assert "ARP response processes stopped." in text
    assert "terminated" not in text


def test_poison_stops_after_first_popen_if_stop_event_set(monkeypatch):
    monkeypatch.setattr(spoofer, "resolve_command", lambda _cmd: "/usr/sbin/arpspoof")
    stop_event = Event()
    proc1 = Mock()
    proc1.poll.return_value = None
    spawned = []

    def fake_popen(argv, **kwargs):
        spawned.append(argv)
        stop_event.set()
        return proc1

    monkeypatch.setattr(spoofer.subprocess, "Popen", fake_popen)

    spoofer.poison(VICTIM_IP, GATEWAY_IP, IFACE, stop_event=stop_event)

    assert spawned == [["/usr/sbin/arpspoof", "-i", IFACE, "-t", VICTIM_IP, GATEWAY_IP]]
    proc1.terminate.assert_called_once_with()
    proc1.wait.assert_called_once_with(timeout=5)


def test_poison_terminates_survivor_when_one_process_exits_early(monkeypatch, output, warnings):
    monkeypatch.setattr(spoofer, "resolve_command", lambda _cmd: "/usr/sbin/arpspoof")
    proc1 = Mock()
    # Alive on first loop check (enters wait), dead on subsequent checks.
    proc1.poll.side_effect = [None, 1, 1, 1]
    proc2 = Mock()
    proc2.poll.return_value = None
    procs = iter([proc1, proc2])
    monkeypatch.setattr(spoofer.subprocess, "Popen", lambda *a, **k: next(procs))

    wait_calls = []
    stop_event = SimpleNamespace(
        is_set=lambda: False,
        wait=lambda timeout: (wait_calls.append(timeout), False)[1],
    )

    spoofer.poison(VICTIM_IP, GATEWAY_IP, IFACE, stop_event=stop_event)

    assert wait_calls == [0.5]
    proc1.terminate.assert_not_called()
    proc2.terminate.assert_called_once_with()
    proc2.wait.assert_called_once_with(timeout=5)
    assert any("arpspoof terminated unexpectedly" in w for w in warnings)
    assert "An arpspoof process terminated" in output.export_text()


def test_poison_handles_keyboard_interrupt_while_waiting(monkeypatch, output):
    monkeypatch.setattr(spoofer, "resolve_command", lambda _cmd: "/usr/sbin/arpspoof")
    procs = [Mock(), Mock()]
    for proc in procs:
        proc.poll.return_value = None
    proc_iter = iter(procs)
    monkeypatch.setattr(spoofer.subprocess, "Popen", lambda *a, **k: next(proc_iter))

    def raise_interrupt(_timeout):
        raise KeyboardInterrupt

    stop_event = SimpleNamespace(is_set=lambda: False, wait=raise_interrupt)

    spoofer.poison(VICTIM_IP, GATEWAY_IP, IFACE, stop_event=stop_event)

    for proc in procs:
        proc.terminate.assert_called_once_with()
        proc.wait.assert_called_once_with(timeout=5)
    text = output.export_text()
    assert "Stopping and restoring network" in text
    assert "ARP response processes stopped." in text


def test_poison_kills_process_that_ignores_terminate(monkeypatch):
    monkeypatch.setattr(spoofer, "resolve_command", lambda _cmd: "/usr/sbin/arpspoof")
    stubborn_events = []

    class _StubbornProc:
        def poll(self):
            return None

        def terminate(self):
            stubborn_events.append("terminate")

        def wait(self, timeout=None):
            stubborn_events.append(("wait", timeout))
            if timeout is not None:
                raise subprocess.TimeoutExpired(cmd="arpspoof", timeout=timeout)
            return -9

        def kill(self):
            stubborn_events.append("kill")

    normal_proc = Mock()
    normal_proc.poll.return_value = None
    procs = iter([_StubbornProc(), normal_proc])
    monkeypatch.setattr(spoofer.subprocess, "Popen", lambda *a, **k: next(procs))

    stop_event = SimpleNamespace(is_set=lambda: False, wait=lambda _t: True)

    spoofer.poison(VICTIM_IP, GATEWAY_IP, IFACE, stop_event=stop_event)

    assert stubborn_events == ["terminate", ("wait", 5), "kill", ("wait", None)]
    normal_proc.terminate.assert_called_once_with()
    normal_proc.wait.assert_called_once_with(timeout=5)


def test_poison_skips_terminate_for_already_exited_processes(monkeypatch):
    monkeypatch.setattr(spoofer, "resolve_command", lambda _cmd: "/usr/sbin/arpspoof")
    proc1, proc2 = Mock(), Mock()
    proc1.poll.return_value = 0
    proc2.poll.return_value = 1
    procs = iter([proc1, proc2])
    monkeypatch.setattr(spoofer.subprocess, "Popen", lambda *a, **k: next(procs))

    spoofer.poison(VICTIM_IP, GATEWAY_IP, IFACE, stop_event=Event())

    for proc in (proc1, proc2):
        proc.terminate.assert_not_called()
        proc.wait.assert_not_called()
        proc.kill.assert_not_called()
