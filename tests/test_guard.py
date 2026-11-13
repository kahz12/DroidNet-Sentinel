"""The ARP-cut guardian: audit journal, graceful shutdown, wake lock, refusal.

No real ARP frames are sent and no signal handler survives a test: the
termination handlers are installed and torn down inside the test, and the
journal writes to the per-test isolated database from conftest.
"""
import os
import signal
import threading
from types import SimpleNamespace

import pytest

from droidnet.core.database import get_guard_events, record_guard_event
from droidnet.core.guard import terminating_signals
from droidnet.modules import sentinel
from droidnet.platform import utils


# ── guard journal ──────────────────────────────────────────────────

def test_journal_records_events_newest_first():
    record_guard_event("guard_start", reason="daemon")
    record_guard_event("cut", ip="192.0.2.9", network="Home", reason="not in trusted_ips")
    record_guard_event("restore", ip="192.0.2.9", network="Home")
    events = get_guard_events()
    assert [e["action"] for e in events] == ["restore", "cut", "guard_start"]
    cut = events[1]
    assert (cut["ip"], cut["network"], cut["reason"]) == \
        ("192.0.2.9", "Home", "not in trusted_ips")


def test_journal_rejects_unknown_actions():
    record_guard_event("nuke", ip="192.0.2.9")
    assert get_guard_events() == []


def test_journal_limit():
    for n in range(5):
        record_guard_event("cut", ip=f"192.0.2.{n}")
    assert len(get_guard_events(limit=3)) == 3


def test_journal_write_never_raises(monkeypatch):
    # A locked or read-only database must not break the caller mid-restore.
    import droidnet.core.database as db

    def boom(*a, **k):
        raise db.sqlite3.OperationalError("database is locked")

    monkeypatch.setattr(db, "_conn", boom)
    record_guard_event("restore", ip="192.0.2.9")   # must return quietly


def test_journal_survives_scan_purge():
    # The journal is its own table, so pruning old scans leaves it intact.
    from droidnet.core import database
    record_guard_event("cut", ip="192.0.2.9")
    database.purge_old_scans(0)                      # opt-out path, deletes nothing
    database.save_scan("Home", "20260101_000000", {"192.0.2.9": ["Shield intact"]})
    assert any(e["action"] == "cut" for e in get_guard_events())


# ── termination signals ────────────────────────────────────────────

def test_sigterm_becomes_keyboardinterrupt_and_handler_is_restored():
    before = signal.getsignal(signal.SIGTERM)
    with pytest.raises(KeyboardInterrupt):
        with terminating_signals():
            assert signal.getsignal(signal.SIGTERM) is not before
            os.kill(os.getpid(), signal.SIGTERM)
    assert signal.getsignal(signal.SIGTERM) is before


def test_sighup_is_also_trapped():
    with pytest.raises(KeyboardInterrupt):
        with terminating_signals():
            os.kill(os.getpid(), signal.SIGHUP)


def test_off_main_thread_is_a_noop():
    error = []

    def worker():
        try:
            with terminating_signals():
                pass
        except Exception as exc:          # installing a handler would raise here
            error.append(exc)

    thread = threading.Thread(target=worker)
    thread.start()
    thread.join()
    assert error == []


# ── wake lock ──────────────────────────────────────────────────────

def test_wake_lock_acquires_and_releases_on_termux(monkeypatch):
    calls = []
    monkeypatch.setattr(utils, "is_termux", lambda: True)
    monkeypatch.setattr(utils, "has_command", lambda cmd: True)
    monkeypatch.setattr(utils.subprocess, "run",
                        lambda argv, **k: calls.append(argv[0]))
    with utils.wake_lock() as held:
        assert held is True
    assert calls == ["termux-wake-lock", "termux-wake-unlock"]


def test_wake_lock_releases_even_on_error(monkeypatch):
    calls = []
    monkeypatch.setattr(utils, "is_termux", lambda: True)
    monkeypatch.setattr(utils, "has_command", lambda cmd: True)
    monkeypatch.setattr(utils.subprocess, "run",
                        lambda argv, **k: calls.append(argv[0]))
    with pytest.raises(RuntimeError):
        with utils.wake_lock():
            raise RuntimeError("boom")
    assert calls == ["termux-wake-lock", "termux-wake-unlock"]


def test_wake_lock_is_a_noop_off_termux(monkeypatch):
    monkeypatch.setattr(utils, "is_termux", lambda: False)
    monkeypatch.setattr(utils.subprocess, "run",
                        lambda *a, **k: pytest.fail("ran a command off Termux"))
    with utils.wake_lock() as held:
        assert held is False


def test_wake_lock_nonzero_exit_reports_not_held_and_skips_unlock(monkeypatch):
    from types import SimpleNamespace

    calls = []
    monkeypatch.setattr(utils, "is_termux", lambda: True)
    monkeypatch.setattr(utils, "has_command", lambda cmd: True)
    monkeypatch.setattr(
        utils.subprocess,
        "run",
        lambda argv, **k: (calls.append(argv[0]), SimpleNamespace(returncode=1))[1],
    )
    with utils.wake_lock() as held:
        assert held is False
    assert calls == ["termux-wake-lock"]


def test_send_notification_falls_back_to_console_when_notify_send_fails(monkeypatch):
    from types import SimpleNamespace

    printed = []
    monkeypatch.setattr(utils, "is_termux", lambda: False)
    monkeypatch.setattr(utils, "has_command", lambda cmd: cmd == "notify-send")
    monkeypatch.setattr(utils.subprocess, "run", lambda *a, **k: SimpleNamespace(returncode=1))
    monkeypatch.setattr(utils, "rprint", printed.append)
    utils.send_notification("Alert", "Body")
    assert len(printed) == 1 and "Alert" in printed[0] and "Body" in printed[0]


# ── auto-cut safety and journaling ─────────────────────────────────

def test_empty_allowlist_refuses_to_cut_and_records_it(monkeypatch):
    monkeypatch.setattr(sentinel, "get_default_gateway",
                        lambda _ip: pytest.fail("reached gateway lookup; should refuse first"))
    jobs = sentinel.AutoCutSession()
    sentinel.cut_unknowns(["192.0.2.9", "192.0.2.10"], "192.0.2.2",
                          {"trusted_ips": []}, jobs, network="Home")
    assert jobs.jobs == {}
    events = get_guard_events()
    assert events and events[0]["action"] == "refused"
    assert events[0]["reason"] == "trusted_ips empty"


def test_cut_and_restore_are_journalled(monkeypatch):
    started = threading.Event()

    def fake_poison(*args, stop_event):
        started.set()
        stop_event.wait(2)

    monkeypatch.setattr("droidnet.modules.spoofer.poison", fake_poison)
    jobs = sentinel.AutoCutSession()
    jobs.network = "Home"
    try:
        jobs.update({("192.0.2.50", "192.0.2.1", "wlan0")})
        assert started.wait(1)
    finally:
        jobs.close()
    actions = [(e["action"], e["ip"]) for e in get_guard_events()]
    assert ("cut", "192.0.2.50") in actions
    assert ("restore", "192.0.2.50") in actions


def test_aborted_poison_does_not_journal_false_cut(monkeypatch):
    # When poison() exits before entering its active loop (e.g. missing
    # arpspoof/scapy or failed MAC resolution), no 'cut' or 'restore' is
    # recorded in the guard journal.
    monkeypatch.setattr("droidnet.modules.spoofer.poison", lambda *a, stop_event: None)
    jobs = sentinel.AutoCutSession()
    jobs.network = "Home"
    jobs.update({("192.0.2.50", "192.0.2.1", "wlan0")})
    jobs.close()
    assert get_guard_events() == []
    assert jobs.jobs == {}


def test_run_sentinel_traps_signals_and_brackets_the_guard(monkeypatch):
    seen = {}

    def fake_loop(interactive, auto_cut, jobs, dhcp):
        # Inside the session the termination handler must be installed.
        seen["handler"] = signal.getsignal(signal.SIGTERM)

    monkeypatch.setattr(sentinel, "_run_sentinel_loop", fake_loop)
    monkeypatch.setattr(sentinel, "DhcpListener",
                        lambda *a, **k: SimpleNamespace(start=lambda: False, stop=lambda: None))
    before = signal.getsignal(signal.SIGTERM)
    sentinel.run_sentinel(interactive=True, auto_cut=True)
    assert seen["handler"] is not before                 # trapped during the run
    assert signal.getsignal(signal.SIGTERM) is before     # restored after
    actions = [e["action"] for e in get_guard_events()]
    assert actions.count("guard_start") == 1 and actions.count("guard_stop") == 1


def test_guard_events_not_recorded_without_auto_cut(monkeypatch):
    monkeypatch.setattr(sentinel, "_run_sentinel_loop", lambda *a: None)
    monkeypatch.setattr(sentinel, "DhcpListener",
                        lambda *a, **k: SimpleNamespace(start=lambda: False, stop=lambda: None))
    sentinel.run_sentinel(interactive=True, auto_cut=False)
    assert get_guard_events() == []


# ── guard-log view ─────────────────────────────────────────────────

def test_guard_log_renders_fields_literally(monkeypatch):
    import io
    from rich.console import Console
    from droidnet.cli import menu

    record_guard_event("cut", ip="192.0.2.9", network="Free[/wifi]", reason="not in trusted_ips")
    rec = Console(file=io.StringIO(), record=True, width=200, color_system=None)
    monkeypatch.setattr(menu, "console", rec)
    menu.show_guard_log()
    text = rec.export_text()
    assert "Free[/wifi]" in text and "192.0.2.9" in text and "cut" in text


def test_guard_log_empty(monkeypatch):
    import io
    from rich.console import Console
    from droidnet.cli import menu

    rec = Console(file=io.StringIO(), record=True, width=200, color_system=None)
    monkeypatch.setattr(menu, "rprint", rec.print)
    menu.show_guard_log()
    assert "empty" in rec.export_text()
