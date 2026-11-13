"""
Graceful shutdown for the scanner and the ARP-cut guardian.

    terminating_signals()  → context manager; SIGTERM/SIGHUP act like Ctrl+C

The ARP-cut guardian restores each victim's ARP table from the `finally`
blocks that run on the way out of a scan session. Those run on Ctrl+C
(SIGINT, which Python already turns into KeyboardInterrupt) but not on a
plain SIGTERM or SIGHUP: Python's default action for those terminates the
process immediately, skipping every `finally`, so the corrective ARP frames
are never sent and a cut victim is left stranded until its cache expires.

A service manager stops a daemon with SIGTERM (`systemctl stop`, Termux:Boot
teardown), and closing the terminal sends SIGHUP, so both are the normal way
the guardian is asked to stop. This turns them into the same KeyboardInterrupt
the rest of the shutdown path already handles.

A SIGKILL cannot be caught by anything — not this, not a wake lock — so a
hard kill (the Android low-memory or phantom-process killer often uses one)
still skips the restore. The network recovers on its own shortly after, as
ARP caches expire; the audit journal keeps the record of what was cut.
"""

import signal
from contextlib import contextmanager

from droidnet.core.logger import get_logger

log = get_logger(__name__)

# SIGHUP is POSIX-only; on platforms without it just handle SIGTERM.
_TERMINATION_SIGNALS = [
    sig for sig in ("SIGTERM", "SIGHUP") if hasattr(signal, sig)
]


@contextmanager
def terminating_signals():
    """Make SIGTERM and SIGHUP raise KeyboardInterrupt, then restore handlers.

    Inside the block, a SIGTERM or SIGHUP unwinds the stack through the same
    `finally`/`except KeyboardInterrupt` path as Ctrl+C, so the guardian's
    ARP restore runs before the process exits. Previous handlers are put back
    on the way out, so this leaves nothing installed behind it.

    Signal handlers can only be installed from the main thread; called from
    any other thread it does nothing but run the block, which keeps it usable
    in tests and when the scanner is driven from a worker thread.
    """
    def _raise(signum, _frame):
        name = signal.Signals(signum).name
        log.info("received %s; shutting down and restoring ARP", name)
        raise KeyboardInterrupt(name)

    installed: list[tuple[int, object]] = []
    try:
        for name in _TERMINATION_SIGNALS:
            signum = getattr(signal, name)
            previous = signal.signal(signum, _raise)
            installed.append((signum, previous))
    except ValueError:
        # Not the main thread: signals keep their defaults for this run.
        for signum, previous in installed:
            signal.signal(signum, previous)
        installed = []
    try:
        yield
    finally:
        for signum, previous in installed:
            signal.signal(signum, previous)
