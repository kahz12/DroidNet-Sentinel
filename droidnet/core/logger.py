"""
Structured logger for DroidNet Sentinel.

Exposes get_logger(name) returning a stdlib logging.Logger with two
handlers attached once per process:

    1. RichHandler on stdout — colourised, level driven by configure().
    2. RotatingFileHandler on  <BASE_DIR>/logs/droidnet.log
       (5 MB × 3 rotations, plain text, ISO timestamps).

The TUI keeps using `rich.print` for user-facing prose; the logger is
for events worth replaying after the fact (scan started/finished, NVD
cache hit, rate-limit triggered, ARP poison launched, …).

Usage:
    from droidnet.core.logger import get_logger
    log = get_logger(__name__)
    log.info("scan started network=%s", ssid)

Verbosity:
    configure(verbose=True)  → DEBUG  on stdout
    configure(quiet=True)    → ERROR  on stdout
    default                  → INFO   on stdout
The file handler always logs at DEBUG to keep a complete trail.
"""

import logging
from logging.handlers import RotatingFileHandler
from pathlib import Path

from droidnet.config import BASE_DIR

_LOG_DIR  = BASE_DIR / "logs"
_LOG_FILE = _LOG_DIR / "droidnet.log"

_FILE_FORMAT  = "%(asctime)s %(levelname)-7s %(name)s :: %(message)s"
_DATE_FORMAT  = "%Y-%m-%d %H:%M:%S"

_configured = False
_stdout_handler: logging.Handler | None = None


def _build_stdout_handler() -> logging.Handler:
    """Prefer RichHandler when rich is available; fall back to plain stream."""
    try:
        from rich.logging import RichHandler
        return RichHandler(
            show_path=False,
            show_time=True,
            rich_tracebacks=True,
            markup=False,
        )
    except Exception:
        h = logging.StreamHandler()
        h.setFormatter(logging.Formatter(_FILE_FORMAT, _DATE_FORMAT))
        return h


def _build_file_handler() -> logging.Handler | None:
    """5 MB × 3 rotations. Returns None if the logs dir cannot be created."""
    try:
        _LOG_DIR.mkdir(parents=True, exist_ok=True)
        h = RotatingFileHandler(
            _LOG_FILE, maxBytes=5 * 1024 * 1024, backupCount=3, encoding="utf-8",
        )
        h.setFormatter(logging.Formatter(_FILE_FORMAT, _DATE_FORMAT))
        h.setLevel(logging.DEBUG)
        return h
    except OSError:
        return None


def configure(verbose: bool = False, quiet: bool = False) -> None:
    """
    Initialise the root droidnet logger. Idempotent.

    *verbose* and *quiet* only affect the stdout handler — file logging
    stays at DEBUG so we always have a full trail.
    """
    global _configured, _stdout_handler

    root = logging.getLogger("droidnet")
    root.setLevel(logging.DEBUG)
    root.propagate = False  # Don't bubble to the python root.

    if not _configured:
        _stdout_handler = _build_stdout_handler()
        root.addHandler(_stdout_handler)
        file_handler = _build_file_handler()
        if file_handler is not None:
            root.addHandler(file_handler)
        _configured = True

    if _stdout_handler is not None:
        if quiet:
            _stdout_handler.setLevel(logging.ERROR)
        elif verbose:
            _stdout_handler.setLevel(logging.DEBUG)
        else:
            _stdout_handler.setLevel(logging.INFO)


def get_logger(name: str) -> logging.Logger:
    """
    Return a logger under the `droidnet` namespace.

    The first call triggers configure() with default verbosity, so
    modules can `log = get_logger(__name__)` at import time without
    worrying about init order.
    """
    if not _configured:
        configure()
    if not name.startswith("droidnet"):
        name = f"droidnet.{name}"
    return logging.getLogger(name)


__all__ = ["configure", "get_logger"]
