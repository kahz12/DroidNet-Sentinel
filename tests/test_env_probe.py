"""The startup probe reports what each module can actually do on this host.

Hunter runs without searchsploit: it falls back to the public Vulners API
(online, rate-limited). Marking it as unavailable sends users looking for a
package they may not be able to install (exploitdb has no Termux package)
for a module that already works, so it is shown as usable in a reduced mode.
"""
import io

import pytest
from rich.console import Console

from droidnet.core import env


def _probe(monkeypatch, *, is_root=False, monitor=False, **tools):
    """Render display_capabilities() for a host with *tools*; return its text."""
    rec = Console(file=io.StringIO(), record=True, width=200, color_system=None)
    monkeypatch.setattr(env, "console", rec)
    env.display_capabilities({
        "platform_name": "Linux", "is_termux": False, "is_root": is_root,
        "raw_sockets_enabled": is_root, "monitor_mode_capable": monitor,
        "default_iface": "wlan0", "tools": {"nmap": True, **tools},
    })
    return rec.export_text()


def _module_line(text, name):
    return next(line.strip() for line in text.splitlines() if name in line)


def test_hunter_without_searchsploit_is_usable_online(monkeypatch):
    line = _module_line(_probe(monkeypatch, searchsploit=False), "Hunter")
    assert line.startswith("~ Hunter")
    assert "Vulners" in line


def test_hunter_with_searchsploit_needs_no_note(monkeypatch):
    line = _module_line(_probe(monkeypatch, searchsploit=True), "Hunter")
    assert line == "+ Hunter (Exploit lookup)"


@pytest.mark.parametrize("name, note", [
    ("Spoofer", "Requires root + arpspoof"),
    ("Deauther", "Requires root + iw + monitor mode"),
])
def test_modules_that_cannot_run_are_still_marked_missing(monkeypatch, name, note):
    line = _module_line(_probe(monkeypatch, searchsploit=False, arpspoof=False), name)
    assert line.startswith(f"x {name}") and note in line


def test_tool_list_still_reports_searchsploit_itself_as_missing(monkeypatch):
    text = _probe(monkeypatch, searchsploit=False)
    assert "x searchsploit" in [line.strip() for line in text.splitlines()]
