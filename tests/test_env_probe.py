"""The startup probe reports what each module can actually do on this host.

Hunter runs without searchsploit: it searches the Exploit-DB catalogue it
downloads on first use, or Vulners when VULNERS_API_KEY is set. Marking it as
unavailable sends users looking for a package they may not be able to install
(exploitdb has no Termux package) for a module that already works, so it is
shown as usable in a reduced mode, naming the source it will use.
"""
import io

import pytest
from rich.console import Console

from droidnet import config
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


@pytest.mark.parametrize("key, source", [
    ("", "Exploit-DB catalogue"),
    ("a-vulners-key", "Vulners API"),
])
def test_hunter_without_searchsploit_names_its_fallback(monkeypatch, key, source):
    monkeypatch.setattr(config, "VULNERS_API_KEY", key)
    line = _module_line(_probe(monkeypatch, searchsploit=False), "Hunter")
    assert line.startswith("~ Hunter")
    assert source in line
    assert key == "" or key not in line          # the key itself is never shown


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


@pytest.mark.parametrize("tools, name, note", [
    # Only what is still missing is listed: with arpspoof installed, a
    # standard user lacks root alone.
    ({"arpspoof": True},  "Spoofer",  "(Requires root)"),
    ({"iw": True},        "Deauther", "(Requires root + monitor mode)"),
])
def test_notes_list_only_the_missing_requirements(monkeypatch, tools, name, note):
    line = _module_line(_probe(monkeypatch, searchsploit=False, **tools), name)
    assert line.endswith(note)


def _tool_line(text, tool):
    """The Tools-section line for *tool* ("+ iw", "x nmcli", ...)."""
    return next(line.strip() for line in text.splitlines()
                if len(line.split()) >= 2 and line.split()[1] == tool)


@pytest.mark.parametrize("tools, tool, expected", [
    # nmcli and iw both read the Wi-Fi network name, so with iw installed a
    # missing nmcli is no gap.
    ({"iw": True, "nmcli": False},  "nmcli", "~ nmcli (not needed: iw in use)"),
    ({"iw": False, "nmcli": False}, "nmcli", "x nmcli"),
    # The reverse does not hold: iw also enables monitor mode for the Deauther.
    ({"iw": False, "nmcli": True},  "iw",    "x iw"),
])
def test_a_tool_covered_by_another_is_not_reported_missing(monkeypatch, tools, tool, expected):
    assert _tool_line(_probe(monkeypatch, **tools), tool) == expected


def test_tool_list_still_reports_searchsploit_itself_as_missing(monkeypatch):
    text = _probe(monkeypatch, searchsploit=False)
    assert "x searchsploit" in [line.strip() for line in text.splitlines()]


def test_evaluate_system_monitor_mode_requires_iw(monkeypatch):
    monkeypatch.setattr(env, "check_root", lambda: True)
    monkeypatch.setattr(env, "get_default_iface", lambda: "wlan0")
    monkeypatch.setattr(env, "get_available_tools", lambda: {"iw": False})
    monkeypatch.setattr(env, "has_command", lambda cmd: cmd == "airmon-ng")
    assert env.evaluate_system()["monitor_mode_capable"] is False

    monkeypatch.setattr(env, "has_command", lambda cmd: cmd == "iw")
    assert env.evaluate_system()["monitor_mode_capable"] is True
