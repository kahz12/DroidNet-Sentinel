"""Untrusted text in Sentinel, Hunter and the menu must never be parsed as Rich markup.

Hostnames (DHCP / mDNS), vendors, banners and SSIDs are controlled by other
devices; exploit titles come from Exploit-DB / Vulners; reports are JSON on
disk. A stray "[/x]" in any of them would raise MarkupError and abort the run,
and a valid "[link=...]" would turn into a terminal hyperlink, so each value is
escaped before it reaches Rich.
"""
import io
import json
import subprocess
from unittest.mock import Mock

import pytest
import requests
from rich.console import Console

from droidnet.cli import menu
from droidnet.core import database as db
from droidnet.core.markup import esc
from droidnet.modules import hunter, sentinel
from droidnet.platform import utils

LINK = "[link=https://evil.example]"
FILE_LINK = "[link=evil]"  # same tag, but legal inside a file name


def _record(monkeypatch, module):
    """Send *module*'s output to a plain recording console; return its text getter."""
    rec = Console(file=io.StringIO(), record=True, width=240, color_system=None)
    monkeypatch.setattr(module, "console", rec)
    monkeypatch.setattr(module, "rprint", rec.print)
    return rec.export_text


# ── shared helper ──────────────────────────────────────────────────

@pytest.mark.parametrize("value", ["a[/x]", f"{LINK}t", "ends\\", None, 42])
def test_esc_renders_value_literally(value):
    rec = Console(file=io.StringIO(), record=True, color_system=None)
    # A trailing backslash must not escape the closing tag that follows.
    rec.print(f"[bold]{esc(value)}[/bold]")
    assert rec.export_text().rstrip("\n") == str(value)


# ── Sentinel ───────────────────────────────────────────────────────

def test_sentinel_table_renders_device_fields_literally(monkeypatch):
    text_of = _record(monkeypatch, sentinel)
    sentinel.display_results_table(
        "ssid[/s]",
        {"192.0.2.5": [f"23/tcp open telnet Evil[/x] {LINK}d 1.0"],
         "192.0.2.6": ["Shield intact"]},
        {"192.0.2.5": {"hostname": "h[/h]", "vendor": "v[/v]"},
         "192.0.2.6": {"hostname": "p[/p]", "vendor": "q[/q]"}},
    )
    text = text_of()
    for token in ("ssid[/s]", "h[/h]", "v[/v]", "p[/p]", "q[/q]",
                  "Evil[/x]", f"{LINK}d"):
        assert token in text, token
    # The module's own risk / status markup still renders as styles.
    assert "CRITICAL" in text and "[bold red]" not in text
    assert "Closed" in text and "[blue]" not in text


@pytest.mark.parametrize("info, shown", [
    ({"ssid": "Free[/wifi]", "ip": "192.0.2.2"}, "Scanning network: Free[/wifi]"),
    ({"ip": "192.0.2.2"},                        "Scanning network: Unknown network"),
])
def test_sentinel_scan_line_prints_ssid_literally(monkeypatch, info, shown):
    text_of = _record(monkeypatch, sentinel)
    monkeypatch.setattr(sentinel, "init_db", lambda: None)
    monkeypatch.setattr(sentinel, "get_wifi_info", lambda: info)
    monkeypatch.setattr(sentinel, "load_user_config", lambda: {"db_retention_days": 0})
    # Discovery failure ends an interactive run right after the scan line.
    monkeypatch.setattr(sentinel, "ping_sweep", lambda *_: None)
    sentinel.run_sentinel(interactive=True)
    assert shown in text_of()


def test_console_notification_fallback_prints_ssid_literally(monkeypatch):
    # Without notify-send / termux-notification, Sentinel's post-scan alert
    # ("N hosts analysed on <SSID>") is printed to the console instead.
    rec = Console(file=io.StringIO(), record=True, width=240, color_system=None)
    monkeypatch.setattr(utils, "rprint", rec.print)
    monkeypatch.setattr(utils, "is_termux", lambda: False)
    monkeypatch.setattr(utils, "has_command", lambda _: False)
    utils.send_notification("Sentinel[/a]", "3 hosts analysed on Free[/wifi]")
    text = rec.export_text()
    assert "Sentinel[/a]" in text and "Free[/wifi]" in text


# ── Hunter ─────────────────────────────────────────────────────────

def test_hunter_renders_network_banner_and_exploit_fields_literally(monkeypatch):
    text_of = _record(monkeypatch, hunter)
    db.save_scan(f"lab{LINK}", "20261109_120000",
                 {"192.0.2.5": ["80/tcp open http Evil[/x] httpd 1.0"]})
    monkeypatch.setattr(hunter, "_searchsploit_path", lambda: "/usr/bin/searchsploit")
    monkeypatch.setattr(hunter, "_hunt_exploits_local", lambda _q: [
        {"Title": "t[/t] [red]x", "Path": "p[/p]", "Date_Published": "d[/d]"},
        {"Title": None, "Path": None, "Date_Published": None},
    ])
    hunter.run_hunter()
    text = text_of()
    for token in (f"lab{LINK}", "Evil[/x] httpd 1.0", "t[/t] [red]x", "p[/p]", "d[/d]"):
        assert token in text, token
    assert "Unknown" in text  # null title from an API falls back to a label


def test_hunter_error_messages_escape_query(monkeypatch):
    text_of = _record(monkeypatch, hunter)
    q = "q[/x]"
    monkeypatch.setattr(hunter.subprocess, "run",
                        Mock(side_effect=subprocess.TimeoutExpired(["searchsploit", q], 30)))
    assert hunter._hunt_exploits_local(q) is None
    monkeypatch.setattr(hunter.subprocess, "run",
                        Mock(return_value=Mock(returncode=0, stdout="not json [/j]")))
    assert hunter._hunt_exploits_local(q) is None
    monkeypatch.setattr(hunter.requests, "post",
                        Mock(side_effect=requests.ConnectionError("boom [/y]")))
    assert hunter._hunt_exploits_vulners(q, "test-key") is None
    assert text_of().count(q) >= 3


# ── Menu ───────────────────────────────────────────────────────────

def test_saved_reports_list_renders_report_fields_literally(monkeypatch, tmp_path):
    text_of = _record(monkeypatch, menu)
    monkeypatch.setattr(menu, "REPORTS_DIR", tmp_path)
    (tmp_path / f"r{FILE_LINK}.json").write_text(json.dumps(
        {"network": "n[/n]", "time": "t[/t]", "targets": {"192.0.2.1": []}}))
    menu.list_reports()
    text = text_of()
    for token in ("n[/n]", "t[/t]", f"r{FILE_LINK}.json"):
        assert token in text, token
