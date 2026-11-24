"""Every command line runs the one action it names, and nothing else.

handle_args() maps the subcommands and the legacy flat flags onto the feature
modules. Each feature entry point is replaced by a recorder, so a dispatch
here runs no scan, starts no server and sends no packet.
"""
import io
import sys

import pytest
from rich.console import Console

from droidnet.cli import args as cli
from droidnet.cli import menu
from droidnet.core import database
from droidnet.modules import cve_watcher, deauther, hunter, sentinel, spoofer
from droidnet.web import dashboard

MAC   = "AA:BB:CC:DD:EE:FF"
BSSID = "11:22:33:44:55:66"

_LOOPBACK = [("banner",  (), {"host": "127.0.0.1"}),
             ("app.run", (), {"host": "127.0.0.1", "port": 5000,
                              "debug": False, "use_reloader": False})]
_EXPOSED  = [("banner",  (), {"host": "0.0.0.0"}),
             ("app.run", (), {"host": "0.0.0.0", "port": 5000,
                              "debug": False, "use_reloader": False})]


@pytest.fixture
def calls(monkeypatch):
    """Record every feature entry point handle_args can reach."""
    log = []

    def recorder(name, result=None):
        def record(*args, **kwargs):
            log.append((name, args, kwargs))
            return result
        return record

    monkeypatch.setattr(sentinel,       "run_sentinel",          recorder("run_sentinel"))
    monkeypatch.setattr(hunter,         "run_hunter",            recorder("run_hunter"))
    monkeypatch.setattr(cve_watcher,    "run_cve_watcher",       recorder("run_cve_watcher"))
    monkeypatch.setattr(dashboard,      "_print_startup_banner", recorder("banner"))
    monkeypatch.setattr(dashboard.app,  "run",                   recorder("app.run"))
    monkeypatch.setattr(menu,           "list_reports",          recorder("list_reports"))
    monkeypatch.setattr(menu,           "show_guard_log",        recorder("show_guard_log"))
    monkeypatch.setattr(spoofer,        "poison",                recorder("poison"))
    monkeypatch.setattr(deauther,       "deauth_target",         recorder("deauth_target"))
    monkeypatch.setattr(database,       "purge_old_scans",       recorder("purge", result=3))
    monkeypatch.setattr(cli, "check_root",        lambda: True)
    monkeypatch.setattr(cli, "get_default_iface", lambda: "wlan7")
    return log


@pytest.fixture
def out(monkeypatch):
    """What handle_args printed, as plain text."""
    rec = Console(file=io.StringIO(), record=True, width=200, color_system=None)
    monkeypatch.setattr(cli, "rprint", rec.print)
    return lambda: rec.export_text(clear=False)


def dispatch(*argv):
    return cli.handle_args(cli._build_parser().parse_args(list(argv)))


# ── parse_args ─────────────────────────────────────────────────────

@pytest.mark.parametrize("flags, verbose, quiet", [
    ([],     False, False),
    (["-v"], True,  False),
    (["-q"], False, True),
])
def test_parse_args_sets_the_log_level_from_the_verbosity_flags(monkeypatch, flags, verbose, quiet):
    seen = []
    monkeypatch.setattr(cli, "_log_configure", lambda **kwargs: seen.append(kwargs))
    monkeypatch.setattr(sys, "argv", ["main.py", *flags, "reports"])
    assert cli.parse_args().cmd == "reports"
    assert seen == [{"verbose": verbose, "quiet": quiet}]


# ── subcommands ────────────────────────────────────────────────────

@pytest.mark.parametrize("argv, expected", [
    (["scan"],                 [("run_sentinel", (), {"interactive": True,  "auto_cut": False})]),
    (["scan", "--auto-cut"],   [("run_sentinel", (), {"interactive": True,  "auto_cut": True})]),
    (["daemon"],               [("run_sentinel", (), {"interactive": False, "auto_cut": False})]),
    (["daemon", "--auto-cut"], [("run_sentinel", (), {"interactive": False, "auto_cut": True})]),
    (["hunt"],                 [("run_hunter", (), {})]),
    (["dashboard"],            _LOOPBACK),
    (["dashboard", "--expose"], _EXPOSED),
    (["reports"],              [("list_reports", (), {})]),
    (["guard-log"],            [("show_guard_log", (50,), {})]),
    (["guard-log", "--limit", "5"], [("show_guard_log", (5,), {})]),
    (["spoof", "10.0.0.5", "10.0.0.1"],
     [("poison", ("10.0.0.5", "10.0.0.1", "wlan7"), {})]),
    (["spoof", "10.0.0.5", "10.0.0.1", "--iface", "eth3"],
     [("poison", ("10.0.0.5", "10.0.0.1", "eth3"), {})]),
    (["deauth", MAC, BSSID, "--iface", "mon0"],
     [("deauth_target", (MAC, BSSID, "mon0"), {"count": 0, "channel": None})]),
    (["deauth", "Broadcast", BSSID, "--iface", "mon0", "--channel", "6", "--count", "20"],
     [("deauth_target", (deauther.BROADCAST, BSSID, "mon0"), {"count": 20, "channel": 6})]),
    (["db", "purge"],                [("purge", (90,), {})]),
    (["db", "purge", "--days", "7"], [("purge", (7,), {})]),
])
def test_subcommand_runs_its_action_once(calls, out, argv, expected):
    assert dispatch(*argv) is True
    assert calls == expected
    assert "deprecated" not in out()


def test_db_purge_reports_how_many_scans_it_deleted(calls, out):
    dispatch("db", "purge", "--days", "7")
    assert "Purged 3 scans older than 7 days." in out()


def test_db_without_an_action_prints_usage_and_deletes_nothing(calls, out):
    assert dispatch("db") is True
    assert calls == []
    assert "Usage: droidnet db purge [--days N]" in out()


def test_no_command_returns_false_so_the_menu_starts(calls):
    assert dispatch() is False
    assert calls == []


def test_a_subcommand_takes_precedence_over_a_legacy_flag(calls):
    assert dispatch("--scan", "hunt") is True
    assert calls == [("run_hunter", (), {})]


# ── legacy flat flags ──────────────────────────────────────────────

_SPOOF_HINT  = "droidnet spoof <VICTIM> <GATEWAY> [--iface IFACE]"
_DEAUTH_HINT = "droidnet deauth <MAC|broadcast> <BSSID> --iface IFACE"


@pytest.mark.parametrize("argv, replacement, expected", [
    (["--scan"],                 "droidnet scan [--auto-cut]",
     [("run_sentinel", (), {"interactive": True,  "auto_cut": False})]),
    (["--scan", "--auto-cut"],   "droidnet scan [--auto-cut]",
     [("run_sentinel", (), {"interactive": True,  "auto_cut": True})]),
    (["--daemon"],               "droidnet daemon [--auto-cut]",
     [("run_sentinel", (), {"interactive": False, "auto_cut": False})]),
    (["--daemon", "--auto-cut"], "droidnet daemon [--auto-cut]",
     [("run_sentinel", (), {"interactive": False, "auto_cut": True})]),
    (["--hunt"],                 "droidnet hunt",
     [("run_hunter", (), {})]),
    (["--dashboard"],            "droidnet dashboard [--expose]", _LOOPBACK),
    (["--dashboard", "--expose"], "droidnet dashboard [--expose]", _EXPOSED),
    (["--reports"],              "droidnet reports",
     [("list_reports", (), {})]),
    (["--spoof", "10.0.0.5", "10.0.0.1"], _SPOOF_HINT,
     [("poison", ("10.0.0.5", "10.0.0.1", "wlan7"), {})]),
    (["--spoof", "10.0.0.5", "10.0.0.1", "eth3"], _SPOOF_HINT,
     [("poison", ("10.0.0.5", "10.0.0.1", "eth3"), {})]),
    (["--deauth", "broadcast", BSSID, "mon0"], _DEAUTH_HINT,
     [("deauth_target", (deauther.BROADCAST, BSSID, "mon0"), {"count": 0, "channel": None})]),
])
def test_legacy_flag_still_works_and_points_to_the_subcommand(calls, out, argv, replacement, expected):
    assert dispatch(*argv) is True
    assert calls == expected
    # Printed literally: "[--auto-cut]" and "<MAC|broadcast>" are not Rich markup.
    assert f"{argv[0]} is deprecated; use: {replacement}" in out()


def test_legacy_spoof_needs_both_victim_and_gateway(calls, out):
    assert dispatch("--spoof", "10.0.0.5") is True
    assert calls == []
    assert "[✗] --spoof needs at least <VICTIM_IP> <GATEWAY_IP>" in out()


# ── root-only commands ─────────────────────────────────────────────

@pytest.mark.parametrize("argv", [
    ["spoof", "10.0.0.5", "10.0.0.1"],
    ["--spoof", "10.0.0.5", "10.0.0.1"],
    ["deauth", MAC, BSSID, "--iface", "mon0"],
    ["--deauth", MAC, BSSID, "mon0"],
])
def test_attacks_refuse_to_start_without_root(calls, out, monkeypatch, argv):
    monkeypatch.setattr(cli, "check_root", lambda: False)
    assert dispatch(*argv) is True
    assert calls == []
    # The marker must survive Rich markup: "[x]" would be parsed as a tag.
    assert "[✗] Root privileges required." in out()
