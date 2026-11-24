"""The interactive menu: rendering, the input loop and every action wrapper.

Keys are typed through sys.stdin, so Rich's real Prompt validates each answer
exactly as it does for a person at the terminal. Every feature entry point is
replaced by a recorder: no test here scans, serves or sends a packet.
"""
import io
import json
import os
import sys
from types import SimpleNamespace

import pytest
from rich.console import Console

from droidnet.cli import menu
from droidnet.core import env, risk
from droidnet.modules import cve_watcher, deauther, hunter, sentinel, spoofer
from droidnet.web import dashboard

MAC   = "AA:BB:CC:DD:EE:FF"
BSSID = "11:22:33:44:55:66"
_MENU_TITLE = "M A I N   M E N U"


@pytest.fixture
def screen(monkeypatch):
    """Send the menu's own output to a recording console; return a reader."""
    rec = Console(file=io.StringIO(), record=True, width=120, color_system=None)
    monkeypatch.setattr(menu, "console", rec)
    monkeypatch.setattr(menu, "rprint", rec.print)
    return lambda: rec.export_text(clear=False)


@pytest.fixture
def keys(monkeypatch):
    """Type lines at the keyboard. Reading past the last one raises EOFError,
    so a prompt that a test did not expect fails it."""
    def type_lines(*lines):
        monkeypatch.setattr(sys, "stdin", io.StringIO("".join(f"{line}\n" for line in lines)))
    type_lines()
    return type_lines


@pytest.fixture
def calls(monkeypatch):
    """Record every feature entry point the action wrappers reach."""
    log = []

    def recorder(name):
        def record(*args, **kwargs):
            log.append((name, args, kwargs))
        return record

    monkeypatch.setattr(sentinel,      "run_sentinel",          recorder("run_sentinel"))
    monkeypatch.setattr(hunter,        "run_hunter",            recorder("run_hunter"))
    monkeypatch.setattr(cve_watcher,   "run_cve_watcher",       recorder("run_cve_watcher"))
    monkeypatch.setattr(dashboard,     "_print_startup_banner", recorder("banner"))
    monkeypatch.setattr(dashboard.app, "run",                   recorder("app.run"))
    monkeypatch.setattr(spoofer,       "poison",                recorder("poison"))
    monkeypatch.setattr(deauther,      "deauth_target",         recorder("deauth_target"))
    monkeypatch.setattr(menu, "check_root",        lambda: True)
    monkeypatch.setattr(menu, "get_default_iface", lambda: "wlan7")
    return log


def _interrupt(*args, **kwargs):
    raise KeyboardInterrupt


# ── banner ─────────────────────────────────────────────────────────

def test_banner_shows_the_version_and_runs_the_environment_probe(screen, monkeypatch):
    shown = []
    monkeypatch.setattr(env, "evaluate_system", lambda: {"root": False})
    monkeypatch.setattr(env, "display_capabilities", shown.append)
    menu.print_banner()
    assert shown == [{"root": False}]
    assert f"v{menu.__version__}" in screen()
    assert "Authorised use only" in screen()


def test_banner_survives_a_failing_environment_probe(screen, monkeypatch):
    monkeypatch.setattr(env, "evaluate_system", lambda: 1 / 0)
    menu.print_banner()
    assert "Authorised use only" in screen()


# ── menu and help rendering ────────────────────────────────────────

def test_menu_shows_every_choice_with_its_label(screen):
    menu.print_menu()
    text = screen()
    for key, label, _desc, _style in menu._RECON_ITEMS + menu._OPS_ITEMS + menu._DATA_ITEMS:
        assert f"[{key}]" in text, key
        assert label in text, label


def test_help_screen_shows_every_section(screen):
    menu._show_help()
    text = screen()
    for title in ("User Guide", "Overview", "Features", "Risk levels",
                  "Safety & ethics", "Command-line equivalents"):
        assert title in text, title


def _rendered(panel):
    rec = Console(file=io.StringIO(), record=True, width=120, color_system=None)
    rec.print(panel)
    return rec.export_text()


def test_risk_help_lists_every_level_the_engine_returns():
    text = _rendered(menu._help_risk())
    # Every value core.risk.classify_risk can return.
    for level in ("CRITICAL", "MEDIUM", "LOW", "MINIMAL", "UNKNOWN"):
        assert level in text, level


# Service name shown in the help for each port the risk engine rates. A port
# added to core/risk.py without a name here fails the test below: name it here
# and in menu._help_risk().
_SERVICE = {
    "21/tcp": "FTP", "23/tcp": "Telnet", "139/tcp": "NetBIOS", "445/tcp": "SMB",
    "3389/tcp": "RDP", "80/tcp": "HTTP", "8080/tcp": "HTTP-alt", "53/tcp": "DNS",
    "1900/tcp": "SSDP", "2049/tcp": "NFS", "1883/tcp": "MQTT", "8883/tcp": "MQTT",
    "5683/tcp": "CoAP",
}


def test_risk_help_names_every_port_the_engine_rates():
    text = _rendered(menu._help_risk())
    for port in sorted(risk._CRITICAL | risk._MEDIUM):
        assert _SERVICE[port] in text, port


# ── main loop ──────────────────────────────────────────────────────

_ACTIONS = {
    "1": "_run_sentinel_interactive",
    "2": "_run_sentinel_daemon",
    "3": "_run_hunter",
    "4": "_run_cve_watcher",
    "5": "_run_dashboard",
    "6": "_run_spoofer_interactive",
    "7": "_run_deauther_interactive",
    "8": "list_reports",
    "9": "_show_help",
}


@pytest.fixture
def actions(monkeypatch):
    """Replace every menu action with a recorder of its name."""
    ran = []
    for name in _ACTIONS.values():
        monkeypatch.setattr(menu, name, lambda name=name: ran.append(name))
    return ran


def test_every_choice_but_exit_has_an_action():
    assert set(_ACTIONS) == set(menu._VALID_CHOICES) - {"0"}


@pytest.mark.parametrize("key, action", sorted(_ACTIONS.items()))
def test_each_choice_runs_its_action_once_then_returns_to_the_menu(
        screen, keys, actions, key, action):
    keys(key, "", "0")              # choose, press Enter, exit
    menu.interactive_menu()
    assert actions == [action]
    assert screen().count(_MENU_TITLE) == 2
    assert "DroidNet Sentinel closed" in screen()


def test_exit_runs_nothing(screen, keys, actions):
    keys("0")
    menu.interactive_menu()
    assert actions == []
    assert screen().count(_MENU_TITLE) == 1
    assert "DroidNet Sentinel closed" in screen()


def test_an_invalid_choice_is_asked_again_without_running_anything(screen, keys, actions):
    keys("42", "x", "0")
    menu.interactive_menu()
    assert actions == []
    # Asked again in place (no menu redraw) until "0" is typed.
    assert screen().count(_MENU_TITLE) == 1
    assert "DroidNet Sentinel closed" in screen()


def test_end_of_input_at_the_prompt_exits_cleanly(screen, keys, actions):
    keys()
    menu.interactive_menu()
    assert actions == []
    assert "Exiting..." in screen()


def test_ctrl_c_at_the_prompt_exits_cleanly(screen, monkeypatch, actions):
    monkeypatch.setattr(menu, "Prompt", SimpleNamespace(ask=_interrupt))
    menu.interactive_menu()
    assert actions == []
    assert "Exiting..." in screen()


def test_end_of_input_after_an_action_exits_cleanly(screen, keys, actions):
    keys("8")                       # stdin ends at "Press Enter"
    menu.interactive_menu()
    assert actions == ["list_reports"]
    assert "Press Enter to return to the menu" in screen()
    assert screen().count(_MENU_TITLE) == 1


# ── scan, daemon, Hunter, CVE Watcher, dashboard ───────────────────

@pytest.mark.parametrize("answer, auto_cut", [("", False), ("n", False), ("y", True)])
def test_quick_scan_asks_for_auto_cut_and_defaults_to_no(screen, keys, calls, answer, auto_cut):
    keys(answer)
    menu._run_sentinel_interactive()
    assert calls == [("run_sentinel", (), {"interactive": True, "auto_cut": auto_cut})]


@pytest.mark.parametrize("answer, auto_cut", [("", False), ("y", True)])
def test_daemon_asks_for_auto_cut_and_defaults_to_no(screen, keys, calls, answer, auto_cut):
    keys(answer)
    menu._run_sentinel_daemon()
    assert calls == [("run_sentinel", (), {"interactive": False, "auto_cut": auto_cut})]


def test_ctrl_c_stops_the_daemon_and_returns_to_the_menu(screen, keys, calls, monkeypatch):
    monkeypatch.setattr(sentinel, "run_sentinel", _interrupt)
    keys("")
    menu._run_sentinel_daemon()     # must not raise
    assert "Daemon stopped." in screen()


def test_hunter_runs(calls):
    menu._run_hunter()
    assert calls == [("run_hunter", (), {})]


@pytest.mark.parametrize("answer, days_back", [("", 120), ("n", 120), ("y", None)])
def test_cve_watcher_defaults_to_the_recent_window(screen, keys, calls, answer, days_back):
    keys(answer)
    menu._run_cve_watcher()
    assert calls == [("run_cve_watcher", (), {"days_back": days_back, "show_history": True})]


def test_dashboard_from_the_menu_always_binds_to_loopback(screen, calls):
    menu._run_dashboard()
    assert calls == [("banner", (), {"host": "127.0.0.1"}),
                     ("app.run", (), {"host": "127.0.0.1", "port": 5000,
                                      "debug": False, "use_reloader": False})]


def test_ctrl_c_stops_the_dashboard_and_returns_to_the_menu(screen, calls, monkeypatch):
    monkeypatch.setattr(dashboard.app, "run", _interrupt)
    menu._run_dashboard()           # must not raise
    assert "Dashboard stopped." in screen()


# ── Spoofer and Deauther ───────────────────────────────────────────

@pytest.mark.parametrize("action, name", [
    (menu._run_spoofer_interactive,  "Spoofer"),
    (menu._run_deauther_interactive, "Deauther"),
])
def test_attacks_refuse_without_root_before_asking_anything(
        screen, keys, calls, monkeypatch, action, name):
    monkeypatch.setattr(menu, "check_root", lambda: False)
    action()                        # nothing typed: a prompt would raise EOFError
    assert calls == []
    assert f"[✗] Root privileges required for the {name}." in screen()


@pytest.mark.parametrize("typed, expected", [
    (("10.0.0.5", "", ""),             ("10.0.0.5", "192.168.1.1", "wlan7")),
    (("10.0.0.5", "10.0.0.1", "eth3"), ("10.0.0.5", "10.0.0.1",    "eth3")),
])
def test_spoofer_asks_for_victim_gateway_and_interface(screen, keys, calls, typed, expected):
    keys(*typed)
    menu._run_spoofer_interactive()
    assert calls == [("poison", expected, {})]


@pytest.mark.parametrize("typed, expected", [
    (("broadcast", BSSID, ""),  (deauther.BROADCAST, BSSID, "wlan0mon")),
    (("BROADCAST", BSSID, ""),  (deauther.BROADCAST, BSSID, "wlan0mon")),
    ((MAC, BSSID, "mon1"),      (MAC, BSSID, "mon1")),
])
def test_deauther_asks_for_target_bssid_and_interface(screen, keys, calls, typed, expected):
    keys(*typed)
    menu._run_deauther_interactive()
    assert calls == [("deauth_target", expected, {})]


# ── saved reports ──────────────────────────────────────────────────

def _report(path, mtime, **data):
    path.write_text(json.dumps(data))
    os.utime(path, (mtime, mtime))


def test_reports_without_files_says_so(screen, monkeypatch, tmp_path):
    monkeypatch.setattr(menu, "REPORTS_DIR", tmp_path)
    menu.list_reports()
    assert "No saved reports yet" in screen()


def test_reports_are_listed_newest_first_with_readable_dates(screen, monkeypatch, tmp_path):
    monkeypatch.setattr(menu, "REPORTS_DIR", tmp_path)
    _report(tmp_path / "a.json", 1_000, network="HomeNet", time="20260101_090500",
            targets={"192.0.2.1": [], "192.0.2.2": []})
    _report(tmp_path / "b.json", 2_000, network="Office", time="20261120_183000", targets={})
    menu.list_reports()
    text = screen()
    assert text.index("Office") < text.index("HomeNet")
    assert "01/01/2026 09:05" in text
    assert "20/11/2026 18:30" in text


def test_a_report_with_an_odd_timestamp_shows_it_as_written(screen, monkeypatch, tmp_path):
    monkeypatch.setattr(menu, "REPORTS_DIR", tmp_path)
    _report(tmp_path / "a.json", 1_000, network="HomeNet", time="yesterday", targets={})
    menu.list_reports()
    assert "yesterday" in screen()


def test_an_unreadable_report_still_gets_a_row(screen, monkeypatch, tmp_path):
    monkeypatch.setattr(menu, "REPORTS_DIR", tmp_path)
    (tmp_path / "broken.json").write_text("{not json")
    menu.list_reports()
    assert "broken.json" in screen()
