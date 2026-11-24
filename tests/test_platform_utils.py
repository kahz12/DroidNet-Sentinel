"""Unit tests for droidnet.platform.utils without running real commands or probing the host."""
import io
import json
from types import SimpleNamespace

import pytest
from rich.console import Console

from droidnet.platform import utils

_ORIG_IS_TERMUX = utils.is_termux
_ORIG_CHECK_ROOT = utils.check_root


def _fail_if_called(*args, **kwargs):
    raise AssertionError(f"Unexpected call with args={args!r}, kwargs={kwargs!r}")


@pytest.fixture(autouse=True)
def _reset_platform_caches(monkeypatch):
    _ORIG_IS_TERMUX.cache_clear()
    _ORIG_CHECK_ROOT.cache_clear()
    monkeypatch.setattr(utils, "_ROUTE_CACHE", (None, 0.0, ""))
    yield
    _ORIG_IS_TERMUX.cache_clear()
    _ORIG_CHECK_ROOT.cache_clear()


@pytest.fixture
def captured_output(monkeypatch):
    """Capture utils.rprint output through a plain-text recording Rich Console."""
    console = Console(file=io.StringIO(), record=True, width=240, color_system=None)
    monkeypatch.setattr(utils, "rprint", lambda *args, **kwargs: console.print(*args, **kwargs))
    return console


# ── Platform detection & privilege check ───────────────────────────

def test_is_termux_detects_prefix(monkeypatch):
    monkeypatch.setenv("PREFIX", "/data/data/com.termux/files/usr")
    assert utils.is_termux() is True

    utils.is_termux.cache_clear()
    monkeypatch.delenv("PREFIX", raising=False)
    assert utils.is_termux() is False


def test_get_platform_name(monkeypatch):
    monkeypatch.setattr(utils, "is_termux", lambda: True)
    assert utils.get_platform_name() == "Android (Termux)"

    monkeypatch.setattr(utils, "is_termux", lambda: False)
    monkeypatch.setattr(utils.platform, "system", lambda: "Linux")
    assert utils.get_platform_name() == "Linux"


def test_check_root_true_when_euid_is_zero(monkeypatch):
    monkeypatch.setattr(utils.os, "geteuid", lambda: 0, raising=False)
    assert utils.check_root() is True


def test_check_root_false_when_euid_is_nonzero(monkeypatch):
    monkeypatch.setattr(utils.os, "geteuid", lambda: 1000, raising=False)
    assert utils.check_root() is False


def test_check_root_false_without_geteuid(monkeypatch):
    monkeypatch.delattr(utils.os, "geteuid", raising=False)
    assert utils.check_root() is False


# ── Tool availability ──────────────────────────────────────────────

def test_get_available_tools_on_termux(monkeypatch):
    present = {"nmap", "termux-wifi-connectioninfo"}
    monkeypatch.setattr(utils, "is_termux", lambda: True)
    monkeypatch.setattr(utils, "has_command", lambda cmd: cmd in present)

    tools = utils.get_available_tools()
    assert tools == {
        "nmap": True,
        "arpspoof": False,
        "searchsploit": False,
        "iw": False,
        "termux-wifi-connectioninfo": True,
        "termux-notification": False,
    }
    assert "nmcli" not in tools
    assert "notify-send" not in tools


# ── Default route cache, interface & gateway ───────────────────────

def test_default_route_output_returns_empty_on_exception(monkeypatch):
    calls = []

    def fail(cmd, **kwargs):
        calls.append(cmd)
        raise FileNotFoundError("ip not found")

    monkeypatch.setattr(utils.subprocess, "run", fail)
    assert utils._default_route_output() == ""
    assert calls == [["ip", "route", "show", "default"]]


def test_default_route_output_reuses_cache_within_ttl(monkeypatch):
    calls = []
    times = iter([100.0, 100.5])

    def fake_run(cmd, **kwargs):
        calls.append(cmd)
        return SimpleNamespace(returncode=0, stdout="default via 192.0.2.1 dev eth0\n")

    monkeypatch.setattr(utils.time, "monotonic", lambda: next(times))
    monkeypatch.setattr(utils.subprocess, "run", fake_run)

    first = utils._default_route_output()
    second = utils._default_route_output()
    assert first == "default via 192.0.2.1 dev eth0\n"
    assert second == first
    assert calls == [["ip", "route", "show", "default"]]


def test_default_route_output_does_not_reuse_cache_for_different_runner(monkeypatch):
    monkeypatch.setattr(utils.time, "monotonic", lambda: 100.0)

    first_calls = []
    second_calls = []

    def runner_one(cmd, **kwargs):
        first_calls.append(cmd)
        return SimpleNamespace(returncode=0, stdout="default via 192.0.2.1 dev eth0\n")

    def runner_two(cmd, **kwargs):
        second_calls.append(cmd)
        return SimpleNamespace(returncode=0, stdout="default via 198.51.100.1 dev wlan0\n")

    monkeypatch.setattr(utils.subprocess, "run", runner_one)
    assert utils._default_route_output() == "default via 192.0.2.1 dev eth0\n"

    monkeypatch.setattr(utils.subprocess, "run", runner_two)
    assert utils._default_route_output() == "default via 198.51.100.1 dev wlan0\n"
    assert first_calls == [["ip", "route", "show", "default"]]
    assert second_calls == [["ip", "route", "show", "default"]]


def test_get_default_iface_on_termux_returns_wlan0_without_running(monkeypatch):
    monkeypatch.setattr(utils, "is_termux", lambda: True)
    monkeypatch.setattr(utils.subprocess, "run", _fail_if_called)
    monkeypatch.setattr(utils.os, "listdir", _fail_if_called)
    assert utils.get_default_iface() == "wlan0"


def test_get_default_iface_parses_dev_from_route(monkeypatch):
    calls = []

    def fake_run(cmd, **kwargs):
        calls.append(cmd)
        return SimpleNamespace(returncode=0, stdout="default via 192.0.2.1 dev enp0s3 proto dhcp\n")

    monkeypatch.setattr(utils, "is_termux", lambda: False)
    monkeypatch.setattr(utils.subprocess, "run", fake_run)
    assert utils.get_default_iface() == "enp0s3"
    assert calls == [["ip", "route", "show", "default"]]


def test_get_default_iface_falls_back_to_first_wireless_dir(monkeypatch):
    monkeypatch.setattr(utils, "is_termux", lambda: False)
    monkeypatch.setattr(utils.subprocess, "run", lambda *a, **k: SimpleNamespace(returncode=0, stdout=""))
    monkeypatch.setattr(
        utils.os,
        "listdir",
        lambda path: ["lo", "eth0", "wlp2s0", "wlan1"] if path == "/sys/class/net" else [],
    )
    monkeypatch.setattr(
        utils.os.path,
        "isdir",
        lambda path: path in {"/sys/class/net/wlp2s0/wireless", "/sys/class/net/wlan1/wireless"},
    )
    assert utils.get_default_iface() == "wlp2s0"


def test_get_default_iface_returns_wlan0_when_listdir_raises(monkeypatch):
    def raise_oserror(path):
        raise OSError("permission denied")

    monkeypatch.setattr(utils, "is_termux", lambda: False)
    monkeypatch.setattr(utils.subprocess, "run", lambda *a, **k: SimpleNamespace(returncode=0, stdout=""))
    monkeypatch.setattr(utils.os, "listdir", raise_oserror)
    assert utils.get_default_iface() == "wlan0"


def test_get_default_iface_returns_wlan0_when_no_wireless_interface(monkeypatch):
    monkeypatch.setattr(utils, "is_termux", lambda: False)
    monkeypatch.setattr(utils.subprocess, "run", lambda *a, **k: SimpleNamespace(returncode=0, stdout=""))
    monkeypatch.setattr(utils.os, "listdir", lambda path: ["lo", "eth0"])
    monkeypatch.setattr(utils.os.path, "isdir", lambda path: False)
    assert utils.get_default_iface() == "wlan0"


def test_get_default_gateway_parses_via_from_route(monkeypatch):
    calls = []

    def fake_run(cmd, **kwargs):
        calls.append(cmd)
        return SimpleNamespace(returncode=0, stdout="default via 192.0.2.254 dev eth0\n")

    monkeypatch.setattr(utils.subprocess, "run", fake_run)
    assert utils.get_default_gateway("198.51.100.42") == "192.0.2.254"
    assert calls == [["ip", "route", "show", "default"]]


def test_get_default_gateway_falls_back_to_local_ip_dot_one(monkeypatch):
    monkeypatch.setattr(
        utils.subprocess,
        "run",
        lambda *a, **k: SimpleNamespace(returncode=0, stdout="default dev ppp0 scope link\n"),
    )
    assert utils.get_default_gateway("198.51.100.42") == "198.51.100.1"


def test_get_default_gateway_returns_none_without_route_or_ipv4(monkeypatch):
    monkeypatch.setattr(utils.subprocess, "run", lambda *a, **k: SimpleNamespace(returncode=0, stdout=""))
    assert utils.get_default_gateway() is None
    assert utils.get_default_gateway("fe80::1") is None


# ── Local IP & Wi-Fi readers ───────────────────────────────────────

def test_get_local_ip_prefers_ip_route_src(monkeypatch):
    calls = []

    def fake_run(cmd, **kwargs):
        calls.append(cmd)
        return SimpleNamespace(
            returncode=0,
            stdout="1.0.0.0 via 192.0.2.1 dev eth0 src 192.0.2.50 uid 1000\n",
        )

    monkeypatch.setattr(utils.subprocess, "run", fake_run)
    assert utils._get_local_ip() == "192.0.2.50"
    assert calls == [["ip", "route", "get", "1"]]


def test_get_local_ip_falls_back_to_hostname_when_ip_raises(monkeypatch):
    calls = []

    def fake_run(cmd, **kwargs):
        calls.append(cmd)
        if cmd[0] == "ip":
            raise FileNotFoundError("ip")
        return SimpleNamespace(returncode=0, stdout="198.51.100.7 10.0.0.5 fe80::1\n")

    monkeypatch.setattr(utils.subprocess, "run", fake_run)
    assert utils._get_local_ip() == "198.51.100.7"
    assert calls == [["ip", "route", "get", "1"], ["hostname", "-I"]]


def test_get_local_ip_falls_back_to_hostname_when_ip_has_no_src(monkeypatch):
    calls = []

    def fake_run(cmd, **kwargs):
        calls.append(cmd)
        if cmd[0] == "ip":
            return SimpleNamespace(returncode=0, stdout="1.0.0.0 via 192.0.2.1 dev eth0\n")
        return SimpleNamespace(returncode=0, stdout="203.0.113.9 203.0.113.10\n")

    monkeypatch.setattr(utils.subprocess, "run", fake_run)
    assert utils._get_local_ip() == "203.0.113.9"
    assert calls == [["ip", "route", "get", "1"], ["hostname", "-I"]]


@pytest.mark.parametrize("mode", ["raise", "empty"])
def test_get_local_ip_returns_none_when_both_fail(monkeypatch, mode):
    calls = []

    def fake_run(cmd, **kwargs):
        calls.append(cmd)
        if mode == "raise":
            raise OSError("command failed")
        return SimpleNamespace(returncode=1, stdout="")

    monkeypatch.setattr(utils.subprocess, "run", fake_run)
    assert utils._get_local_ip() is None
    assert calls == [["ip", "route", "get", "1"], ["hostname", "-I"]]


def test_wifi_info_termux_completed_returns_dict(monkeypatch):
    calls = []
    payload = json.dumps({
        "supplicant_state": "COMPLETED",
        "ssid": "LabWiFi",
        "ip": "192.0.2.20",
        "bssid": "AA:BB:CC:DD:EE:FF",
    })

    def fake_run(cmd, **kwargs):
        calls.append(cmd)
        return SimpleNamespace(returncode=0, stdout=payload)

    monkeypatch.setattr(utils.subprocess, "run", fake_run)
    assert utils._get_wifi_info_termux() == {
        "ssid": "LabWiFi",
        "ip": "192.0.2.20",
        "bssid": "AA:BB:CC:DD:EE:FF",
        "platform": "termux",
    }
    assert calls == [["termux-wifi-connectioninfo"]]


def test_wifi_info_termux_defaults_missing_ssid_and_bssid(monkeypatch):
    payload = json.dumps({"supplicant_state": "COMPLETED", "ip": "192.0.2.21"})
    monkeypatch.setattr(
        utils.subprocess,
        "run",
        lambda *a, **k: SimpleNamespace(returncode=0, stdout=payload),
    )
    assert utils._get_wifi_info_termux() == {
        "ssid": "Unknown",
        "ip": "192.0.2.21",
        "bssid": "Unknown",
        "platform": "termux",
    }


@pytest.mark.parametrize("stdout", [
    json.dumps({"supplicant_state": "DISCONNECTED", "ssid": "LabWiFi", "ip": "192.0.2.20"}),
    "not valid json{",
])
def test_wifi_info_termux_returns_none_for_other_state_or_bad_json(monkeypatch, stdout):
    monkeypatch.setattr(
        utils.subprocess,
        "run",
        lambda *a, **k: SimpleNamespace(returncode=0, stdout=stdout),
    )
    assert utils._get_wifi_info_termux() is None


def test_split_nmcli_fields_keeps_trailing_lone_backslash():
    assert utils._split_nmcli_fields("yes:Office\\") == ["yes", "Office\\"]


def test_wifi_info_nmcli_nonzero_exit_and_c_locale(monkeypatch):
    calls = []
    envs = []
    monkeypatch.setenv("LC_ALL", "es_ES.UTF-8")

    def fake_run(cmd, **kwargs):
        calls.append(cmd)
        envs.append(kwargs.get("env"))
        return SimpleNamespace(returncode=1, stdout="yes:Net:AA\\:BB\\:CC\\:DD\\:EE\\:FF\n")

    monkeypatch.setattr(utils.subprocess, "run", fake_run)
    assert utils._get_wifi_info_nmcli() is None
    assert calls == [["nmcli", "-t", "-f", "active,ssid,bssid", "dev", "wifi"]]
    assert envs[0]["LC_ALL"] == "C"


def test_wifi_info_iw_returns_none_on_nonzero_exit(monkeypatch):
    calls = []

    def fake_run(cmd, **kwargs):
        calls.append(cmd)
        return SimpleNamespace(returncode=2, stdout="")

    monkeypatch.setattr(utils, "resolve_command", lambda cmd: "/usr/sbin/iw")
    monkeypatch.setattr(utils, "get_default_iface", lambda: "wlan0")
    monkeypatch.setattr(utils.subprocess, "run", fake_run)

    assert utils._get_wifi_info_iw() is None
    assert calls == [["/usr/sbin/iw", "dev", "wlan0", "link"]]


def test_get_wifi_info_on_termux_delegates_to_termux_reader(monkeypatch):
    expected = {
        "ssid": "MobileNet",
        "ip": "192.0.2.30",
        "bssid": "11:22:33:44:55:66",
        "platform": "termux",
    }
    monkeypatch.setattr(utils, "is_termux", lambda: True)
    monkeypatch.setattr(utils, "_get_wifi_info_termux", lambda: expected)
    monkeypatch.setattr(utils, "has_command", _fail_if_called)

    assert utils.get_wifi_info() == expected


@pytest.mark.parametrize("local_ip", [None, "127.0.0.1"])
def test_get_wifi_info_returns_none_without_usable_ip(monkeypatch, local_ip):
    monkeypatch.setattr(utils, "is_termux", lambda: False)
    monkeypatch.setattr(utils, "has_command", lambda cmd: False)
    monkeypatch.setattr(utils, "_get_local_ip", lambda: local_ip)

    assert utils.get_wifi_info() is None


# ── Notifications ──────────────────────────────────────────────────

def test_send_notification_termux_success(monkeypatch, captured_output):
    calls = []

    def fake_run(cmd, **kwargs):
        calls.append(cmd)
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(utils, "is_termux", lambda: True)
    monkeypatch.setattr(utils.subprocess, "run", fake_run)

    utils.send_notification("Scan Done", "4 hosts")
    assert calls == [["termux-notification", "-t", "Scan Done", "-c", "4 hosts"]]
    assert captured_output.export_text() == ""


@pytest.mark.parametrize("outcome", ["nonzero", "error"])
def test_send_notification_termux_fallback_on_failure(monkeypatch, captured_output, outcome):
    calls = []

    def fake_run(cmd, **kwargs):
        calls.append(cmd)
        if outcome == "error":
            raise OSError("termux-api unavailable")
        return SimpleNamespace(returncode=1)

    monkeypatch.setattr(utils, "is_termux", lambda: True)
    monkeypatch.setattr(utils.subprocess, "run", fake_run)

    utils.send_notification("Alert", "New host")
    assert calls == [["termux-notification", "-t", "Alert", "-c", "New host"]]
    output = captured_output.export_text()
    assert "Alert" in output and "New host" in output


def test_send_notification_linux_notify_send_success(monkeypatch, captured_output):
    calls = []

    def fake_run(cmd, **kwargs):
        calls.append(cmd)
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(utils, "is_termux", lambda: False)
    monkeypatch.setattr(utils, "has_command", lambda cmd: cmd == "notify-send")
    monkeypatch.setattr(utils.subprocess, "run", fake_run)

    utils.send_notification("Scan Done", "4 hosts")
    assert calls == [["notify-send", "-t", "5000", "Scan Done", "4 hosts"]]
    assert captured_output.export_text() == ""


@pytest.mark.parametrize("outcome", ["nonzero", "error"])
def test_send_notification_linux_notify_send_fallback_on_failure(monkeypatch, captured_output, outcome):
    calls = []

    def fake_run(cmd, **kwargs):
        calls.append(cmd)
        if outcome == "error":
            raise OSError("dbus error")
        return SimpleNamespace(returncode=1)

    monkeypatch.setattr(utils, "is_termux", lambda: False)
    monkeypatch.setattr(utils, "has_command", lambda cmd: cmd == "notify-send")
    monkeypatch.setattr(utils.subprocess, "run", fake_run)

    utils.send_notification("Alert", "New host")
    assert calls == [["notify-send", "-t", "5000", "Alert", "New host"]]
    output = captured_output.export_text()
    assert "Alert" in output and "New host" in output


def test_send_notification_linux_without_notify_send_escapes_markup(monkeypatch, captured_output):
    monkeypatch.setattr(utils, "is_termux", lambda: False)
    monkeypatch.setattr(utils, "has_command", lambda cmd: False)
    monkeypatch.setattr(utils.subprocess, "run", _fail_if_called)

    utils.send_notification("[bold]Title", "Hosts on [bold]SSID")
    output = captured_output.export_text()
    assert "[bold]Title" in output
    assert "Hosts on [bold]SSID" in output


# ── Power management (wake_lock) ───────────────────────────────────

def test_wake_lock_outside_termux_yields_false_and_runs_nothing(monkeypatch):
    monkeypatch.setattr(utils, "is_termux", lambda: False)
    monkeypatch.setattr(utils, "has_command", _fail_if_called)
    monkeypatch.setattr(utils.subprocess, "run", _fail_if_called)

    with utils.wake_lock() as held:
        assert held is False


def test_wake_lock_on_termux_without_binary_yields_false(monkeypatch):
    monkeypatch.setattr(utils, "is_termux", lambda: True)
    monkeypatch.setattr(utils, "has_command", lambda cmd: False)
    monkeypatch.setattr(utils.subprocess, "run", _fail_if_called)

    with utils.wake_lock() as held:
        assert held is False


def test_wake_lock_on_termux_acquires_and_unlocks(monkeypatch):
    calls = []

    def fake_run(cmd, **kwargs):
        calls.append(cmd)
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(utils, "is_termux", lambda: True)
    monkeypatch.setattr(utils, "has_command", lambda cmd: cmd == "termux-wake-lock")
    monkeypatch.setattr(utils.subprocess, "run", fake_run)

    with utils.wake_lock() as held:
        assert held is True
        assert calls == [["termux-wake-lock"]]

    assert calls == [["termux-wake-lock"], ["termux-wake-unlock"]]


def test_wake_lock_unlocks_when_block_raises_and_propagates(monkeypatch):
    calls = []

    def fake_run(cmd, **kwargs):
        calls.append(cmd)
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(utils, "is_termux", lambda: True)
    monkeypatch.setattr(utils, "has_command", lambda cmd: cmd == "termux-wake-lock")
    monkeypatch.setattr(utils.subprocess, "run", fake_run)

    with pytest.raises(RuntimeError, match="scan failed"):
        with utils.wake_lock() as held:
            assert held is True
            raise RuntimeError("scan failed")

    assert calls == [["termux-wake-lock"], ["termux-wake-unlock"]]


@pytest.mark.parametrize("outcome", ["nonzero", "error"])
def test_wake_lock_failure_yields_false_and_skips_unlock(monkeypatch, outcome):
    calls = []

    def fake_run(cmd, **kwargs):
        calls.append(cmd)
        if outcome == "error":
            raise OSError("termux-wake-lock failed")
        return SimpleNamespace(returncode=1)

    monkeypatch.setattr(utils, "is_termux", lambda: True)
    monkeypatch.setattr(utils, "has_command", lambda cmd: cmd == "termux-wake-lock")
    monkeypatch.setattr(utils.subprocess, "run", fake_run)

    with utils.wake_lock() as held:
        assert held is False

    assert calls == [["termux-wake-lock"]]


def test_wake_lock_swallows_unlock_exception(monkeypatch):
    calls = []

    def fake_run(cmd, **kwargs):
        calls.append(cmd)
        if cmd == ["termux-wake-unlock"]:
            raise OSError("unlock failed")
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(utils, "is_termux", lambda: True)
    monkeypatch.setattr(utils, "has_command", lambda cmd: cmd == "termux-wake-lock")
    monkeypatch.setattr(utils.subprocess, "run", fake_run)

    with utils.wake_lock() as held:
        assert held is True

    assert calls == [["termux-wake-lock"], ["termux-wake-unlock"]]
