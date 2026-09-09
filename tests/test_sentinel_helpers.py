"""Unit tests for sentinel module helpers (no network/subprocess)."""

from unittest.mock import Mock

import droidnet.modules.sentinel as sentinel
import droidnet.platform.utils as utils
from droidnet.modules.sentinel import _sanitize_ssid
from droidnet.platform.utils import get_default_gateway, _get_local_ip


def test_sanitize_alpha_passthrough():
    assert _sanitize_ssid("HomeWiFi") == "HomeWiFi"


def test_sanitize_replaces_path_separators():
    # Path traversal attempt — six invalid leading chars (../../) + slash before passwd.
    assert _sanitize_ssid("../../etc/passwd") == "______etc_passwd"


def test_sanitize_keeps_hyphen_and_underscore():
    assert _sanitize_ssid("Home-WiFi_5G") == "Home-WiFi_5G"


def test_sanitize_strips_spaces_and_punct():
    assert _sanitize_ssid("My Cafe!@") == "My_Cafe__"


def test_sanitize_empty_returns_unknown():
    assert _sanitize_ssid("") == "unknown"


def test_sanitize_punct_only_becomes_underscores():
    # All-invalid input → underscores (one per char). Falls back to "unknown"
    # only when the input itself is empty.
    assert _sanitize_ssid("!!!") == "___"


# ── gateway detection + cut_unknowns self/gateway protection ────────

class _FakeProc:
    def __init__(self, stdout: str):
        self.stdout = stdout


def test_gateway_parses_via_from_route(monkeypatch):
    monkeypatch.setattr(utils.subprocess, "run",
                        lambda *a, **k: _FakeProc("default via 10.0.0.254 dev eth0"))
    assert get_default_gateway("192.168.7.42") == "10.0.0.254"


def test_gateway_falls_back_to_dot_one(monkeypatch):
    # No usable route output → conventional .1 host of the local /24.
    monkeypatch.setattr(utils.subprocess, "run", lambda *a, **k: _FakeProc(""))
    assert get_default_gateway("192.168.7.42") == "192.168.7.1"


def test_gateway_none_without_route_or_ip(monkeypatch):
    monkeypatch.setattr(utils.subprocess, "run", lambda *a, **k: _FakeProc(""))
    assert get_default_gateway(None) is None


def test_cut_unknowns_protects_self_gateway_and_trusted(monkeypatch):
    jobs = Mock()
    monkeypatch.setattr(sentinel, "get_default_gateway", lambda my_ip: "192.168.1.1")
    monkeypatch.setattr(sentinel, "get_default_iface", lambda: "wlan0")

    targets = ["192.168.1.1", "192.168.1.10", "192.168.1.50", "192.168.1.99"]
    sentinel.cut_unknowns(targets, my_ip="192.168.1.10",
                          config={"trusted_ips": ["192.168.1.50"]}, jobs=jobs)

    # gateway (.1), self (.10) and trusted (.50) are spared; only .99 is cut.
    jobs.update.assert_called_once_with({("192.168.1.99", "192.168.1.1", "wlan0")})


def test_cut_unknowns_aborts_when_gateway_unknown(monkeypatch):
    jobs = Mock()
    monkeypatch.setattr(sentinel, "get_default_gateway", lambda my_ip: None)

    sentinel.cut_unknowns(["192.168.1.99"], my_ip="192.168.1.10", config={}, jobs=jobs)
    jobs.update.assert_called_once_with(set())


def test_cut_unknowns_protects_cidr_and_host_prefix(monkeypatch):
    jobs = Mock()
    monkeypatch.setattr(sentinel, "get_default_gateway", lambda _: "192.168.1.1")
    monkeypatch.setattr(sentinel, "get_default_iface", lambda: "fake0")
    sentinel.cut_unknowns(["192.168.1.50", "192.168.2.50", "192.168.3.50"],
                          "192.168.1.10", {"trusted_ips": ["192.168.1.0/24", "192.168.2.50/32"]}, jobs)
    jobs.update.assert_called_once_with({("192.168.3.50", "192.168.1.1", "fake0")})


def test_menu_daemon_interrupt_reaches_scanner_cleanup(monkeypatch, capsys):
    from droidnet.cli import menu
    cleaned = []

    def scanner(**kwargs):
        assert kwargs == {"interactive": False, "auto_cut": False}
        try:
            raise KeyboardInterrupt
        finally:
            cleaned.append(True)

    monkeypatch.setattr(menu, "_ask_auto_cut", lambda: False)
    monkeypatch.setattr(sentinel, "run_sentinel", scanner)
    menu._run_sentinel_daemon()
    assert cleaned == [True]
    assert "Daemon stopped" in capsys.readouterr().out


# ── risk markup colour + single classify call ───────────────────────

def test_evaluate_risk_low_is_blue(monkeypatch):
    # README + dashboard contract: LOW renders blue.
    monkeypatch.setattr(sentinel, "classify_risk", lambda ports: "LOW")
    assert sentinel.evaluate_risk(["whatever"]) == "[bold blue]LOW[/bold blue]"


def test_evaluate_risk_unknown_label_passthrough_single_call(monkeypatch):
    calls = []
    monkeypatch.setattr(sentinel, "classify_risk",
                        lambda ports: (calls.append(1), "WEIRD")[1])
    out = sentinel.evaluate_risk(["x"])
    assert out == "WEIRD"      # label absent from _RISK_MARKUP → returned as-is
    assert len(calls) == 1     # classify_risk is evaluated exactly once


# ── _get_local_ip prefers `ip route get` over `hostname -I` ──────────

def test_get_local_ip_prefers_ip_route(monkeypatch):
    calls = []

    def fake_run(cmd, **_):
        calls.append(cmd[0])
        if cmd[:3] == ["ip", "route", "get"]:
            return _FakeProc("1.0.0.0 dev wlan0 src 192.168.5.20 uid 0")
        return _FakeProc("should-not-be-used")

    monkeypatch.setattr(utils.subprocess, "run", fake_run)
    assert _get_local_ip() == "192.168.5.20"
    assert calls == ["ip"]     # hostname -I is never reached when ip route wins
