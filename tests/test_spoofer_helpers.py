"""Unit tests for spoofer input validation."""

import droidnet.modules.spoofer as spoofer
from droidnet.modules.spoofer import _valid_ip, poison


def test_valid_ip_accepts_v4_and_v6():
    assert _valid_ip("192.168.1.1")
    assert _valid_ip("10.0.0.254")
    assert _valid_ip("::1")
    assert _valid_ip("fe80::1")


def test_valid_ip_rejects_malformed():
    for bad in ["not-an-ip", "192.168.1.256", "192.168.1", "aa:bb:cc:dd:ee:ff", "", "1.2.3.4;rm"]:
        assert not _valid_ip(bad)


def test_poison_aborts_before_backend_on_invalid_ip(monkeypatch):
    # Validation must run before any backend selection: if it didn't, this
    # sentinel would fire. A bad victim/gateway IP returns early instead.
    def _boom():
        raise AssertionError("backend reached despite invalid IP")

    monkeypatch.setattr(spoofer, "_arpspoof_available", _boom)
    poison("not-an-ip", "192.168.1.1")     # bad victim
    poison("192.168.1.10", "999.999.0.1")  # bad gateway
