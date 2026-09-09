"""Simulated interface lifecycle: no hardware or frames are used."""
from unittest.mock import Mock

import pytest

from droidnet.modules import deauther as deauth


@pytest.fixture
def monitor(monkeypatch):
    monkeypatch.setattr(deauth, "_SCAPY_OK", True)
    monkeypatch.setattr(deauth, "check_root", lambda: True)
    monkeypatch.setattr(deauth, "_check_monitor_mode", lambda _: False)
    monkeypatch.setattr(deauth, "_enable_monitor", lambda _: True)
    monkeypatch.setattr(deauth, "_injection_supported", lambda _: True)
    monkeypatch.setattr(deauth, "_set_channel", lambda *a: True)
    monkeypatch.setattr(deauth, "_build_deauth", lambda *a: object())
    monkeypatch.setattr(deauth, "sendp", Mock(), raising=False)
    restore = Mock()
    monkeypatch.setattr(deauth, "_disable_monitor", restore)
    hopper = Mock()
    monkeypatch.setattr(deauth, "_ChannelHopper", lambda _: hopper)
    return restore, hopper


@pytest.mark.parametrize("stage", ["_enable_monitor", "_injection_supported", "_build_deauth", "sendp"])
def test_restore_after_any_setup_or_send_failure(monkeypatch, monitor, stage):
    restore, hopper = monitor
    monkeypatch.setattr(deauth, stage, Mock(side_effect=OSError("simulated failure")))
    with pytest.raises(OSError):
        deauth.deauth_target(deauth.BROADCAST, "AA:BB:CC:DD:EE:FF", "fake0", count=1)
    restore.assert_called_once_with("fake0")
    if stage in ("_build_deauth", "sendp"):
        hopper.stop.assert_called_once()


def test_restore_after_partial_enable_returns_false(monkeypatch, monitor):
    monkeypatch.setattr(deauth, "_enable_monitor", lambda _: False)
    deauth.deauth_target(deauth.BROADCAST, "AA:BB:CC:DD:EE:FF", "fake0", count=1)
    monitor[0].assert_called_once_with("fake0")


def test_existing_monitor_mode_is_preserved(monkeypatch, monitor):
    monkeypatch.setattr(deauth, "_check_monitor_mode", lambda _: True)
    deauth.deauth_target(deauth.BROADCAST, "AA:BB:CC:DD:EE:FF", "fake0", count=1, interval=0)
    monitor[0].assert_not_called()
    monitor[1].stop.assert_called_once()


def test_failed_restoration_step_still_brings_link_up(monkeypatch):
    run = Mock(side_effect=[OSError("missing ip"), OSError("missing iw"), Mock()])
    monkeypatch.setattr(deauth.subprocess, "run", run)
    deauth._disable_monitor("fake0")
    assert run.call_count == 3
    assert run.call_args.args[0] == ["ip", "link", "set", "fake0", "up"]
