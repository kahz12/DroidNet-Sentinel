"""Platform command parsing and timeout handling, without running real commands."""
import subprocess
from types import SimpleNamespace

import pytest

from droidnet.platform import utils


def test_nmcli_preserves_colons_and_backslashes(monkeypatch):
    output = r"yes:Office\:Guest\\WiFi:AA\:BB\:CC\:DD\:EE\:FF"
    monkeypatch.setattr(utils.subprocess, "run", lambda *a, **k: SimpleNamespace(returncode=0, stdout=output))
    monkeypatch.setattr(utils, "_get_local_ip", lambda: "192.0.2.10")
    info = utils._get_wifi_info_nmcli()
    assert info["ssid"] == "Office:Guest\\WiFi"
    assert info["bssid"] == "AA:BB:CC:DD:EE:FF"


@pytest.mark.parametrize("function", [utils._get_wifi_info_termux, utils._get_wifi_info_nmcli,
                                     utils._get_wifi_info_iw, utils._get_local_ip])
def test_platform_timeouts_return_no_connection(monkeypatch, function):
    def timeout(cmd, **kwargs):
        assert 0 < kwargs["timeout"] <= 10
        raise subprocess.TimeoutExpired(cmd, kwargs["timeout"])

    monkeypatch.setattr(utils.subprocess, "run", timeout)
    monkeypatch.setattr(utils, "get_default_iface", lambda: "fake0")
    assert function() is None
