"""Finding tools when PATH is trimmed, as under cron or systemd.

Network admin tools (iw, arpspoof) install under /usr/sbin, which cron and
systemd routinely leave out of PATH. A bare PATH lookup then reports them
missing, so the daemon loses the real SSID (iw) and the probe understates what
is installed. resolve_command() searches the sbin directories as well.
"""
import os

import pytest

from droidnet.platform import utils


@pytest.fixture
def tool_in(tmp_path, monkeypatch):
    """Install a fake executable in a chosen directory; control PATH."""
    def place(directory, name="iw"):
        d = tmp_path / directory
        d.mkdir(parents=True, exist_ok=True)
        exe = d / name
        exe.write_text("#!/bin/sh\n")
        exe.chmod(0o755)
        return str(exe)

    def set_path(*dirs):
        monkeypatch.setenv("PATH", os.pathsep.join(str(tmp_path / d) for d in dirs))

    monkeypatch.setattr(utils, "_SBIN_DIRS", (str(tmp_path / "sbin"),))
    return lambda directory, path_dirs: (place(directory), set_path(*path_dirs))


def test_tool_on_path_is_found(tool_in):
    exe, _ = tool_in("bin", path_dirs=["bin"])
    assert utils.resolve_command("iw") == exe
    assert utils.has_command("iw") is True


def test_tool_in_sbin_is_found_though_not_on_path(tool_in):
    # The scheduled-daemon case: iw sits in sbin, PATH holds only bin.
    exe, _ = tool_in("sbin", path_dirs=["bin"])
    assert utils.resolve_command("iw") == exe
    assert utils.has_command("iw") is True


def test_missing_tool_is_reported_missing(tool_in):
    tool_in("bin", path_dirs=["bin"])
    assert utils.resolve_command("nonexistent-tool") is None
    assert utils.has_command("nonexistent-tool") is False


def test_path_is_preferred_over_sbin(tool_in, tmp_path):
    # A tool present in both is taken from PATH, so a local override wins.
    on_path, _ = tool_in("bin", path_dirs=["bin"])
    (tmp_path / "sbin").mkdir(exist_ok=True)
    (tmp_path / "sbin" / "iw").write_text("#!/bin/sh\n")
    (tmp_path / "sbin" / "iw").chmod(0o755)
    assert utils.resolve_command("iw") == on_path


def test_spoofer_finds_arpspoof_in_sbin_when_path_is_trimmed(tmp_path, monkeypatch):
    from droidnet.modules import spoofer

    sbin = tmp_path / "sbin"
    sbin.mkdir()
    exe = sbin / "arpspoof"
    exe.write_text("#!/bin/sh\n")
    exe.chmod(0o755)
    monkeypatch.setenv("PATH", str(tmp_path / "bin"))
    monkeypatch.setattr(utils, "_SBIN_DIRS", (str(sbin),))
    assert spoofer._arpspoof_available() is True
