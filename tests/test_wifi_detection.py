"""Wi-Fi network detection on Linux: nmcli first, then ``iw dev <iface> link``.

wireless-tools (iwconfig) is retired; iw is the current diagnostic tool and
works without root. The SSID is the network's identity everywhere downstream
(history, scan diffs, reports, daemon re-scans on network change), so it must
be read exactly — including the bytes iw escapes.

iw prints the SSID through print_ssid_escaped(): printable ASCII as-is,
inner spaces as-is, and every other byte — non-ASCII, a backslash, a leading
or trailing space — as \\xNN. A UTF-8 name like "Señal" therefore arrives as
"Se\\xc3\\xb1al".
"""
from types import SimpleNamespace

import pytest

from droidnet.platform import utils

IW_CONNECTED = (
    "Connected to aa:bb:cc:dd:ee:ff (on wlp3s0)\n"
    "\tSSID: {ssid}\n"
    "\tfreq: 5180.0\n"
    "\tRX: 123456 bytes (789 packets)\n"
    "\tTX: 23456 bytes (234 packets)\n"
    "\tsignal: -52 dBm\n"
    "\trx bitrate: 866.7 MBit/s VHT-MCS 9 80MHz short GI VHT-NSS 2\n"
    "\tbss flags: short-slot-time\n"
    "\tdtim period: 1\n"
    "\tbeacon int: 100\n"
)


@pytest.fixture
def iw(monkeypatch):
    """Fake ``iw``: set ``.stdout``; every call's argv is kept in ``.calls``."""
    fake = SimpleNamespace(stdout="", calls=[])

    def run(args, **kwargs):
        fake.calls.append(args)
        return SimpleNamespace(returncode=0, stdout=fake.stdout, stderr="")

    monkeypatch.setattr(utils.subprocess, "run", run)
    # Pin resolution to the bare name so the recorded argv is the same whether
    # or not iw is installed on the machine running the tests.
    monkeypatch.setattr(utils, "resolve_command", lambda cmd: cmd)
    monkeypatch.setattr(utils, "get_default_iface", lambda: "wlp3s0")
    monkeypatch.setattr(utils, "_get_local_ip", lambda: "192.0.2.11")
    return fake


# ── _get_wifi_info_iw ──────────────────────────────────────────────

def test_iw_reads_ssid_and_bssid_of_the_default_interface(iw):
    iw.stdout = IW_CONNECTED.format(ssid="Home Office")
    assert utils._get_wifi_info_iw() == {
        "ssid": "Home Office", "ip": "192.0.2.11",
        "bssid": "AA:BB:CC:DD:EE:FF", "platform": "linux"}
    assert iw.calls == [["iw", "dev", "wlp3s0", "link"]]


@pytest.mark.parametrize("printed, ssid", [
    (r"Caf\xc3\xa9",        "Café"),           # UTF-8 bytes
    (r"Se\xc3\xb1al 5G",    "Señal 5G"),       # inner space printed as-is
    (r"\x20Guest\x20",      " Guest "),        # leading/trailing spaces escaped
    (r"back\x5cslash",      "back\\slash"),    # a real backslash
    (r"lit\x5cx41",         "lit\\x41"),       # the text "\x41" stays literal
    (r"bad\xff",            "bad�"),      # invalid UTF-8 cannot crash it
])
def test_iw_decodes_escaped_ssids(iw, printed, ssid):
    iw.stdout = IW_CONNECTED.format(ssid=printed)
    assert utils._get_wifi_info_iw()["ssid"] == ssid


@pytest.mark.parametrize("stdout", ["Not connected.\n", ""])
def test_iw_without_a_connection_returns_none(iw, stdout):
    iw.stdout = stdout
    assert utils._get_wifi_info_iw() is None


# ── get_wifi_info: source order and fallback label ─────────────────

@pytest.fixture
def sources(monkeypatch, tmp_path):
    """Control which tools exist and what each reader returns."""
    state = SimpleNamespace(tools=set(), nmcli=None, iw=None, sys_net=tmp_path)
    monkeypatch.setattr(utils, "is_termux", lambda: False)
    monkeypatch.setattr(utils, "has_command", lambda cmd: cmd in state.tools)
    monkeypatch.setattr(utils, "_get_wifi_info_nmcli", lambda: state.nmcli)
    monkeypatch.setattr(utils, "_get_wifi_info_iw", lambda: state.iw)
    monkeypatch.setattr(utils, "get_default_iface", lambda: "wlp3s0")
    monkeypatch.setattr(utils, "_get_local_ip", lambda: "192.0.2.11")
    monkeypatch.setattr(utils, "_SYS_NET", tmp_path)
    return state


def info(ssid):
    return {"ssid": ssid, "ip": "192.0.2.11", "bssid": "AA:BB:CC:DD:EE:FF", "platform": "linux"}


def test_nmcli_wins_when_present(sources):
    sources.tools = {"nmcli", "iw"}
    sources.nmcli, sources.iw = info("from-nmcli"), info("from-iw")
    assert utils.get_wifi_info()["ssid"] == "from-nmcli"


def test_iw_is_used_without_nmcli(sources):
    sources.tools = {"iw"}
    sources.iw = info("from-iw")
    assert utils.get_wifi_info()["ssid"] == "from-iw"


def test_iw_is_used_when_nmcli_finds_no_wifi(sources):
    sources.tools = {"nmcli", "iw"}
    sources.iw = info("from-iw")
    assert utils.get_wifi_info()["ssid"] == "from-iw"


def test_wireless_interface_without_tools_is_not_called_wired(sources):
    (sources.sys_net / "wlp3s0" / "phy80211").mkdir(parents=True)
    got = utils.get_wifi_info()
    assert got["ssid"] == "Unknown Wi-Fi"
    assert got["ip"] == "192.0.2.11"


def test_wired_interface_keeps_the_wired_label(sources):
    (sources.sys_net / "wlp3s0").mkdir()   # a netdev without phy80211
    assert utils.get_wifi_info()["ssid"] == "Wired Network"


def test_tool_probe_lists_iw_not_iwconfig(monkeypatch):
    # wireless-tools is retired on current distributions; reporting iwconfig
    # as missing would point users at a package they should not install.
    monkeypatch.setattr(utils, "is_termux", lambda: False)
    tools = utils.get_available_tools()
    assert "iwconfig" not in tools and "iw" in tools
