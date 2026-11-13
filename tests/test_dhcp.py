"""Passive DHCP fingerprinting: parsing client requests, OS hints, the listener.

Packets are built here byte by byte, as a DHCP client puts them on the wire.
The listener tests bind a free loopback port instead of 67 and send it
those packets; nothing leaves the machine.
"""
import inspect
import io
import re
import socket
import struct
import time

import pytest
from rich.console import Console

from droidnet.core import dhcp
from droidnet.core.dhcp import DhcpListener, DhcpRequest, os_hint, parse_request
from droidnet.modules import sentinel

MAC = "DA:A1:19:00:00:01"            # a randomized address, as nmap prints it

# Parameter request lists (option 55) as the clients send them.
ANDROID_PRL = (1, 3, 6, 15, 26, 28, 51, 58, 59, 43)
APPLE_PRL = (1, 121, 3, 6, 15, 119, 252, 95, 44, 46)
WINDOWS_PRL = (1, 3, 6, 15, 31, 33, 43, 44, 46, 47, 119, 121, 249, 252)


def _option(code: int, value: bytes) -> bytes:
    return bytes([code, len(value)]) + value


def build_request(message_type=1, mac=MAC, hostname=None, vendor=None, prl=(),
                  requested_ip=None, ciaddr="0.0.0.0", op=1, cookie=b"\x63\x82\x53\x63",
                  extra=b"", end=True) -> bytes:
    """A BOOTP/DHCP packet as a client sends it (RFC 2131 §2, RFC 2132)."""
    chaddr = bytes.fromhex(mac.replace(":", "")).ljust(16, b"\x00")
    header = (struct.pack("!BBBBIHH", op, 1, 6, 0, 0x1234ABCD, 0, 0x8000)
              + socket.inet_aton(ciaddr) + b"\x00" * 12           # ciaddr, yiaddr, siaddr, giaddr
              + chaddr + b"\x00" * 192)                          # chaddr, sname, file
    options = _option(53, bytes([message_type]))
    if hostname is not None:
        options += _option(12, hostname.encode("latin-1"))
    if vendor is not None:
        options += _option(60, vendor.encode())
    if prl:
        options += _option(55, bytes(prl))
    if requested_ip:
        options += _option(50, socket.inet_aton(requested_ip))
    options += extra + (b"\xff" if end else b"")
    return header + cookie + options


# ── parsing ────────────────────────────────────────────────────────

def test_parses_an_android_discover():
    request = parse_request(build_request(
        hostname="Pixel-8", vendor="android-dhcp-14", prl=ANDROID_PRL,
        requested_ip="192.0.2.43"), seen=5.0)
    assert request == DhcpRequest(
        mac="da:a1:19:00:00:01", message_type=1, hostname="Pixel-8",
        vendor_class="android-dhcp-14", parameter_list=ANDROID_PRL,
        requested_ip="192.0.2.43", client_ip=None, seen=5.0)
    assert request.fingerprint == "1,3,6,15,26,28,51,58,59,43"


def test_client_ip_comes_from_ciaddr():
    request = parse_request(build_request(message_type=3, ciaddr="192.0.2.7"))
    assert request.client_ip == "192.0.2.7" and request.message_type == 3


def test_padding_and_a_missing_end_option_are_tolerated():
    packet = build_request(extra=b"\x00\x00" + _option(12, b"box"), end=False)
    assert parse_request(packet).hostname == "box"


@pytest.mark.parametrize("packet", [
    b"",
    build_request()[:239],                                   # shorter than the header
    build_request(op=2),                                     # a server reply
    build_request(message_type=2),                           # DHCPOFFER
    build_request(message_type=5),                           # DHCPACK
    build_request(cookie=b"\x00\x00\x00\x00"),               # plain BOOTP
    build_request(extra=b"\x0c\x10short", end=False),        # option runs past the end
    build_request()[:240] + b"\x0c",                         # option without a length
], ids=["empty", "short", "reply", "offer", "ack", "bootp", "truncated", "no-length"])
def test_non_client_or_malformed_packets_are_ignored(packet):
    assert parse_request(packet) is None


def test_device_chosen_text_is_cleaned():
    request = parse_request(build_request(hostname="evil\x1b[2J\x07", vendor="  MSFT\t5.0 "))
    assert request.hostname == "evil[2J"
    assert request.vendor_class == "MSFT 5.0"


# ── operating system hints ─────────────────────────────────────────

@pytest.mark.parametrize("vendor, prl, expected", [
    ("android-dhcp-14", ANDROID_PRL, "Android 14"),
    ("android-dhcp-8.1.0", ANDROID_PRL, "Android 8.1.0"),
    ("MSFT 5.0", WINDOWS_PRL, "Windows"),
    ("dhcpcd-9.4.1:Linux-6.1.21-v8+:aarch64:Raspberry Pi", (1, 3, 6), "Linux (Raspberry Pi)"),
    ("dhcpcd-10.0.6:Linux-6.8.0:x86_64", (1, 3, 6), "Linux"),
    ("dhcpcd-5.5.6", (1, 3, 6), "Linux"),
    ("udhcp 1.36.1", (1, 3, 6, 12, 15), "Embedded Linux"),
    ("HUAWEI:android:CDY", (1, 3, 6), "HUAWEI:android:CDY"),   # unknown: shown as sent
    (None, APPLE_PRL, "Apple (iOS/macOS)"),
    (None, ANDROID_PRL, None),                                # no vendor class: no guess
    (None, (), None),
])
def test_os_hint(vendor, prl, expected):
    assert os_hint(DhcpRequest(mac="aa:bb:cc:dd:ee:ff", message_type=1,
                               vendor_class=vendor, parameter_list=prl)) == expected


# ── the listener ───────────────────────────────────────────────────

def _free_udp_port() -> int:
    probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    probe.bind(("127.0.0.1", 0))
    port = probe.getsockname()[1]
    probe.close()
    return port


def _wait_for(condition, timeout=2.0):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        if condition():
            return True
        time.sleep(0.02)
    return False


@pytest.fixture
def listening():
    """A running listener on a free loopback port, and a function that sends to it."""
    port = _free_udp_port()
    with DhcpListener(port=port, address="127.0.0.1") as listener, \
         socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
        assert listener.running
        yield listener, lambda packet: client.sendto(packet, ("127.0.0.1", port))


def test_listener_records_requests_and_keeps_earlier_fields(listening):
    listener, send = listening
    # DISCOVER without a hostname, then the REQUEST that names the device,
    # then another DISCOVER without it: the name must survive.
    send(build_request(1, vendor="android-dhcp-14", prl=ANDROID_PRL))
    send(build_request(3, hostname="Pixel-8", requested_ip="192.0.2.43"))
    assert _wait_for(lambda: listener.clients().get("da:a1:19:00:00:01", None) is not None
                     and listener.clients()["da:a1:19:00:00:01"].hostname == "Pixel-8")
    send(build_request(1, prl=ANDROID_PRL))
    assert _wait_for(lambda: listener.clients()["da:a1:19:00:00:01"].message_type == 1)
    request = listener.clients()["da:a1:19:00:00:01"]
    assert (request.hostname, request.vendor_class, request.requested_ip) == \
        ("Pixel-8", "android-dhcp-14", "192.0.2.43")


def test_listener_ignores_other_traffic(listening):
    listener, send = listening
    send(b"not dhcp at all")
    send(build_request(message_type=5))            # an ACK from a server
    send(build_request(mac="02:00:00:00:00:09"))
    assert _wait_for(lambda: "02:00:00:00:00:09" in listener.clients())
    assert list(listener.clients()) == ["02:00:00:00:00:09"]


def test_lookup_by_mac_then_by_ip():
    listener = DhcpListener()
    listener._record(DhcpRequest("aa:00:00:00:00:01", 3, requested_ip="192.0.2.5", seen=1.0))
    listener._record(DhcpRequest("aa:00:00:00:00:02", 3, requested_ip="192.0.2.5", seen=2.0))
    listener._record(DhcpRequest("aa:00:00:00:00:03", 8, client_ip="192.0.2.6", seen=3.0))
    # nmap prints MACs in upper case.
    assert listener.lookup("AA:00:00:00:00:01", "192.0.2.5").mac == "aa:00:00:00:00:01"
    # Without a MAC, the most recent client using that address wins.
    assert listener.lookup(None, "192.0.2.5").mac == "aa:00:00:00:00:02"
    assert listener.lookup(None, "192.0.2.6").mac == "aa:00:00:00:00:03"
    assert listener.lookup("ff:ff:ff:ff:ff:ff", "192.0.2.99") is None


def test_client_table_is_bounded(monkeypatch):
    monkeypatch.setattr(dhcp, "_MAX_CLIENTS", 3)
    listener = DhcpListener()
    for n in range(5):
        listener._record(DhcpRequest(f"aa:00:00:00:00:0{n}", 1, seen=float(n)))
    assert sorted(listener.clients()) == ["aa:00:00:00:00:02", "aa:00:00:00:00:03",
                                          "aa:00:00:00:00:04"]


def test_listener_stays_off_when_the_port_is_taken():
    taken = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    taken.bind(("127.0.0.1", 0))                     # no SO_REUSEADDR: exclusive
    try:
        listener = DhcpListener(port=taken.getsockname()[1], address="127.0.0.1")
        assert listener.start() is False
        assert not listener.running
        listener.stop()                              # harmless when never started
    finally:
        taken.close()


# ── host firewall ──────────────────────────────────────────────────

UFW_ON = 'ENABLED=yes\nLOGLEVEL=low\n'
UFW_DROP = 'IPV6=yes\nDEFAULT_INPUT_POLICY="DROP"\n'
# What `ufw allow proto udp from any port 68 to any port 67` writes.
UFW_RULE_67 = ("### tuple ### allow udp 67 0.0.0.0/0 68 0.0.0.0/0 in\n"
               "-A ufw-user-input -p udp --dport 67 --sport 68 -j ACCEPT\n")
UFW_RULE_LAN = ("### tuple ### allow udp any 0.0.0.0/0 any 192.168.2.0/24 in\n"
                "-A ufw-user-input -p udp -s 192.168.2.0/24 -j ACCEPT\n")


@pytest.fixture
def ufw_files(tmp_path, monkeypatch):
    """Point the ufw check at files the test writes; None leaves one missing."""
    def write(conf=None, defaults=None, rules=None):
        for name, content in (("_UFW_CONF", conf), ("_UFW_DEFAULTS", defaults),
                              ("_UFW_RULES", rules)):
            path = tmp_path / name
            if content is not None:
                path.write_text(content)
            monkeypatch.setattr(dhcp, name, path)
    return write


@pytest.mark.parametrize("conf, defaults, rules, blocks", [
    (None, None, None, False),                      # no ufw installed
    ("ENABLED=no\n", UFW_DROP, "", False),
    (UFW_ON, UFW_DROP, None, True),                 # rules unreadable without root
    (UFW_ON, UFW_DROP, "", True),
    (UFW_ON, UFW_DROP, UFW_RULE_LAN, True),         # LAN rule: DISCOVER comes from 0.0.0.0
    (UFW_ON, UFW_DROP, UFW_RULE_67, False),
    (UFW_ON, 'DEFAULT_INPUT_POLICY="ACCEPT"\n', None, False),
], ids=["no-ufw", "disabled", "unreadable-rules", "no-rules", "lan-rule-only",
        "port-67-rule", "accept-policy"])
def test_ufw_blocks_dhcp(ufw_files, conf, defaults, rules, blocks):
    ufw_files(conf, defaults, rules)
    assert dhcp.ufw_blocks_dhcp() is blocks


def test_listener_warns_when_ufw_would_drop_the_requests(ufw_files, monkeypatch):
    warnings = []
    monkeypatch.setattr(dhcp.log, "warning", lambda msg, *args: warnings.append(msg % args))
    ufw_files(UFW_ON, UFW_DROP, None)
    with DhcpListener(port=_free_udp_port(), address="127.0.0.1"):
        pass
    assert len(warnings) == 1 and dhcp.UFW_ALLOW_DHCP in warnings[0]
    warnings.clear()
    ufw_files(UFW_ON, UFW_DROP, UFW_RULE_67)
    with DhcpListener(port=_free_udp_port(), address="127.0.0.1"):
        pass
    assert warnings == []


def test_listener_never_sends():
    # Passive by construction: no call in the module can put a packet on the wire.
    assert not re.search(r"\.send(to|all|msg)?\(", inspect.getsource(dhcp))


# ── Sentinel integration ───────────────────────────────────────────

class _FakeListener:
    running = True

    def __init__(self, requests):
        self.requests = requests

    def lookup(self, mac, ip):
        return self.requests.get(mac) or self.requests.get(ip)

    def clients(self):
        return self.requests


def test_dhcp_fingerprints_reach_the_metadata():
    metadata = {
        "192.0.2.7":  {"hostname": None, "mac": MAC, "vendor": None},
        "192.0.2.8":  {"hostname": "nas.lan", "mac": None, "vendor": None},
        "192.0.2.9":  {"hostname": None, "mac": None, "vendor": None},
    }
    sentinel.add_dhcp_fingerprints(metadata, _FakeListener({
        MAC: DhcpRequest(MAC.lower(), 3, hostname="Pixel-8", vendor_class="android-dhcp-14"),
        "192.0.2.8": DhcpRequest("aa:bb:cc:dd:ee:08", 3, hostname="other", vendor_class="MSFT 5.0"),
    }))
    assert metadata["192.0.2.7"] == {"hostname": "Pixel-8", "mac": MAC, "vendor": None,
                                     "os": "Android 14"}
    assert metadata["192.0.2.8"]["hostname"] == "nas.lan"      # an earlier name is kept
    assert metadata["192.0.2.8"]["os"] == "Windows"
    assert "os" not in metadata["192.0.2.9"]


def test_no_listener_changes_nothing():
    metadata = {"192.0.2.7": {"hostname": None, "mac": MAC}}
    sentinel.add_dhcp_fingerprints(metadata, None)
    off = _FakeListener({MAC: DhcpRequest(MAC.lower(), 3, vendor_class="MSFT 5.0")})
    off.running = False
    sentinel.add_dhcp_fingerprints(metadata, off)
    assert metadata == {"192.0.2.7": {"hostname": None, "mac": MAC}}


def _device_column(monkeypatch, meta) -> str:
    rec = Console(file=io.StringIO(), record=True, width=240, color_system=None)
    monkeypatch.setattr(sentinel, "console", rec)
    sentinel.display_results_table("lab", {"192.0.2.7": ["Shield intact"]}, {"192.0.2.7": meta})
    return rec.export_text()


def test_os_line_under_a_randomized_mac(monkeypatch):
    text = _device_column(monkeypatch, {"mac": MAC, "vendor": None, "os": "Android 14"})
    lines = [line for line in text.splitlines() if "Randomized MAC" in line or "Android 14" in line]
    assert len(lines) == 2, "the OS goes on its own line under the MAC note"


def test_os_line_is_escaped_and_not_repeated(monkeypatch):
    text = _device_column(monkeypatch, {"mac": None, "vendor": None, "os": "Evil[/x]"})
    assert "Evil[/x]" in text
    text = _device_column(monkeypatch, {"model": "Windows Dev Kit", "os": "Windows"})
    assert text.count("Windows") == 1


def test_scan_session_starts_and_stops_the_listener(monkeypatch):
    events = []

    class Recording(DhcpListener):
        def start(self):
            events.append("start")
            return False

        def stop(self):
            events.append("stop")

    monkeypatch.setattr(sentinel, "DhcpListener", Recording)
    monkeypatch.setattr(sentinel, "_run_sentinel_loop", lambda *a: events.append("loop"))
    sentinel.run_sentinel(interactive=True)
    assert events == ["start", "loop", "stop"]
