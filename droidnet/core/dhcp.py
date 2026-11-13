"""
Passive DHCP fingerprinting.

    DhcpListener          → background thread on UDP port 67 that records the
                            requests DHCP clients broadcast; it never sends
    parse_request(packet) → DhcpRequest, or None for anything else
    os_hint(request)      → "Android 14", "Windows", "Apple (iOS/macOS)", ...

A client joining the network broadcasts DHCPDISCOVER and DHCPREQUEST to
every host on the segment. Those packets carry its MAC, the hostname it
announces (option 12), its vendor class (option 60: "android-dhcp-14",
"MSFT 5.0", "dhcpcd-9.4.1:Linux-6.1:...") and its parameter request list
(option 55): the options it asks the server for, in an order fixed by its
DHCP client software. A randomized MAC hides the maker, but not the DHCP
client, so these fields still tell what kind of system is behind it.

Binding port 67 needs root (or CAP_NET_BIND_SERVICE); without it the
listener simply does not start. Lease renewals go unicast to the server and
are never seen here, so a device only shows up when it joins or rejoins the
network (a Wi-Fi reconnect, waking from sleep). The listener therefore pays
off in daemon mode, where it runs for hours; a one-shot scan only catches
the devices that happen to join while it runs. Access points that do not
forward client broadcasts to other clients hide these packets altogether,
and so does a host firewall that drops them (see ufw_blocks_dhcp).
"""

import ipaddress
import re
import socket
import threading
import time
from dataclasses import dataclass, field, replace
from pathlib import Path

from droidnet.core.devices import clean_text
from droidnet.core.logger import get_logger

log = get_logger(__name__)

DHCP_SERVER_PORT = 67

_BOOTREQUEST   = 1
_HTYPE_ETHER   = 1
_MAGIC_COOKIE  = b"\x63\x82\x53\x63"
_OPTIONS_START = 240            # fixed BOOTP header (236 bytes) + magic cookie

_OPT_PAD, _OPT_END = 0, 255
_OPT_HOSTNAME      = 12
_OPT_REQUESTED_IP  = 50
_OPT_MESSAGE_TYPE  = 53
_OPT_PARAM_REQUEST = 55
_OPT_VENDOR_CLASS  = 60

# DHCPDISCOVER, DHCPREQUEST and DHCPINFORM come from clients. Server replies
# (OFFER, ACK, ...) carry no client fingerprint and are ignored.
_DISCOVER, _REQUEST, _INFORM = 1, 3, 8
_CLIENT_MESSAGES = {_DISCOVER, _REQUEST, _INFORM}

# Distinct clients remembered at once. Anyone on the LAN can broadcast
# requests with made-up MACs, so the table is bounded; the oldest entry
# makes room for a new one.
_MAX_CLIENTS = 512


@dataclass(frozen=True)
class DhcpRequest:
    """What one client said in its latest DHCP request."""
    mac: str                                   # "aa:bb:cc:dd:ee:ff", lowercase
    message_type: int
    hostname: str | None = None                # option 12
    vendor_class: str | None = None            # option 60
    parameter_list: tuple[int, ...] = ()       # option 55, in the client's order
    requested_ip: str | None = None            # option 50
    client_ip: str | None = None               # ciaddr, set once the client has a lease
    seen: float = field(default=0.0, compare=False)

    @property
    def fingerprint(self) -> str:
        """Option 55 as fingerbank.org writes it, e.g. "1,3,6,15,26,28,51,58,59,43"."""
        return ",".join(str(code) for code in self.parameter_list)


def _ipv4(raw: bytes) -> str | None:
    """Dotted address from 4 bytes, or None for 0.0.0.0 and malformed values."""
    if len(raw) != 4 or raw == b"\x00\x00\x00\x00":
        return None
    return str(ipaddress.IPv4Address(raw))


def _options(packet: bytes) -> dict[int, bytes] | None:
    """Option code → value from the options area; None when it is malformed.

    The first occurrence of a code wins. Option overloading (option 52, which
    moves options into the sname/file fields) is not followed: clients do not
    use it in the requests this module reads.
    """
    options: dict[int, bytes] = {}
    pos = _OPTIONS_START
    while pos < len(packet):
        code = packet[pos]
        if code == _OPT_PAD:
            pos += 1
            continue
        if code == _OPT_END:
            return options
        if pos + 1 >= len(packet):
            return None
        length = packet[pos + 1]
        value = packet[pos + 2:pos + 2 + length]
        if len(value) != length:
            return None
        options.setdefault(code, value)
        pos += 2 + length
    return options                             # no END option: tolerated


def parse_request(packet: bytes, seen: float = 0.0) -> DhcpRequest | None:
    """Read a client's DHCP request; None for replies, non-DHCP or malformed data.

    Every text field comes from another device, so it is reduced to
    printable characters before it is kept.
    """
    if (len(packet) < _OPTIONS_START or packet[0] != _BOOTREQUEST
            or packet[1] != _HTYPE_ETHER or packet[2] != 6
            or packet[236:240] != _MAGIC_COOKIE):
        return None
    options = _options(packet)
    if options is None:
        return None
    message_type = options.get(_OPT_MESSAGE_TYPE, b"")
    if len(message_type) != 1 or message_type[0] not in _CLIENT_MESSAGES:
        return None

    def text(code: int) -> str | None:
        raw = options.get(code)
        return clean_text(raw.decode("utf-8", "replace")) if raw else None

    return DhcpRequest(
        mac=":".join(f"{byte:02x}" for byte in packet[28:34]),
        message_type=message_type[0],
        hostname=text(_OPT_HOSTNAME),
        vendor_class=text(_OPT_VENDOR_CLASS),
        parameter_list=tuple(options.get(_OPT_PARAM_REQUEST, b"")),
        requested_ip=_ipv4(options.get(_OPT_REQUESTED_IP, b"")),
        client_ip=_ipv4(packet[12:16]),
        seen=seen,
    )


# ══════════════════════════════════════════════════════════════════
#  Operating system hints
# ══════════════════════════════════════════════════════════════════
# Only signals that name the system outright are used. The vendor class is
# set by the DHCP client itself: Android's sends "android-dhcp-<release>",
# Windows' "MSFT 5.0", dhcpcd "dhcpcd-<version>:<OS>-<kernel>:<arch>:<board>"
# and BusyBox's udhcpc "udhcp <version>". Apple's client sends no vendor
# class; its parameter list is recognised by options 95 (LDAP) and 252
# (proxy autodiscovery) together, a pair the other common clients do not
# request. Any other parameter list is logged as a fingerprint, which
# fingerbank.org can look up, instead of guessed at here.

_ANDROID_VENDOR = re.compile(r"android-dhcp-(\d+(?:\.\d+)*)", re.IGNORECASE)
_APPLE_OPTIONS = {95, 252}


def os_hint(request: DhcpRequest) -> str | None:
    """A short operating-system label for *request*, or None when unsure."""
    vendor = request.vendor_class
    if vendor:
        android = _ANDROID_VENDOR.match(vendor)
        if android:
            return f"Android {android.group(1)}"
        lowered = vendor.lower()
        if lowered.startswith("msft"):
            return "Windows"
        if lowered.startswith("dhcpcd"):
            # "dhcpcd-9.4.1:Linux-6.1.21-v8+:aarch64:Raspberry Pi"
            fields = vendor.split(":")
            system = fields[1].split("-")[0] if len(fields) > 1 and fields[1] else "Linux"
            return clean_text(f"{system} ({fields[3]})") if len(fields) > 3 else system
        if lowered.startswith("udhcp"):
            return "Embedded Linux"
        return vendor                          # already cleaned; often names the maker
    if _APPLE_OPTIONS <= set(request.parameter_list):
        return "Apple (iOS/macOS)"
    return None


# ══════════════════════════════════════════════════════════════════
#  Host firewall
# ══════════════════════════════════════════════════════════════════
# tcpdump sees a client's broadcast because it captures before the
# firewall; the listener's socket only gets what the firewall lets through.
# ufw drops inbound packets no rule allows, and a client's DHCP broadcast is
# not a reply to anything this host sent, so ufw's stateful rules never let
# it in: with ufw enabled and no rule for port 67, the listener runs and
# hears nothing. On a real network the phone's DHCPREQUEST showed up in
# tcpdump and never in the listener until such a rule was added.

UFW_ALLOW_DHCP = "sudo ufw allow proto udp from any port 68 to any port 67"

_UFW_CONF     = Path("/etc/ufw/ufw.conf")             # readable by everyone
_UFW_DEFAULTS = Path("/etc/default/ufw")              # readable by everyone
_UFW_RULES    = Path("/etc/ufw/user.rules")           # root only
_UFW_ENABLED  = re.compile(r'^\s*ENABLED\s*=\s*"?yes"?\s*$', re.MULTILINE | re.IGNORECASE)
_UFW_INPUT_ACCEPT = re.compile(r'^\s*DEFAULT_INPUT_POLICY\s*=\s*"?ACCEPT"?\s*$',
                               re.MULTILINE | re.IGNORECASE)
_UFW_ALLOWS_67 = re.compile(r"-p udp\b.*--dport 67\b.*-j ACCEPT")


def ufw_blocks_dhcp() -> bool:
    """True when ufw is enabled and nothing shows that it lets UDP port 67 in.

    Enabled state and default policy are readable by any user. The rules
    themselves are readable by root only, which is how the listener usually
    runs; when they cannot be read, the answer leans towards a warning.
    """
    try:
        if not _UFW_ENABLED.search(_UFW_CONF.read_text()):
            return False
    except OSError:
        return False                           # no ufw on this system
    try:
        if _UFW_INPUT_ACCEPT.search(_UFW_DEFAULTS.read_text()):
            return False
    except OSError:
        pass
    try:
        rules = _UFW_RULES.read_text()
    except OSError:
        return True
    return not any(_UFW_ALLOWS_67.search(line) for line in rules.splitlines())


# ══════════════════════════════════════════════════════════════════
#  Listener
# ══════════════════════════════════════════════════════════════════

class DhcpListener:
    """Records DHCP client requests seen on the LAN, from a background thread.

    It only binds a UDP socket to port 67 and reads: it never answers, so it
    cannot interfere with the network's DHCP server. Use it as a context
    manager, or call start() and stop().
    """

    def __init__(self, port: int = DHCP_SERVER_PORT, address: str = "0.0.0.0") -> None:
        self._port, self._address = port, address
        self._clients: dict[str, DhcpRequest] = {}
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._sock: socket.socket | None = None
        self._thread: threading.Thread | None = None

    @property
    def running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    def start(self) -> bool:
        """Start listening; False when port 67 cannot be bound (no root, or in use)."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        except OSError as exc:
            log.debug("dhcp listener off: %s", exc)
            return False
        try:
            # Coexist with a local DHCP server that also allows address reuse.
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind((self._address, self._port))
            sock.settimeout(0.5)               # how often stop() is noticed
        except OSError as exc:
            sock.close()
            log.debug("dhcp listener off (port %d needs root or is in use): %s", self._port, exc)
            return False
        self._sock = sock
        self._stop.clear()
        self._thread = threading.Thread(target=self._run, name="dhcp-listener", daemon=True)
        self._thread.start()
        log.info("dhcp listener on port %d", self._port)
        if ufw_blocks_dhcp():
            log.warning("ufw is enabled and drops the DHCP broadcasts this listener waits "
                        "for; allow them with: %s", UFW_ALLOW_DHCP)
        return True

    def stop(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=2)
            self._thread = None
        if self._sock is not None:
            self._sock.close()
            self._sock = None

    def __enter__(self) -> "DhcpListener":
        self.start()
        return self

    def __exit__(self, *exc) -> None:
        self.stop()

    def _run(self) -> None:
        sock = self._sock
        while not self._stop.is_set() and sock is not None:
            try:
                packet, _ = sock.recvfrom(2048)
            except socket.timeout:
                continue
            except OSError:
                if self._stop.is_set():
                    break
                continue
            request = parse_request(packet, seen=time.time())
            if request is not None:
                self._record(request)

    def _record(self, request: DhcpRequest) -> None:
        """Keep the client's latest request, without losing fields it left out.

        A DHCPDISCOVER often omits the hostname that the DHCPREQUEST right
        after it carries, so a field missing from the new request keeps its
        earlier value.
        """
        with self._lock:
            known = self._clients.get(request.mac)
            if known is not None:
                kept = {name: getattr(known, name)
                        for name in ("hostname", "vendor_class", "requested_ip", "client_ip")
                        if getattr(request, name) is None and getattr(known, name) is not None}
                if not request.parameter_list and known.parameter_list:
                    kept["parameter_list"] = known.parameter_list
                request = replace(request, **kept)
            elif len(self._clients) >= _MAX_CLIENTS:
                oldest = min(self._clients.values(), key=lambda r: r.seen)
                del self._clients[oldest.mac]
            self._clients[request.mac] = request
        log.debug("dhcp request mac=%s type=%d hostname=%s vendor=%s prl=%s ip=%s",
                 request.mac, request.message_type, request.hostname, request.vendor_class,
                 request.fingerprint, request.client_ip or request.requested_ip)

    def clients(self) -> dict[str, DhcpRequest]:
        """A copy of every client seen so far, by MAC."""
        with self._lock:
            return dict(self._clients)

    def lookup(self, mac: str | None, ip: str) -> DhcpRequest | None:
        """The latest request from the device at *ip* with MAC *mac*, if any.

        The MAC is the reliable key. Without one (an unprivileged nmap reports
        no MAC), a client counts when it said it uses *ip*: as the address it
        requested, or as the one it already holds. Among several, the most
        recent wins, since addresses get reassigned.
        """
        with self._lock:
            if mac:
                found = self._clients.get(mac.lower())
                if found is not None:
                    return found
            by_ip = [r for r in self._clients.values() if ip in (r.client_ip, r.requested_ip)]
        return max(by_ip, key=lambda r: r.seen) if by_ip else None
