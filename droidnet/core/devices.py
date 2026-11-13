"""
Device identity helpers for the scan table.

    is_locally_administered(mac) → True for a randomized / locally assigned MAC
    reverse_lookup(ips, server)  → {ip: name} from a DNS server's PTR records
    mdns_probe(ips)              → {ip: {hostname, model, name}} over mDNS

All of them work without root. Names, models and MACs are reported by the
devices themselves: text is reduced to printable characters here, and
callers still escape it before printing.
"""

import contextlib
import ipaddress
import random
import re
import select
import socket
import struct
import time
from typing import NamedTuple

# ══════════════════════════════════════════════════════════════════
#  MAC addresses and device-supplied text
# ══════════════════════════════════════════════════════════════════

_MAC = re.compile(r"[0-9A-Fa-f]{2}([:-]?)[0-9A-Fa-f]{2}(?:\1[0-9A-Fa-f]{2}){4}")


def is_locally_administered(mac: str | None) -> bool:
    """True when *mac* is a unicast address with the locally administered bit set.

    Factory addresses start with the maker's OUI and have that bit clear.
    Android and iOS set it when they use a per-network randomized ("private")
    address, which is why the OUI lookup finds no vendor for them. Virtual
    machines and containers set it too, so it marks an address the vendor
    lookup cannot identify, not an intruder. In hex, the second character of
    such an address is 2, 6, A or E.
    """
    if not mac or not _MAC.fullmatch(mac.strip()):
        return False
    first_octet = int(mac.strip()[:2], 16)
    # Bit 0 is the multicast flag (never set on a device), bit 1 the LA flag.
    return first_octet & 0b11 == 0b10


def clean_text(value: str | None, limit: int = 64) -> str | None:
    """Printable form of text a device chose, or None if nothing is left.

    Control characters (terminal escape sequences included) are dropped,
    whitespace runs collapse to one space and the result is capped at
    *limit* characters.
    """
    if not value:
        return None
    kept = "".join(ch if ch.isprintable() else " " if ch.isspace() else ""
                   for ch in value)
    text = " ".join(kept.split())
    return text[:limit] or None


# ══════════════════════════════════════════════════════════════════
#  DNS wire format (shared by unicast DNS and mDNS)
# ══════════════════════════════════════════════════════════════════

_DNS_PORT   = 53
_MDNS_PORT  = 5353
_TYPE_PTR   = 12
_TYPE_TXT   = 16
_CLASS_IN   = 1
_CLASS_MASK = 0x7FFF     # mDNS borrows the top bit (cache flush / unicast reply)
_FLAG_QR    = 0x8000
_FLAG_RD    = 0x0100
_RCODE      = 0x000F
_MAX_HOPS   = 16         # compression pointers followed before giving up
_HOSTNAME_LABEL = re.compile(r"[A-Za-z0-9_-]{1,63}")


class _Record(NamedTuple):
    name: list[str]      # owner name, as labels from _read_name
    rtype: int
    offset: int          # where the RDATA starts in the message
    length: int          # RDLENGTH
    answer: bool         # in the answer section (not authority / additional)


def _reverse_name(ip: str) -> str:
    """192.0.2.5 → 5.2.0.192.in-addr.arpa"""
    return ipaddress.IPv4Address(ip).reverse_pointer


def _build_query(qname: str, qtype: int, txid: int, flags: int = _FLAG_RD) -> bytes:
    """A one-question query for *qname* with transaction id *txid*."""
    header = struct.pack("!HHHHHH", txid, flags, 1, 0, 0, 0)
    labels = b"".join(bytes([len(part)]) + part.encode("ascii")
                      for part in qname.split("."))
    return header + labels + b"\x00" + struct.pack("!HH", qtype, _CLASS_IN)


def _build_ptr_query(qname: str, txid: int) -> bytes:
    """A recursive PTR query for *qname* with transaction id *txid*."""
    return _build_query(qname, _TYPE_PTR, txid)


def _read_name(data: bytes, offset: int) -> tuple[list[str], int]:
    """Decode the domain name at *offset*.

    Returns (labels, offset just past the name in the record). Labels are
    decoded as latin-1 so every byte maps to one character; callers decide
    which characters they accept. Raises ValueError on a malformed name.
    """
    labels: list[str] = []
    end = None
    hops = 0
    while True:
        if offset >= len(data):
            raise ValueError("name runs past the message")
        length = data[offset]
        if length == 0:
            offset += 1
            break
        if length & 0xC0 == 0xC0:
            if offset + 1 >= len(data):
                raise ValueError("truncated compression pointer")
            hops += 1
            if hops > _MAX_HOPS:
                raise ValueError("compression loop")
            if end is None:
                end = offset + 2
            offset = ((length & 0x3F) << 8) | data[offset + 1]
            continue
        if length & 0xC0:
            raise ValueError("reserved label type")
        label = data[offset + 1:offset + 1 + length]
        if len(label) != length:
            raise ValueError("label runs past the message")
        labels.append(label.decode("latin-1"))
        offset += 1 + length
    return labels, (end if end is not None else offset)


def _parse_message(data: bytes) -> tuple[int, int, list[list[str]], list[_Record]]:
    """Split a DNS message into (txid, flags, question names, records).

    Records of all three sections come back in order, located but not
    decoded; callers decode the types they need. Records outside class IN
    are left out. Raises ValueError on anything malformed.
    """
    if len(data) < 12:
        raise ValueError("short header")
    txid, flags, qdcount, ancount, nscount, arcount = struct.unpack("!6H", data[:12])
    offset = 12
    questions = []
    for _ in range(qdcount):
        labels, offset = _read_name(data, offset)
        offset += 4                                  # QTYPE, QCLASS
        if offset > len(data):
            raise ValueError("question runs past the message")
        questions.append(labels)
    records = []
    for index in range(ancount + nscount + arcount):
        labels, offset = _read_name(data, offset)
        if offset + 10 > len(data):
            raise ValueError("record header runs past the message")
        rtype, rclass, _ttl, rdlength = struct.unpack("!HHIH", data[offset:offset + 10])
        offset += 10
        if offset + rdlength > len(data):
            raise ValueError("record data runs past the message")
        if rclass & _CLASS_MASK == _CLASS_IN:
            records.append(_Record(labels, rtype, offset, rdlength, index < ancount))
        offset += rdlength
    return txid, flags, questions, records


def _txt_pairs(data: bytes, record: _Record) -> dict[str, str]:
    """A TXT record's key=value strings (RFC 6763 §6). Keys are lowercased
    and, as the RFC says, the first occurrence of a key wins."""
    pairs: dict[str, str] = {}
    offset, end = record.offset, record.offset + record.length
    while offset < end:
        size = data[offset]
        chunk = data[offset + 1:min(offset + 1 + size, end)]
        offset += 1 + size
        key, _, value = chunk.partition(b"=")
        if key:
            pairs.setdefault(key.decode("ascii", "replace").lower(),
                             value.decode("utf-8", "replace"))
    return pairs


def _hostname(labels: list[str]) -> str | None:
    """Join *labels* into a hostname, or None if any label is not a plain one.

    A name another device chose ends up on the terminal, so only letters,
    digits, '-' and '_' are kept: no control characters, no spaces.
    """
    if not labels or not all(_HOSTNAME_LABEL.fullmatch(label) for label in labels):
        return None
    name = ".".join(labels)
    return name if len(name) <= 253 else None


def _query_ids(count: int) -> list[int]:
    """*count* distinct, unpredictable transaction ids."""
    return random.SystemRandom().sample(range(1, 0x10000), count)


# ══════════════════════════════════════════════════════════════════
#  Reverse DNS against a chosen server
# ══════════════════════════════════════════════════════════════════
# Home routers (dnsmasq, OpenWrt, most ISP boxes) answer PTR queries for
# their LAN with the hostname each device sent in its DHCP request (option
# 12). nmap asks the system resolver instead, and Termux's resolver is a
# public DNS server that knows nothing about the LAN. A tiny client is used
# rather than ``nmap --dns-servers`` because nmap keeps retrying a server that
# does not answer for minutes, while this one has a hard deadline.

def _parse_ptr_response(data: bytes) -> tuple[int, str, str | None] | None:
    """Parse a reply to one of our PTR queries.

    Returns (txid, question name, hostname or None), or None when *data* is
    not a usable reply. A reply that says "no such name", or whose answer is
    not a plain hostname, still returns its txid so the caller stops waiting
    for it.
    """
    try:
        txid, flags, questions, records = _parse_message(data)
        if not flags & _FLAG_QR or len(questions) != 1:
            return None
        qname = ".".join(questions[0]).lower()
        if flags & _RCODE:
            return txid, qname, None
        for record in records:
            if record.answer and record.rtype == _TYPE_PTR:
                return txid, qname, _hostname(_read_name(data, record.offset)[0])
        return txid, qname, None
    except (ValueError, struct.error):
        return None


def reverse_lookup(ips: list[str], server: str, timeout: float = 2.0,
                   port: int = _DNS_PORT) -> dict[str, str]:
    """Ask *server* for the PTR name of each IP in *ips*.

    All queries go out at once over one UDP socket and the whole lookup stops
    after *timeout* seconds, answered or not, so a router without a DNS
    service costs at most that long (usually less: its "port unreachable"
    reply ends the wait). IPs without a usable name are left out.
    """
    if not ips:
        return {}
    names: dict[str, str] = {}
    pending: dict[int, tuple[str, str]] = {}
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    except OSError:
        return names
    with sock:
        try:
            # A connected socket only receives datagrams from the server.
            sock.connect((server, port))
            for txid, ip in zip(_query_ids(len(ips)), ips, strict=True):
                qname = _reverse_name(ip)
                sock.send(_build_ptr_query(qname, txid))
                pending[txid] = (ip, qname)
        except (OSError, ValueError):
            if not pending:
                return names
        deadline = time.monotonic() + timeout
        while pending:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            sock.settimeout(remaining)
            try:
                data = sock.recv(4096)
            except OSError:          # timeout, or the server refused (no DNS)
                break
            reply = _parse_ptr_response(data)
            if reply is None:
                continue
            txid, qname, name = reply
            query = pending.get(txid)
            if query is None or query[1] != qname:
                continue
            del pending[txid]
            if name:
                names[query[0]] = name
    return names


# ══════════════════════════════════════════════════════════════════
#  mDNS (Bonjour / Avahi), asked of each host directly
# ══════════════════════════════════════════════════════════════════
# A query sent straight to a device's port 5353 from any other port is a
# "legacy unicast" query (RFC 6762 §6.7): the device answers by unicast to
# the sender. That needs no root and dodges Android's multicast filter, which
# drops multicast for apps without a MulticastLock (Termux cannot take one).
#
# Every host is first asked which service types it offers and what it calls
# its own address. Hosts offering a service whose TXT record carries a model
# are then asked for that service, and the device returns the TXT record
# together with the answer. Hosts without such a service get no second query.
#
# A device may run more than one mDNS responder on port 5353: a Google Nest
# Mini runs one for Cast (_googlecast, which carries the model) and another
# for Matter. Its kernel hands each unicast query to just one of them,
# chosen by a hash of the sender's address and port, so a given source port
# always reaches the same responder. On a real Nest Mini the share of source
# ports that reached the Cast responder ranged from 90% down to 30% over an
# hour; asking from a single port left the device unidentified in up to a
# third of the scans. So when a host lists services but none that carries
# a model, its service list is asked again from _MDNS_EXTRA_PORTS new
# sockets at once, each with its own source port. At 30% per port, all of
# them missing is about a 1% chance, and it costs one short round, not one
# per port. Follow-up queries go out on the socket that reached the
# responder knowing the service.

_SERVICE_LIST = ["_services", "_dns-sd", "_udp", "local"]
_MDNS_EXTRA_PORTS = 12
# Extra listening once every query has had a first reply packet, for the
# rest of answers split over several packets (see _exchange). The parts of
# one answer arrived within 10 ms of each other on a real Nest Mini.
_MDNS_LINGER = 0.15

# Service type → TXT key holding the model, in the order models are trusted.
_MODEL_KEYS = {
    ("_device-info", "_tcp"):    "model",   # Apple: "iPhone15,2", "MacBookPro18,3"
    ("_companion-link", "_tcp"): "rpmd",    # Apple devices
    ("_airplay", "_tcp"):        "model",   # Apple TV, HomePod, AirPlay TVs
    ("_raop", "_tcp"):           "am",      # AirPlay audio receivers
    ("_googlecast", "_tcp"):     "md",      # "Chromecast", "Google Nest Mini"
    ("_hap", "_tcp"):            "md",      # HomeKit accessories
    ("_ipp", "_tcp"):            "ty",      # printers: make and model
    ("_ipps", "_tcp"):           "ty",
    ("_printer", "_tcp"):        "ty",
    ("_pdl-datastream", "_tcp"): "ty",
}
# Service type → TXT key holding the name the owner gave the device.
_NAME_KEYS = {("_googlecast", "_tcp"): "fn"}


class _Hints:
    """What one host has said about itself over mDNS."""

    def __init__(self) -> None:
        self.services: set[tuple[str, str]] = set()
        self.hostname: str | None = None
        self.models: dict[tuple[str, str], str] = {}
        self.names: dict[tuple[str, str], str] = {}

    def absorb(self, data: bytes) -> bool:
        """Take in one reply. Returns False if *data* is not a DNS response."""
        try:
            _, flags, _, records = _parse_message(data)
        except (ValueError, struct.error):
            return False
        if not flags & _FLAG_QR:
            return False
        for record in records:
            owner = [label.lower() for label in record.name]
            try:
                if record.rtype == _TYPE_PTR:
                    self._absorb_ptr(owner, _read_name(data, record.offset)[0])
                elif record.rtype == _TYPE_TXT and len(owner) >= 4 and owner[-1] == "local":
                    self._absorb_txt((owner[-3], owner[-2]), _txt_pairs(data, record))
            except ValueError:
                continue
        return True

    def _absorb_ptr(self, owner: list[str], target: list[str]) -> None:
        if owner == _SERVICE_LIST:
            if len(target) == 3 and target[2].lower() == "local":
                self.services.add((target[0].lower(), target[1].lower()))
        elif owner[-2:] == ["in-addr", "arpa"]:
            self.hostname = self.hostname or _hostname(target)
        elif (len(owner) == 3 and owner[2] == "local" and len(target) == 4
              and [label.lower() for label in target[1:]] == owner):
            # "<name the owner chose>.<service type>.local"; UTF-8 on the wire.
            stype = (owner[0], owner[1])
            label = target[0].encode("latin-1").decode("utf-8", "replace")
            if stype == ("_raop", "_tcp"):
                label = label.partition("@")[2] or label    # "A1B2C3D4E5F6@Kitchen"
            name = clean_text(label)
            if name:
                self.names.setdefault(stype, name)

    def _absorb_txt(self, stype: tuple[str, str], pairs: dict[str, str]) -> None:
        key = _MODEL_KEYS.get(stype)
        model = clean_text(pairs.get(key)) if key else None
        if model:
            self.models.setdefault(stype, model)
        key = _NAME_KEYS.get(stype)
        name = clean_text(pairs.get(key)) if key else None
        if name:
            self.names[stype] = name                 # beats the instance label

    def wanted_services(self) -> list[tuple[str, str]]:
        """Offered services that carry a model not seen yet, most trusted first."""
        return [s for s in _MODEL_KEYS if s in self.services and s not in self.models]

    def offers_model_service(self) -> bool:
        """True once the host has listed a service whose TXT carries a model."""
        return any(s in self.services for s in _MODEL_KEYS)

    def lists_only_other_services(self) -> bool:
        """True when the host listed services but none whose TXT carries a model.

        That is the answer of a second responder on the same device (see the
        section comment above), so the service list is worth asking again
        from other source ports.
        """
        return bool(self.services) and not self.offers_model_service()

    def summary(self) -> dict[str, str | None]:
        model = next((self.models[s] for s in _MODEL_KEYS if s in self.models), None)
        name = next((self.names[s] for s in (*_NAME_KEYS, *_MODEL_KEYS) if s in self.names), None)
        return {"hostname": self.hostname, "model": model, "name": name}


def _ptr_queries(asks: list[tuple[str, str]]) -> list[tuple[str, int, bytes]]:
    """(ip, name) pairs → (ip, txid, mDNS PTR query) with fresh transaction ids."""
    return [(ip, txid, _build_query(name, _TYPE_PTR, txid, flags=0))
            for (ip, name), txid in zip(asks, _query_ids(len(asks)), strict=True)]


def _exchange(asks: dict[socket.socket, list[tuple[str, str]]], hints: dict[str, _Hints],
              timeout: float, port: int) -> dict[str, socket.socket]:
    """Send each socket its PTR queries ((ip, name) pairs) and read all of them.

    Every reply packet is fed to *hints*. Returns, for each host that listed
    a service carrying a model for the first time here, the socket that
    received that list: its source port reaches the responder that knows
    the service, so the follow-up query must go out on it.

    A responder may spread one answer over several packets: a Nest Mini
    sends one packet per service type, a few milliseconds apart. So the wait
    is tracked per query (socket, host, transaction id), not by counting
    packets, and once every query has had a first packet the sockets are
    read _MDNS_LINGER seconds more for the rest. Stopping at the first packet
    loses the others: on the Nest Mini that dropped _googlecast, the one
    service that carries its model.

    Halfway through, queries still unanswered are sent once more, with the
    same transaction id, as DNS clients do: a Wi-Fi device occasionally
    misses one (the Nest Mini did in about one scan in twenty). Hosts
    without mDNS get that second packet too, which costs nothing but a few
    bytes. The whole exchange never exceeds *timeout* seconds.
    """
    pending: dict[tuple[socket.socket, str, int], bytes] = {}
    for sock, pairs in asks.items():
        for ip, txid, packet in _ptr_queries(pairs):
            try:
                sock.sendto(packet, (ip, port))
                pending[(sock, ip, txid)] = packet
            except OSError:
                continue
    reached: dict[str, socket.socket] = {}
    if not pending:
        return reached
    sockets = list(asks)
    start = time.monotonic()
    deadline = start + timeout
    resend_at: float | None = start + timeout / 2
    while True:
        now = time.monotonic()
        if resend_at is not None and now >= resend_at:
            for (sock, ip, _), packet in pending.items():
                try:
                    sock.sendto(packet, (ip, port))
                except OSError:
                    continue
            resend_at = None
        remaining = deadline - now
        if remaining <= 0:
            break
        wait = remaining if resend_at is None else min(remaining, resend_at - now)
        readable, _, _ = select.select(sockets, [], [], wait)
        if not readable:
            if resend_at is None:
                break
            continue
        for sock in readable:
            try:
                data, (source, _) = sock.recvfrom(9000)
            except OSError:
                continue
            host = hints.get(source)
            if host is None:
                continue
            had_model_service = host.offers_model_service()
            if not host.absorb(data):                      # absorbed: at least a header
                continue
            if not had_model_service and host.offers_model_service():
                reached.setdefault(source, sock)
            if pending:
                pending.pop((sock, source, struct.unpack("!H", data[:2])[0]), None)
                if not pending:
                    deadline = min(deadline, time.monotonic() + _MDNS_LINGER)
                    resend_at = None
    return reached


def _follow_up(reached: dict[str, socket.socket], hints: dict[str, _Hints],
               timeout: float, port: int) -> None:
    """Ask each reached host for its model-carrying services, on the socket that found them."""
    asks: dict[socket.socket, list[tuple[str, str]]] = {}
    for ip, sock in reached.items():
        asks.setdefault(sock, []).extend(
            (ip, f"{service}.{proto}.local") for service, proto in hints[ip].wanted_services())
    if any(asks.values()):
        _exchange(asks, hints, timeout, port)


def mdns_probe(ips: list[str], timeout: float = 1.0,
               port: int = _MDNS_PORT) -> dict[str, dict[str, str | None]]:
    """Ask each host in *ips* about itself over mDNS.

    Returns {ip: {"hostname", "model", "name"}} for the hosts that said
    anything useful: the host name they use on the LAN ("Ales-iPhone.local"),
    a model ("iPhone15,2", "Chromecast", a printer's make and model) and the
    name their owner gave them ("Living Room TV"). Each round of queries
    waits *timeout* seconds at most and ends shortly after every query has
    been answered. Hosts without mDNS just stay silent; the extra-port round
    only asks hosts that already answered, so it costs a fraction of a
    second, not another timeout.
    """
    if not ips:
        return {}
    hints = {ip: _Hints() for ip in ips}
    service_list = ".".join(_SERVICE_LIST)
    with contextlib.ExitStack() as stack:
        try:
            first = stack.enter_context(socket.socket(socket.AF_INET, socket.SOCK_DGRAM))
        except OSError:
            return {}
        asks = [(ip, service_list) for ip in ips] + [(ip, _reverse_name(ip)) for ip in ips]
        _follow_up(_exchange({first: asks}, hints, timeout, port), hints, timeout, port)

        retry = [ip for ip in ips if hints[ip].lists_only_other_services()]
        if retry:
            extra = []
            for _ in range(_MDNS_EXTRA_PORTS):
                try:
                    extra.append(stack.enter_context(
                        socket.socket(socket.AF_INET, socket.SOCK_DGRAM)))
                except OSError:
                    break
            if extra:
                reached = _exchange({sock: [(ip, service_list) for ip in retry] for sock in extra},
                                    hints, timeout, port)
                _follow_up(reached, hints, timeout, port)

    found = {}
    for ip, host in hints.items():
        summary = host.summary()
        if any(summary.values()):
            found[ip] = summary
    return found
