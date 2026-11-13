"""Device identification without root, and how Sentinel shows it.

Covers randomized-MAC detection, reverse DNS against the router, mDNS asked
of each host, the cleaning of text devices send, and how identify_devices
merges every source into the Hostname and Device columns.

Network tests use fake servers on loopback addresses (127.0.0.x); nothing
leaves the machine.
"""
import io
import socket
import struct
import threading
import time

import pytest
from rich.console import Console

from droidnet.core import devices
from droidnet.core.devices import (
    _build_ptr_query,
    _parse_ptr_response,
    is_locally_administered,
    reverse_lookup,
)
from droidnet.modules import sentinel


# ── locally administered bit ───────────────────────────────────────

@pytest.mark.parametrize("mac, expected", [
    ("DA:A1:19:00:00:01", True),    # Android / iOS private address
    ("02:42:AC:11:00:02", True),    # Docker
    ("52:54:00:12:34:56", True),    # QEMU
    ("aa-bb-cc-dd-ee-ff", True),
    ("AABBCCDDEEFF",      True),
    ("e6:00:00:00:00:00", True),
    ("00:1A:2B:3C:4D:5E", False),   # factory address
    ("F4:F5:D8:00:00:00", False),
    ("01:00:5E:00:00:FB", False),   # multicast, never a device
    ("03:00:00:00:00:00", False),   # multicast with the LA bit
    ("AA:BB-CC:DD:EE:FF", False),   # mixed separators
    ("AA:BB:CC:DD:EE",    False),
    ("ZZ:BB:CC:DD:EE:FF", False),
    ("",                  False),
    (None,                False),
])
def test_locally_administered_bit(mac, expected):
    assert is_locally_administered(mac) is expected


# ── Device column ──────────────────────────────────────────────────

def _table_text(monkeypatch, metadata):
    rec = Console(file=io.StringIO(), record=True, width=240, color_system=None)
    monkeypatch.setattr(sentinel, "console", rec)
    sentinel.display_results_table(
        "lab", {ip: ["Shield intact"] for ip in metadata}, metadata)
    return rec.export_text()


def test_randomized_mac_without_vendor_is_labelled(monkeypatch):
    text = _table_text(monkeypatch, {
        "192.0.2.5": {"mac": "DA:A1:19:00:00:01", "vendor": None},
        "192.0.2.6": {"mac": "00:1A:2B:3C:4D:5E", "vendor": None},
    })
    assert text.count("Randomized MAC") == 1
    assert "[italic]" not in text


def test_known_vendor_wins_over_the_label(monkeypatch):
    text = _table_text(monkeypatch, {
        "192.0.2.5": {"mac": "52:54:00:12:34:56", "vendor": "QEMU virtual NIC"}})
    assert "QEMU virtual NIC" in text
    assert "Randomized MAC" not in text


# ── DNS wire format ────────────────────────────────────────────────

def _reply(query: bytes, rcode: int = 0, answer: bytes | None = None,
           ptr_name: str | None = None) -> bytes:
    """Answer *query*: its question echoed, then one PTR record if asked."""
    txid = struct.unpack("!H", query[:2])[0]
    question = query[12:]
    if ptr_name is not None:
        answer = b"".join(bytes([len(p)]) + p.encode() for p in ptr_name.split(".")) + b"\x00"
    records = b""
    if answer is not None:
        # Owner name is a compression pointer to the question (offset 12).
        records = b"\xc0\x0c" + struct.pack("!HHIH", 12, 1, 60, len(answer)) + answer
    header = struct.pack("!HHHHHH", txid, 0x8180 | rcode, 1, 1 if records else 0, 0, 0)
    return header + question + records


QNAME = "5.2.0.192.in-addr.arpa"


def test_query_encodes_reverse_name():
    query = _build_ptr_query(QNAME, 0x1234)
    assert query[:2] == b"\x12\x34"
    assert b"\x015\x012\x010\x03192\x07in-addr\x04arpa\x00" in query
    assert query.endswith(b"\x00\x0c\x00\x01")


def test_parse_ptr_answer():
    query = _build_ptr_query(QNAME, 7)
    assert _parse_ptr_response(_reply(query, ptr_name="pixel-8.lan")) == (7, QNAME, "pixel-8.lan")


def test_parse_compressed_answer_name():
    # The answer reuses the question's labels through a compression pointer.
    query = _build_ptr_query(QNAME, 7)
    answer = b"\x04host\xc0\x0c"            # host.<question name>
    assert _parse_ptr_response(_reply(query, answer=answer)) == (7, QNAME, f"host.{QNAME}")


def test_nxdomain_ends_the_wait_without_a_name():
    query = _build_ptr_query(QNAME, 7)
    assert _parse_ptr_response(_reply(query, rcode=3)) == (7, QNAME, None)


@pytest.mark.parametrize("name", ["evil\x1b[31m", "two words", "caf\xe9"])
def test_unsafe_hostnames_are_dropped(name):
    query = _build_ptr_query(QNAME, 7)
    raw = name.encode("latin-1")
    answer = bytes([len(raw)]) + raw + b"\x00"
    assert _parse_ptr_response(_reply(query, answer=answer)) == (7, QNAME, None)


def _looping_reply() -> bytes:
    """A reply whose answer name is a compression pointer to itself."""
    query = _build_ptr_query(QNAME, 7)
    head = struct.pack("!HHHHHH", 7, 0x8180, 1, 1, 0, 0) + query[12:]
    return head + b"\xc0" + bytes([len(head)]) + struct.pack("!HHIH", 12, 1, 60, 0)


@pytest.mark.parametrize("data", [
    b"",
    b"\x00" * 11,
    # A query, not a reply (QR clear).
    _build_ptr_query(QNAME, 7),
    _looping_reply(),
    # Record cut short.
    _reply(_build_ptr_query(QNAME, 7), ptr_name="host.lan")[:-4],
])
def test_malformed_replies_are_ignored(data):
    assert _parse_ptr_response(data) is None


# ── lookups against a fake server ──────────────────────────────────

class FakeDNS:
    """UDP server on loopback answering PTR queries from a fixed table.

    IPs mapped to a name get it, IPs mapped to None get NXDOMAIN, and IPs not
    in the table get no answer at all.
    """

    def __init__(self, table, before=b""):
        self.table = {devices._reverse_name(ip): name for ip, name in table.items()}
        self.before = before
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.settimeout(0.1)
        self.port = self.sock.getsockname()[1]
        self.stop = threading.Event()
        self.thread = threading.Thread(target=self._serve, daemon=True)

    def _serve(self):
        while not self.stop.is_set():
            try:
                query, addr = self.sock.recvfrom(512)
            except OSError:
                continue
            qname = _parse_name(query)
            if qname not in self.table:
                continue
            if self.before:
                self.sock.sendto(self.before, addr)
            name = self.table[qname]
            reply = _reply(query, rcode=3) if name is None else _reply(query, ptr_name=name)
            self.sock.sendto(reply, addr)

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *exc):
        self.stop.set()
        self.thread.join()
        self.sock.close()


def _parse_name(query: bytes) -> str:
    return ".".join(devices._read_name(query, 12)[0])


def test_lookup_returns_names_and_skips_nxdomain():
    with FakeDNS({"192.0.2.5": "iphone.lan", "192.0.2.6": None}) as dns:
        start = time.monotonic()
        names = reverse_lookup(["192.0.2.5", "192.0.2.6"], "127.0.0.1", timeout=3, port=dns.port)
        elapsed = time.monotonic() - start
    assert names == {"192.0.2.5": "iphone.lan"}
    assert elapsed < 1.5, "every query was answered; no need to wait for the deadline"


def test_silent_server_stops_at_the_deadline():
    with FakeDNS({"192.0.2.5": "iphone.lan"}) as dns:
        start = time.monotonic()
        names = reverse_lookup(["192.0.2.5", "192.0.2.7"], "127.0.0.1", timeout=0.5, port=dns.port)
        elapsed = time.monotonic() - start
    assert names == {"192.0.2.5": "iphone.lan"}
    assert 0.4 < elapsed < 2


def test_garbage_before_the_answer_is_skipped():
    with FakeDNS({"192.0.2.5": "iphone.lan"}, before=b"\xff" * 40) as dns:
        names = reverse_lookup(["192.0.2.5"], "127.0.0.1", timeout=2, port=dns.port)
    assert names == {"192.0.2.5": "iphone.lan"}


def test_router_without_dns_answers_fast():
    probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    probe.bind(("127.0.0.1", 0))
    closed_port = probe.getsockname()[1]
    probe.close()
    start = time.monotonic()
    assert reverse_lookup(["192.0.2.5"], "127.0.0.1", timeout=5, port=closed_port) == {}
    assert time.monotonic() - start < 2, "port unreachable should end the wait"


def test_no_ips_sends_nothing(monkeypatch):
    monkeypatch.setattr(devices.socket, "socket", lambda *a: pytest.fail("socket opened"))
    assert reverse_lookup([], "127.0.0.1") == {}


# ── device-supplied text ───────────────────────────────────────────

@pytest.mark.parametrize("value, expected", [
    ("Living Room TV",          "Living Room TV"),
    ("  two   spaces\tand tab", "two spaces and tab"),
    ("evil\x1b[31mred\x07",     "evil[31mred"),
    ("Ale’s iPhone",            "Ale’s iPhone"),
    ("\x00\x1b",                None),
    ("",                        None),
    (None,                      None),
    ("x" * 100,                 "x" * 64),
])
def test_clean_text(value, expected):
    assert devices.clean_text(value) == expected


# ── mDNS ───────────────────────────────────────────────────────────

def _name(labels) -> bytes:
    if isinstance(labels, str):
        labels = labels.split(".")
    return b"".join(bytes([len(raw)]) + raw for raw in (label.encode() for label in labels)) + b"\x00"


def _rr(owner, rtype: int, rdata: bytes) -> bytes:
    # 0x8001: class IN with mDNS's cache-flush bit, which must be ignored.
    return _name(owner) + struct.pack("!HHIH", rtype, 0x8001, 120, len(rdata)) + rdata


def _txt(**pairs) -> bytes:
    strings = [f"{key}={value}".encode() for key, value in pairs.items()]
    return b"".join(bytes([len(s)]) + s for s in strings)


def _mdns_reply(query: bytes, answers: list[bytes], additional: list[bytes] = ()) -> bytes:
    txid = struct.unpack("!H", query[:2])[0]
    header = struct.pack("!HHHHHH", txid, 0x8400, 1, len(answers), 0, len(additional))
    return header + query[12:] + b"".join(answers) + b"".join(additional)


class FakeMDNS:
    """A device answering legacy unicast mDNS queries on (address, port).

    *services* maps a service type ("_googlecast._tcp") to its instance
    label and TXT pairs. Each reply is sent *copies* times, after *delay*
    seconds. With *split*, the service list goes out as one packet per
    service type, as a Nest Mini sends it.

    *other_services* adds a second responder on the same device, as a Nest
    Mini runs one for Cast and one for Matter. Like the kernel's choice by
    source port, a given port always reaches the same responder: the first
    *other_ports* distinct source ports reach the second one.

    With *drop_first*, the first copy of every query is ignored, as if the
    device had missed it.
    """

    def __init__(self, address, port=0, hostname=None, services=None, copies=1,
                 delay=0.0, split=False, other_services=None, other_ports=0, drop_first=False):
        self.address = address
        self.hostname = hostname
        self.services = services or {}
        self.copies, self.delay, self.split = copies, delay, split
        self.drop_first, self.dropped = drop_first, set()
        self.other_services = other_services or {}
        self.other_ports = other_ports
        self.responder_for_port = {}
        self.queries = []
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind((address, port))
        self.sock.settimeout(0.1)
        self.port = self.sock.getsockname()[1]
        self.stop = threading.Event()
        self.thread = threading.Thread(target=self._serve, daemon=True)

    def _services_for(self, source_port: int) -> dict:
        if source_port not in self.responder_for_port:
            other = len(self.responder_for_port) < self.other_ports
            self.responder_for_port[source_port] = self.other_services if other else self.services
        return self.responder_for_port[source_port]

    def _answer(self, query: bytes, source_port: int) -> list[bytes]:
        qname = _parse_name(query)
        self.queries.append((qname, source_port))
        if self.drop_first and (qname, source_port) not in self.dropped:
            self.dropped.add((qname, source_port))
            return []
        services = self._services_for(source_port)
        if qname == "_services._dns-sd._udp.local":
            records = [_rr(qname, 12, _name(f"{stype}.local")) for stype in services]
            if self.split:
                return [_mdns_reply(query, [record]) for record in records]
            return [_mdns_reply(query, records)]
        if qname == devices._reverse_name(self.address) and self.hostname:
            return [_mdns_reply(query, [_rr(qname, 12, _name(self.hostname))])]
        stype = qname.removesuffix(".local")
        if stype in services:
            label, pairs = services[stype]
            instance = [label, *qname.split(".")]
            return [_mdns_reply(query, [_rr(qname, 12, _name(instance))],
                                [_rr(instance, 16, _txt(**pairs))])]
        return []

    def _serve(self):
        while not self.stop.is_set():
            try:
                query, addr = self.sock.recvfrom(512)
            except OSError:
                continue
            replies = self._answer(query, addr[1])
            if replies and self.delay:
                time.sleep(self.delay)
            for reply in replies:
                for _ in range(self.copies):
                    self.sock.sendto(reply, addr)

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *exc):
        self.stop.set()
        self.thread.join()
        self.sock.close()


def test_mdns_probe_reads_names_and_models():
    # Each fake host has its own loopback address, all on one port.
    with FakeMDNS("127.0.0.2", hostname="Ales-iPhone.local", services={
            "_companion-link._tcp": ("Ale’s iPhone", {"rpMd": "iPhone15,2"}),
            "_rdlink._tcp":         ("ignored", {"model": "not read"}),
    }) as phone, FakeMDNS("127.0.0.3", port=phone.port, services={
            "_googlecast._tcp": ("Chromecast-1a2b3c", {"md": "Chromecast", "fn": "Living Room TV"}),
    }):
        start = time.monotonic()
        found = devices.mdns_probe(["127.0.0.2", "127.0.0.3", "127.0.0.4"],
                                   timeout=0.5, port=phone.port)
        elapsed = time.monotonic() - start
    assert found == {
        "127.0.0.2": {"hostname": "Ales-iPhone.local", "model": "iPhone15,2", "name": "Ale’s iPhone"},
        "127.0.0.3": {"hostname": None, "model": "Chromecast", "name": "Living Room TV"},
    }
    # Follow-up queries only ask for services whose TXT record carries a model.
    assert "_rdlink._tcp.local" not in {qname for qname, _ in phone.queries}
    assert elapsed < 1.5


def test_mdns_asks_from_more_ports_to_reach_the_other_responder():
    # The first six source ports reach the Matter responder, which lists no
    # service carrying a model; the later ones reach the Cast responder. As
    # on the real device, the Cast responder sends its list one packet per
    # service, _googlezone first: the round must also wait for _googlecast.
    with FakeMDNS("127.0.0.2", split=True, other_ports=6,
                  services={"_googlezone._tcp": ("zone", {}),
                            "_googlecast._tcp": ("Google-Nest-Mini-1a2b",
                                                 {"md": "Google Nest Mini", "fn": "Bedroom"})},
                  other_services={"_googcrossdevice._tcp": ("x", {}),
                                  "_matter._tcp": ("y", {})}) as nest:
        start = time.monotonic()
        found = devices.mdns_probe(["127.0.0.2", "127.0.0.3"], timeout=0.5, port=nest.port)
        elapsed = time.monotonic() - start
    assert found == {"127.0.0.2": {"hostname": None, "model": "Google Nest Mini", "name": "Bedroom"}}
    # The follow-up for _googlecast goes out on a socket whose port reached
    # the Cast responder; from any other port it would get no answer.
    cast_ports = {port for port, services in nest.responder_for_port.items()
                  if services is nest.services}
    followups = [port for qname, port in nest.queries if qname == "_googlecast._tcp.local"]
    assert followups and set(followups) <= cast_ports
    # One full wait for the silent host; the extra-port round and the
    # follow-up end as soon as the Nest Mini has answered.
    assert elapsed < 1.0


def test_mdns_extra_ports_are_one_round_for_hosts_without_a_model_service():
    # A host listing only services that carry no model (an Avahi box with
    # SSH, say) is asked once more from every extra port, all at once, then
    # left alone.
    with FakeMDNS("127.0.0.2", hostname="box.local",
                  services={"_ssh._tcp": ("box", {})}) as box:
        start = time.monotonic()
        found = devices.mdns_probe(["127.0.0.2"], timeout=0.5, port=box.port)
        elapsed = time.monotonic() - start
    assert found == {"127.0.0.2": {"hostname": "box.local", "model": None, "name": None}}
    service_lists = [q for q in box.queries if q[0] == "_services._dns-sd._udp.local"]
    assert len(service_lists) == 1 + devices._MDNS_EXTRA_PORTS
    assert len({port for _, port in service_lists}) == 1 + devices._MDNS_EXTRA_PORTS
    assert elapsed < 0.5, "every query was answered; no round waits for the timeout"


def test_unanswered_queries_are_sent_again_halfway():
    # The device misses the first copy of every query, the service list and
    # the follow-up alike; the second copy, sent halfway, gets through.
    with FakeMDNS("127.0.0.2", drop_first=True, hostname="cast.local",
                  services={"_googlecast._tcp": ("Kitchen", {"md": "Chromecast"})}) as cast:
        found = devices.mdns_probe(["127.0.0.2"], timeout=0.6, port=cast.port)
    # Without the resend nothing would be answered at all.
    assert found == {"127.0.0.2": {"hostname": "cast.local", "model": "Chromecast",
                                   "name": "Kitchen"}}
    resent = [q for q in cast.queries if q[0] == "_googlecast._tcp.local"]
    assert len(resent) == 2 and resent[0] == resent[1], "same query, same socket, twice"


def test_hosts_with_a_model_service_get_no_extra_ports():
    with FakeMDNS("127.0.0.2", hostname="cast.local",
                  services={"_googlecast._tcp": ("cast", {"md": "Chromecast"})}) as cast:
        found = devices.mdns_probe(["127.0.0.2"], timeout=0.5, port=cast.port)
    assert found["127.0.0.2"]["model"] == "Chromecast"
    assert len({port for _, port in cast.queries}) == 1


def test_extra_reply_packets_do_not_end_the_wait_early():
    # The fast host sends every reply twice at once; the slow one answers
    # once, later. Counting packets would stop before the slow host answers.
    with FakeMDNS("127.0.0.2", copies=2, hostname="fast.local",
                  services={"_googlecast._tcp": ("fast", {"md": "Fast"})}) as fast, \
         FakeMDNS("127.0.0.3", port=fast.port, delay=0.2, hostname="slow.local",
                  services={"_googlecast._tcp": ("slow", {"md": "Slow"})}):
        found = devices.mdns_probe(["127.0.0.2", "127.0.0.3"], timeout=1.0, port=fast.port)
    assert found["127.0.0.3"]["model"] == "Slow"


def test_mdns_probe_with_no_answers_is_empty():
    with FakeMDNS("127.0.0.2") as quiet:
        assert devices.mdns_probe(["127.0.0.2"], timeout=0.3, port=quiet.port) == {}
    assert devices.mdns_probe([]) == {}


def _absorbed(*replies) -> dict:
    hints = devices._Hints()
    for reply in replies:
        hints.absorb(reply)
    return hints.summary()


def _answer_for(qname: str, answers, additional=()):
    return _mdns_reply(devices._build_query(qname, 12, 1, flags=0), answers, additional)


def test_mdns_model_priority_and_raop_names():
    raop = ["5C1A2B3C4D5E@Kitchen", "_raop", "_tcp", "local"]
    info = ["Kitchen", "_device-info", "_tcp", "local"]
    summary = _absorbed(
        _answer_for("_raop._tcp.local", [_rr("_raop._tcp.local", 12, _name(raop))],
                    [_rr(raop, 16, _txt(am="AudioAccessory5,1")),
                     _rr(info, 16, _txt(model="AudioAccessory6,1"))]))
    # _device-info is trusted over _raop; the MAC prefix is cut from the name.
    assert summary == {"hostname": None, "model": "AudioAccessory6,1", "name": "Kitchen"}


def test_mdns_hostile_text_is_cleaned_or_dropped():
    instance = ["Evil\x1b[2J", "_googlecast", "_tcp", "local"]
    summary = _absorbed(
        _answer_for("_googlecast._tcp.local",
                    [_rr("_googlecast._tcp.local", 12, _name(instance))],
                    [_rr(instance, 16, _txt(md="Cast\x07er", fn="\x1b"))]),
        _answer_for("1.0.0.127.in-addr.arpa",
                    [_rr("1.0.0.127.in-addr.arpa", 12, _name(["bad host", "local"]))]))
    assert summary == {"hostname": None, "model": "Caster", "name": "Evil[2J"}


def test_mdns_ignores_queries_and_garbage():
    hints = devices._Hints()
    assert not hints.absorb(b"\xff" * 30)
    assert not hints.absorb(devices._build_query("_services._dns-sd._udp.local", 12, 1, flags=0))
    assert hints.summary() == {"hostname": None, "model": None, "name": None}


# ── Sentinel integration ───────────────────────────────────────────

def _patch_probes(monkeypatch, router=None, mdns=None, ssdp=None, cast=None,
                  gateway="192.0.2.1"):
    calls = {}

    def probe(name, result):
        def run(*args):
            calls[name] = args
            if isinstance(result, Exception):
                raise result
            return result or {}
        return run

    monkeypatch.setattr(sentinel, "get_default_gateway", lambda _ip: gateway)
    monkeypatch.setattr(sentinel, "reverse_lookup", probe("router", router))
    monkeypatch.setattr(sentinel, "mdns_probe", probe("mdns", mdns))
    monkeypatch.setattr(sentinel, "ssdp_probe", probe("ssdp", ssdp))
    monkeypatch.setattr(sentinel, "cast_probe", probe("cast", cast))
    return calls


def test_identify_merges_sources_by_priority(monkeypatch):
    calls = _patch_probes(
        monkeypatch,
        router={"192.0.2.6": "pixel.lan"},
        mdns={"192.0.2.5": {"hostname": "nas.local", "model": "DS220+", "name": None},
              "192.0.2.6": {"hostname": "Pixel.local", "model": None, "name": None},
              "192.0.2.7": {"hostname": None, "model": "Chromecast", "name": "Living Room"}},
        ssdp={"192.0.2.7": {"model": "Google Eureka", "name": "Cast"},
              "192.0.2.8": {"model": "TP-Link Archer C6", "name": "Archer C6"}},
        cast={"192.0.2.7": {"model": "Google Inc. Chromecast", "name": "Cast DIAL"},
              "192.0.2.8": {"model": "Cast model", "name": "Cast name"},
              "192.0.2.9": {"model": "onn. Full HD Streaming Device", "name": "Family Room TV"}},
    )
    ips = ("192.0.2.5", "192.0.2.6", "192.0.2.7", "192.0.2.8", "192.0.2.9", "192.0.2.11")
    metadata = {ip: {"hostname": None, "mac": None, "vendor": None} for ip in ips}
    metadata["192.0.2.5"]["hostname"] = "nas.lan"
    sentinel.identify_devices(metadata, "192.0.2.10")

    assert calls["router"] == (list(ips[1:]), "192.0.2.1")
    assert calls["ssdp"][0] == "192.0.2.10"
    assert calls["cast"] == (list(ips),)
    got = {ip: (meta["hostname"], meta["model"]) for ip, meta in metadata.items()}
    assert got == {
        "192.0.2.5":  ("nas.lan", "DS220+"),             # nmap's name kept
        "192.0.2.6":  ("pixel.lan", None),               # router beats mDNS
        "192.0.2.7":  ("Living Room", "Chromecast"),     # mDNS beats UPnP and Cast
        "192.0.2.8":  ("Archer C6", "TP-Link Archer C6"),  # UPnP beats Cast
        "192.0.2.9":  ("Family Room TV", "onn. Full HD Streaming Device"),  # Cast alone
        "192.0.2.11": (None, None),
    }


def test_identify_survives_a_failing_probe(monkeypatch):
    _patch_probes(monkeypatch, router=OSError("boom"), mdns=RuntimeError("mdns failed"),
                  ssdp={"192.0.2.5": {"model": "Router", "name": None}})
    metadata = {"192.0.2.5": {"hostname": None}}
    sentinel.identify_devices(metadata, "192.0.2.10")
    assert metadata["192.0.2.5"] == {"hostname": None, "model": "Router"}


def test_identify_skips_router_lookup_when_not_needed(monkeypatch):
    calls = _patch_probes(monkeypatch, gateway=None)
    sentinel.identify_devices({"192.0.2.5": {"hostname": None}}, "192.0.2.10")
    assert "router" not in calls
    monkeypatch.setattr(sentinel, "get_default_gateway", lambda _ip: pytest.fail("gateway read"))
    sentinel.identify_devices({"192.0.2.5": {"hostname": "nas.lan"}}, "192.0.2.10")
    sentinel.identify_devices({}, "192.0.2.10")


def test_model_wins_the_device_column(monkeypatch):
    text = _table_text(monkeypatch, {
        "192.0.2.5": {"mac": "DA:A1:19:00:00:01", "vendor": None, "model": "iPhone15,2"},
        "192.0.2.6": {"mac": "00:1A:2B:3C:4D:5E", "vendor": "Apple", "model": "Mac[/x]"},
    })
    assert "iPhone15,2" in text and "Mac[/x]" in text
    assert "Randomized MAC" not in text and "Apple" not in text
