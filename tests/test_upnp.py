"""UPnP descriptions found with SSDP.

Network tests use fake responders on 127.0.0.1; nothing leaves the machine.
"""
import socket
import threading
import time

import pytest

from droidnet.core import upnp

DESCRIPTION = b"""<?xml version="1.0"?>
<root xmlns="urn:schemas-upnp-org:device-1-0">
  <specVersion><major>1</major><minor>0</minor></specVersion>
  <device>
    <deviceType>urn:schemas-upnp-org:device:InternetGatewayDevice:1</deviceType>
    <friendlyName>Archer C6</friendlyName>
    <manufacturer>TP-Link</manufacturer>
    <modelName>Archer C6</modelName>
    <modelNumber>2.0</modelNumber>
  </device>
</root>"""


# ── M-SEARCH replies ───────────────────────────────────────────────

@pytest.mark.parametrize("reply, expected", [
    (b"HTTP/1.1 200 OK\r\nCACHE-CONTROL: max-age=1800\r\nLOCATION: http://192.0.2.1:1900/igd.xml\r\n\r\n",
     "http://192.0.2.1:1900/igd.xml"),
    (b"HTTP/1.1 200 OK\nLocation:http://192.0.2.1/d.xml\n\n", "http://192.0.2.1/d.xml"),
    (b"HTTP/1.1 404 Not Found\r\nLOCATION: http://192.0.2.1/x\r\n\r\n", None),
    (b"NOTIFY * HTTP/1.1\r\nLOCATION: http://192.0.2.1/x\r\n\r\n", None),
    (b"HTTP/1.1 200 OK\r\nSERVER: x\r\n\r\n", None),
    (b"", None),
])
def test_location_header(reply, expected):
    assert upnp._location(reply) == expected


# ── descriptions ───────────────────────────────────────────────────

def test_description_maker_model_and_name():
    assert upnp._parse_description(DESCRIPTION) == {"model": "TP-Link Archer C6", "name": "Archer C6"}


@pytest.mark.parametrize("maker, model, expected", [
    ("TP-Link",     "Archer C6", "TP-Link Archer C6"),
    ("Sonos, Inc.", "Sonos One", "Sonos One"),
    ("Samsung",     None,        "Samsung"),
    (None,          "UE55RU7100", "UE55RU7100"),
    (None,          None,        None),
])
def test_join_maker(maker, model, expected):
    assert upnp._join_maker(maker, model) == expected


@pytest.mark.parametrize("body", [
    b"not xml",
    b"<root><nodevice/></root>",
    # Entity expansion is refused before parsing.
    b'<?xml version="1.0"?><!DOCTYPE r [<!ENTITY a "aaaa">]><root><device>'
    b"<modelName>&a;</modelName></device></root>",
])
def test_unusable_descriptions(body):
    assert upnp._parse_description(body) == {}


def test_description_text_is_cleaned():
    body = (b"<root><device><manufacturer>Evil\x1b[31m</manufacturer>"
            b"<modelName>   </modelName><friendlyName>a\tb</friendlyName></device></root>")
    # \x1b is not valid XML 1.0 either; the parser refuses it outright.
    assert upnp._parse_description(body) == {}
    body = (b"<root><device><manufacturer>Acme</manufacturer>"
            b"<modelName>   </modelName><friendlyName>a\tb</friendlyName></device></root>")
    assert upnp._parse_description(body) == {"model": "Acme", "name": "a b"}


@pytest.mark.parametrize("location", [
    "https://192.0.2.5/desc.xml",               # TLS: not fetched
    "http://192.0.2.6/desc.xml",                # another host
    "http://127.0.0.1:5000/",                   # this machine (e.g. the dashboard)
    "http://user:pw@192.0.2.5/desc.xml",
    "http://192.0.2.5:99999/desc.xml",          # bad port
    "http://192.0.2.5/a b",                     # space in the path
    "http://192.0.2.5/a\r\nX-Injected: 1",      # header injection
    "http://router.lan/desc.xml",               # a name, not the address
    "file:///etc/passwd",
])
def test_describe_only_fetches_from_the_device_itself(monkeypatch, location):
    monkeypatch.setattr(upnp, "_fetch", lambda *a: pytest.fail(f"fetched {a}"))
    assert upnp._describe(location, "192.0.2.5", 1.0) == {}


def test_describe_builds_the_request(monkeypatch):
    seen = []
    monkeypatch.setattr(upnp, "_fetch", lambda *a: seen.append(a) or DESCRIPTION)
    info = upnp._describe("http://192.0.2.5:49152/desc.xml?v=1", "192.0.2.5", 1.0)
    assert info["model"] == "TP-Link Archer C6"
    assert seen == [("192.0.2.5", 49152, "/desc.xml?v=1", 1.0)]


# ── fake servers ───────────────────────────────────────────────────

class FakeHTTP:
    """One-shot-per-connection HTTP server on loopback with a canned reply.

    Several fake hosts can share one port by binding different loopback
    addresses (127.0.0.1, 127.0.0.2, ...), as real hosts share port 8008.
    """

    def __init__(self, reply: bytes, drip: float = 0.0,
                 address: str = "127.0.0.1", port: int = 0, keep_open: bool = False):
        self.reply, self.drip, self.keep_open = reply, drip, keep_open
        self.requests = []
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((address, port))
        self.sock.listen()
        self.sock.settimeout(0.1)
        self.port = self.sock.getsockname()[1]
        self.stop = threading.Event()
        self.thread = threading.Thread(target=self._serve, daemon=True)

    def _serve(self):
        while not self.stop.is_set():
            try:
                conn, _ = self.sock.accept()
            except OSError:
                continue
            with conn:
                try:
                    self.requests.append(conn.recv(4096))
                    if self.drip:
                        for byte in self.reply:
                            if self.stop.is_set():
                                break
                            conn.sendall(bytes([byte]))
                            time.sleep(self.drip)
                    else:
                        conn.sendall(self.reply)
                    if self.keep_open:
                        # Like the Google TV: ignore "Connection: close".
                        self.stop.wait(5)
                except OSError:
                    pass

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *exc):
        self.stop.set()
        self.thread.join()
        self.sock.close()


def _http(body: bytes, status: bytes = b"200 OK") -> bytes:
    return b"HTTP/1.1 " + status + b"\r\nContent-Type: text/xml\r\n\r\n" + body


def test_fetch_returns_the_body():
    with FakeHTTP(_http(DESCRIPTION)) as server:
        assert upnp._fetch("127.0.0.1", server.port, "/desc.xml", 2.0) == DESCRIPTION
    request = server.requests[0]
    # HTTP/1.1: some devices close an HTTP/1.0 request without a reply.
    assert request.startswith(b"GET /desc.xml HTTP/1.1\r\n")
    assert b"Host: 127.0.0.1:%d\r\n" % server.port in request
    assert b"Connection: close\r\n" in request


def test_fetch_stops_at_content_length_when_the_server_keeps_the_connection():
    reply = (b"HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n" % len(DESCRIPTION)
             + DESCRIPTION)
    with FakeHTTP(reply, keep_open=True) as server:
        start = time.monotonic()
        assert upnp._fetch("127.0.0.1", server.port, "/", 2.0) == DESCRIPTION
        assert time.monotonic() - start < 1.0, "must not wait for the server to close"


def test_fetch_decodes_a_chunked_body():
    half = len(DESCRIPTION) // 2
    chunks = (b"%x\r\n" % half + DESCRIPTION[:half] + b"\r\n"
              + b"%x;ext=1\r\n" % (len(DESCRIPTION) - half) + DESCRIPTION[half:] + b"\r\n"
              + b"0\r\n\r\n")
    reply = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n" + chunks
    with FakeHTTP(reply, keep_open=True) as server:
        start = time.monotonic()
        assert upnp._fetch("127.0.0.1", server.port, "/", 2.0) == DESCRIPTION
        assert time.monotonic() - start < 1.0


@pytest.mark.parametrize("reply", [
    _http(b"gone", b"404 Not Found"),
    b"HTTP/1.1 302 Found\r\nLocation: http://192.0.2.9/\r\n\r\n",
    _http(b"x" * (70 * 1024)),                  # over the size cap
    b"garbage without headers",
    b"",                                        # closed without a reply
    b"HTTP/1.1 200 OK\r\nContent-Length: 50\r\n\r\ncut short",
    b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nzz\r\nbad\r\n0\r\n\r\n",
    b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n40\r\ncut short",
])
def test_fetch_refuses_bad_replies(reply):
    with FakeHTTP(reply) as server:
        assert upnp._fetch("127.0.0.1", server.port, "/", 2.0) is None


def test_fetch_has_a_total_deadline():
    # One byte every 50 ms never times out a single read; the deadline must.
    with FakeHTTP(_http(DESCRIPTION), drip=0.05) as server:
        start = time.monotonic()
        assert upnp._fetch("127.0.0.1", server.port, "/", 0.5) is None
        assert time.monotonic() - start < 1.5


def test_fetch_closed_port():
    probe = socket.socket()
    probe.bind(("127.0.0.1", 0))
    port = probe.getsockname()[1]
    probe.close()
    assert upnp._fetch("127.0.0.1", port, "/", 1.0) is None


class FakeSSDP:
    """Answers any datagram with an M-SEARCH reply pointing at *location*."""

    def __init__(self, location: str):
        self.location = location
        self.searches = []
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.settimeout(0.1)
        self.addr = self.sock.getsockname()
        self.stop = threading.Event()
        self.thread = threading.Thread(target=self._serve, daemon=True)

    def _serve(self):
        while not self.stop.is_set():
            try:
                data, addr = self.sock.recvfrom(2048)
            except OSError:
                continue
            self.searches.append(data)
            self.sock.sendto(b"HTTP/1.1 200 OK\r\nST: upnp:rootdevice\r\n"
                             b"LOCATION: " + self.location.encode() + b"\r\n\r\n", addr)

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *exc):
        self.stop.set()
        self.thread.join()
        self.sock.close()


def test_ssdp_probe_end_to_end():
    with FakeHTTP(_http(DESCRIPTION)) as http, \
         FakeSSDP(f"http://127.0.0.1:{http.port}/desc.xml") as ssdp:
        start = time.monotonic()
        found = upnp.ssdp_probe("127.0.0.1", ["127.0.0.1"], timeout=1.0, group=ssdp.addr)
        elapsed = time.monotonic() - start
    assert found == {"127.0.0.1": {"model": "TP-Link Archer C6", "name": "Archer C6"}}
    assert ssdp.searches[0].startswith(b"M-SEARCH * HTTP/1.1\r\n")
    assert b"ST: upnp:rootdevice" in ssdp.searches[0]
    assert elapsed < 1.0, "every target answered; no need to wait for the deadline"


def test_ssdp_ignores_hosts_outside_the_scan():
    with FakeSSDP("http://127.0.0.1/desc.xml") as ssdp:
        assert upnp.ssdp_probe("127.0.0.1", ["192.0.2.5"], timeout=0.3, group=ssdp.addr) == {}


# ── Google Cast description on port 8008 ───────────────────────────

# The DIAL description a Google TV streaming stick served (names changed).
# That device answered neither mDNS nor SSDP, so this file was the only way
# to identify it.
CAST_DESCRIPTION = b"""<?xml version="1.0"?>
<root xmlns="urn:schemas-upnp-org:device-1-0">
  <specVersion><major>1</major><minor>0</minor></specVersion>
  <URLBase>http://192.0.2.18:8008</URLBase>
  <device>
    <deviceType>urn:dial-multiscreen-org:device:dial:1</deviceType>
    <friendlyName>Living Room TV</friendlyName>
    <manufacturer>onn</manufacturer>
    <modelName>onn. Full HD Streaming Device</modelName>
    <UDN>uuid:00000000-0000-0000-0000-000000000000</UDN>
  </device>
</root>"""


def test_cast_probe_reads_the_dial_description():
    # 127.0.0.1 is a Cast device, 127.0.0.2 serves something else on the
    # same port, and nothing listens on 127.0.0.3.
    with FakeHTTP(_http(CAST_DESCRIPTION)) as cast, \
         FakeHTTP(_http(b"not here", b"404 Not Found"), address="127.0.0.2", port=cast.port):
        start = time.monotonic()
        found = upnp.cast_probe(["127.0.0.1", "127.0.0.2", "127.0.0.3"],
                                timeout=1.0, port=cast.port)
        elapsed = time.monotonic() - start
    assert found == {"127.0.0.1": {"model": "onn. Full HD Streaming Device",
                                   "name": "Living Room TV"}}
    assert cast.requests[0].startswith(b"GET /ssdp/device-desc.xml HTTP/1.1\r\n")
    assert elapsed < 1.0, "a refused connection must not wait for the timeout"


def test_cast_probe_without_hosts_opens_nothing(monkeypatch):
    monkeypatch.setattr(upnp, "_fetch", lambda *a: pytest.fail("fetched"))
    assert upnp.cast_probe([]) == {}
