"""
UPnP device descriptions: found with SSDP, or at Google Cast's fixed path.

    ssdp_probe(my_ip, ips) → {ip: {"model", "name"}}
    cast_probe(ips)        → {ip: {"model", "name"}}

One multicast M-SEARCH goes out and devices answer by unicast, so neither
root nor Android's multicast filter gets in the way. Each answer points at an
XML description served by the device itself, which names its maker, model
and the name its owner gave it. Routers, smart TVs, media servers and
speakers usually answer; phones usually do not.

Google Cast devices serve the same kind of description at a fixed URL, which
identifies them even when they answer neither SSDP nor mDNS.
"""

import ipaddress
import re
import socket
import time
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlsplit

from droidnet.core.devices import clean_text

SSDP_GROUP = ("239.255.255.250", 1900)

_SEARCH = (
    "M-SEARCH * HTTP/1.1\r\n"
    "HOST: 239.255.255.250:1900\r\n"
    'MAN: "ssdp:discover"\r\n'
    "MX: 1\r\n"
    "ST: upnp:rootdevice\r\n"
    "\r\n"
).encode("ascii")

_MAX_REPLY      = 64 * 1024     # a device description is a few KiB
_FETCH_TIMEOUT  = 2.0
_FETCH_WORKERS  = 8
_SAFE_PATH      = re.compile(r"/[\x21-\x7e]*")    # printable ASCII, no spaces

# Google Cast devices (Chromecast, Google TV, Nest speakers and displays, TVs
# with Cast built in) serve a DIAL description at this path on port 8008.
# Some of them ignore both mDNS and SSDP from other LAN clients, yet still
# serve this file. Every scanned host is asked at once: a host without the
# port refuses the connection immediately, and one that drops it costs the
# timeout, in parallel with the rest.
_CAST_PORT        = 8008
_CAST_DESCRIPTION = "/ssdp/device-desc.xml"
_CAST_TIMEOUT     = 1.5
_CAST_WORKERS     = 32


def _location(data: bytes) -> str | None:
    """The LOCATION header of a successful M-SEARCH reply, or None."""
    lines = data.decode("latin-1").splitlines()
    status = lines[0].split() if lines else []
    if len(status) < 2 or not status[0].upper().startswith("HTTP/") or status[1] != "200":
        return None
    for line in lines[1:]:
        key, sep, value = line.partition(":")
        if sep and key.strip().lower() == "location":
            return value.strip() or None
    return None


def _search(my_ip: str, targets: set[str], timeout: float,
            group: tuple[str, int] = SSDP_GROUP) -> dict[str, str]:
    """Send the M-SEARCH and return {ip: LOCATION} for replies from *targets*."""
    locations: dict[str, str] = {}
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    except OSError:
        return locations
    with sock:
        try:
            # Leave through the scanned network, not through a VPN's route.
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(my_ip))
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
        except OSError:
            pass
        try:
            # Wi-Fi sends multicast without retries, so ask twice.
            for _ in range(2):
                sock.sendto(_SEARCH, group)
        except OSError:
            return locations
        deadline = time.monotonic() + timeout
        while len(locations) < len(targets):
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            sock.settimeout(remaining)
            try:
                data, (source, _) = sock.recvfrom(4096)
            except socket.timeout:
                break
            except OSError:
                continue
            if source in targets and source not in locations:
                location = _location(data)
                if location:
                    locations[source] = location
    return locations


def _framing(head: bytes) -> tuple[int | None, bool]:
    """(Content-Length or None, whether the body is chunked) from response headers."""
    length, chunked = None, False
    for line in head.split(b"\r\n")[1:]:
        name, _, value = line.partition(b":")
        name = name.strip().lower()
        if name == b"content-length" and value.strip().isdigit():
            length = int(value.strip())
        elif name == b"transfer-encoding" and b"chunked" in value.lower():
            chunked = True
    return length, chunked


def _reply_complete(reply: bytes) -> bool:
    """True once *reply* holds a whole response by its own framing.

    A reply without Content-Length or chunking ends when the server closes
    the connection, which the read loop sees as EOF.
    """
    head, sep, body = reply.partition(b"\r\n\r\n")
    if not sep:
        return False
    length, chunked = _framing(head)
    if chunked:
        return body.endswith(b"0\r\n\r\n")           # last chunk, no trailers
    return length is not None and len(body) >= length


def _dechunk(body: bytes) -> bytes | None:
    """Decode a chunked body (RFC 9112 §7.1), or None if it is malformed or cut short."""
    out = bytearray()
    pos = 0
    while True:
        end = body.find(b"\r\n", pos)
        if end < 0:
            return None
        size_field = body[pos:end].split(b";", 1)[0].strip()
        try:
            size = int(size_field, 16)
        except ValueError:
            return None
        pos = end + 2
        if size == 0:
            return bytes(out)
        if size < 0 or pos + size > len(body):
            return None
        out += body[pos:pos + size]
        pos += size + 2                                # chunk data, then CRLF


def _fetch(ip: str, port: int, path: str, timeout: float) -> bytes | None:
    """GET http://ip:port/path within *timeout* seconds in total; the body or None.

    The request is HTTP/1.1 because some devices refuse HTTP/1.0 outright
    (a Google TV closed the connection without a reply). It asks the server
    to close the connection, but devices do not always do so (the same
    Google TV kept it open), so the read ends as soon as the body is
    complete by Content-Length or by its last chunk, not only at EOF.
    Nothing is followed: no redirects, no proxy, no compression. Replies
    over 64 KiB are dropped.
    """
    deadline = time.monotonic() + timeout
    request = (f"GET {path} HTTP/1.1\r\nHost: {ip}:{port}\r\n"
               "Accept-Encoding: identity\r\nConnection: close\r\n\r\n").encode("ascii")
    reply = bytearray()
    try:
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            sock.sendall(request)
            while not _reply_complete(reply):
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return None
                sock.settimeout(remaining)
                chunk = sock.recv(8192)
                if not chunk:
                    break
                reply += chunk
                if len(reply) > _MAX_REPLY:
                    return None
    except OSError:
        return None
    head, sep, body = bytes(reply).partition(b"\r\n\r\n")
    status = head.split(b"\r\n", 1)[0].split()
    if not sep or len(status) < 2 or status[1] != b"200":
        return None
    length, chunked = _framing(head)
    if chunked:
        return _dechunk(body)
    if length is not None:
        return body[:length] if len(body) >= length else None   # cut short
    return body


def _join_maker(maker: str | None, model: str | None) -> str | None:
    """"TP-Link" + "Archer C6" → "TP-Link Archer C6"; "Sonos, Inc." + "Sonos One" → "Sonos One"."""
    if not model or not maker:
        return model or maker
    brand = maker.split()[0].strip(",.").lower()
    return model if brand in model.lower() else clean_text(f"{maker} {model}")


def _parse_description(body: bytes) -> dict[str, str | None]:
    """Maker, model and friendly name from a UPnP device description."""
    # Descriptions never need a DTD; refusing one rules out entity expansion.
    if b"<!DOCTYPE" in body or b"<!ENTITY" in body:
        return {}
    try:
        root = ET.fromstring(body)
    except ET.ParseError:
        return {}
    device = root.find("{*}device")
    if device is None:
        return {}
    maker = clean_text(device.findtext("{*}manufacturer"))
    model = clean_text(device.findtext("{*}modelName"))
    return {"model": _join_maker(maker, model),
            "name":  clean_text(device.findtext("{*}friendlyName"))}


def _describe(location: str, ip: str, timeout: float) -> dict[str, str | None]:
    """Fetch and parse the description at *location*, if it lives on *ip*.

    The URL comes from the device, so only plain http to the address that
    answered is fetched: never another host, this machine, or a TLS URL.
    """
    try:
        parts = urlsplit(location)
        same_host = (parts.scheme == "http"
                     and ipaddress.ip_address(parts.hostname or "") == ipaddress.ip_address(ip))
        port = parts.port or 80
    except ValueError:
        return {}
    path = (parts.path or "/") + (f"?{parts.query}" if parts.query else "")
    if not same_host or parts.username or parts.password or not _SAFE_PATH.fullmatch(path):
        return {}
    body = _fetch(ip, port, path, timeout)
    return _parse_description(body) if body else {}


def ssdp_probe(my_ip: str, ips: list[str], timeout: float = 1.5,
               group: tuple[str, int] = SSDP_GROUP) -> dict[str, dict[str, str | None]]:
    """Find UPnP devices among *ips* and read their descriptions.

    Returns {ip: {"model", "name"}} for devices whose description named a
    maker, model or friendly name. The search waits *timeout* seconds and
    each description gets two more.
    """
    locations = _search(my_ip, set(ips), timeout, group)
    if not locations:
        return {}
    found = {}
    with ThreadPoolExecutor(max_workers=min(_FETCH_WORKERS, len(locations))) as pool:
        futures = {ip: pool.submit(_describe, location, ip, _FETCH_TIMEOUT)
                   for ip, location in locations.items()}
        for ip, future in futures.items():
            info = future.result()
            if any(info.values()):
                found[ip] = info
    return found


def _cast_description(ip: str, port: int, timeout: float) -> dict[str, str | None]:
    body = _fetch(ip, port, _CAST_DESCRIPTION, timeout)
    return _parse_description(body) if body else {}


def cast_probe(ips: list[str], timeout: float = _CAST_TIMEOUT,
               port: int = _CAST_PORT) -> dict[str, dict[str, str | None]]:
    """Read the Google Cast description of each host in *ips* that serves one.

    Returns {ip: {"model", "name"}}, e.g. {"model": "onn. Full HD Streaming
    Device", "name": "Living Room TV"}. Each host gets *timeout* seconds in
    total; hosts are asked in parallel, so a typical LAN costs one timeout
    at most.
    """
    if not ips:
        return {}
    found = {}
    with ThreadPoolExecutor(max_workers=min(_CAST_WORKERS, len(ips))) as pool:
        futures = {ip: pool.submit(_cast_description, ip, port, timeout) for ip in ips}
        for ip, future in futures.items():
            info = future.result()
            if any(info.values()):
                found[ip] = info
    return found
