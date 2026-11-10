"""
Single source of truth for host risk classification.

A host's risk is derived from the set of its open TCP ports:

    CRITICAL → at least one port in _CRITICAL  (FTP/Telnet/SMB/RDP)
    MEDIUM   → at least one port in _MEDIUM   (HTTP/DNS/SSDP/NFS)
    LOW      → has open ports but none of the above
    MINIMAL  → no open ports (closed host)
    UNKNOWN  → failed or inconclusive scan

Both modules.sentinel.evaluate_risk (Rich-decorated) and
core.database.save_scan / get_*_with_diffs build on top of
classify_risk(); changes here propagate everywhere.

It is also the single place that tells port lines from markers
(is_port_line / is_scan_error), for every module that reads scan results.
"""

import re

# Frozensets so callers cannot mutate the canonical sets by accident.
_CRITICAL: frozenset[str] = frozenset({
    "21/tcp",   # FTP
    "23/tcp",   # Telnet
    "445/tcp",  # SMB over TCP
    "139/tcp",  # NetBIOS Session Service
    "3389/tcp", # RDP
})

_MEDIUM: frozenset[str] = frozenset({
    "80/tcp",   # HTTP
    "8080/tcp", # HTTP alt
    "53/tcp",   # DNS over TCP
    "1900/tcp", # SSDP
    "2049/tcp", # NFS
    "1883/tcp", # MQTT (often unauthenticated)
    "8883/tcp", # MQTT over TLS
    "5683/tcp", # CoAP
})

_CLOSED_MARKER = "Shield intact"

# deep_scan writes either port lines ("80/tcp open http nginx 1.18.0") or a
# marker in their place: _CLOSED_MARKER when nothing is exposed, "Error" or
# "Error: <why>" when the host could not be assessed. A port line's banner is
# free text and can itself contain those words ("Apache httpd (Error page)"),
# so markers are told apart by their exact form, never by searching a word.
_PORT_LINE = re.compile(r"\d+/(?:tcp|udp)\s+open\b")


def is_port_line(entry) -> bool:
    """True for an open-port line such as "80/tcp open http nginx 1.18.0"."""
    return isinstance(entry, str) and bool(_PORT_LINE.match(entry))


def is_scan_error(entry) -> bool:
    """True for the markers of a host that could not be assessed."""
    return isinstance(entry, str) and (entry == "Error" or entry.startswith("Error:"))


def classify_risk(ports: list[str]) -> str:
    """
    Plain-text risk label for a host based on its open ports.

    *ports* is the list returned by sentinel.deep_scan: each entry is a
    string like "80/tcp open http nginx 1.18.0". Only the first whitespace
    token (the port id) is consulted.

    Possible return values: MINIMAL / LOW / MEDIUM / CRITICAL / UNKNOWN.
    """
    if not ports or ports == [_CLOSED_MARKER]:
        return "MINIMAL"
    if any(is_scan_error(entry) for entry in ports):
        return "UNKNOWN"

    level = "LOW"
    for entry in ports:
        # Defensive: an empty string would IndexError on .split()[0].
        tokens = entry.split(None, 1)
        head = tokens[0] if tokens else ""
        if head in _CRITICAL:
            return "CRITICAL"
        if head in _MEDIUM:
            level = "MEDIUM"
    return level


__all__ = ["classify_risk", "is_port_line", "is_scan_error"]
