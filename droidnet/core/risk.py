"""
Single source of truth for host risk classification.

A host's risk is derived from the set of its open TCP ports:

    CRITICAL → at least one port in _CRITICAL  (FTP/Telnet/SMB/RDP)
    MEDIUM   → at least one port in _MEDIUM   (HTTP/DNS/SSDP/NFS)
    LOW      → has open ports but none of the above
    MINIMAL  → no open ports (closed host)

Both modules.sentinel.evaluate_risk (Rich-decorated) and
core.database.save_scan / get_*_with_diffs build on top of
classify_risk(); changes here propagate everywhere.
"""

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


def classify_risk(ports: list[str]) -> str:
    """
    Plain-text risk label for a host based on its open ports.

    *ports* is the list returned by sentinel.deep_scan: each entry is a
    string like "80/tcp open http nginx 1.18.0". Only the first whitespace
    token (the port id) is consulted.

    Possible return values: MINIMAL / LOW / MEDIUM / CRITICAL.
    """
    if not ports or ports == [_CLOSED_MARKER]:
        return "MINIMAL"

    level = "LOW"
    for entry in ports:
        # Defensive: an empty string would IndexError on .split()[0].
        head = entry.split(None, 1)[0] if entry else ""
        if head in _CRITICAL:
            return "CRITICAL"
        if head in _MEDIUM:
            level = "MEDIUM"
    return level


__all__ = ["classify_risk"]
