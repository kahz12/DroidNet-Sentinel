"""
Centralised configuration for DroidNet Sentinel.

All paths are resolved relative to the project root (the directory
that contains the droidnet/ package), so the toolkit works regardless
of the current working directory when main.py is launched.

Telegram credentials are read from environment variables so they never
need to be hard-coded. Set them once in ~/.bashrc or ~/.zshrc:
    export TELEGRAM_TOKEN="..."
    export TELEGRAM_CHAT_ID="..."
"""

import os
import json
import ipaddress
from pathlib import Path

# ── Project root ──────────────────────────────────────────────────
# config.py lives at  <root>/droidnet/config.py
# .parent       →     <root>/droidnet/
# .parent.parent →    <root>/
BASE_DIR      = Path(__file__).resolve().parent.parent
REPORTS_DIR   = BASE_DIR / "reports"
CONFIG_FILE   = BASE_DIR / "config.json"
DB_PATH       = BASE_DIR / "sentinel.db"
NVD_CACHE_DIR = BASE_DIR / "nvd_cache"

# ── Daemon tuning ─────────────────────────────────────────────────
CHECK_INTERVAL = 300  # seconds between daemon scan cycles
RESCAN_HOURS   = 6    # hours before re-scanning the same network

# ── Telegram C2 ───────────────────────────────────────────────────
# Reads from env vars; falls back to placeholder strings that the
# notifier module treats as "not configured" → silent no-op.
TELEGRAM_TOKEN   = os.environ.get("TELEGRAM_TOKEN",   "TOKEN_DE_BOTFATHER")
TELEGRAM_CHAT_ID = os.environ.get("TELEGRAM_CHAT_ID", "ID_NUMERICO")


_CONFIG_SCHEMA: dict = {
    # key                 (type,  element_type or None for non-list, default)
    "excluded_ips":       (list,  str,  []),
    "trusted_ips":        (list,  str,  []),
    "db_retention_days":  (int,   None, 90),
}


# Schema keys whose list entries must be valid IP addresses or CIDR ranges.
_IP_LIST_KEYS = frozenset({"excluded_ips", "trusted_ips"})


def _is_ip_or_cidr(value: str) -> bool:
    """True if *value* parses as an IPv4/IPv6 address or CIDR network."""
    try:
        ipaddress.ip_network(value, strict=False)
        return True
    except ValueError:
        return False


def _fresh_default(default):
    """
    Return a copy of *default* so callers never share mutable schema state.

    The schema holds a single ``[]`` per list field; lists are copied per call
    so each returned config gets its own, while scalars pass through unchanged.
    """
    return list(default) if isinstance(default, list) else default


def _validate_config(raw: dict) -> dict:
    """
    Coerce *raw* (parsed JSON) to the declared _CONFIG_SCHEMA.

    Drops bad keys/elements, fills missing keys with defaults, prints one
    warning per problem so the user can fix config.json.
    Returns a new dict — never raises.
    """
    if not isinstance(raw, dict):
        print(f"[!] config.json: top-level is not a JSON object ({type(raw).__name__}); using defaults.")
        return {key: _fresh_default(default) for key, (_, _, default) in _CONFIG_SCHEMA.items()}

    out: dict = {}
    for key, (expected_type, elem_type, default) in _CONFIG_SCHEMA.items():
        if key not in raw:
            out[key] = _fresh_default(default)
            continue
        value = raw[key]
        if not isinstance(value, expected_type) or isinstance(value, bool):
            # bool is a subclass of int, reject it explicitly for int fields.
            print(f"[!] config.json['{key}']: invalid type "
                  f"({type(value).__name__}, expected {expected_type.__name__}); using default.")
            out[key] = _fresh_default(default)
            continue
        if elem_type is not None:  # list with element type
            cleaned = [v for v in value if isinstance(v, elem_type)]
            if len(cleaned) != len(value):
                bad = len(value) - len(cleaned)
                print(f"[!] config.json['{key}']: discarding {bad} non-{elem_type.__name__} entry(ies).")
            if key in _IP_LIST_KEYS:
                valid = [v for v in cleaned if _is_ip_or_cidr(v)]
                if len(valid) != len(cleaned):
                    bad = len(cleaned) - len(valid)
                    print(f"[!] config.json['{key}']: discarding {bad} invalid IP/CIDR entry(ies).")
                cleaned = valid
            out[key] = cleaned
        else:
            out[key] = value

    extra = set(raw) - set(_CONFIG_SCHEMA)
    if extra:
        print(f"[!] config.json: unrecognised keys {sorted(extra)} (ignored).")
    return out


def load_user_config() -> dict:
    """
    Load and validate config.json from the project root.

    Expected format:
        {
            "excluded_ips":      ["192.168.1.100"],
            "trusted_ips":       ["192.168.1.1", "192.168.1.50"],
            "db_retention_days": 90
        }

    Returns:
        dict: Validated config (always with all schema keys), or defaults
        if the file is missing/corrupt.
    """
    defaults = {key: _fresh_default(default) for key, (_, _, default) in _CONFIG_SCHEMA.items()}
    if not CONFIG_FILE.exists():
        return defaults
    try:
        with CONFIG_FILE.open() as fh:
            raw = json.load(fh)
    except (json.JSONDecodeError, OSError) as exc:
        # A corrupt config.json should not break all scans.
        print(f"[!] config.json invalid ({exc}); using defaults.")
        return defaults
    return _validate_config(raw)
