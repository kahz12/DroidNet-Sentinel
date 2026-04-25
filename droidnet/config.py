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
from pathlib import Path

# ── Project root ──────────────────────────────────────────────────
# config.py lives at  <root>/droidnet/config.py
# .parent       →     <root>/droidnet/
# .parent.parent →    <root>/
BASE_DIR    = Path(__file__).resolve().parent.parent
REPORTS_DIR = BASE_DIR / "reports"
CONFIG_FILE = BASE_DIR / "config.json"
DB_PATH     = BASE_DIR / "sentinel.db"

# ── Daemon tuning ─────────────────────────────────────────────────
CHECK_INTERVAL = 300  # seconds between daemon scan cycles
RESCAN_HOURS   = 6    # hours before re-scanning the same network

# ── Telegram C2 ───────────────────────────────────────────────────
# Reads from env vars; falls back to placeholder strings that the
# notifier module treats as "not configured" → silent no-op.
TELEGRAM_TOKEN   = os.environ.get("TELEGRAM_TOKEN",   "TOKEN_DE_BOTFATHER")
TELEGRAM_CHAT_ID = os.environ.get("TELEGRAM_CHAT_ID", "ID_NUMERICO")


def load_user_config() -> dict:
    """
    Load config.json from the project root.

    Expected format:
        {
            "excluded_ips": ["192.168.1.100"],
            "trusted_ips":  ["192.168.1.1", "192.168.1.50"]
        }

    Returns:
        dict: Parsed config, or safe defaults if the file does not exist.
    """
    defaults: dict = {"excluded_ips": [], "trusted_ips": []}
    if not CONFIG_FILE.exists():
        return defaults
    try:
        with CONFIG_FILE.open() as fh:
            return json.load(fh)
    except (json.JSONDecodeError, OSError) as exc:
        # Un config.json corrupto no debe romper todos los escaneos.
        print(f"[!] config.json inválido ({exc}); usando defaults.")
        return defaults
