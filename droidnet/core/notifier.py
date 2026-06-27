"""
Notification hub for DroidNet Sentinel.

Provides a single send_alert() entry point that fires both a local
OS notification and a Telegram C2 message in one call.

Telegram credentials are read from droidnet.config (which itself
reads from environment variables). If the token is still the
placeholder value the Telegram call is silently skipped.
"""

import re

import requests
from rich import print as rprint

from droidnet.config import TELEGRAM_TOKEN, TELEGRAM_CHAT_ID
from droidnet.platform.utils import send_notification as _send_local


# Telegram "Markdown" (legacy) parse_mode treats these as formatting:
#   _italic_   *bold*   `code`   [link](url)
# An attacker-controlled SSID like "My_Cafe*" would either break the
# message ("entity at byte X") or inject formatting. Apply this escape
# at the boundary to any value that originates from user/network input.
_TG_MD_SPECIAL = re.compile(r"([_*`\[\]])")


def escape_markdown(text: str) -> str:
    """
    Escape Telegram Markdown (legacy) metacharacters in *text*.

    Use on user/network-controlled values (SSIDs, banners, network names)
    before interpolating them into a Markdown-mode Telegram message.
    """
    if not text:
        return ""
    return _TG_MD_SPECIAL.sub(r"\\\1", text)


def send_local(title: str, message: str) -> None:
    """Fire a local OS notification (Termux / libnotify)."""
    _send_local(title, message)


def send_telegram(message: str) -> None:
    """
    Post *message* to the configured Telegram bot channel.

    No-op when TELEGRAM_TOKEN is the placeholder string.
    Fails silently on network errors to avoid blocking the scan loop.
    """
    if (
        not TELEGRAM_TOKEN
        or not TELEGRAM_CHAT_ID
        or TELEGRAM_TOKEN == "TOKEN_DE_BOTFATHER"
        or TELEGRAM_CHAT_ID == "ID_NUMERICO"
    ):
        return

    url     = f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage"
    payload = {
        "chat_id":    TELEGRAM_CHAT_ID,
        "text":       message,
        "parse_mode": "Markdown",
    }
    try:
        requests.post(url, json=payload, timeout=5)
    except Exception as exc:
        rprint(f"[dim][-] Telegram delivery failed: {exc}[/dim]")


def send_alert(title: str, local_msg: str, telegram_msg: str) -> None:
    """
    Convenience wrapper: fire both a local notification and a Telegram message.

    Args:
        title        : Title for the local OS notification.
        local_msg    : Body for the local OS notification.
        telegram_msg : Markdown-formatted text for the Telegram channel.
    """
    send_local(title, local_msg)
    send_telegram(telegram_msg)
