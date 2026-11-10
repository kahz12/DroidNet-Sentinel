"""
Notification hub for DroidNet Sentinel.

Provides a single send_alert() entry point that fires both a local
OS notification and a Telegram alert message in one call.

Telegram credentials are read from droidnet.config (which itself
reads from environment variables). If the token is still the
placeholder value the Telegram call is silently skipped.
"""

import html
import re
from urllib.parse import quote

import requests
from rich import print as rprint

from droidnet.config import TELEGRAM_TOKEN, TELEGRAM_CHAT_ID
from droidnet.core.logger import get_logger
from droidnet.core.markup import esc
from droidnet.platform.utils import send_notification as _send_local

log = get_logger(__name__)

# requests puts the full request URL — "/bot<token>/sendMessage" — in its
# exception messages. Any such path is redacted, whatever token it holds.
_BOT_PATH = re.compile(r"/bot[^/\s'\"]+")


def _redact_token(text: str) -> str:
    """Remove the bot token from *text*: raw, percent-encoded or in a URL."""
    if TELEGRAM_TOKEN:
        for form in {TELEGRAM_TOKEN, quote(TELEGRAM_TOKEN, safe="")}:
            text = text.replace(form, "<redacted>")
    return _BOT_PATH.sub("/bot<redacted>", text)


# Messages use Telegram's HTML parse mode. Legacy Markdown cannot escape
# inside an entity ("Escaping inside entities is not allowed", Bot API
# docs), so a "_" in an italic line or a "`" in an SSID inside `code` makes
# Telegram reject the whole message. In HTML only <, > and & need escaping,
# and the escape works inside every tag.

def escape_html(text) -> str:
    """
    Escape *text* for a Telegram HTML-mode message.

    Use on every user/network-controlled value (SSIDs, banners, NVD text)
    before interpolating it into a message. Truncate *before* escaping,
    never after, or an entity such as "&amp;" can be cut in half.
    """
    if text is None:
        return ""
    return html.escape(str(text), quote=False)


def send_local(title: str, message: str) -> None:
    """Fire a local OS notification (Termux / libnotify)."""
    _send_local(title, message)


def send_telegram(message: str) -> bool | None:
    """
    Post the HTML-formatted *message* to the configured Telegram chat.

    Returns True when Telegram accepted it, False when delivery failed
    (network error or rejection — reported, never raised, so the scan loop
    keeps running), and None when Telegram is not configured.
    """
    if (
        not TELEGRAM_TOKEN
        or not TELEGRAM_CHAT_ID
        or TELEGRAM_TOKEN == "TOKEN_DE_BOTFATHER"
        or TELEGRAM_CHAT_ID == "ID_NUMERICO"
    ):
        return None

    url     = f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage"
    payload = {
        "chat_id":    TELEGRAM_CHAT_ID,
        "text":       message,
        "parse_mode": "HTML",
    }
    try:
        resp = requests.post(url, json=payload, timeout=5)
    except Exception as exc:
        # Never print str(exc) raw: it carries the token (see _BOT_PATH)
        # and can contain "[...]" that Rich would parse as markup.
        reason = _redact_token(str(exc))
        rprint(f"[dim][-] Telegram delivery failed: {esc(reason)}[/dim]")
        log.warning("telegram delivery failed: %s", reason)
        return False

    if resp.ok:
        return True
    # Telegram answers 200/ok=true on success and 4xx on a rejected message
    # (unparseable entities, wrong chat, revoked token), explaining why in
    # "description". Surface that reason so a dropped alert is never silent.
    try:
        description = resp.json().get("description", "")
    except (ValueError, AttributeError):
        description = ""
    reason = _redact_token(str(description)) or "no description"
    rprint(f"[yellow][-] Telegram rejected the message (HTTP {resp.status_code}): "
           f"{esc(reason)}[/yellow]")
    log.warning("telegram rejected message status=%s reason=%s", resp.status_code, reason)
    return False


def send_alert(title: str, local_msg: str, telegram_msg: str) -> bool | None:
    """
    Convenience wrapper: fire both a local notification and a Telegram message.

    Args:
        title        : Title for the local OS notification.
        local_msg    : Body for the local OS notification.
        telegram_msg : HTML-formatted text for the Telegram channel; escape
                       interpolated values with escape_html().

    Returns the Telegram outcome (see send_telegram).
    """
    send_local(title, local_msg)
    return send_telegram(telegram_msg)
