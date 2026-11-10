"""Unit tests for Telegram escaping, delivery results and error output."""

import io
from unittest.mock import Mock
from urllib.parse import quote

import pytest
import requests
from rich.console import Console

from droidnet.core import notifier
from droidnet.core.notifier import escape_html


# ── escape_html: Telegram HTML parse mode ───────────────────────────

def test_escape_passthrough_for_plain_text():
    assert escape_html("HomeWiFi") == "HomeWiFi"


def test_escape_leaves_markdown_characters_alone():
    # In HTML parse mode these carry no meaning, so an SSID like "My_Cafe*"
    # needs no escaping and is delivered verbatim.
    assert escape_html("My_Cafe *x* `y` [z]") == "My_Cafe *x* `y` [z]"


def test_escape_html_metacharacters():
    assert escape_html("<b>a & b</b>") == "&lt;b&gt;a &amp; b&lt;/b&gt;"


def test_escape_combined_attack_string():
    # An SSID trying to close a tag, open a link and inject an entity.
    out = escape_html('evil</code><a href="x">&amp;')
    assert "<" not in out and ">" not in out
    # A pre-escaped entity in the input is not trusted: it shows literally.
    assert out.endswith("&amp;amp;")


@pytest.mark.parametrize("value, expected", [("", ""), (None, ""), (42, "42")])
def test_escape_empty_none_and_non_str(value, expected):
    assert escape_html(value) == expected


# ── send_telegram: delivery result and safe error output ────────────

TOKEN = "123456789:AAH-fake_SECRET-token"


def _response(status: int, body: dict) -> Mock:
    resp = Mock(status_code=status, ok=200 <= status < 300)
    resp.json.return_value = body
    return resp


@pytest.fixture
def tg(monkeypatch):
    """Configure a token and record console output; return the post() mock."""
    rec = Console(file=io.StringIO(), record=True, width=400, color_system=None)
    monkeypatch.setattr(notifier, "rprint", rec.print)
    monkeypatch.setattr(notifier, "TELEGRAM_TOKEN", TOKEN)
    monkeypatch.setattr(notifier, "TELEGRAM_CHAT_ID", "42")
    post = Mock(return_value=_response(200, {"ok": True}))
    monkeypatch.setattr(notifier.requests, "post", post)
    post.text_of = rec.export_text
    return post


def test_delivery_uses_html_and_reports_success(tg):
    assert notifier.send_telegram("<b>hi</b>") is True
    assert tg.call_args.kwargs["json"]["parse_mode"] == "HTML"


def test_rejected_message_is_reported_not_silent(tg):
    # Telegram answers HTTP 400 when it cannot parse the message entities.
    tg.return_value = _response(400, {
        "ok": False, "error_code": 400,
        "description": "Bad Request: can't parse entities: Can't find end of "
                       "the entity starting at byte offset 120"})
    assert notifier.send_telegram("x") is False
    text = tg.text_of()
    assert "400" in text and "can't parse entities" in text


def test_unconfigured_telegram_is_skipped(tg, monkeypatch):
    monkeypatch.setattr(notifier, "TELEGRAM_TOKEN", "TOKEN_DE_BOTFATHER")
    assert notifier.send_telegram("x") is None
    tg.assert_not_called()


def test_send_alert_returns_telegram_result(tg, monkeypatch):
    local = Mock()
    monkeypatch.setattr(notifier, "_send_local", local)
    assert notifier.send_alert("t", "local", "tg") is True
    local.assert_called_once_with("t", "local")


def test_connection_error_does_not_print_token(tg):
    # Exact shape of a real requests.ConnectionError: the URL, with the
    # token in its path, is part of the message.
    tg.side_effect = requests.ConnectionError(
        "HTTPSConnectionPool(host='api.telegram.org', port=443): Max retries "
        f"exceeded with url: /bot{TOKEN}/sendMessage (Caused by "
        "NameResolutionError(\"Failed to resolve 'api.telegram.org'\"))")
    assert notifier.send_telegram("hello") is False
    text = tg.text_of()
    assert TOKEN not in text and "SECRET" not in text
    assert "/bot<redacted>/sendMessage" in text
    # The useful diagnosis survives the redaction.
    assert "NameResolutionError" in text


@pytest.mark.parametrize("message", [
    f"error near token={TOKEN}",                      # bare token, no /bot path
    f"url: /bot{quote(TOKEN, safe='')}/sendMessage",  # percent-encoded
    "url: /bot987654321:OtherToken_xyz/sendMessage",  # any /bot<token>/ path
])
def test_token_redacted_in_any_form(tg, message):
    tg.side_effect = requests.RequestException(message)
    notifier.send_telegram("hello")
    text = tg.text_of()
    assert "SECRET" not in text and "OtherToken" not in text
    assert "<redacted>" in text


def test_error_text_is_not_parsed_as_markup(tg):
    tg.side_effect = requests.RequestException("boom [/x]")
    notifier.send_telegram("hello")  # a "[/x]" in the error must not reach Rich unescaped
    assert "boom [/x]" in tg.text_of()
