"""Telegram reports must be valid HTML parse-mode text whatever the input.

Telegram's legacy Markdown cannot escape inside an entity ("Escaping inside
entities is not allowed", Bot API docs): a "_" in the italic impact line
(e.g. the common "mini_httpd") or a "`" in an SSID inside `code` would make
Telegram reject the whole message with HTTP 400 and drop the alert. HTML parse
mode escapes cleanly inside every tag, and these tests hold the report to it.
"""
import re
from html import unescape

import pytest

from droidnet.modules import cve_watcher as cve
from droidnet.modules import sentinel

HOSTILE = "Café_`*[x]` <script> & co"
_TAG = re.compile(r"<(/?)(b|i|code)>")
_RAW_AMP = re.compile(r"&(?!(?:lt|gt|amp|quot|#\d+|#x[0-9a-fA-F]+);)")


def visible_text(message: str) -> str:
    """Check *message* against Telegram's HTML rules; return its visible text."""
    stack = []
    for m in _TAG.finditer(message):
        if m.group(1):
            assert stack and stack.pop() == m.group(2), f"unbalanced </{m.group(2)}>"
        else:
            stack.append(m.group(2))
    assert not stack, f"unclosed tags {stack}"
    text = _TAG.sub("", message)
    # Outside supported tags, <, > and & must be entities.
    assert "<" not in text and ">" not in text, "raw < or > in message"
    assert not _RAW_AMP.search(text), "raw & in message"
    return unescape(text)


def match(**over):
    base = {"cve_id": "CVE-2026-0001", "severity": "HIGH", "score": 7.5,
            "service": "mini_httpd 1.30", "ips": ["192.0.2.5"],
            "impact": "Affected service: mini_httpd 1.30 on 1 host(s)",
            "match_type": "cpe"}
    return {**base, **over}


def test_cve_report_keeps_underscores_and_hostile_text_literal():
    report = cve._build_telegram_report(
        [match(impact="Affected service: mini_httpd 1.30 | a <b> & c")], HOSTILE)
    text = visible_text(report)
    assert "mini_httpd 1.30" in text          # no "\_" escapes leaking through
    assert HOSTILE in text
    assert "a <b> & c" in text


def test_cve_report_truncates_before_escaping():
    # Truncating an escaped string could cut "&amp;" in half.
    text = visible_text(cve._build_telegram_report([match(impact="&" * 150)], "lab"))
    assert "&" * 100 in text and "&" * 101 not in text


def test_cve_report_lists_overflow():
    report = cve._build_telegram_report([match(cve_id=f"CVE-2026-{i:04}") for i in range(7)], "lab")
    assert "2 more" in visible_text(report)


@pytest.mark.parametrize("kind, label", [("cpe", "CPE match"), ("candidate", "candidate")])
def test_cve_report_labels_match_type(kind, label):
    assert label in visible_text(cve._build_telegram_report([match(match_type=kind)], "lab"))


def test_sentinel_report_is_valid_html():
    text = visible_text(sentinel._build_sentinel_report(HOSTILE, 3))
    assert HOSTILE in text and "3" in text
