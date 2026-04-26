"""Unit tests for the Telegram Markdown escaper."""

from droidnet.core.notifier import escape_markdown


def test_escape_passthrough_for_plain_text():
    assert escape_markdown("HomeWiFi") == "HomeWiFi"


def test_escape_underscore():
    assert escape_markdown("My_Cafe") == r"My\_Cafe"


def test_escape_asterisk():
    assert escape_markdown("Net*work") == r"Net\*work"


def test_escape_backtick():
    assert escape_markdown("foo`bar") == "foo\\`bar"


def test_escape_brackets():
    assert escape_markdown("a[b]c") == r"a\[b\]c"


def test_escape_combined_attack_string():
    # SSID an attacker might try: closes the code block, opens bold, opens link.
    raw = "evil`*x*[link]_"
    out = escape_markdown(raw)
    # Every special char must be backslash-escaped.
    for ch in "_*`[]":
        assert f"\\{ch}" in out
    # And no unescaped specials remain.
    assert "`*" not in out and "[link]" not in out


def test_escape_empty():
    assert escape_markdown("") == ""


def test_escape_none_safe():
    # Defensive: callers occasionally hand us None-like values.
    assert escape_markdown(None) == ""  # type: ignore[arg-type]
