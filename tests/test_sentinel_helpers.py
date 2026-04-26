"""Unit tests for sentinel module helpers (no network/subprocess)."""

from droidnet.modules.sentinel import _sanitize_ssid


def test_sanitize_alpha_passthrough():
    assert _sanitize_ssid("HomeWiFi") == "HomeWiFi"


def test_sanitize_replaces_path_separators():
    # Path traversal attempt — six invalid leading chars (../../) + slash before passwd.
    assert _sanitize_ssid("../../etc/passwd") == "______etc_passwd"


def test_sanitize_keeps_hyphen_and_underscore():
    assert _sanitize_ssid("Home-WiFi_5G") == "Home-WiFi_5G"


def test_sanitize_strips_spaces_and_punct():
    assert _sanitize_ssid("My Cafe!@") == "My_Cafe__"


def test_sanitize_empty_returns_unknown():
    assert _sanitize_ssid("") == "unknown"


def test_sanitize_punct_only_becomes_underscores():
    # All-invalid input → underscores (one per char). Falls back to "unknown"
    # only when the input itself is empty.
    assert _sanitize_ssid("!!!") == "___"
