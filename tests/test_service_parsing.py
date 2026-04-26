"""Unit tests for nmap port-line parsing helpers."""

from droidnet.modules.cve_watcher import (
    parse_service_info,
    build_cpe_name,
)
from droidnet.modules.hunter import clean_service_name


# ── parse_service_info ───────────────────────────────────────────

def test_parse_apache_ubuntu():
    info = parse_service_info("80/tcp open http Apache httpd 2.4.29 ((Ubuntu))")
    assert info == {
        "port":    "80/tcp",
        "proto":   "http",
        "product": "Apache httpd",
        "version": "2.4.29",
        "raw":     "Apache httpd 2.4.29",
    }


def test_parse_no_version():
    info = parse_service_info("22/tcp open ssh OpenSSH")
    assert info is not None
    assert info["product"] == "OpenSSH"
    assert info["version"] == ""


def test_parse_returns_none_for_marker():
    assert parse_service_info("Escudo intacto") is None


def test_parse_returns_none_for_error():
    assert parse_service_info("Error: timeout") is None


def test_parse_returns_none_for_short_line():
    assert parse_service_info("80/tcp open http") is None  # no banner


# ── clean_service_name ───────────────────────────────────────────

def test_clean_strips_parens_and_returns_query():
    assert clean_service_name(
        "80/tcp open http Apache httpd 2.4.29 ((Ubuntu))"
    ) == "Apache httpd 2.4.29"


def test_clean_returns_none_for_marker():
    assert clean_service_name("Escudo intacto") is None


def test_clean_returns_none_for_short_line():
    assert clean_service_name("80/tcp open http") is None


# ── build_cpe_name ───────────────────────────────────────────────

def test_build_cpe_apache_known():
    cpe = build_cpe_name("Apache httpd", "2.4.29")
    assert cpe is not None
    assert cpe.startswith("cpe:2.3:a:apache:")
    assert "2.4.29" in cpe


def test_build_cpe_unknown_product_returns_none():
    assert build_cpe_name("FooBar Custom Server", "1.0") is None


def test_build_cpe_no_version_returns_none():
    assert build_cpe_name("Apache httpd", "") is None
