"""Full-audit mode: CVEs of any publication date for the detected versions.

The default watch only looks at CVEs published in the last 120 days, which
is right for spotting new disclosures but blind to old software: a home
router running libupnp 1.6.19 carries a 9.8 CRITICAL from 2016 that a
recent-only search never reports. With days_back=None every NVD query drops
the publication-date filter; for typical products the description search
still fits in one page (live NVD: "PostgreSQL" has 596 hits all-time against
2000 per page), so the audit costs the same number of requests.

libupnp's CVEs are split across two NVD vendor names with no overlap
(1.6.19: 3 under libupnp_project, 7 more under pupnp_project), so one product
can map to several CPEs whose results are merged.
"""
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from droidnet.cli import args as cli
from droidnet.core import database as db
from droidnet.modules import cve_watcher as cve

EMPTY_PAGE = {"startIndex": 0, "resultsPerPage": 0, "totalResults": 0, "vulnerabilities": []}
LIBUPNP = "cpe:2.3:a:libupnp_project:libupnp:1.6.19:*:*:*:*:*:*:*"
PUPNP = "cpe:2.3:a:pupnp_project:pupnp:1.6.19:*:*:*:*:*:*:*"


@pytest.fixture
def offline(monkeypatch, tmp_path):
    monkeypatch.setattr(cve, "NVD_CACHE_DIR", tmp_path)
    monkeypatch.setattr(cve.time, "sleep", lambda _: None)
    get = Mock(return_value=EMPTY_PAGE)
    monkeypatch.setattr(cve, "_nvd_get", get)
    return get


# ── query_nvd ──────────────────────────────────────────────────────

def test_all_time_query_has_no_publication_window(offline):
    assert cve.query_nvd("dnsmasq", days_back=None) == []
    params = offline.call_args.args[0]
    assert "pubStartDate" not in params and "pubEndDate" not in params


def test_windowed_and_all_time_results_are_cached_separately(offline):
    cve.query_nvd("dnsmasq")                      # last 120 days
    cve.query_nvd("dnsmasq", days_back=None)      # must not reuse the windowed cache
    cve.query_nvd("dnsmasq", days_back=None)      # served from its own cache
    assert offline.call_count == 2
    assert "pubStartDate" in offline.call_args_list[0].args[0]


@pytest.mark.parametrize("days", [0, 121, True, 1.5, "all"])
def test_invalid_windows_are_still_rejected(days):
    with pytest.raises(ValueError):
        cve.query_nvd("dnsmasq", days_back=days)
    with pytest.raises(ValueError):
        cve.run_cve_watcher(days_back=days)


# ── several CPEs per product ───────────────────────────────────────

@pytest.mark.parametrize("product", ["Portable SDK for UPnP devices", "Portable SDK for UPnP"])
def test_libupnp_maps_to_both_nvd_vendor_names(product):
    assert cve.build_cpe_names(product, "1.6.19") == [LIBUPNP, PUPNP]
    assert cve.build_cpe_name(product, "1.6.19") == LIBUPNP


def test_single_vendor_products_keep_one_cpe():
    assert cve.build_cpe_names("nginx", "1.18.0") == ["cpe:2.3:a:nginx:nginx:1.18.0:*:*:*:*:*:*:*"]
    assert cve.build_cpe_names("Unknown thing", "1.0") == []


def nvd(cve_id):
    return {"cve_id": cve_id, "description": "x", "severity": "HIGH", "score": 7.5,
            "cwes": [], "kev": False, "analysed": True, "attack_vector": "NETWORK"}


@pytest.fixture
def router(monkeypatch):
    """A home router's UPnP banner in the history DB; NVD scripted per CPE."""
    db.save_scan("lab", "20261109_120000", {"192.0.2.1": [
        "1900/tcp open upnp Portable SDK for UPnP devices 1.6.19 (Linux 3.18.21; UPnP 1.0)"]})
    fake = SimpleNamespace(by_cpe={}, calls=[])

    def query_nvd(keyword, days_back=120, cpe_name=None):
        fake.calls.append((cpe_name or keyword, days_back))
        return fake.by_cpe.get(cpe_name, []) if cpe_name else []

    monkeypatch.setattr(cve, "query_nvd", query_nvd)
    monkeypatch.setattr(cve.time, "sleep", lambda _: None)
    monkeypatch.setattr(cve, "send_alert", lambda **_: None)
    return fake


def test_cves_from_every_cpe_are_merged_once(router):
    router.by_cpe = {LIBUPNP: [nvd("CVE-2016-8863"), nvd("CVE-2020-13848")],
                     PUPNP:   [nvd("CVE-2020-13848"), nvd("CVE-2021-28302")]}
    result = cve.run_cve_watcher(days_back=None)
    assert sorted(m["cve_id"] for m in result) == ["CVE-2016-8863", "CVE-2020-13848", "CVE-2021-28302"]
    assert {m["match_type"] for m in result} == {"cpe"}
    # Every query — both CPEs and the description search — drops the window.
    assert [days for _, days in router.calls] == [None, None, None]


def test_failure_of_any_cpe_query_marks_the_service_incomplete(router):
    router.by_cpe = {LIBUPNP: [nvd("CVE-2016-8863")], PUPNP: None}
    result = cve.run_cve_watcher(days_back=None)
    assert not result.complete
    assert list(result) == []


# ── command line ───────────────────────────────────────────────────

@pytest.fixture
def watcher_calls(monkeypatch):
    calls = []
    monkeypatch.setattr(cve, "run_cve_watcher", lambda **kwargs: calls.append(kwargs))
    monkeypatch.setattr(cli, "get_default_iface", lambda: "wlan0")
    return calls


@pytest.mark.parametrize("argv, days_back", [
    (["cve", "--all-time"], None),
    (["cve"],               120),
    (["cve-watch"],         120),
    (["--cve-watch"],       120),   # legacy flag keeps the default window
])
def test_cli_selects_the_window(watcher_calls, argv, days_back):
    assert cli.handle_args(cli._build_parser().parse_args(argv)) is True
    assert watcher_calls == [{"days_back": days_back, "show_history": True}]
