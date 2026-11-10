"""Keyword "candidate" matches: precise, version-checked, never a flood.

A plain keyword search is far too broad: "nginx" returns 112 CVEs over a
120-day window (real NVD data), nearly none about nginx itself — Laravel,
WooCommerce, "Nginx UI", plugins "served by nginx". A candidate therefore only
counts when the description names the product immediately followed by a version
range that covers the detected version. The search also reaches CVEs NVD has
not analysed yet (no configurations, so invisible to a cpeName search), which a
CPE-only lookup would miss.

Descriptions below are real NVD text (trimmed).
"""
import pytest

from droidnet.core import database as db
from droidnet.modules import cve_watcher as cve
from droidnet.modules.cve_watcher import _description_name, _keyword_candidates


def nvd(cve_id, description, analysed=False):
    return {"cve_id": cve_id, "description": description, "severity": "HIGH",
            "score": 7.5, "cwes": [], "kev": False, "analysed": analysed,
            "attack_vector": None}


OPENSSH = nvd("CVE-2026-106588", "In sshd in OpenSSH through 10.6, use of the macOS 27 "
              "(or later) SDK has the side effect of loss of sandboxing.")
REDIS = nvd("CVE-2026-66373", "Redis before 8.8.0, in the unusual case where an authenticated "
            "attacker can execute RESTORE, allows remote code execution.")
TOMCAT = nvd("CVE-2026-59083", "Improper Handling of URL Encoding (Hex Encoding) vulnerability in "
             "Apache Tomcat.\n\nThis issue affects Apache Tomcat: from 11.0.0-M1 through 11.0.23, "
             "from 10.1.0-M1 through 10.1.56, from 9.0.0.M1 through 9.0.119.", analysed=True)
TOMCAT_NEWER = nvd("CVE-2026-66299", "Uncontrolled Resource Consumption vulnerability in Apache "
                   "Tomcat's WebSocket implementation.\xa0This issue affects Apache Tomcat: from "
                   "11.0.0-M20 through 11.0.24, from 10.1.24 through 10.1.57, from 9.0.89 through "
                   "9.0.120.", analysed=True)

# The product is named, but the versions belong to other software.
NOISE = [
    nvd("CVE-2026-49972", "Laravel-Mediable before 7.0.0 contains a file upload vulnerability "
        "that allows unauthenticated attackers to upload files when served by nginx."),
    nvd("CVE-2026-84313", "Nginx UI is a web user interface for the Nginx web server. Prior to "
        "2.4.1, POST /api/otp_enroll is registered as anonymous."),
    nvd("CVE-2026-105620", "PostgreSQL Anonymizer doesn't mask data returned by a sub-query in a "
        "rule. The problem is resolved in PostgreSQL Anonymizer 3.3.0 and later versions."),
    nvd("CVE-2026-18546", "IBM CockroachDB PostgreSQL for IBM VPC 26.2.0 through 26.2.3 is "
        "vulnerable to server-side request forgery."),
    nvd("CVE-2026-84372", "Predis is a flexible and feature-complete Redis and Valkey client for "
        "PHP. From version 3.0.0-RC1 until version 3.3.0, pipeline handling is unsafe."),
]


def ids(cves):
    return [c["cve_id"] for c in cves]


# ── which CVEs count as being about the product ────────────────────

@pytest.mark.parametrize("name", ["nginx", "PostgreSQL", "Redis"])
def test_mentions_in_other_products_are_dropped(name):
    assert _keyword_candidates(NOISE, name, "1.0", cpe_checked=False, exclude=set()) == []


@pytest.mark.parametrize("cve_, name, inside, outside", [
    (OPENSSH, "OpenSSH", "9.6p1", "10.7"),     # "through 10.6": inclusive
    (REDIS,   "Redis",   "7.2.4", "8.8.0"),    # "before 8.8.0": exclusive
])
def test_detected_version_must_fall_in_the_stated_range(cve_, name, inside, outside):
    assert ids(_keyword_candidates([cve_], name, inside, cpe_checked=False, exclude=set())) == [cve_["cve_id"]]
    assert _keyword_candidates([cve_], name, outside, cpe_checked=False, exclude=set()) == []


@pytest.mark.parametrize("version, expected", [
    ("9.0.31",  ["CVE-2026-59083"]),                    # only the older range covers it
    ("10.1.30", ["CVE-2026-59083", "CVE-2026-66299"]),
    ("11.0.25", []),                                    # newer than every range
])
def test_apache_style_range_lists(version, expected):
    got = _keyword_candidates([TOMCAT, TOMCAT_NEWER], "Apache Tomcat", version,
                              cpe_checked=False, exclude=set())
    assert ids(got) == expected


@pytest.mark.parametrize("sentence, inside, outside", [
    ("Foo 2.4.62 and earlier allows X.",          "2.4.62", "2.4.63"),
    ("Foo prior to 3.0 allows X.",                 "2.9",    "3.0"),
    ("Foo versions 1.2 to 1.5 allow X.",           "1.4",    "1.6"),
    ("Foo from 2.2.0 until 2.6.0 allows X.",       "2.5.9",  "2.6.0"),
    ("Foo up to and including 4.1 allows X.",      "4.1",    "4.1.1"),
])
def test_range_phrasings(sentence, inside, outside):
    cves = [nvd("CVE-2026-0001", sentence)]
    assert _keyword_candidates(cves, "Foo", inside, cpe_checked=False, exclude=set())
    assert not _keyword_candidates(cves, "Foo", outside, cpe_checked=False, exclude=set())


def test_cpe_mapped_products_only_take_unanalysed_cves():
    # NVD already matched analysed CVEs against CPEs; an analysed CVE the CPE
    # query did not return does not affect this version.
    got = _keyword_candidates([TOMCAT, OPENSSH], "Apache Tomcat", "9.0.31",
                              cpe_checked=True, exclude=set())
    assert got == []
    assert ids(_keyword_candidates([OPENSSH], "OpenSSH", "9.6p1", cpe_checked=True,
                                   exclude=set())) == ["CVE-2026-106588"]


def test_cpe_confirmed_cves_are_not_duplicated():
    assert _keyword_candidates([OPENSSH], "OpenSSH", "9.6p1", cpe_checked=True,
                               exclude={"CVE-2026-106588"}) == []


def test_unknown_version_yields_no_candidates():
    # Without a version no stated range can be checked; keeping the CVEs
    # would list the product's whole history (live NVD, full audit: 55 for
    # Samba, 32 for Dovecot). CVE Watcher reports such services as not checked.
    assert _keyword_candidates([OPENSSH, *NOISE], "OpenSSH", "", cpe_checked=False,
                               exclude=set()) == []


@pytest.mark.parametrize("product, name", [
    ("Apache httpd",          "Apache HTTP Server"),   # how its CVEs name it
    ("PostgreSQL DB",         "PostgreSQL"),
    ("Redis key-value store", "Redis"),
    ("Samba smbd",            "Samba"),
    ("OpenSSH",               "OpenSSH"),
    ("Apache Tomcat",         "Apache Tomcat"),
])
def test_description_name(product, name):
    assert _description_name(product) == name


# ── run_cve_watcher ────────────────────────────────────────────────

@pytest.fixture
def scan_of(monkeypatch):
    """Store one scan with *banner* and script NVD; return the per-query log."""
    calls = []

    def setup(banner, cpe_results, keyword_results):
        db.save_scan("lab", "20261109_120000", {"192.0.2.5": [banner]})

        def query_nvd(keyword, days_back=120, cpe_name=None):
            calls.append(cpe_name or keyword)
            return cpe_results if cpe_name else keyword_results

        monkeypatch.setattr(cve, "query_nvd", query_nvd)
        monkeypatch.setattr(cve.time, "sleep", lambda _: None)
        monkeypatch.setattr(cve, "send_alert", lambda **_: None)
        return calls

    return setup


def test_empty_cpe_result_does_not_flood(scan_of):
    analysed_nginx = nvd("CVE-2026-90439", "NGINX Plus and NGINX Open Source have a "
                         "vulnerability in the ngx_http_v3_module module.", analysed=True)
    calls = scan_of("80/tcp open http nginx 1.18.0", [], [*NOISE, analysed_nginx])
    result = cve.run_cve_watcher()
    assert calls == ["cpe:2.3:a:nginx:nginx:1.18.0:*:*:*:*:*:*:*", "nginx"]
    assert list(result) == [] and result.complete


def test_unanalysed_cve_found_alongside_cpe_matches(scan_of):
    confirmed = nvd("CVE-2026-73283", "In sshd in OpenSSH before 10.5, the restrict keyword "
                    "is not honoured.", analysed=True)
    scan_of("22/tcp open ssh OpenSSH 9.6p1 Ubuntu 3ubuntu13", [confirmed], [confirmed, OPENSSH])
    result = cve.run_cve_watcher()
    assert {(m["cve_id"], m["match_type"]) for m in result} == {
        ("CVE-2026-73283", "cpe"), ("CVE-2026-106588", "candidate")}
    candidate = next(m for m in result if m["match_type"] == "candidate")
    assert "not yet confirmed by NVD" in candidate["impact"]


def test_failed_description_search_keeps_cpe_matches_but_is_incomplete(scan_of):
    confirmed = nvd("CVE-2026-73283", "In sshd in OpenSSH before 10.5, x.", analysed=True)
    scan_of("22/tcp open ssh OpenSSH 9.6p1", [confirmed], None)
    result = cve.run_cve_watcher()
    assert [m["cve_id"] for m in result] == ["CVE-2026-73283"]
    assert not result.complete
