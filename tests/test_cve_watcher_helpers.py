"""Unit tests for cve_watcher NVD payload parsing."""

from droidnet.modules.cve_watcher import _parse_nvd_payload, generate_impact_summary


def test_parse_handles_non_dict_description():
    # Malformed NVD payload: a description entry that isn't a dict must not
    # raise AttributeError on `.get`.
    payload = {"vulnerabilities": [
        {"cve": {"id": "CVE-2024-9999", "descriptions": ["not-a-dict-entry"]}},
    ]}
    out = _parse_nvd_payload(payload)
    assert out[0]["cve_id"] == "CVE-2024-9999"
    assert out[0]["description"] == ""


def test_parse_prefers_english_description():
    payload = {"vulnerabilities": [
        {"cve": {"id": "CVE-2024-0001", "descriptions": [
            {"lang": "es", "value": "hola"},
            {"lang": "en", "value": "hello"},
        ]}},
    ]}
    out = _parse_nvd_payload(payload)
    assert out[0]["description"] == "hello"


def test_parse_falls_back_to_first_when_no_english():
    payload = {"vulnerabilities": [
        {"cve": {"id": "CVE-2024-0002", "descriptions": [
            {"lang": "es", "value": "hola"},
        ]}},
    ]}
    out = _parse_nvd_payload(payload)
    assert out[0]["description"] == "hola"


def test_parse_extracts_cwes_and_kev():
    payload = {"vulnerabilities": [
        {"cve": {"id": "CVE-2024-1",
                 "descriptions": [{"lang": "en", "value": "x"}],
                 "weaknesses": [{"description": [
                     {"lang": "en", "value": "CWE-79"},
                     {"lang": "en", "value": "NVD-CWE-noinfo"},  # ignored
                 ]}],
                 "cisaExploitAdd": "2024-01-01"}},
    ]}
    out = _parse_nvd_payload(payload)
    assert out[0]["cwes"] == ["CWE-79"]
    assert out[0]["kev"] is True


def test_parse_survives_null_cwe_value():
    # A weakness description whose value is null (JSON null -> None) must be
    # skipped, not crash the parser with AttributeError.
    payload = {"vulnerabilities": [
        {"cve": {"id": "CVE-2024-3",
                 "descriptions": [{"lang": "en", "value": "x"}],
                 "weaknesses": [{"description": [
                     {"lang": "en", "value": None},
                     {"lang": "en", "value": "CWE-89"},
                 ]}]}},
    ]}
    out = _parse_nvd_payload(payload)
    assert out[0]["cwes"] == ["CWE-89"]


def test_parse_defaults_when_no_cwe_or_kev():
    payload = {"vulnerabilities": [
        {"cve": {"id": "CVE-2024-2", "descriptions": [{"lang": "en", "value": "x"}]}},
    ]}
    out = _parse_nvd_payload(payload)
    assert out[0]["cwes"] == []
    assert out[0]["kev"] is False


def test_impact_summary_flags_kev_and_cwe():
    cve = {"description": "remote code execution", "severity": "HIGH", "score": 8.0,
           "published": "", "cwes": ["CWE-79"], "kev": True}
    summary = generate_impact_summary(cve, {"product": "nginx", "version": "1.0"},
                                      ["1.2.3.4"])
    assert "CISA KEV" in summary
    assert "CWE-79" in summary
    assert "ACTION REQUIRED" in summary   # KEV escalates the recommendation
