"""Attack hints in the impact summary must come from whole words, not fragments.

A naive substring check reads "rce" in "resource"/"source"/"force", "hang" in
"change"/"exchange", "root" in "chroot", "sensitive" in "case-sensitive", and
"network" anywhere as "remotely exploitable" — each a false claim that would be
saved with the alert and sent to Telegram. These tests pin the whole-word and
CVSS-driven behaviour that keeps the hints honest.
"""
import pytest

from droidnet.modules.cve_watcher import _parse_nvd_payload, generate_impact_summary


def hints(description, attack_vector=None):
    cve = {"description": description, "severity": "MEDIUM", "score": 5.0,
           "cwes": [], "kev": False, "attack_vector": attack_vector}
    summary = generate_impact_summary(cve, {"product": "x", "version": "1"}, ["192.0.2.1"])
    line = next((p for p in summary.split(" | ") if p.startswith("Attack vector: ")), "")
    return set(line.removeprefix("Attack vector: ").split(", ")) - {""}


def test_resource_exhaustion_sentence_is_not_code_execution():
    # "rce" lives inside "resource" and "hang" inside "changes", so a substring
    # check flags both code execution and DoS here; only the DoS is real.
    got = hints("A resource exhaustion issue when the configuration file changes")
    assert "allows code execution" not in got
    assert got == {"can cause denial of service"}   # resource exhaustion is a DoS


@pytest.mark.parametrize("description, wrong_hint", [
    ("The source parser can force a reload of the resource list.", "allows code execution"),
    ("Key exchange negotiation may change the cipher.",            "can cause denial of service"),
    ("The chroot directory path is not validated.",                "privilege escalation"),
    ("A case-sensitive regex matcher is used for the route.",      "information leak"),
    ("Malcolm is a network traffic analysis tool suite.",          "remotely exploitable"),
    ("Requires high privileges to configure the admin panel.",     "privilege escalation"),
    # Real NVD phrasings (CVE-2026-58257, CVE-2026-110506): context, not escalation.
    ("The impact is amplified when the server runs with elevated privileges.",
     "privilege escalation"),
    ("Allows Stored Cross-Site Scripting attacks against higher-privileged users.",
     "privilege escalation"),
])
def test_word_fragments_do_not_trigger_hints(description, wrong_hint):
    assert wrong_hint not in hints(description)


@pytest.mark.parametrize("description, hint", [
    ("Allows remote code execution (RCE) via a crafted request.", "allows code execution"),
    ("A command injection in the web UI.",                        "allows code execution"),
    ("A malformed packet leads to a crash of the worker.",        "can cause denial of service"),
    ("The daemon hangs on a truncated header.",                   "can cause denial of service"),
    ("A denial-of-service via uncontrolled resource consumption.", "can cause denial of service"),
    ("Allows local users to gain privileges.",                    "privilege escalation"),
    ("Lets an attacker run commands as root.",                    "privilege escalation"),
    # Real NVD phrasings (CVE-2026-76780, CVE-2026-111582).
    ("Contributors can elevate their privileges to that of an Administrator.",
     "privilege escalation"),
    ("Allows a local user with low privileges to execute arbitrary code with elevated "
     "privileges.",                                               "privilege escalation"),
    ("Leads to information disclosure of session tokens.",        "information leak"),
    ("Memory contents can leak to the client.",                   "information leak"),
    ("An authentication bypass in the login handler.",            "authentication bypass"),
    ("A remote attacker can trigger it.",                         "remotely exploitable"),
])
def test_real_cues_still_trigger_hints(description, hint):
    assert hint in hints(description)


def test_cvss_attack_vector_decides_remote_exploitability():
    # CVSS is authoritative; the description is only a fallback.
    assert "remotely exploitable" in hints("Crafted input triggers it.", attack_vector="NETWORK")
    assert "remotely exploitable" not in hints("A remote user can trigger it.", attack_vector="LOCAL")


@pytest.mark.parametrize("metrics, vector", [
    ({"cvssMetricV31": [{"type": "Primary", "cvssData": {
        "baseScore": 7.5, "baseSeverity": "HIGH", "attackVector": "NETWORK"}}]}, "NETWORK"),
    ({"cvssMetricV40": [{"type": "Secondary", "cvssData": {
        "baseScore": 6.8, "baseSeverity": "MEDIUM", "attackVector": "LOCAL"}}]}, "LOCAL"),
    ({"cvssMetricV2": [{"type": "Primary", "baseSeverity": "MEDIUM", "cvssData": {
        "baseScore": 5.0, "accessVector": "ADJACENT_NETWORK"}}]}, "ADJACENT_NETWORK"),
    ({}, None),
])
def test_attack_vector_is_parsed_from_the_scoring_metric(metrics, vector):
    [parsed] = _parse_nvd_payload({"vulnerabilities": [
        {"cve": {"id": "CVE-2026-0001", "descriptions": [], "metrics": metrics}}]})
    assert parsed["attack_vector"] == vector
