"""Per-host scan: port discovery and version detection run as separate passes.

Version detection (-sV) is the slow part of a host scan: services that never
answer nmap's probes make each probe wait out its timeout. On a real home
router the four open ports took 124 s under -sV while the port scan itself
took 1 s. The port list decides the host's risk, so it must survive a slow or
failed -sV; only the version strings are optional.

The router fixtures below are the XML a real router returned (trimmed).
"""
import subprocess
from types import SimpleNamespace

import pytest

from droidnet.core.risk import classify_risk
from droidnet.modules import sentinel

IP = "192.0.2.1"


def nmap_xml(ports="", extraports=(), state="up"):
    extra = "".join(f'<extraports state="{s}" count="{n}"/>' for s, n in extraports)
    return (f'<nmaprun><host><status state="{state}"/><ports>{extra}{ports}</ports></host>'
            '<runstats><finished exit="success"/></runstats></nmaprun>')


def port(portid, state="open", **service):
    attrs = " ".join(f'{key}="{value}"' for key, value in service.items())
    return f'<port protocol="tcp" portid="{portid}"><state state="{state}"/><service {attrs}/></port>'


ROUTER_PORTS = nmap_xml(
    port(53, name="domain") + port(80, name="http") + port(1900, name="upnp")
    + port(8080, name="http-proxy"),
    extraports=[("closed", 96)],
)
ROUTER_VERSIONS = nmap_xml(
    port(53, name="domain", product="dnsmasq", version="2.85") + port(80, name="http")
    + port(1900, name="upnp", product="Portable SDK for UPnP devices", version="1.6.19",
           extrainfo="Linux 3.18.21; UPnP 1.0")
    + port(8080, name="http-proxy"),
)


@pytest.fixture
def nmap(monkeypatch):
    """Script the two nmap passes (``script``) and record each call (``calls``)."""
    fake = SimpleNamespace(calls=[], script={})

    def run(args, **kwargs):
        fake.calls.append((args, kwargs))
        outcome = fake.script["versions" if "-sV" in args else "ports"]
        if isinstance(outcome, BaseException):
            raise outcome
        return outcome

    monkeypatch.setattr(sentinel.subprocess, "run", run)
    return fake


def ok(xml):
    return SimpleNamespace(returncode=0, stdout=xml, stderr="")


# ── two passes ─────────────────────────────────────────────────────

def test_versions_are_detected_only_on_open_ports(nmap):
    nmap.script.update(ports=ok(ROUTER_PORTS), versions=ok(ROUTER_VERSIONS))
    _, lines = sentinel._scan_one(IP)
    assert lines == [
        "53/tcp open domain dnsmasq 2.85",
        "80/tcp open http",
        "1900/tcp open upnp Portable SDK for UPnP devices 1.6.19 (Linux 3.18.21; UPnP 1.0)",
        "8080/tcp open http-proxy",
    ]
    (port_args, port_kw), (version_args, version_kw) = nmap.calls
    assert port_args == ["nmap", "-F", "-T4", "-oX", "-", IP]
    assert version_args == ["nmap", "-sV", "-T4", "-p", "53,80,1900,8080", "-oX", "-", IP]
    # -sV gets a budget well above the 124 s the real router needed.
    assert version_kw["timeout"] > 124 > port_kw["timeout"] / 2


def test_slow_version_detection_keeps_the_open_ports(nmap):
    nmap.script.update(ports=ok(ROUTER_PORTS),
                       versions=subprocess.TimeoutExpired(["nmap"], 300))
    _, lines = sentinel._scan_one(IP)
    assert lines == ["53/tcp open domain", "80/tcp open http",
                     "1900/tcp open upnp", "8080/tcp open http-proxy"]
    assert classify_risk(lines) == "MEDIUM"   # assessed, not UNKNOWN


@pytest.mark.parametrize("failure", [
    SimpleNamespace(returncode=1, stdout="", stderr="boom"),
    ok("not xml"),
    ok('<nmaprun><runstats><finished exit="error"/></runstats></nmaprun>'),
])
def test_failed_version_detection_keeps_the_open_ports(nmap, failure):
    nmap.script.update(ports=ok(ROUTER_PORTS), versions=failure)
    _, lines = sentinel._scan_one(IP)
    assert [line.split()[0] for line in lines] == ["53/tcp", "80/tcp", "1900/tcp", "8080/tcp"]


def test_port_closing_between_passes_keeps_the_first_pass_line(nmap):
    nmap.script.update(ports=ok(ROUTER_PORTS),
                       versions=ok(nmap_xml(port(53, name="domain", product="dnsmasq",
                                                 version="2.85"))))
    _, lines = sentinel._scan_one(IP)
    assert lines[0] == "53/tcp open domain dnsmasq 2.85"
    assert lines[1:] == ["80/tcp open http", "1900/tcp open upnp", "8080/tcp open http-proxy"]


def test_port_scan_timeout_is_still_reported(nmap):
    nmap.script.update(ports=subprocess.TimeoutExpired(["nmap"], 120))
    assert sentinel._scan_one(IP) == (IP, ["Error: timeout"])
    assert len(nmap.calls) == 1


# ── hosts without open ports ───────────────────────────────────────

@pytest.mark.parametrize("extraports, ports", [
    ([("closed", 100)], ""),
    # Real host: 99 closed and one port dropped by its firewall.
    ([("closed", 99)], port(7, state="filtered", name="echo")),
    # A host firewall dropping every probe exposes nothing either.
    ([("filtered", 100)], ""),
])
def test_closed_or_filtered_ports_mean_nothing_is_exposed(nmap, extraports, ports):
    nmap.script.update(ports=ok(nmap_xml(ports, extraports=extraports)))
    assert sentinel._scan_one(IP) == (IP, ["Shield intact"])
    assert len(nmap.calls) == 1   # no version pass without open ports


@pytest.mark.parametrize("xml", [
    nmap_xml(),                                                    # no port data at all
    nmap_xml(port(53, state="open|filtered", name="domain")),     # undecided state
])
def test_undetermined_port_states_stay_inconclusive(nmap, xml):
    nmap.script.update(ports=ok(xml))
    _, lines = sentinel._scan_one(IP)
    assert lines == ["Error: inconclusive port states"]
    assert classify_risk(lines) == "UNKNOWN"


# ── hosts the first scan could not assess ──────────────────────────

@pytest.fixture
def scans(monkeypatch):
    """Script deep_scan's per-host results: each scan of an IP takes its next outcome.

    A host scanned more often than scripted raises IndexError, which fails
    the test.
    """
    fake = SimpleNamespace(outcomes={}, calls=[])

    def scan_one(ip):
        fake.calls.append(ip)
        return ip, fake.outcomes[ip].pop(0)

    monkeypatch.setattr(sentinel, "_scan_one", scan_one)
    monkeypatch.setattr(sentinel, "rprint", lambda *a, **k: None)
    return fake


def test_a_host_that_slept_through_its_scan_is_scanned_again(scans):
    # Real case: a phone answered discovery, then dozed off (Wi-Fi power
    # saving) and missed its port scan, leaving it UNKNOWN for the whole cycle.
    scans.outcomes.update({
        "192.0.2.1":  [["80/tcp open http"]],
        "192.0.2.5":  [["8080/tcp open http-proxy Error: 404 page"]],   # banner, not a marker
        "192.0.2.10": [["Shield intact"]],
        "192.0.2.17": [["Error: host unreachable"], ["Shield intact"]],
    })
    assert sentinel.deep_scan(list(scans.outcomes)) == {
        "192.0.2.1":  ["80/tcp open http"],
        "192.0.2.5":  ["8080/tcp open http-proxy Error: 404 page"],
        "192.0.2.10": ["Shield intact"],
        "192.0.2.17": ["Shield intact"],
    }
    # The retry starts once every first scan is done, and covers only the failure.
    assert sorted(scans.calls[:4]) == sorted(scans.outcomes)
    assert scans.calls[4:] == ["192.0.2.17"]


@pytest.mark.parametrize("marker", ["Error: host unreachable", "Error: timeout",
                                    "Error: nmap failed", "Error: incomplete scan",
                                    "Error: inconclusive port states", "Error"])
def test_a_host_is_retried_once_and_a_second_failure_is_reported(scans, marker):
    scans.outcomes["192.0.2.17"] = [[marker], ["Error: host unreachable"]]
    assert sentinel.deep_scan(["192.0.2.17"]) == {"192.0.2.17": ["Error: host unreachable"]}
    assert scans.calls == ["192.0.2.17", "192.0.2.17"]


def test_no_retry_when_every_host_was_assessed(scans):
    scans.outcomes.update({"192.0.2.1": [["80/tcp open http"]],
                           "192.0.2.10": [["Shield intact"]]})
    sentinel.deep_scan(list(scans.outcomes))
    assert sorted(scans.calls) == ["192.0.2.1", "192.0.2.10"]
