"""Unit tests for droidnet.core.risk.classify_risk."""

from droidnet.core.risk import classify_risk


def test_empty_ports_is_minimal():
    assert classify_risk([]) == "MINIMAL"


def test_closed_marker_is_minimal():
    assert classify_risk(["Shield intact"]) == "MINIMAL"


def test_only_high_ports_is_low():
    # 22/tcp (SSH) is not in CRITICAL nor MEDIUM → LOW.
    assert classify_risk(["22/tcp open ssh OpenSSH 8.4"]) == "LOW"


def test_medium_port_http():
    assert classify_risk(["80/tcp open http nginx 1.18.0"]) == "MEDIUM"


def test_mqtt_port_is_medium():
    # IoT broker ports are classified MEDIUM rather than LOW.
    assert classify_risk(["1883/tcp open mqtt"]) == "MEDIUM"


def test_medium_with_other_ports_stays_medium():
    ports = [
        "22/tcp open ssh OpenSSH 8.4",
        "80/tcp open http nginx 1.18.0",
    ]
    assert classify_risk(ports) == "MEDIUM"


def test_critical_port_telnet():
    assert classify_risk(["23/tcp open telnet"]) == "CRITICAL"


def test_critical_overrides_medium():
    ports = [
        "80/tcp open http",
        "445/tcp open microsoft-ds",
    ]
    assert classify_risk(ports) == "CRITICAL"


def test_unknown_low_port_is_low():
    assert classify_risk(["5555/tcp open freeciv"]) == "LOW"


def test_empty_string_entry_does_not_raise():
    # Defensive: empty string should not throw.
    assert classify_risk([""]) == "LOW"
