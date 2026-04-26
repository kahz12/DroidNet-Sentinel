"""Unit tests for droidnet.core.risk.classify_risk."""

from droidnet.core.risk import classify_risk


def test_empty_ports_is_minimo():
    assert classify_risk([]) == "MÍNIMO"


def test_closed_marker_is_minimo():
    assert classify_risk(["Escudo intacto"]) == "MÍNIMO"


def test_only_high_ports_is_bajo():
    # 22/tcp (SSH) is not in CRITICAL nor MEDIUM → BAJO.
    assert classify_risk(["22/tcp open ssh OpenSSH 8.4"]) == "BAJO"


def test_medium_port_http():
    assert classify_risk(["80/tcp open http nginx 1.18.0"]) == "MEDIO"


def test_medium_with_other_ports_stays_medio():
    ports = [
        "22/tcp open ssh OpenSSH 8.4",
        "80/tcp open http nginx 1.18.0",
    ]
    assert classify_risk(ports) == "MEDIO"


def test_critical_port_telnet():
    assert classify_risk(["23/tcp open telnet"]) == "CRÍTICO"


def test_critical_overrides_medium():
    ports = [
        "80/tcp open http",
        "445/tcp open microsoft-ds",
    ]
    assert classify_risk(ports) == "CRÍTICO"


def test_unknown_low_port_is_bajo():
    assert classify_risk(["5555/tcp open freeciv"]) == "BAJO"


def test_empty_string_entry_does_not_raise():
    # Defensive: empty string should not throw.
    assert classify_risk([""]) == "BAJO"
