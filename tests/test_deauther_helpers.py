"""Unit tests for deauther input validation."""

from droidnet.modules.deauther import BROADCAST, _valid_mac


def test_valid_mac_accepts_well_formed():
    assert _valid_mac("aa:bb:cc:dd:ee:ff")
    assert _valid_mac("00:11:22:33:44:55")
    assert _valid_mac(BROADCAST)


def test_valid_mac_rejects_malformed():
    for bad in ["aa:bb:cc:dd:ee", "gg:bb:cc:dd:ee:ff", "aabbccddeeff", "1.2.3.4", ""]:
        assert not _valid_mac(bad)
