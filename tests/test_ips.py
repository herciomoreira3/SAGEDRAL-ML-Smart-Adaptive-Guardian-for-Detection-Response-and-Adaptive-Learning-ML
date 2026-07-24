"""
Unit tests for IPSModule and Whitelist Protection.
"""

from sagedral_ml.ips.response import IPSModule, validate_ip, HARDCODED_WHITELIST


def test_ip_validation():
    assert validate_ip("192.168.1.1") == "192.168.1.1"
    assert validate_ip("  10.0.0.1  ") == "10.0.0.1"

    try:
        validate_ip("invalid-ip")
        assert False, "Should have raised ValueError"
    except ValueError:
        pass


def test_whitelist_protection():
    ips = IPSModule(enabled=True, whitelist=["192.168.1.254"])

    # Hardcoded loopback must be whitelisted
    assert ips.is_whitelisted("127.0.0.1") is True
    assert ips.is_whitelisted("::1") is True

    # Custom whitelist
    assert ips.is_whitelisted("192.168.1.254") is True

    # Non-whitelisted IP
    assert ips.is_whitelisted("10.99.99.99") is False


def test_block_whitelisted_ip_aborted():
    ips = IPSModule(enabled=True)
    # Attempting to block loopback must return False
    blocked = ips.block_ip("127.0.0.1")
    assert blocked is False
