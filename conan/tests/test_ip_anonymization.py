"""Test anonymization of IP addresses and related functions."""

import pytest
import random

from conan.ip_anonymization import tree_node, anonymize_ip_addr, _convert_to_anon_ip, _ip_to_int, _is_mask


@pytest.fixture(scope='module')
def ip_tree():
    """Generate an IP tree once for all tests in this module."""
    # Setting seed here so the ip anonymization results are consistent for testing
    random.seed(1)
    return tree_node(None)


@pytest.mark.parametrize('line, ip_addr', [
                         ('ip address {} 255.255.255.254', '123.45.67.89'),
                         ('ip address {} 255.0.0.0', '10.0.0.0'),
                         ('ip address {}/16', '10.0.0.0'),
                         ('tacacs-server host {}', '10.1.1.17'),
                         ('tacacs-server host {}', '001.021.201.012'),
                         ('syscon address {} Password', '10.73.212.5')
                         ])
def test_anonymize_ip_addr(ip_tree, line, ip_addr):
    """Test IP address removal config lines."""
    line_w_ip = line.format(ip_addr)
    anon_line = anonymize_ip_addr(ip_tree, line_w_ip)

    # Make sure the original ip address is removed from the anonymized line
    assert(ip_addr not in anon_line)


@pytest.mark.parametrize('ip_addr', [
                         ('10.11.12.13'),
                         ('92.210.0.255')
                         ])
def test__convert_to_anon_ip(ip_tree, ip_addr):
    """Test conversion from original to anonymized IP address."""
    ip_int = _ip_to_int(ip_addr)
    ip_int_anon = _convert_to_anon_ip(ip_tree, ip_int)

    # Anonymized ip address should not match the original address
    assert(ip_int != ip_int_anon)

    # Confirm prefixes for similar addresses are preserved after anonymization
    for i in range(0, 32):
        # Flip the ith bit of the org address and use that as the similar address
        diff_mask = (1 << i)
        ip_int_similar = ip_int ^ diff_mask
        ip_int_similar_anon = _convert_to_anon_ip(ip_tree, ip_int_similar)

        # Using i + 1 since same_mask should mask off ith bit, not preserve it
        same_mask = 0xFFFFFFFF & (0xFFFFFFFF << (i + 1))

        # Common prefix for addresses should match after anonymization
        assert(ip_int_similar_anon & same_mask == ip_int_anon & same_mask)

        # Confirm the bit that is different in the original addresses is different in the anonymized addresses
        assert(ip_int_similar_anon & diff_mask != ip_int_anon & diff_mask)


@pytest.mark.parametrize('ip_addr, ip_int', [
                         ('0.0.0.0', 0),
                         ('0.0.0.3', 3),
                         ('128.0.0.0', 2147483648),
                         ('0.127.0.0', 8323072),
                         ('10.73.212.5', 172610565),
                         ('010.73.212.05', 172610565),
                         ('255.255.255.255', 4294967295),
                         ('170.255.85.1', 2868860161),
                         ('10.11.12.13', 168496141),
                         ('010.11.12.13', 168496141),
                         ('10.011.12.13', 168496141),
                         ('10.011.12.13', 168496141),
                         ('10.11.012.13', 168496141),
                         ('10.11.12.013', 168496141),
                         ('010.0011.00000012.000', 168496128)
                         ])
def test__ip_to_int(ip_addr, ip_int):
    """Test ability to convert from IP address string to integer representation."""
    assert(_ip_to_int(ip_addr) == ip_int)


@pytest.mark.parametrize('possible_mask, is_mask_result', [
                         (0b00000000000000000000000000000000, True),
                         (0b00000000000000000000000000000001, True),
                         (0b00000000000000000000000000001111, True),
                         (0b11110000000000000000000000000000, True),
                         (0b10000000000000000000000000000000, True),
                         (0b01111111111000000000000000000000, False),
                         (0b00000011111000000000000000000000, False),
                         (0b00000000000100000000000000000000, False),
                         (0b00010101001001000000000000000000, False),
                         (0b00000000000000000010000000000000, False),
                         (0b00000000000000000011111111111110, False),
                         (0b00000000010000000100000000000000, False)
                         ])
def test__is_mask(possible_mask, is_mask_result):
    """Test ability to detect masks vs IP addresses."""
    assert(_is_mask(possible_mask) == is_mask_result)
