"""Test anonymization of IP addresses and related functions."""

import pytest
import random

from conan.ip_anonymization import tree_node, anonymize_ip_addr, _convert_to_anon_ip, _ip_addr_to_int, _ip_int_to_str, _is_mask


@pytest.fixture(scope='module')
def ip_tree():
    """Generate an IP tree once for all tests in this module."""
    # Just using a set seed here so the ip_tree results are consistent for testing
    random.seed(1)
    return tree_node(None)


@pytest.mark.parametrize('line, ip_addr', [
                         ('ip address {} 255.255.255.254', '123.45.67.89'),
                         ('ip address {} 255.0.0.0', '10.0.0.0'),
                         ('ip address {}/16', '10.0.0.0'),
                         ('tacacs-server host {}', '10.1.1.17'),
                         ('syscon address {} Password', '10.73.212.5')
                         ])
def test_anonymize_ip_addr(ip_tree, line, ip_addr):
    """Test IP address anonymization within config lines."""
    line_w_ip = line.format(ip_addr)
    anon_line = anonymize_ip_addr(ip_tree, line_w_ip)
    assert(ip_addr not in anon_line)


@pytest.mark.parametrize('byte0, byte1, byte2, byte3', [
                         (10, 11, 12, 13),
                         (92, 210, 0, 255)
                         ])
def test__convert_to_anon_ip(ip_tree, byte0, byte1, byte2, byte3):
    """Test conversion from original to anonymized IP address."""
    ip_int = _ip_addr_to_int(byte0, byte1, byte2, byte3)
    ip_int_anon = _convert_to_anon_ip(ip_tree, ip_int)
    assert(ip_int != ip_int_anon)

    # Confirm prefixes are preserved after anonymization
    for i in range(0, 32):
        # Using i + 1 since same_mask should mask off ith bit, not preserve it
        same_mask = 0xFFFFFFFF & (0xFFFFFFFF << (i + 1))
        diff_mask = (1 << i)
        ip_int_similar = ip_int ^ diff_mask
        ip_int_similar_anon = _convert_to_anon_ip(ip_tree, ip_int_similar)
        assert(ip_int_similar & same_mask == ip_int & same_mask)
        assert(ip_int_similar_anon & same_mask == ip_int_anon & same_mask)
        assert(ip_int_similar & diff_mask != ip_int & diff_mask)
        assert(ip_int_similar_anon & diff_mask != ip_int_anon & diff_mask)

    # Confirm for subnet_bits < 32, we anonymize exactly the right number of bits
    for i in range(0, 32):
        subnet_mask = 0xFFFFFFFF & (0xFFFFFFFF << (32 - i))
        masked_ip_int_anon = _convert_to_anon_ip(ip_tree, ip_int, subnet_bits=i)
        assert(masked_ip_int_anon == (ip_int_anon & subnet_mask))
        assert((masked_ip_int_anon & ~subnet_mask) == 0)


@pytest.mark.parametrize('byte0, byte1, byte2, byte3, ip_int_result', [
                         (0, 0, 0, 0, 0),
                         (255, 255, 255, 255, 4294967295),
                         (10, 170, 7, 224, 178915296),
                         (1, 128, 0, 212, 25166036)
                         ])
def test__ip_addr_to_int(byte0, byte1, byte2, byte3, ip_int_result):
    """Test conversion from bytes to single integer."""
    ip_int = _ip_addr_to_int(byte0, byte1, byte2, byte3)
    assert(ip_int == ip_int_result)


@pytest.mark.parametrize('ip_int, ip_addr_result', [
                         (0, '0.0.0.0'),
                         (4294967295, '255.255.255.255'),
                         (178915296, '10.170.7.224'),
                         (25166036, '1.128.0.212')
                         ])
def test__ip_int_to_str(ip_int, ip_addr_result):
    """Test conversion from integer to IP addr string."""
    ip_addr = _ip_int_to_str(ip_int)
    assert(ip_addr == ip_addr_result)


@pytest.mark.parametrize('possible_mask, _is_mask_result', [
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
def test__is_mask(possible_mask, _is_mask_result):
    """Test ability to detect masks vs IP addresses."""
    assert(_is_mask(possible_mask) == _is_mask_result)
