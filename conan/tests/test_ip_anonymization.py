"""Test anonymization of IP addresses and related functions."""
from __future__ import unicode_literals

import ipaddress
import pytest
import regex

from conan.ip_anonymization import IpAnonymizer, anonymize_ip_addr, _is_mask

ip_list = [
    ('10.11.12.13'),
    ('10.10.10.10'),
    ('10.1.1.17'),
    ('237.73.212.5'),
    ('123.45.67.89'),
    ('92.210.0.255'),
    ('128.7.55.12'),
    ('223.123.21.99'),
    ('193.99.99.99'),
    ('225.99.99.99'),
    ('241.99.99.99'),
    ('249.99.99.99'),
    ('254.254.254.254'),
]

SALT = 'saltForTest'


@pytest.fixture(scope='module')
def anonymizer():
    """All tests in this module use a single IPv4 anonymizer."""
    return IpAnonymizer(SALT)


@pytest.fixture(scope='module')
def flip_anonymizer():
    """Create an anonymizer that flips every bit."""
    return IpAnonymizer(SALT, salter=lambda a, b: 1)


@pytest.mark.parametrize('line, ip_addrs', [
                         ('ip address {} 255.255.255.254', ['123.45.67.89']),
                         ('ip address {} 255.0.0.0', ['10.0.0.0']),
                         ('ip address {}/16', ['10.0.0.0']),
                         ('tacacs-server host {}', ['10.1.1.17']),
                         ('tacacs-server host {}', ['001.021.201.012']),
                         ('syscon address {} Password', ['10.73.212.5']),
                         ('1 permit tcp host {} host {} eq 2', ['1.2.3.4', '1.2.3.45']),
                         ('1 permit tcp host {} host {} eq 2', ['1.2.123.4', '11.2.123.4']),
                         ('1 permit tcp host {} host {} eq 2', ['1.2.30.45', '1.2.30.4']),
                         ('1 permit tcp host {} host {} eq 2', ['11.20.3.4', '1.20.3.4']),
                         ('something host {} host {} host {}', ['1.2.3.4', '1.2.3.5', '1.2.3.45']),
                         ])
def test_anonymize_ip_addr(anonymizer, line, ip_addrs):
    """Test IP address removal config lines."""
    line_w_ip = line.format(*ip_addrs)
    anon_line = anonymize_ip_addr(anonymizer, line_w_ip)

    # Now anonymize each IP address individually & build another anonymized line
    anon_ip_addrs = [anonymize_ip_addr(anonymizer, ip_addr) for ip_addr in ip_addrs]
    individually_anon_line = line.format(*anon_ip_addrs)

    # Make sure anonymizing each address individually is the same as
    # anonymizing all at once
    assert(anon_line == individually_anon_line)

    for ip_addr in ip_addrs:
        # Make sure the original ip address(es) are removed from the anonymized line
        assert(ip_addr not in anon_line)


def get_ip_class(ip_int):
    """Return the letter corresponding to the IP class the ip_int is in."""
    if ((ip_int & 0x80000000) == 0x00000000):
        return 'A'
    elif ((ip_int & 0xC0000000) == 0x80000000):
        return 'B'
    elif ((ip_int & 0xE0000000) == 0xC0000000):
        return 'C'
    elif ((ip_int & 0xF0000000) == 0xE0000000):
        return 'D'
    else:
        return 'E'


def get_ip_class_mask(ip_int):
    """Return a mask indicating bits preserved when preserving class."""
    if (ip_int & 0xE0000000) == 0xE0000000:
        return 0xF0000000
    elif (ip_int & 0xC0000000) == 0xC0000000:
        return 0xE0000000
    elif (ip_int & 0x80000000) == 0x80000000:
        return 0xC0000000
    else:
        return 0x80000000


@pytest.mark.parametrize('ip_addr', [
    '0.0.0.0', '127.255.255.255',  # Class A
    '128.0.0.0', '191.255.255.255',  # Class B
    '192.0.0.0', '223.255.255.255',  # Class C
    '224.0.0.0', '239.255.255.255',  # Class D
    '240.0.0.0', '247.255.255.255',  # Class E
])
def test_v4_class_preserved(flip_anonymizer, ip_addr):
    """Test that IPv4 classes are preserved."""
    ip_int = int(flip_anonymizer.make_addr(ip_addr))
    ip_int_anon = flip_anonymizer.anonymize(ip_int)

    # IP v4 class should match after anonymization
    assert(get_ip_class(ip_int) == get_ip_class(ip_int_anon))

    # Anonymized ip address should not match the original ip address
    assert(ip_int != ip_int_anon)

    # All bits that are not forced to be preserved are flipped
    class_mask = get_ip_class_mask(ip_int)
    assert(0xFFFFFFFF ^ class_mask == ip_int ^ ip_int_anon)


@pytest.mark.parametrize('ip_addr', ip_list)
def test_anonymize(anonymizer, ip_addr):
    """Test conversion from original to anonymized IP address."""
    ip_int = int(anonymizer.make_addr(ip_addr))
    ip_int_anon = anonymizer.anonymize(ip_int)

    # Anonymized ip address should not match the original address
    assert(ip_int != ip_int_anon)

    # Confirm prefixes for similar addresses are preserved after anonymization
    for i in range(0, 32):
        # Flip the ith bit of the org address and use that as the similar address
        diff_mask = (1 << i)
        ip_int_similar = ip_int ^ diff_mask
        ip_int_similar_anon = anonymizer.anonymize(ip_int_similar)

        # Using i + 1 since same_mask should mask off ith bit, not preserve it
        same_mask = 0xFFFFFFFF & (0xFFFFFFFF << (i + 1))

        # Common prefix for addresses should match after anonymization
        assert(ip_int_similar_anon & same_mask == ip_int_anon & same_mask)

        # Confirm the bit that is different in the original addresses is different in the anonymized addresses
        assert(ip_int_similar_anon & diff_mask != ip_int_anon & diff_mask)


def test_anonymize_ip_order_independent():
    """Test to make sure order does not affect anonymization of addresses."""
    anonymizer_forward = IpAnonymizer(SALT)
    ip_lookup_forward = {}
    for ip_addr in ip_list:
        ip_int = int(anonymizer_forward.make_addr(ip_addr))
        ip_int_anon = anonymizer_forward.anonymize(ip_int)
        ip_lookup_forward[ip_int] = ip_int_anon

    anonymizer_reverse = IpAnonymizer(SALT)
    for ip_addr in reversed(ip_list):
        ip_int_reverse = int(anonymizer_reverse.make_addr(ip_addr))
        ip_int_anon_reverse = anonymizer_reverse.anonymize(ip_int_reverse)
        # Confirm anonymizing in reverse order does not affect
        # anonymization results
        assert(ip_int_anon_reverse == ip_lookup_forward[ip_int_reverse])

    anonymizer_extras = IpAnonymizer(SALT)
    for ip_addr in ip_list:
        ip_int_extras = int(anonymizer_extras.make_addr(ip_addr))
        ip_int_anon_extras = anonymizer_extras.anonymize(ip_int_extras)
        ip_int_inverted = ip_int_extras ^ 0xFFFFFFFF
        anonymizer_extras.anonymize(ip_int_inverted)
        # Confirm anonymizing with extra addresses in-between does not
        # affect anonymization results
        assert(ip_int_anon_extras == ip_lookup_forward[ip_int_extras])


@pytest.mark.parametrize('ip_addr', ip_list)
def test_deanonymize_ip(anonymizer, ip_addr):
    """Test reversing IP anonymization."""
    ip_int = int(anonymizer.make_addr(ip_addr))
    ip_int_anon = anonymizer.anonymize(ip_int)
    ip_int_unanon = anonymizer.deanonymize(ip_int_anon)

    # Make sure unanonymizing an anonymized address produces the original address
    assert(ip_int == ip_int_unanon)


def test_dump_iptree(tmpdir, anonymizer):
    """Test ability to accurately dump IP address anonymization mapping."""
    ip_mapping = {}
    ip_mapping_from_dump = {}

    # Make sure all addresses to be checked are in ip_tree and generate reference mapping
    for ip_addr in ip_list:
        ip_int = int(anonymizer.make_addr(ip_addr))
        ip_int_anon = anonymizer.anonymize(ip_int)
        ip_addr_anon = str(ipaddress.IPv4Address(ip_int_anon))
        ip_mapping[ip_addr] = ip_addr_anon

    filename = str(tmpdir.mkdir("test").join("test_dump_iptree.txt"))
    with open(filename, 'w') as f_tmp:
        anonymizer.dump_to_file(f_tmp)

    with open(filename, 'r') as f_tmp:
        # Build mapping dict from the output of the ip_tree dump
        for line in f_tmp.readlines():
            m = regex.match('\s*(\d+\.\d+.\d+.\d+)\s+(\d+\.\d+.\d+.\d+)\s*', line)
            ip_addr = m.group(1)
            ip_addr_anon = m.group(2)
            ip_mapping_from_dump[ip_addr] = ip_addr_anon

    for ip_addr in ip_mapping:
        # Confirm anon addresses from ip_tree dump match anon addresses from _convert_to_anon_ip
        assert(ip_mapping[ip_addr] == ip_mapping_from_dump[ip_addr])


@pytest.mark.parametrize('zeros, no_zeros', [
                         ('0.0.0.0', '0.0.0.0'),
                         ('0.0.0.3', '0.0.0.3'),
                         ('128.0.0.0', '128.0.0.0'),
                         ('0.127.0.0', '0.127.0.0'),
                         ('10.73.212.5', '10.73.212.5'),
                         ('010.73.212.05', '10.73.212.5'),
                         ('255.255.255.255', '255.255.255.255'),
                         ('170.255.85.1', '170.255.85.1'),
                         ('10.11.12.13', '10.11.12.13'),
                         ('010.11.12.13', '10.11.12.13'),
                         ('10.011.12.13', '10.11.12.13'),
                         ('10.11.012.13', '10.11.12.13'),
                         ('10.11.12.013', '10.11.12.13'),
                         ('010.0011.00000012.000', '10.11.12.0'),
                         ])
def test_v4_anonymizer_ignores_leading_zeros(zeros, no_zeros):
    """Test that v4 IP address ignore leading zeros & don't interpret octal."""
    assert(ipaddress.IPv4Address(no_zeros) == IpAnonymizer.make_addr(zeros))


@pytest.mark.parametrize('possible_mask, expected', [
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
                         (0b00000000010000000100000000000000, False),
                         ])
def test__is_mask(possible_mask, expected):
    """Test ability to detect masks vs IP addresses."""
    assert(expected == _is_mask(possible_mask, 32))
