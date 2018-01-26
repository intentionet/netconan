"""Test anonymization of IP addresses and related functions."""

import ipaddress
import pytest
import regex

from conan.ip_anonymization import tree_node, anonymize_ip_addr, _convert_to_anon_ip, _ip_to_int, _is_mask

ip_list = [('10.11.12.13'),
           ('10.10.10.10'),
           ('10.1.1.17'),
           ('237.73.212.5'),
           ('123.45.67.89'),
           ('92.210.0.255'),
           ('128.7.55.12'),
           ('223.123.21.99')]

SALT = 'saltForTest'


@pytest.fixture(scope='module')
def ip_tree():
    """Generate an IP tree once for all tests in this module."""
    root = tree_node(None)
    root.preserve_ipv4_class()
    return root


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
                         ('something host {} host {} host {}', ['1.2.3.4', '1.2.3.5', '1.2.3.45'])
                         ])
def test_anonymize_ip_addr(ip_tree, line, ip_addrs):
    """Test IP address removal config lines."""
    line_w_ip = line.format(*ip_addrs)
    anon_line = anonymize_ip_addr(ip_tree, line_w_ip, SALT)

    # Now anonymize each IP address individually & build another anonymized line
    anon_ip_addrs = [anonymize_ip_addr(ip_tree, ip_addr, SALT) for ip_addr in ip_addrs]
    individually_anon_line = line.format(*anon_ip_addrs)

    # Make sure anonymizing each address individually is the same as
    # anonymizing all at once
    assert(anon_line == individually_anon_line)

    for ip_addr in ip_addrs:
        # Make sure the original ip address(es) are removed from the anonymized line
        assert(ip_addr not in anon_line)


def check_ip_class(ip_int):
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


@pytest.mark.parametrize('ip_addr', ip_list)
def test__convert_to_anon_ip(ip_tree, ip_addr):
    """Test conversion from original to anonymized IP address."""
    ip_int = _ip_to_int(ip_addr)
    ip_int_anon = _convert_to_anon_ip(ip_tree, ip_int, SALT)

    # Anonymized ip address should not match the original address
    assert(ip_int != ip_int_anon)

    # Anonymized ip address class should match the class of the original ip address
    assert(check_ip_class(ip_int) == check_ip_class(ip_int_anon))

    # Confirm prefixes for similar addresses are preserved after anonymization
    for i in range(0, 32):
        # Flip the ith bit of the org address and use that as the similar address
        diff_mask = (1 << i)
        ip_int_similar = ip_int ^ diff_mask
        ip_int_similar_anon = _convert_to_anon_ip(ip_tree, ip_int_similar, SALT)

        # Using i + 1 since same_mask should mask off ith bit, not preserve it
        same_mask = 0xFFFFFFFF & (0xFFFFFFFF << (i + 1))

        # Common prefix for addresses should match after anonymization
        assert(ip_int_similar_anon & same_mask == ip_int_anon & same_mask)

        # Confirm the bit that is different in the original addresses is different in the anonymized addresses
        assert(ip_int_similar_anon & diff_mask != ip_int_anon & diff_mask)


def test__convert_to_anon_ip_order_independent():
    """Test to make sure order does not affect anonymization of addresses."""
    ip_tree_forward = tree_node(None)
    ip_tree_forward.preserve_ipv4_class()
    ip_lookup_forward = {}
    for ip_addr in ip_list:
        ip_int = _ip_to_int(ip_addr)
        ip_int_anon = _convert_to_anon_ip(ip_tree_forward, ip_int, SALT)
        ip_lookup_forward[ip_int] = ip_int_anon

    ip_tree_reverse = tree_node(None)
    ip_tree_reverse.preserve_ipv4_class()
    for ip_addr in reversed(ip_list):
        ip_int_reverse = _ip_to_int(ip_addr)
        ip_int_anon_reverse = _convert_to_anon_ip(ip_tree_reverse, ip_int_reverse, SALT)
        # Confirm training the tree in reverse order does not affect
        # anonymization results
        assert(ip_int_anon_reverse == ip_lookup_forward[ip_int_reverse])

    ip_tree_extras = tree_node(None)
    ip_tree_extras.preserve_ipv4_class()
    for ip_addr in ip_list:
        ip_int_extras = _ip_to_int(ip_addr)
        ip_int_anon_extras = _convert_to_anon_ip(ip_tree_extras, ip_int_extras, SALT)
        ip_int_inverted = ip_int_extras ^ 0xFFFFFFFF
        _convert_to_anon_ip(ip_tree_extras, ip_int_inverted, SALT)
        # Confirm training the tree with extra addresses in-between does not
        # affect anonymization results
        assert(ip_int_anon_extras == ip_lookup_forward[ip_int_extras])


def test_dump_iptree(tmpdir, ip_tree):
    """Test ability to accurately dump IP address anonymization mapping."""
    ip_mapping = {}
    ip_mapping_from_dump = {}

    # Make sure all addresses to be checked are in ip_tree and generate reference mapping
    for ip_addr in ip_list:
        ip_int = _ip_to_int(ip_addr)
        ip_int_anon = _convert_to_anon_ip(ip_tree, ip_int, SALT)
        ip_addr_anon = str(ipaddress.IPv4Address(ip_int_anon))
        ip_mapping[ip_addr] = ip_addr_anon

    filename = str(tmpdir.mkdir("test").join("test_dump_iptree.txt"))
    with open(filename, 'w') as f_tmp:
        ip_tree.dump_to_file(f_tmp)

    with open(filename, 'r') as f_tmp:
        # Build mapping dict from the output of the ip_tree dump
        for line in f_tmp.readlines():
            m = regex.match('\s*(\d+\.\d+.\d+.\d+)\s+(\d+\.\d+.\d+.\d+)\s*', line)
            ip_addr = m.group(1)
            ip_addr_anon = m.group(2)
            print('{}\t{}'.format(ip_addr, ip_addr_anon))
            ip_mapping_from_dump[ip_addr] = ip_addr_anon

    for ip_addr in ip_mapping:
        # Confirm anon addresses from ip_tree dump match anon addresses from _convert_to_anon_ip
        assert(ip_mapping[ip_addr] == ip_mapping_from_dump[ip_addr])


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
