"""Identify and anonymize IP addresses."""

import logging
import random
import re


class tree_node():
    """Simple binary tree with a value, left node, and right node."""

    def __init__(self, value):
        """Initialize new node."""
        self.left = None
        self.right = None
        self.value = value


def anonymize_ip_addr(my_ip_tree, line):
    """Replace each IP address in the line with an anonymized IP address.

    Quad-octets that look like masks will be left unchanged.  That is, any
    quad-octet that consists solely of an initial group of 1s followed by 0s
    or initial 0s followed by 1s will be unchanged.
    """
    pattern = '((\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3}))(/(\d{1,3}))?'
    matches = re.findall(pattern, line)
    if matches is None:
        return line
    for match in matches:
        ip_str = match[0]
        byte1 = int(match[1])
        byte2 = int(match[2])
        byte3 = int(match[3])
        byte4 = int(match[4])
        ip_int = _ip_addr_to_int(byte1, byte2, byte3, byte4)
        if _is_mask(ip_int):
            logging.debug("Skipping mask {}".format(ip_str))
            continue

        if len(match[6]) > 0:
            subnet_bits = int(match[6])
        else:
            subnet_bits = 32

        new_ip = _convert_to_anon_ip(my_ip_tree, ip_int, subnet_bits)
        new_ip_str = _ip_int_to_str(new_ip)
        line = line.replace(ip_str, new_ip_str)

        logging.debug("Replaced {} with {}".format(ip_str, new_ip_str))
    return line


def _convert_to_anon_ip(node, ip_int, subnet_bits=32):
    """Anonymize an IP address using an existing IP tree root node.

    If there is not already an anonymized address for the input address,
    one is generated.
    """
    i = 32
    new_ip_int = 0
    zeros_count = 32 - subnet_bits

    # Shift bits onto new_ip_int from the ip tree
    while i > zeros_count:
        i -= 1
        msb = (ip_int >> i) & 1
        new_ip_int = (new_ip_int << 1)
        # Go ahead and populate both child nodes
        # Sacrifice some space to simplify control flow
        if node.left is None:
            node.left = tree_node(random.randint(0, 1))
            node.right = tree_node(1 - node.left.value)
        if msb:
            node = node.right
            new_ip_int += node.value
        else:
            node = node.left
            new_ip_int += node.value
    new_ip_int = new_ip_int << zeros_count
    return new_ip_int


def _ip_addr_to_int(byte0, byte1, byte2, byte3):
    """Convert four bytes of an IP address into a single integer."""
    return (byte0 << 24) + (byte1 << 16) + (byte2 << 8) + byte3


def _ip_int_to_str(ip_addr):
    """Convert integer IP address into a quad-octet-style string."""
    byte4 = str(ip_addr & 0xFF)
    byte3 = str((ip_addr >> 8) & 0xFF)
    byte2 = str((ip_addr >> 16) & 0xFF)
    byte1 = str((ip_addr >> 24) & 0xFF)
    return "{}.{}.{}.{}".format(byte1, byte2, byte3, byte4)


def _is_mask(possible_mask_int):
    """Determine if the input int is a mask or not.

    If the binary representation starts with all 1s and ends with all 0s
    (or starts with 0s and ends with 1s), then we assume it is a mask.
    """
    # Counting the number of times consecutive bits do not match (transitions)
    # gives us a reasonable idea of whether or not something is a mask
    # e.g.  1100 has only one place where consecutive bits don't match
    #       0000 has zero
    #       0110 has two
    #       0101 has three
    prev_bit = possible_mask_int & 1
    delta_count = 0
    for pos in range(1, 32):
        cur_bit = (possible_mask_int >> pos) & 1
        delta_count += (prev_bit ^ cur_bit)
        prev_bit = cur_bit
    # With 0 or 1 transitions, we will assume the value is a mask
    return (delta_count < 2)
