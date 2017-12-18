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
        byte0 = int(match[1])
        byte1 = int(match[2])
        byte2 = int(match[3])
        byte3 = int(match[4])
        ip_int = _ip_addr_to_int(byte0, byte1, byte2, byte3)
        if _is_mask(ip_int):
            logging.debug("Skipping mask {}".format(ip_str))
            continue

        if len(match[6]) > 0:
            prefix_bits = int(match[6])
        else:
            prefix_bits = 32

        new_ip = _convert_to_anon_ip(my_ip_tree, ip_int, prefix_bits)
        new_ip_str = _ip_int_to_str(new_ip)
        line = line.replace(ip_str, new_ip_str)

        logging.debug("Replaced {} with {}".format(ip_str, new_ip_str))
    return line


def _convert_to_anon_ip(node, ip_int, prefix_bits=32):
    """Anonymize an IP address using an existing IP tree root node.

    If there is not already an anonymized address for the input address,
    one is generated and added to the tree.
    """
    new_ip_int = 0
    for i in range(31, 31 - prefix_bits, -1):
        # This is the next bit to anonymize
        msb = (ip_int >> i) & 1
        # Go ahead and populate both left and right nodes
        # Sacrifice space to simplify control flow
        if node.left is None:
            node.left = tree_node(random.randint(0, 1))
            node.right = tree_node(1 - node.left.value)
        if msb:
            node = node.right
        else:
            node = node.left
        new_ip_int |= node.value << i
    return new_ip_int


def _ip_addr_to_int(byte0, byte1, byte2, byte3):
    """Convert four bytes of an IP address into a single integer."""
    return (byte0 << 24) + (byte1 << 16) + (byte2 << 8) + byte3


def _ip_int_to_str(ip_addr):
    """Convert integer IP address into a quad-octet-style string."""
    byte3 = str(ip_addr & 0xFF)
    byte2 = str((ip_addr >> 8) & 0xFF)
    byte1 = str((ip_addr >> 16) & 0xFF)
    byte0 = str((ip_addr >> 24) & 0xFF)
    return "{}.{}.{}.{}".format(byte0, byte1, byte2, byte3)


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
