"""Identify and anonymize IP addresses."""

import ipaddress
import logging
import regex

from hashlib import md5
from six import u


class tree_node():
    """Simple binary tree with a value, left node, and right node.

    This is used for holding a translation from original to anonymized IP
    addresses.
    """

    def __init__(self, value):
        """Initialize new node."""
        self.left = None
        self.right = None
        self.value = value

    def dump_to_file(self, file_out, depth=0, input_addr=0, output_addr=0):
        """Recursively traverse tree and write translations to output file."""
        # Root node value does not contribute to output_addr, so only update
        # output_addr for nodes after root (depth > 0)
        if depth > 0:
            output_addr = (output_addr << 1) + self.value

        # Only dump nodes at max depth (32) i.e. full 32bit anonymization
        if depth == 32:
            org_ip_str = str(ipaddress.IPv4Address(input_addr))
            new_ip_str = str(ipaddress.IPv4Address(output_addr))
            logging.debug('dumped {}\t{}'.format(org_ip_str, new_ip_str))
            file_out.write('{}\t{}\n'.format(org_ip_str, new_ip_str))
            return

        depth += 1
        if self.left is not None:
            left_path = (input_addr << 1)
            self.left.dump_to_file(file_out, depth, left_path, output_addr)
        if self.right is not None:
            right_path = (input_addr << 1) + 1
            self.right.dump_to_file(file_out, depth, right_path, output_addr)

    def preserve_ipv4_class(self):
        """Initialize tree to preserve IPv4 classes (call only on root node)."""
        node = self
        # IP classes are defined by the number of leading 1's in the address up
        # to the fourth 1, so setup the tree to preserve those
        for i in range(0, 4):
            node.left = tree_node(0)
            node.right = tree_node(1)
            node = node.right


def convert_ip_addr(my_ip_tree, line, salt, undo_ip_anon=False):
    """Replace each IP address in the line with an (un)anonymized IP address.

    Quad-octets that look like masks will be left unchanged.  That is, any
    quad-octet that consists solely of an initial group of 1s followed by 0s
    or initial 0s followed by 1s will be unchanged.

    If undo_ip_anon is True, then each IP address encountered will be
    treated as an address already anonymized using the specified salt, and it
    will be replaced with the unanonymized address.
    """
    pattern = '((\d{1,3})\.\d{1,3}\.\d{1,3}\.\d{1,3})(?=/(\d{1,3}))?'
    matches = regex.findall(pattern, line)
    if matches is None:
        return line

    # Escape existing curly braces since string.format will be used to insert
    # anonymized IP addresses
    new_line = line.replace('{', '{{')
    new_line = new_line.replace('}', '}}')
    new_line = regex.sub(pattern, '{}', new_line)

    ip_addrs = []
    for match in matches:
        ip_str = match[0]
        first_octet = match[1]
        ip_int = _ip_to_int(ip_str)
        if _is_mask(ip_int):
            logging.debug("Skipping mask {}".format(ip_str))
            ip_addrs.append(ip_str)
        elif int(first_octet) >= 224:
            # TODO: consider just removing this and anonymizing (if preserving
            # class), but skipping anything in IP class D and class E for now
            logging.debug("Skipping addresses reserved for multicast and R&D {}"
                          .format(ip_str))
            ip_addrs.append(ip_str)
        else:
            if undo_ip_anon:
                new_ip = _convert_to_unanon_ip(ip_int, salt)
            else:
                new_ip = _convert_to_anon_ip(my_ip_tree, ip_int, salt)
            new_ip_str = str(ipaddress.IPv4Address(new_ip))
            ip_addrs.append(new_ip_str)
            logging.debug("Replaced {} with {}".format(ip_str, new_ip_str))

    return new_line.format(*ip_addrs)


def _convert_to_anon_ip(node, ip_int, salt):
    """Anonymize an IP address using an existing IP tree root node.

    The bits of a given source IP address define a branch in the binary tree,
    where each source bit selects an edge (1=right, 0=left) from the previous
    node and the value at the next node is the anonymized bit.  This process
    is repeated until all prefix bits are exhausted.  The values at each node
    are pseudorandomly generated as needed and are the inverse of their sibling.
    """
    new_ip_int = 0

    for i in range(31, -1, -1):
        # msb is the next bit to anonymize
        msb = (ip_int >> i) & 1
        if node.left is None:
            # Use a salted hash as a deterministic bit generator here so address
            # anonymization is the same regardless of order/context

            # This is a string of all source bits preceding the one to be anonymized
            preceding_bits = '{:032b}'.format(ip_int)[:31 - i]
            anon_bit = _generate_bit_from_hash(salt + preceding_bits)

            # Go ahead and populate both left and right nodes, sacrificing
            # space to simplify control flow
            node.left = tree_node(anon_bit)
            node.right = tree_node(1 - anon_bit)
        if msb:
            node = node.right
        else:
            node = node.left
        new_ip_int |= node.value << i
    return new_ip_int


def _convert_to_unanon_ip(anon_ip_int, salt, preserve_ipv4_class=True):
    """Reverse hash-based anonymization for the anonymized IP int and salt."""
    unanon_ip_int = 0
    preceding_bits = ''
    for i in range(31, -1, -1):
        anon_bit = (anon_ip_int >> i) & 1
        if preserve_ipv4_class:
            # Preserve number of leading ones (up to the 4th bit) to preserve class
            unanon_bit = anon_bit
            if not anon_bit or i < 29:
                preserve_ipv4_class = False
        else:
            # This is the value of the anonymized bit if unanonymized bit was 0
            zero_bit = _generate_bit_from_hash(salt + preceding_bits)
            # So, if zero_bit = anon_bit, then unanon bit is 0
            unanon_bit = zero_bit ^ anon_bit
        preceding_bits += str(unanon_bit)
        unanon_ip_int |= unanon_bit << i
    return unanon_ip_int


def _generate_bit_from_hash(hash_input):
    """Return the last bit of the result from hashing the input string."""
    last_hash_digit = md5((hash_input).encode()).hexdigest()[-1]
    return int(last_hash_digit, 16) & 1


def _ip_to_int(ip_str):
    """Convert an IP address string to integer representation."""
    # Need to strip leading zeros so ipaddress does not assume octal notation
    ip_str = regex.sub('0*(\d+)\.0*(\d+)\.0*(\d+)\.0*(\d+)',
                       r'\1.\2.\3.\4', ip_str)
    ip_int = int(ipaddress.IPv4Address(u(ip_str)))
    return int(ip_int)


def _is_mask(possible_mask_int):
    """Determine if the input int is a mask or not.

    If the binary representation starts with all 1s and ends with all 0s
    (or starts with 0s and ends with 1s), then we assume it is a mask.

    Counting the number of times consecutive bits do not match (transitions)
    gives us a reasonable idea of whether or not something is a mask.  With 0
    or 1 transitions, assume the value is a mask.
    e.g. 1100 has only one place where consecutive bits don't match
         0000 has zero
         0110 has two
         0101 has three
    """
    prev_bit = possible_mask_int & 1
    delta_count = 0
    for pos in range(1, 32):
        cur_bit = (possible_mask_int >> pos) & 1
        delta_count += (prev_bit ^ cur_bit)
        prev_bit = cur_bit
    return (delta_count < 2)
