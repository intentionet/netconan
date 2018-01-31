"""Identify and anonymize IP addresses."""

from bidict import bidict
import ipaddress
import logging
import regex

from hashlib import md5
from six import iteritems, u


class BaseIpAnonymizer():
    def __init__(self, salt, length):
        self.salt = salt
        self.cache = bidict({'': ''})
        self.length = length
        self.fmt = '{:0lengthb}'.replace('length', str(length))

    def anonymize(self, ip_int):
        bits = self.fmt.format(ip_int)
        anon_bits = self._anonymize_bits(bits)
        return int(anon_bits, 2)

    def _anonymize_bits(self, bits):
        ret = self.cache.get(bits)
        if ret is not None:
            return ret

        head, last = bits[:-1], int(bits[-1])
        flip_last = _generate_bit_from_hash(self.salt + head)
        ret = self._anonymize_bits(head) + str(flip_last ^ last)

        # Cache before returning.
        self.cache[bits] = ret
        return ret

    def deanonymize(self, ip_int):
        bits = self.fmt.format(ip_int)
        anon_bits = self._deanonymize_bits(bits)
        return int(anon_bits, 2)

    def _deanonymize_bits(self, bits):
        ret = self.cache.inv.get(bits)
        if ret is not None:
            return ret

        head, last = bits[:-1], int(bits[-1])
        orig_head = self._deanonymize_bits(head)
        flip_last = _generate_bit_from_hash(self.salt + orig_head)
        ret = orig_head + str(flip_last ^ last)

        # Cache before returning.
        self.cache.inv[bits] = ret
        return ret

    def dump_to_file(self, file_out):
        ips = ((bits, anon_bits)
               for bits, anon_bits in iteritems(self.cache)
               if len(bits) == self.length)
        for bits, anon_bits in ips:
            ip = self._ip_to_str(bits)
            anon = self._ip_to_str(anon_bits)
            file_out.write('{}\t{}\n'.format(ip, anon))

    def _ip_to_str(self, bits):
        raise NotImplementedError()


class IpAnonymizer(BaseIpAnonymizer):
    def __init__(self, salt):
        super(IpAnonymizer, self).__init__(salt, 32)
        # preserve IPv4 classes
        for i in range(16):
            bits = '{:04b}'.format(i)
            self.cache[bits] = bits

    def _ip_to_str(self, bits):
        return str(ipaddress.IPv4Address(int(bits, 2)))


class IpV6Anonymizer(BaseIpAnonymizer):
    def __init__(self, salt):
        super(IpV6Anonymizer, self).__init__(salt, 128)

    def _ip_to_str(self, bits):
        return str(ipaddress.IPv6Address(int(bits, 2)))


def anonymize_ip_addr(anonymizer, line, undo_ip_anon=False):
    """Replace each IP address in the line with an anonymized IP address.

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
                new_ip = anonymizer.deanonymize(ip_int)
            else:
                new_ip = anonymizer.anonymize(ip_int)
            new_ip_str = str(ipaddress.IPv4Address(new_ip))
            ip_addrs.append(new_ip_str)
            logging.debug("Replaced {} with {}".format(ip_str, new_ip_str))

    return new_line.format(*ip_addrs)


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
