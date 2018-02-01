"""Identify and anonymize IP addresses."""

from abc import ABCMeta, abstractmethod
from bidict import bidict
import ipaddress
import logging
import re

from hashlib import md5
from six import add_metaclass, iteritems


# Deliberately catching more than valid IPs so we can remove 0s later.
IPv4_PATTERN = re.compile(
    r'((\d{1,3})\.\d{1,3}\.\d{1,3}\.\d{1,3})(?=/(\d{1,3}))?')

# Modified from https://stackoverflow.com/a/17871737/1715495
IPv6_PATTERN = re.compile(
    r'(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}'
    '|([0-9a-fA-F]{1,4}:){1,7}:'
    '|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}'
    '|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}'
    '|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}'
    '|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}'
    '|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}'
    '|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})'
    '|:((:[0-9a-fA-F]{1,4}){1,7}|:)'
    '|[fF][eE]80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}'
    '|::([fF][fF][fF][fF](:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])'
    '|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))')


def _generate_bit_from_hash(salt, string):
    """Return the last bit of the result from hashing the input string."""
    last_hash_digit = md5((salt + string).encode()).hexdigest()[-1]
    return int(last_hash_digit, 16) & 1


@add_metaclass(ABCMeta)
class _BaseIpAnonymizer:
    def __init__(self, salt, length, salter=_generate_bit_from_hash):
        self.salt = salt
        self.cache = bidict({'': ''})
        self.length = length
        self.fmt = '{{:0{length}b}}'.format(length=length)
        self.salter = salter

    def anonymize(self, ip_int):
        bits = self.fmt.format(ip_int)
        anon_bits = self._anonymize_bits(bits)
        return int(anon_bits, 2)

    def _anonymize_bits(self, bits):
        ret = self.cache.get(bits)
        if ret is not None:
            return ret

        head, last = bits[:-1], int(bits[-1])
        flip_last = self.salter(self.salt, head)
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
        flip_last = self.salter(self.salt, orig_head)
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

    @classmethod
    @abstractmethod
    def _ip_to_str(cls, bits):
        raise NotImplementedError()

    @classmethod
    @abstractmethod
    def get_addr_pattern(cls):
        raise NotImplementedError()

    @classmethod
    @abstractmethod
    def make_addr(cls, addr_str):
        raise NotImplementedError()

    @classmethod
    @abstractmethod
    def make_addr_from_int(cls, ip_int):
        raise NotImplementedError()


class IpAnonymizer(_BaseIpAnonymizer):
    """An anonymizer for IPv4 addresses."""

    _DROP_ZEROS_PATTERN = re.compile(r'0*(\d+)\.0*(\d+)\.0*(\d+)\.0*(\d+)')

    def __init__(self, salt, **kwargs):
        """Create an anonymizer using the specified salt."""
        super(IpAnonymizer, self).__init__(salt, 32, **kwargs)
        # preserve IPv4 classes
        for i in range(4):
            bits = '1' * i
            self.cache[bits + '1'] = bits + '1'
            self.cache[bits + '0'] = bits + '0'

    @classmethod
    def _ip_to_str(cls, bits):
        return str(ipaddress.IPv4Address(int(bits, 2)))

    @classmethod
    def get_addr_pattern(cls):
        """Return a compiled regex pattern to recognize IPv4 addresses."""
        return IPv4_PATTERN

    @classmethod
    def make_addr(cls, addr_str):
        """
        Return an IPv4 address from the given string.

        If the octets in `addr_str` have leading zeros, such as in 1.2.3.040,
        those zeros will be ignored (1.2.3.40) -- they will NOT be interpreted
        as octal (1.2.3.32).
        """
        addr_str = IpAnonymizer._DROP_ZEROS_PATTERN.sub(r'\1.\2.\3.\4', addr_str)
        return ipaddress.IPv4Address(addr_str)

    @classmethod
    def make_addr_from_int(cls, ip_int):
        """Return an IPv4 address with the given int representation."""
        return ipaddress.IPv4Address(ip_int)


class IpV6Anonymizer(_BaseIpAnonymizer):
    """An anonymizer for IPv6 addresses."""

    def __init__(self, salt, **kwargs):
        """Create an anonymizer using the specified salt."""
        super(IpV6Anonymizer, self).__init__(salt, 128, **kwargs)

    @classmethod
    def _ip_to_str(cls, bits):
        return str(ipaddress.IPv6Address(int(bits, 2)))

    @classmethod
    def get_addr_pattern(cls):
        """Return a compiled regex pattern to recognize IPv6 addresses."""
        return IPv6_PATTERN

    @classmethod
    def make_addr(cls, addr_str):
        """Return an IPv6 address from the given string."""
        return ipaddress.IPv6Address(addr_str)

    @classmethod
    def make_addr_from_int(cls, ip_int):
        """Return an IPv6 address with the given int representation."""
        return ipaddress.IPv6Address(ip_int)


def anonymize_ip_addr(anonymizer, line, undo_ip_anon=False):
    """Replace each IP address in the line with an anonymized IP address.

    Masks will be unchanged. That is, any IP address that, when written in
    binary, that consists solely of an initial group of 1s followed by 0s
    or initial 0s followed by 1s will be unchanged.

    If undo_ip_anon is True, then each IP address encountered will be
    treated as an address already anonymized using the specified salt, and it
    will be replaced with the unanonymized address.
    """
    pattern = anonymizer.get_addr_pattern()
    matches = pattern.findall(line)
    if matches is None:
        return line

    # Escape existing curly braces, then replace IPs to be substituted with {}.
    # `string.format` will be used to replace them later.
    new_line = line.replace('{', '{{').replace('}', '}}')
    new_line = pattern.sub('{}', new_line)

    ip_addrs = []
    for match in matches:
        ip = anonymizer.make_addr(match[0])
        ip_int = int(ip)
        if _is_mask(ip_int, anonymizer.length):
            logging.debug("Skipping mask {}".format(ip))
            ip_addrs.append(ip)
        else:
            if undo_ip_anon:
                new_ip_int = anonymizer.deanonymize(ip_int)
            else:
                new_ip_int = anonymizer.anonymize(ip_int)
            new_ip = anonymizer.make_addr_from_int(new_ip_int)
            ip_addrs.append(new_ip)
            logging.debug("Replacing {} with {}".format(ip, new_ip))

    return new_line.format(*ip_addrs)


def _is_mask(possible_mask_int, length):
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
    flipped = False
    for pos in range(1, length):
        cur_bit = (possible_mask_int >> pos) & 1
        if prev_bit != cur_bit:
            if flipped:
                return False
            else:
                flipped = True
        prev_bit = cur_bit

    return True
