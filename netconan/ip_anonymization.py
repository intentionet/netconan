"""Identify and anonymize IP addresses."""
#   Copyright 2018 Intentionet
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.

from abc import ABCMeta, abstractmethod

from bidict import bidict
import ipaddress
import logging
# Need regex instead of re for variable look behind
import regex

from hashlib import md5
from six import add_metaclass, iteritems, text_type, u


_IPv4_OCTET_PATTERN = r'(25[0-5]|(2[0-4]|1?[0-9])?[0-9])'

# Deliberately allowing leading zeros and will remove them later
IPv4_PATTERN = regex.compile(
    r'(?<=^|[\s:<>/\'",=\(])((0*{octet}\.){{3}}0*{octet})'
    r'(?=/(\d{{1,3}}))?(?=[-\s:<>/\'",=\]\)]|$)'.format(octet=_IPv4_OCTET_PATTERN))

# Modified from https://stackoverflow.com/a/17871737/1715495
IPv6_PATTERN = regex.compile(
    r'(?<=^|[\s<>/\'",=\(])(([0-9a-f]{1,4}:){7,7}[0-9a-f]{1,4}'
    r'|([0-9a-f]{1,4}:){1,7}:'
    r'|([0-9a-f]{1,4}:){1,6}:[0-9a-f]{1,4}'
    r'|([0-9a-f]{1,4}:){1,5}(:[0-9a-f]{1,4}){1,2}'
    r'|([0-9a-f]{1,4}:){1,4}(:[0-9a-f]{1,4}){1,3}'
    r'|([0-9a-f]{1,4}:){1,3}(:[0-9a-f]{1,4}){1,4}'
    r'|([0-9a-f]{1,4}:){1,2}(:[0-9a-f]{1,4}){1,5}'
    r'|[0-9a-f]{1,4}:((:[0-9a-f]{1,4}){1,6})'
    r'|:((:[0-9a-f]{1,4}){1,7}|:)'
    r'|fe80:(:[0-9a-f]{0,4}){0,4}%[0-9a-z]{1,}' +
    r'|::(ffff(:0{{1,4}})?:)?({octet}\.){{3}}{octet}'
    r'|([0-9a-f]{{1,4}}:){{1,4}}:({octet}\.){{3}}{octet})'.format(
        octet=_IPv4_OCTET_PATTERN) +
    r'(?=[-\s<>/\'",=\]\)]|$)',
    regex.IGNORECASE)


def _generate_bit_from_hash(salt, string):
    """Return the last bit of the result from hashing the input string."""
    last_hash_digit = md5((salt + string).encode()).hexdigest()[-1]
    return int(last_hash_digit, 16) & 1


def _ensure_unicode(str):
    if not isinstance(str, text_type):
        str = u(str)
    return str


@add_metaclass(ABCMeta)
class _BaseIpAnonymizer(object):
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
    def _ip_to_str(cls, bits):
        return str(cls.make_addr_from_int(int(bits, 2)))

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

    @abstractmethod
    def should_anonymize(self, ip_int):
        raise NotImplementedError()


class IpAnonymizer(_BaseIpAnonymizer):
    """An anonymizer for IPv4 addresses."""

    _DROP_ZEROS_PATTERN = regex.compile(r'0*(\d+)\.0*(\d+)\.0*(\d+)\.0*(\d+)')

    def __init__(self, salt, **kwargs):
        """Create an anonymizer using the specified salt."""
        super(IpAnonymizer, self).__init__(salt, 32, **kwargs)
        # preserve IPv4 classes
        for i in range(4):
            bits = '1' * i
            self.cache[bits + '1'] = bits + '1'
            self.cache[bits + '0'] = bits + '0'

    def _is_mask(self, possible_mask_int):
        """Return True if the input int can be used as a 32-bit prefix mask.

        An IP address used as a prefix mask in IPv4 is either 1s followed by 0s,
        or the reverse. For example, 128.0.0.0, 0.0.63.255, etc.

        0.0.0.0 and 255.255.255.255 are considered masks.
        """
        # Implemented by counting the transitions between 1 and 0. All masks
        # will have at most one transition.
        diff = (possible_mask_int ^ (possible_mask_int >> 1)) & 0x7FFFFFFF
        # This code is a bit twiddle to determine if diff has at most 1 bit set.
        return (diff & ((0xFFFFFFFF ^ diff) + 1)) == diff

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
        return ipaddress.IPv4Address(_ensure_unicode(addr_str))

    @classmethod
    def make_addr_from_int(cls, ip_int):
        """Return an IPv4 address with the given int representation."""
        return ipaddress.IPv4Address(ip_int)

    def should_anonymize(self, ip_int):
        """Check if a given address should be anonymized (e.g. is it a mask or address?)."""
        return not self._is_mask(ip_int)


class IpV6Anonymizer(_BaseIpAnonymizer):
    """An anonymizer for IPv6 addresses."""

    def __init__(self, salt, **kwargs):
        """Create an anonymizer using the specified salt."""
        super(IpV6Anonymizer, self).__init__(salt, 128, **kwargs)

    @classmethod
    def get_addr_pattern(cls):
        """Return a compiled regex pattern to recognize IPv6 addresses."""
        return IPv6_PATTERN

    @classmethod
    def make_addr(cls, addr_str):
        """Return an IPv6 address from the given string."""
        return ipaddress.IPv6Address(_ensure_unicode(addr_str))

    @classmethod
    def make_addr_from_int(cls, ip_int):
        """Return an IPv6 address with the given int representation."""
        return ipaddress.IPv6Address(ip_int)

    def should_anonymize(self, ip_int):
        """Check if a given address should be anonymized."""
        return True


def _anonymize_match(anonymizer, match, undo_ip_anon):
    ip = anonymizer.make_addr(match)
    ip_int = int(ip)
    if not anonymizer.should_anonymize(ip_int):
        logging.debug("Should not anonymize %s, skipping", ip)
        return match

    if undo_ip_anon:
        new_ip_int = anonymizer.deanonymize(ip_int)
    else:
        new_ip_int = anonymizer.anonymize(ip_int)
    new_ip = anonymizer.make_addr_from_int(new_ip_int)
    logging.debug("Replacing %s with %s", ip, new_ip)
    return str(new_ip)


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
    return pattern.sub(lambda match: _anonymize_match(anonymizer, match[0], undo_ip_anon), line)
