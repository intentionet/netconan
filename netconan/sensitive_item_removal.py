"""Generate & apply default regexes for finding & removing sensitive info."""
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

from __future__ import absolute_import
# Need regex here instead of re for variable length lookbehinds
import regex
import logging

from binascii import b2a_hex
from enum import Enum
from hashlib import md5
from .default_pwd_regexes import default_pwd_line_regexes, default_com_line_regexes
from .default_reserved_words import default_reserved_words
# Using passlib for digests not supported by hashlib
from passlib.hash import cisco_type7, md5_crypt, sha512_crypt
from six import b


# A regex matching any of the characters that are allowed to precede a password
# regex (e.g. sensitive line is allowed to be in quotes or after a colon)
# This is an ignored group, so it does not muck with the password regex indicies
_ALLOWED_REGEX_PREFIX = r'(?:[^-_a-zA-Z\d] ?|^ ?)'

# Number of digits to extract from hash for sensitive keyword replacement
_ANON_SENSITIVE_WORD_LEN = 6

# BGP communities should be ignored/not anonymized, and can be detected by the
# following patterns, mostly extracted from examples at
# https://www.cisco.com/c/en/us/td/docs/routers/crs/software/crs_r4-1/routing/command/reference/b_routing_cr41crs/b_routing_cr41crs_chapter_01000.html
# Text followed by the word 'additive'
_IGNORED_COMM_ADDITIVE = r'\S+ additive'
# Numeric, colon separated, and parameter ($) communities
_IGNORED_COMM_COLON = r'(peeras|\$\w+|\d+)\:(peeras|\$\w+|\d+)'
# List of communities enclosed in parenthesis, being permissive here for the
# content inside the parenthesis for simplicity
_IGNORED_COMM_LIST = r'\([\S ]+\)'
# Well-known BPG communities
_IGNORED_COMM_WELL_KNOWN = 'gshut|internet|local-AS|no-advertise|no-export|none'
_IGNORED_COMMUNITIES = (r'((\d+|{additive}|{colon}|{list}|{well_known})(?!\S))'
                        .format(additive=_IGNORED_COMM_ADDITIVE,
                                colon=_IGNORED_COMM_COLON,
                                list=_IGNORED_COMM_LIST,
                                well_known=_IGNORED_COMM_WELL_KNOWN))

# Text that is allowed to surround passwords, to be preserved
_PASSWORD_ENCLOSING_TEXT = ['\'', '"', '\\\'', '\\"']

# These are extra regexes to find lines that seem like they might contain
# sensitive info (these are not already caught by RANCID default regexes)
extra_password_regexes = [
    [(r'encrypted-password \K(\S+)', None)],
    [(r'key "\K([^"]+)', 1)],
    [(r'key-hash sha256 (\S+)', 1)],
    # Replace communities that do not look like well-known BGP communities
    # i.e. snmp communities
    [(r'set community \K((?!{ignore})\S+)'
      .format(ignore=_IGNORED_COMMUNITIES), 1)],
    [(r'snmp-server mib community-map \K([^ :]+)', 1)],
    [(r'snmp-community \K(\S+)', 1)],
    # Catch-all's matching what looks like hashed passwords
    [(r'\K("?\$9\$[^\s;"]+)', 1)],
    [(r'\K("?\$1\$[^\s;"]+)', 1)],
]


class AsNumberAnonymizer(object):
    """An anonymizer for AS numbers."""

    # AS number block boundaries - each number corresponds to beginning of the next AS num block
    # Except the last, which just serves to indicate the end of the previous block
    _AS_NUM_BOUNDARIES = [0, 64512, 65536, 4200000000, 4294967296]

    def __init__(self, as_numbers, salt):
        """Create an anonymizer for the specified list of AS numbers (strings) and salt."""
        self.salt = salt
        self._generate_as_number_regex(as_numbers)
        self._generate_as_number_replacement_map(as_numbers)

    def anonymize(self, as_number):
        """Anonymize the specified AS number (string)."""
        return self.as_num_map[as_number]

    def _generate_as_number_regex(self, as_numbers):
        """Generate regex for finding AS number."""
        # Match a non-digit, any of the AS numbers and another non-digit
        # Using lookahead and lookbehind to match on context but not include that context in the match
        self.as_num_regex = regex.compile(r'(\D|^)\K({})(?=\D|$)'.format(
            '|'.join(as_numbers)))

    def _generate_as_number_replacement(self, as_number):
        """Generate a replacement AS number for the given AS number and salt."""
        hash_val = int(md5((self.salt + as_number).encode()).hexdigest(), 16)
        as_number = int(as_number)
        if as_number < 0 or as_number > 4294967295:
            raise ValueError('AS number provided was outside accepted range (0-4294967295)')

        block_begin = 0
        for next_block_begin in self._AS_NUM_BOUNDARIES:
            if as_number < next_block_begin:
                return str(hash_val % (next_block_begin - block_begin) + block_begin)
            block_begin = next_block_begin

    def _generate_as_number_replacement_map(self, as_numbers):
        """Generate map of AS numbers and their replacements."""
        self.as_num_map = {as_num: self._generate_as_number_replacement(as_num) for as_num in as_numbers}

    def get_as_number_pattern(self):
        """Return the compiled regex to find AS numbers."""
        return self.as_num_regex


class SensitiveWordAnonymizer(object):
    """An anonymizer for sensitive keywords."""

    def __init__(self, sensitive_words, salt, reserved_words=default_reserved_words):
        """Create an anonymizer for specified list of sensitive words and set of reserved words to leave alone."""
        self.reserved_words = reserved_words
        self.sens_regex = self._generate_sensitive_word_regex(sensitive_words)
        self.sens_word_replacements = self._generate_sensitive_word_replacements(sensitive_words, salt)
        # Figure out which reserved words may clash with sensitive words, so they can be preserved in anonymization
        self.conflicting_words = self._generate_conflicting_reserved_word_list(sensitive_words)

    def anonymize(self, line):
        """Anonymize sensitive words from the input line."""
        if self.sens_regex.search(line) is not None:
            leading, words, trailing = _split_line(line)
            # Anonymize only words that do not match the conflicting (reserved) words
            words = [
                w if w in self.conflicting_words else self.sens_regex.sub(self._lookup_anon_word, w) for w in words
            ]
            # Restore leading and trailing whitespace since those were removed when splitting into words
            line = leading + ' '.join(words) + trailing
        return line

    def _generate_conflicting_reserved_word_list(self, sensitive_words):
        """Return a list of reserved words that may conflict with the specified sensitive words."""
        conflicting_words = set()
        for sensitive_word in sensitive_words:
            conflicting_words.update(set([w for w in self.reserved_words if sensitive_word in w]))
        if conflicting_words:
            logging.warning('Specified sensitive words overlap with reserved words. '
                            'The following reserved words will be preserved: %s', conflicting_words)
        return conflicting_words

    @classmethod
    def _generate_sensitive_word_regex(cls, sensitive_words):
        """Compile and return regex for the specified list of sensitive words."""
        return regex.compile('({})'.format('|'.join(sensitive_words)), regex.IGNORECASE)

    @classmethod
    def _generate_sensitive_word_replacements(cls, sensitive_words, salt):
        """Compile and return a dict of sensitive word replacements."""
        # Only using part of the md5 hash result as the anonymized replacement
        # to cut down on the size of the replacements
        return {
            sens_word.lower(): md5((salt + sens_word.lower()).encode()).hexdigest()[:_ANON_SENSITIVE_WORD_LEN]
            for sens_word in sensitive_words
        }

    def _lookup_anon_word(self, match):
        """Lookup anonymized word for the given sensitive word regex match."""
        return self.sens_word_replacements[match.group(0).lower()]


class _sensitive_item_formats(Enum):
    """Enum for recognized sensitive item formats (e.g. type7, md5, text)."""

    cisco_type7 = 1
    numeric = 2
    hexadecimal = 3
    md5 = 4
    text = 5
    sha512 = 6
    juniper_type9 = 7


def anonymize_as_numbers(anonymizer, line):
    """Anonymize AS numbers in the input line."""
    as_number_regex = anonymizer.get_as_number_pattern()
    return as_number_regex.sub(lambda match: anonymizer.anonymize(match.group(0)), line)


def anonymize_sensitive_words(sensitive_word_regexes, line, salt):
    """Anonymize words from specified sensitive words list in the input line."""
    for sens_word_regex in sensitive_word_regexes:
        if sens_word_regex.search(line) is not None:
            sens_word = sens_word_regex.pattern
            # Only using part of the hash result as the anonymized replacement
            # to cut down on the size of the replacements
            anon_word = md5((salt + sens_word).encode()).hexdigest()[:_ANON_SENSITIVE_WORD_LEN]
            line = sens_word_regex.sub(anon_word, line)
    return line


def _anonymize_value(val, lookup):
    """Generate an anonymized replacement for the input value.

    This function tries to determine what type of value was passed in and
    returns an anonymized value of the same format.  If the source value has
    already been anonymized in the provided lookup, then the previous anon
    value will be used.
    """
    # Separate enclosing text (e.g. quotes) from the underlying value
    enclosing_text, val = _extract_enclosing_text(val)
    item_format = _check_sensitive_item_format(val)

    anon_val = 'netconanRemoved{}'.format(len(lookup))
    if val in lookup:
        return enclosing_text + lookup[val] + enclosing_text

    if item_format == _sensitive_item_formats.cisco_type7:
        # Not salting sensitive data, using static salt here to more easily
        # identify anonymized lines
        anon_val = cisco_type7.using(salt=9).hash(anon_val)

    if item_format == _sensitive_item_formats.numeric:
        # These are the ASCII character values for anon_val converted to decimal
        anon_val = str(int(b2a_hex(b(anon_val)), 16))

    if item_format == _sensitive_item_formats.hexadecimal:
        # These are the ASCII character values for anon_val in hexadecimal
        anon_val = b2a_hex(b(anon_val)).decode()

    if item_format == _sensitive_item_formats.md5:
        old_salt_size = len(val.split('$')[2])
        # Not salting sensitive data, using static salt here to more easily
        # identify anonymized lines
        anon_val = md5_crypt.using(salt='0' * old_salt_size).hash(anon_val)

    if item_format == _sensitive_item_formats.sha512:
        # Hash anon_val w/standard rounds=5000 to omit rounds parameter from hash output
        anon_val = sha512_crypt.using(rounds=5000).hash(anon_val)

    if item_format == _sensitive_item_formats.juniper_type9:
        # TODO(https://github.com/intentionet/netconan/issues/16)
        # Encode base anon_val instead of just returning a constant here
        # This value corresponds to encoding: Conan812183
        anon_val = '$9$0000IRc-dsJGirewg4JDj9At0RhSreK8Xhc'

    lookup[val] = anon_val
    return enclosing_text + anon_val + enclosing_text


def _check_sensitive_item_format(val):
    """Determine the type/format of the value passed in."""
    item_format = _sensitive_item_formats.text

    # Order is important here (e.g. type 7 looks like hex or text, but has a
    # specific format so it should override hex or text)
    if regex.match(r'^\$9\$[\S]+$', val):
        item_format = _sensitive_item_formats.juniper_type9
    if regex.match(r'^\$6\$[\S]+$', val):
        item_format = _sensitive_item_formats.sha512
    if regex.match(r'^\$1\$[\S]+\$[\S]+$', val):
        item_format = _sensitive_item_formats.md5
    if regex.match(r'^[0-9a-fA-F]+$', val):
        item_format = _sensitive_item_formats.hexadecimal
    if regex.match(r'^[01][0-9]([0-9a-fA-F]{2})+$', val):
        item_format = _sensitive_item_formats.cisco_type7
    if regex.match(r'^[0-9]+$', val):
        item_format = _sensitive_item_formats.numeric
    return item_format


def _extract_enclosing_text(val):
    """Extract enclosing quotes from text and return the enclosing text and enclosed text."""
    enclosing_text = ''
    for surround_text in _PASSWORD_ENCLOSING_TEXT:
        if val.endswith(surround_text) and val.startswith(surround_text):
            enclosing_text = surround_text
            val = val[len(surround_text):-len(surround_text)]
            break
    return enclosing_text, val


def generate_default_sensitive_item_regexes():
    """Compile and return the default password and community line regexes."""
    combined_regexes = default_pwd_line_regexes + default_com_line_regexes + \
        extra_password_regexes
    return [[(regex.compile(_ALLOWED_REGEX_PREFIX + regex_), num) for regex_, num in group]
            for group in combined_regexes]


def replace_matching_item(compiled_regexes, input_line, pwd_lookup, reserved_words=default_reserved_words):
    """If line matches a regex, anonymize or remove the line."""
    # Collapse whitespace to simplify regexes, also preserve leading and trailing whitespace
    leading, words, trailing = _split_line(input_line)
    output_line = ' '.join(words)

    # Note: compiled_regexes is a list of lists; the inner list is a group of
    # related regexes
    for compiled_regex_grp in compiled_regexes:
        match_found = False

        # Apply all related regexes before returning the output_line
        for compiled_re, sensitive_item_num in compiled_regex_grp:
            # Using search instead of match here to find the match anywhere in the input line
            match = compiled_re.search(output_line)
            if match is None:
                continue
            match_found = True
            logging.debug('Match found on %s', output_line.rstrip())

            # If this regex cannot preserve text around sensitive info,
            # then just remove the whole line
            if sensitive_item_num is None:
                logging.warning(
                    'Anonymizing sensitive info in lines like "%s" is currently'
                    ' unsupported, so removing this line completely',
                    compiled_re.pattern)
                return '! Sensitive line SCRUBBED by netconan\n'

            sensitive_val = match.group(sensitive_item_num)
            if sensitive_val in reserved_words:
                logging.debug('Skipping anonymization of reserved word: "%s"', sensitive_val)
                continue
            anon_val = _anonymize_value(sensitive_val, pwd_lookup)
            output_line = compiled_re.sub(anon_val, output_line)
            logging.debug(
                'Anonymized input "%s" to "%s"', sensitive_val, anon_val)

        # If any matches existed in this regex group, stop processing more regexes
        if match_found:
            break

    # Restore leading and trailing whitespace for readability and context
    return leading + output_line + trailing


def _split_line(line):
    """Split line into leading whitespace, list of words, and trailing whitespace."""
    return line[:-len(line.lstrip())], line.split(), line[len(line.rstrip()):]
