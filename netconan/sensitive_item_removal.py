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
# Using passlib for digests not supported by hashlib
from passlib.hash import cisco_type7, md5_crypt, sha512_crypt
from six import b

# These are catch-all regexes to find lines that seem like they might contain
# sensitive info
default_catch_all_regexes = [
    [('set community \K(\S+)(?= ?.*)', 1)],
    [('(\S* )*"?\K(\$9\$[^\s;"]+)(?="? ?.*)', 2)],
    [('(\S* )*"?\K(\$1\$[^\s;"]+)(?="? ?.*)', 2)],
    [('(\S* )*encrypted-password \K(\S+)(?= ?.*)', None)],
    [('(\S* ?)*key "\K([^"]+)(?=".*)', 2)]
]

# A regex matching any of the characters that are allowed to precede a password regex
# (e.g. sensitive line is allowed to be in quotes or after a colon)
# This is an ignored group, so it does not muck with the password regex indicies
_ALLOWED_REGEX_PREFIX = '(?:["\'{:] ?|^ ?)'

# Number of digits to extract from hash for sensitive keyword replacement
_ANON_SENSITIVE_WORD_LEN = 6

# Text that is allowed to surround passwords, to be preserved
_PASSWORD_ENCLOSING_TEXT = ['\'', '"', '\\\'', '\\"']


class AsNumberAnonymizer:
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
        self.as_num_regex = regex.compile('(\D|^)\K(' + '|'.join(as_numbers) + ')(?=\D|$)')

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
    enclosing_text, item_format = _check_sensitive_item_format(val)

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
    enclosing_text = ''
    item_format = _sensitive_item_formats.text

    for surround_text in _PASSWORD_ENCLOSING_TEXT:
        if val.endswith(surround_text) and val.startswith(surround_text):
            enclosing_text = surround_text
            val = val[len(surround_text):-len(surround_text)]
            break

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
    return enclosing_text, item_format


def generate_default_sensitive_item_regexes():
    """Compile and return the default password and community line regexes."""
    combined_regexes = default_pwd_line_regexes + default_com_line_regexes + \
        default_catch_all_regexes
    return [[(regex.compile(_ALLOWED_REGEX_PREFIX + regex_), num) for regex_, num in group]
            for group in combined_regexes]


def generate_sensitive_word_regexes(sensitive_words):
    """Compile and return regexes for the specified list of sensitive words."""
    return [regex.compile(sens_word, regex.IGNORECASE) for sens_word in sensitive_words]


def replace_matching_item(compiled_regexes, input_line, pwd_lookup):
    """If line matches a regex, anonymize or remove the line."""
    # Collapse all whitespace to simplify regexes
    output_line = '{}\n'.format(' '.join(input_line.split()))

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
            anon_val = _anonymize_value(sensitive_val, pwd_lookup)
            output_line = compiled_re.sub(anon_val, output_line)
            logging.debug(
                'Anonymized input "%s" to "%s"', sensitive_val, anon_val)

        # If any matches existed in this regex group, stop processing more regexes
        if match_found:
            break
    return output_line
