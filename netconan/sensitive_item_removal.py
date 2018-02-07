"""Generate & apply default regexes for finding & removing sensitive info."""

# Need regex here instead of re for variable length lookbehinds
import regex
import logging

from binascii import b2a_hex
from enum import Enum
from hashlib import md5
# Using passlib for digests not supported by hashlib
from passlib.hash import cisco_type7, md5_crypt, sha512_crypt
from six import b


# Regexes taken from RANCID password scrubbing
#
# Multiple regexes in a single inner list will all be run before returning
# the anonymized line.  This is useful for config lines that may have multiple
# sensitive items (e.g. snmp-server auth password and priv password).
#
# Format for these tuples are:
#  1. sensitive line regex
#       note that the regexes use lookbehinds and lookaheads so we can easily
#       extract and replace just the sensitive information
#  2. sensitive item regex-match-index
#       note that if this is None, any matching config line will be removed
default_pwd_line_regexes = [
    [('(password( level)?( \d)?) \K(\S+)(?= ?.*)', 4)],
    [('(username( \S+)+ (password|secret)( \d| sha512)?) \K(\S+)(?= ?.*)', 5)],
    [('((enable )?(password|passwd)( level \d+)?( \d)?) \K(\S+)(?= ?.*)', 6)],
    [('((enable )?secret( \d)?) \K(\S+)(?= ?.*)', 4)],
    [('(ip ftp password( \d)?) \K(\S+)(?= ?.*)', 3)],
    [('(ip ospf authentication-key( \d)?) \K(\S+)(?= ?.*)', 3)],
    [('(isis password) \K(\S+)(?=( level-\d)?( ?.*))', 2)],
    [('((domain-password|area-password)) \K(\S+)(?= ?.*)', 3)],
    [('(ip ospf message-digest-key \d+ md5( \d)?) \K(\S+)(?= ?.*)', 3)],
    [('(standby( \d*)? authentication( text| md5 key-string( \d)?)?) \K(\S+)(?= ?.*)', 5)],
    [('(l2tp tunnel( \S+)? password( \d)?) \K(\S+)(?= ?.*)', 4)],
    [('(digest secret( \d)?) \K(\S+)(?= ?.*)', 3)],
    [('(ppp .* hostname) \K(\S+)(?= ?.*)', 2)],
    [('(ppp .* password( \d)?) \K(\S+)(?= ?.*)', 3)],
    [('((ikev2 )?(local|remote)-authentication pre-shared-key) \K(\S+)(?= ?.*)', 4)],
    [('((\S )*pre-shared-key( remote| local)?( hex| \d)?) \K(\S+)(?= ?.*)', 5)],
    [('((tacacs|radius)-server (\S+ )*key)( \d)? \K(\S+)(?= ?.*)', 5)],
    [('(key( \d)?) \K(\S+)(?= ?.*)', 3)],
    [('(ntp authentication-key \d+ md5) \K(\S+)(?= ?.*)', 2)],
    [('(syscon( password| address \S+)) \K(\S+)(?= ?.*)', 3)],
    [('(snmp-server user( \S+)+ (auth (md5|sha))) \K(\S+)(?= ?.*)', 5),
     ('(snmp-server user( \S+)+ priv (3des|aes|des)) \K(\S+)(?= ?.*)', 4)],
    [('((crypto )?isakmp key( \d)?) \K(\S+)(?= .*)', 4)],
    [('(set session-key (in|out)bound ah \d+) \K(\S+)(?= ?.*)', 3)],
    [('(set session-key (in|out)bound esp \d+ cipher?) \K(\S+)(?= ?.*)', 3),
     ('(set session-key (in|out)bound esp \d+(( cipher \S+)? authenticator)) \K(\S+)(?= ?.*)', 5)],
    # TODO(https://github.com/intentionet/netconan/issues/3):
    # Follow-up on these.  They were just copied from RANCID so currently:
    #   They are untested in general and need cases added for unit tests
    #   They do not specifically capture sensitive info
    #   They just identify lines where sensitive info exists
    [('(cable shared-secret) (.*)', None)],
    [('(wpa-psk ascii|hex \d) (.*)', None)],
    [('(ldap-login-password) \S+(.*)', None)],
    [('((ikev1 )?(pre-shared-key |key |failover key )(ascii-text |hexadecimal )?).*(.*)', None)],
    [('(vpdn username (\S+) password)(.*)', None)],
    [('(key-string \d?)(.*)', None)],
    [('(message-digest-key \d+ md5 (7|encrypted)) (.*)', None)],
    [('(.*?neighbor.*?) (\S*) password (.*)', None)],
    [('(wlccp \S+ username (\S+)( .*)? password( \d)?) (\S+)(.*)', None)],

    # These are regexes for JUNOS
    # TODO(https://github.com/intentionet/netconan/issues/4):
    # Follow-up on these.  They were modified from RANCID's regexes and currently:
    #   They do not have capture groups for sensitive info
    #   They just identify lines where sensitive info exists
    #   They need to be tested against config lines generated on a JUNOS router
    #     (to make sure the regex handles different syntaxes allowed in the line)
    [('(\S* )*authentication-key [^ ;]+(.*)', None)],
    [('(\S* )*md5 \d+ key [^ ;]+(.*)', None)],
    [('(\S* )*hello-authentication-key [^ ;]+(.*)', None)],
    [('(\S* )*(secret|simple-password) [^ ;]+(.*)', None)],
    [('(\S* )*encrypted-password [^ ;]+(.*)', None)],
    [('(\S* )*ssh-(rsa|dsa) \"(.*)', None)],
    [('(\S* )*((pre-shared-|)key (ascii-text|hexadecimal)) [^ ;]+(.*)', None)]
]
# Taken from RANCID community scrubbing regexes
default_com_line_regexes = [
    [('((snmp-server .*community)( [08])?) \K(\S+)(?=.*)', 4)],
    # TODO(https://github.com/intentionet/netconan/issues/5):
    # Confirm this catches all community possibilities for snmp-server
    [('(snmp-server host (\S+)( informs| traps| version '
     '(?:1|2c|3 \S+)| vrf \S+)*) \K(\S+)(?=.*)', 4)],
    # This is from JUNOS
    # TODO(https://github.com/intentionet/netconan/issues/4):
    # See if we need to make the snmp keyword optional for Juniper
    # Also, this needs to be tested against config lines generated on a JUNOS router
    #     (to make sure the regex handles different syntaxes allowed in the line)
    [('((\S* )*snmp( \S+)* (community|trap-group)) \K([^ ;]+)(?=.*)', 5)]
]
# These are catch-all regexes to find lines that seem like they might contain
# sensitive info
default_catch_all_regexes = [
    [('(\S* )*"?\K(\$9\$[^ ;"]+)(?="? ?.*)', 2)],
    [('(\S* )*"?\K(\$1\$[^ ;"]+)(?="? ?.*)', 2)],
    [('(\S* )*encrypted-password \K(\S+)(?= ?.*)', None)],
    [('(\S* ?)*key "\K([^"]+)(?=".*)', 2)]
]

# Number of digits to extract from hash for sensitive keyword replacement
_ANON_SENSITIVE_WORD_LEN = 6


class _sensitive_item_formats(Enum):
    """Enum for recognized sensitive item formats (e.g. type7, md5, text)."""

    cisco_type7 = 1
    numeric = 2
    hexadecimal = 3
    md5 = 4
    text = 5
    sha512 = 6
    juniper_type9 = 7


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
    item_format = _check_sensitive_item_format(val)

    anon_val = 'netconanRemoved{}'.format(len(lookup))
    if val in lookup:
        return lookup[val]

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
    return anon_val


def _check_sensitive_item_format(val):
    """Determine the type/format of the value passed in."""
    # Order is important here (e.g. type 7 looks like hex or text, but has a
    # specific format so it should be identified before hex or text)
    if regex.match(r'^[0-9]+$', val):
        return _sensitive_item_formats.numeric
    if regex.match(r'^[01][0-9]([0-9a-fA-F]{2})+$', val):
        return _sensitive_item_formats.cisco_type7
    if regex.match(r'^[0-9a-fA-F]+$', val):
        return _sensitive_item_formats.hexadecimal
    if regex.match(r'^\$1\$[\S]+\$[\S]+$', val):
        return _sensitive_item_formats.md5
    if regex.match(r'^\$6\$[\S]+$', val):
        return _sensitive_item_formats.sha512
    if regex.match(r'^\$9\$[\S]+$', val):
        return _sensitive_item_formats.juniper_type9
    return _sensitive_item_formats.text


def generate_default_sensitive_item_regexes():
    """Compile and return the default password and community line regexes."""
    combined_regexes = default_pwd_line_regexes + default_com_line_regexes + \
        default_catch_all_regexes
    return [[(regex.compile(regex_), num) for regex_, num in group]
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
            match = compiled_re.match(output_line)
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
