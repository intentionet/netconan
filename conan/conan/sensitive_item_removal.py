"""Generate & apply default regexes for finding & removing sensitive info."""

# Need regex here instead of re for variable length lookbehinds
import regex
import logging

from binascii import b2a_hex
from enum import Enum
from passlib.hash import cisco_type7, md5_crypt
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
    [('^(\s*password( level)?( \d)?) \K(\S+)(?= ?.*)', 4)],
    [('^(\s*username( \S+)+ (password|secret)( \d)?) \K(\S+)(?= ?.*)', 5)],
    [('^(\s*(enable )?(password|passwd)( level \d+)?( \d)?) \K(\S+)(?= ?.*)', 6)],
    [('^(\s*(enable )?secret( \d)?) \K(\S+)(?= ?.*)', 4)],
    [('^(\s*ip ftp password( \d)?) \K(\S+)(?= ?.*)', 3)],
    [('^(\s*ip ospf authentication-key( \d)?) \K(\S+)(?= ?.*)', 3)],
    [('^(\s*isis password) \K(\S+)(?=( level-\d)?( ?.*))', 2)],
    [('^(\s*(domain-password|area-password)) \K(\S+)(?= ?.*)', 3)],
    [('^(\s*ip ospf message-digest-key \d+ md5( \d)?) \K(\S+)(?= ?.*)', 3)],
    [('^(\s*standby( \d*)? authentication( text| md5 key-string( \d)?)?) \K(\S+)(?= ?.*)', 5)],
    [('^(\s*l2tp tunnel( \S+)? password( \d)?) \K(\S+)(?= ?.*)', 4)],
    [('^(\s*digest secret(\s\d)?) \K(\S+)(?= ?.*)', 3)],
    [('^(\s*ppp .* hostname) \K(\S+)(?= ?.*)', 2)],
    [('^(\s*ppp .* password( \d)?) \K(\S+)(?= ?.*)', 3)],
    [('^(\s*(ikev2 )?(local|remote)-authentication pre-shared-key) \K(\S+)(?= ?.*)', 4)],
    [('^(\s*(\S )*pre-shared-key( remote| local)?( hex| \d)?) \K(\S+)(?= ?.*)', 5)],
    [('^(\s*(tacacs|radius)-server\s(\w*[-\s\s\S+])*\s?key)( ?\d?) \K(\S+)(?= ?.*)', 5)],
    [('^(\s*key( \d)?) \K(\S+)(?= ?.*)', 3)],
    [('^(\s*ntp authentication-key \d+ md5) \K(\S+)(?= ?.*)', 2)],
    [('^(\s*syscon( password| address \S+)) \K(\S+)(?= ?.*)', 3)],
    [('^(\s*snmp-server user( \S+)+ (auth (md5|sha))) \K(\S+)(?= ?.*)', 5),
     ('^(\s*snmp-server user( \S+)+ priv (3des|aes|des)) \K(\S+)(?= ?.*)', 4)],
    [('^((crypto )?isakmp key( \d)?) \K(\S+)(?= .*)', 4)],
    [('^(\s*set session-key (in|out)bound ah \d+) \K(\S+)(?= ?.*)', 3)],
    [('^(\s*set session-key (in|out)bound esp \d+ cipher?) \K(\S+)(?= ?.*)', 3),
     ('^(\s*set session-key (in|out)bound esp \d+(( cipher \S+)? authenticator)) \K(\S+)(?= ?.*)', 5)],
    # TODO: Follow-up on these.  They were just copied from RANCID so currently:
    #       They are untested in general and need cases added for unit tests
    #       They do not specifically capture sensitive info
    #       They just identify lines where sensitive info exists
    [('^( cable shared-secret) (.*)', None)],
    [('^\s+(wpa-psk ascii|hex \d) (.*)', None)],
    [('(\s+ldap-login-password) \S+(.*)', None)],
    [('^(( ikev1)?( pre-shared-key | key |\s?failover key )(ascii-text |hexadecimal )?).*(.*)', None)],
    [('^(vpdn username (\S+) password)(.*)', None)],
    [('^(\s*key-string \d?)(.*)', None)],
    [('^(\s*message-digest-key \d+ md5 (7|encrypted)) (.*)', None)],
    [('^\s*(.*?neighbor.*?) (\S*) password (.*)', None)],
    [('^(wlccp \S+ username (\S+)(\s.*)? password( \d)?) (\S+)(.*)', None)],
    # These are from JUNOS
    [('(\s*authentication-key )[^ ;]+(.*)', None)],
    [('(\s*md5 \d+ key )[^ ;]+(.*)', None)],
    [('(\s*hello-authentication-key )[^ ;]+(.*)', None)],
    [('^(.*\s(secret|simple-password) )[^ ;]+(.*)', None)],
    [('(\s+encrypted-password )[^ ;]+(.*)', None)],
    [('(\s+ssh-(rsa|dsa) )\"(.*)', None)],
    [('^\s+((pre-shared-|)key (ascii-text|hexadecimal)) [^ ;]+(.*)', None)]
]
# Taken from RANCID community scrubbing regexes
default_com_line_regexes = [
    [('^((snmp-server .*community)( [08])?) \K(\S+)(?=.*)', 4)],
    # TODO: confirm this catches all community possibilities for snmp-server
    [('^(snmp-server host (\S+)( informs| traps| version '
     '(?:1|2c|3 \S+)| vrf \S+)*) \K(\S+)(?=.*)', 4)],
    # This is from JUNOS
    # TODO: see if we need to make the snmp keyword optional for Juniper
    [('^(\s?snmp( \S+)* (community|trap-group)) \K([^ ;]+)(?=.*)', 4)]
]
# These are catch-all regexes to find lines that seem like they might contain
# sensitive info
default_catch_all_regexes = [
    [('.*\s\K(\$9\$[^ ;]+)(?=\s?.*)', None)],
    [('.*\s\K(\$1\$[^ ;]+)(?=\s?.*)', None)],
    [('.*encrypted-password\s\K(\S+)(?=\s?.*)', None)]
]


class _sensitive_item_formats(Enum):
    """Enum for recognized sensitive item formats (e.g. type7, md5, text)."""

    type7 = 1
    numeric = 2
    hexadecimal = 3
    md5 = 4
    text = 5


def _anonymize_value(val, lookup):
    """Generate an anonymized replacement for the input value.

    This function tries to determine what type of value was passed in and
    returns an anonymized value of the same format.  If the source value has
    already been anonymized in the provided lookup, then the previous anon
    value will be used.
    """
    item_format = _check_sensitive_item_format(val)

    anon_val = 'ConanRemoved{}'.format(len(lookup))
    if val in lookup:
        return lookup[val]

    if item_format == _sensitive_item_formats.type7:
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
        # Not salting sensitive data, using static salt here to more easily
        # identify anonymized lines
        anon_val = md5_crypt.using(salt='CNAN').hash(anon_val)

    lookup[val] = anon_val
    return anon_val


def _check_sensitive_item_format(val):
    """Determine the type/format of the value passed in."""
    # Order is important here (e.g. type 7 looks like hex or text, but has a
    # specific format so it should be identified before hex or text)
    if regex.match(r'^[0-9]+$', val):
        return _sensitive_item_formats.numeric
    if regex.match(r'^[01][0-9]([0-9a-fA-F]{2})+$', val):
        return _sensitive_item_formats.type7
    if regex.match(r'^[0-9a-fA-F]+$', val):
        return _sensitive_item_formats.hexadecimal
    if regex.match(r'^\$1\$[\S]{4}\$[\S]{22}$', val):
        return _sensitive_item_formats.md5
    return _sensitive_item_formats.text


def generate_default_sensitive_item_regexes():
    """Compile and return the default password and community line regexes."""
    combined_regexes = default_pwd_line_regexes + default_com_line_regexes + \
        default_catch_all_regexes
    return [[(regex.compile(regex_), num) for regex_, num in group]
            for group in combined_regexes]


def replace_matching_item(compiled_regexes, input_line, pwd_lookup):
    """If line matches a regex, anonymize or remove the line."""
    output_line = input_line

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
            logging.debug('Match found on ' + output_line.rstrip())

            # If this regex cannot preserve text around sensitive info,
            # then just remove the whole line
            if sensitive_item_num is None:
                logging.warning('Anonymizing sensitive info in lines like "{}"'
                                ' is currently unsupported, so removing this '
                                'line completely'.format(compiled_re.pattern))
                return '! Sensitive line SCRUBBED by Conan\n'

            sensitive_val = match.group(sensitive_item_num)
            anon_val = _anonymize_value(sensitive_val, pwd_lookup)
            output_line = compiled_re.sub(anon_val, output_line)
            logging.debug('Anonymized input "{}" to "{}"'
                          .format(sensitive_val, anon_val))

        # If any matches existed in this regex group, stop processing more regexes
        if match_found:
            break
    return output_line
