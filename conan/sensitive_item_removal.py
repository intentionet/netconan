"""Generate & apply default regexes for finding & removing sensitive info."""

import re
import logging

# Taken from RANCID password scrubbing regexes
default_pwd_line_regexes = [
    '^(\s*password( \d)?) (\S+)( .*)?',
    '^(\s*username (\S+) password( \d)?) (\S+)( .*)?',
    '^(\s*(enable )?(password|passwd)( level \d+)?)( \d)? (\S+)( .*)?',
    '^(\s*(enable )?secret) (\S+)( .*)?',
    '^(\s*ip ftp password) (\S+)( .*)?',
    '^(\s*ip ospf authentication-key) (\S+)( .*)?',
    '^(\s*isis password) (\S+)( level-\d)?( .*)?',
    '^(\s*(domain-password|area-password)) (\S+)( .*)?',
    '^(\s*ip ospf message-digest-key \d+ md5) (\S+)( .*)?',
    '^(\s*standby( \d*)? authentication) (\S+)( .*)?',
    '^(\s*l2tp tunnel( \S+)? password) (\S+)( .*)?',
    '^(\s*digest secret(\s7)?) (\S+)( .*)?',
    '^(\s*ppp .* hostname) (\S+)( .*)?',
    '^(\s*ppp .* password( \d)?) (\S+)( .*)?',
    '^(\s*(ikev2 )?(local|remote)-authentication pre-shared-key) (\S+)( .*)?',
    '^(\s*(\S )*pre-shared-key( remote| local)?( hex| \d)?) (\S+)( .*)?',
    '^(\s*(tacacs|radius)-server\s(\w*[-\s(\s\S+])*\s?key)( \d)? (\S+)( .*)?',
    '^(\s*key( \d)?) (\S+)( .*)?',
    '^(\s*ntp authentication-key \d+ md5) (\S+)( .*)?',
    '^(\s*syscon( password| address \S+)) (\S+)( .*)?',
    '^(\s*snmp-server user( \S+)+ (auth (md5|sha))) (\S+)( .*)?',
    # TODO: These overlap with others, merge them into other regexes above
    '^(\s*username (\S+)(\s.*)? secret) (\S+)( .*)?',
    '^(\s*username (\S+)(\s.*)? password( \d)?) (\S+)( .*)?',
    # TODO: Followup on these; just copied from RANCID, they do not have tests
    # I didn't see how to generate config lines for these in Cisco
    '^( cable shared-secret) (.*)',
    '^\s+(wpa-psk ascii|hex \d) (.*)',
    '(\s+ldap-login-password) \S+(.*)',
    '^(( ikev1)?( pre-shared-key | key |\s?failover key )\
    (ascii-text |hexadecimal )?).*(.*)',
    '^(vpdn username (\S+) password)(.*)',
    '^(\s+key-string \d?)(.*)',
    '^((crypto )?isakmp key( \d)?) \S+ (.*)',
    '^(  message-digest-key \d+ md5 (7|encrypted)) (.*)',
    '^\s*(.*?neighbor.*?) (\S*) password (.*)',
    '^( set session-key (in|out)bound ah \d+) (.*)',
    '^( set session-key (in|out)bound esp \d+ (authenticator|cypher)) (.*)',
    '^(wlccp \S+ username (\S+)(\s.*)? password( \d)?) (\S+)(.*)',
    # These are from JUNOS
    '(\s*authentication-key )[^ ;]+(.*)',
    '(\s*md5 \d+ key )[^ ;]+(.*)',
    '(\s*hello-authentication-key )[^ ;]+(.*)',
    '^(.*\s(secret|simple-password) )[^ ;]+(.*)',
    '(\s+encrypted-password )[^ ;]+(.*)',
    '(\s+ssh-(rsa|dsa) )\"(.*)',
    '^\s+((pre-shared-|)key (ascii-text|hexadecimal)) [^ ;]+(.*)']
# Taken from RANCID community scrubbing regexes
default_com_line_regexes = [
    '^((snmp-server .*community)( [08])?) (\S+)(.*)',
    # TODO: confirm this catches all community possibilities for snmp-server
    '^(snmp-server host (\S+)( informs| traps| version \
    (1|2c|3 (\S+))| vrf (\S+))*) (\S+)(.*)',
    # This is from JUNOS
    # TODO: see if we need to make the snmp keyword optional for Juniper
    '^(\s?snmp( \S+)* (community|trap-group)) [^ ;]+(.*)']


def generate_default_sensitive_item_regexes():
    """Compile and return the default password and community line regexes."""
    combined_regexes = default_pwd_line_regexes + default_com_line_regexes
    return [(re.compile(line)) for line in combined_regexes]


def replace_matching_item(compiled_regexes, input_line):
    """If line matches a regex, replace the line with a comment."""
    for compiled_regex in compiled_regexes:
        if compiled_regex.match(input_line) is not None:
            logging.debug("Match found on " + input_line.rstrip())
            return "! Sensitive line SCRUBBED\n"
    return input_line
