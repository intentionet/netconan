import re
import logging

# Taken from RANCID password scrubbing regexes
default_password_line_regexes = [
            '^(\s+password \d+) (.*)',
            '^(username (\S+) password (\d)) (\S+)(.*)',
            '^((enable )?(password|passwd)( level \d+)?) (.*)',
            '^(enable secret) (.*)',
            '^(username (\S+)(\s.*)? secret) (.*)',
            '^(username (\S+)(\s.*)? password( \d)?) \S+(.*)',
            '^(wlccp \S+ username (\S+)(\s.*)? password( \d)?) (\S+)(.*)',
            '^( set session-key (in|out)bound ah \d+) (.*)',
            '^( set session-key (in|out)bound esp \d+ (authenticator|cypher)) (.*)',
            '^((\s*)password) (.*)',
            '^((\s*)secret) (.*)',
            '^\s*(.*?neighbor.*?) (\S*) password (.*)',
            '^(\s*ppp .* hostname) .*(.*)',
            '^(\s*ppp .* password \d) .*(.*)',
            '^(ip ftp password) (.*)',
            '^( ip ospf authentication-key) (.*)',
            '^(\s+isis password) (\S+)(.*)',
            '^\s+(domain-password|area-password) (\S+)(\s?(.*))',
            '^( ip ospf message-digest-key \d+ md5) (.*)',
            '^(  message-digest-key \d+ md5 (7|encrypted)) (.*)',
            '^((crypto )?isakmp key( \d)?) \S+ (.*)',
            '^(\s+standby \d+ authentication) (.*)',
            '^(\s+key-string \d?)(.*)',
            '^( l2tp tunnel \S+ password)(.*)',
            '^( digest secret(\s7)?) (.*)',
            '^(vpdn username (\S+) password)(.*)',
            '^(( ikev2)? (local|remote)-authentication pre-shared-key) (.*)',
            '^(( ikev1)?( pre-shared-key | key |\s?failover key )(ascii-text |hexadecimal )?).*(.*)',
            '(\s+ldap-login-password) \S+(.*)',
            '^\s+(wpa-psk ascii|hex \d) (.*)',
            '^( cable shared-secret) (.*)',
            '^((tacacs|radius)-server\s(\w*[-\s(\s\S+])*\s?key) (\d )?\S+(.*)',
            '^(ntp authentication-key \d+ md5) (.*)',
            '^(syscon password) (\S*)(.*)',
            '^(snmp-server user( \S+)+ (auth (md5|sha))) (\S+)(.*)',
            # These are from JUNOS
            '(\s*authentication-key )[^ ;]+(.*)',
            '(\s*md5 \d+ key )[^ ;]+(.*)',
            '(\s*hello-authentication-key )[^ ;]+(.*)',
            '^(.*\s(secret|simple-password) )[^ ;]+(.*)',
            '(\s+encrypted-password )[^ ;]+(.*)',
            '(\s+ssh-(rsa|dsa) )\"(.*)',
            '^\s+((pre-shared-|)key (ascii-text|hexadecimal)) [^ ;]+(.*)']
# Taken from RANCID community scrubbing regexes
default_community_line_regexes = [
            '^((snmp-server .*community)( [08])?) (\S+)(.*)',
            # TODO: confirm this catches all community possibilities for snmp-server
            '^(snmp-server host (\S+)( informs| traps| version (1|2c|3 (\S+))| vrf (\S+))*) (\S+)(.*)',
            # TODO: see if we need to make the occurence of snmp keyword optional for Juniper
            '^(\s?snmp( \S+)* (community|trap-group)) [^ ;]+(.*)']

def generate_default_sensitive_item_regexes():
    """Compile and return the default password and community line regexes."""
    return [(re.compile(line)) for line in default_password_line_regexes + default_community_line_regexes]

def replace_matching_item(compiled_regexes, input_line):
    """Check a line against compiled regexes and replace the line with a comment upon the first match."""
    for compiled_regex in compiled_regexes:
        if compiled_regex.match(input_line) is not None:
            logging.debug("Match found on " + input_line.rstrip())
            return "! Sensitive line SCRUBBED\n"
    return input_line
