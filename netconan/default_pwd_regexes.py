"""Default regexes from RANCID for finding & removing passwords."""
# Copyright (c) 1997-2017 by Henry Kilmer and John Heasley
# All rights reserved.
#
# This code is derived from software contributed to and maintained by
# Henry Kilmer, John Heasley, Andrew Partan,
# Pete Whiting, Austin Schutz, and Andrew Fort.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
# 3. Neither the name of RANCID nor the names of its
#    contributors may be used to endorse or promote products derived from
#    this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY Henry Kilmer, John Heasley AND CONTRIBUTORS
# ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
# TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
# PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE COMPANY OR CONTRIBUTORS
# BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
# CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
# SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
# CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
# ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.


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
    [(r'((password|passwd)( level \d+)?( \d+)?) \K(\S+)', 5)],
    [(r'(username( \S+)+ (password|secret)( \d| sha512)?) \K(\S+)', 5)],
    [(r'((enable )?secret( \d)?) \K(\S+)', 4)],
    [(r'(ip ftp password( \d)?) \K(\S+)', 3)],
    [(r'(ip ospf authentication-key( \d)?) \K(\S+)', 3)],
    [(r'(isis password) \K(\S+)(?=( level-\d)?)', 2)],
    [(r'((domain-password|area-password)) \K(\S+)', 3)],
    [(r'(ip ospf message-digest-key \d+ md5( \d)?) \K(\S+)', 3)],
    [(r'(standby( \d*)? authentication( text| md5 key-string( \d)?)?) \K(\S+)', 5)],
    [(r'(l2tp tunnel( \S+)? password( \d)?) \K(\S+)', 4)],
    [(r'(digest secret( \d)?) \K(\S+)', 3)],
    [(r'(ppp .* hostname) \K(\S+)', 2)],
    [(r'(ppp .* password( \d)?) \K(\S+)', 3)],
    [(r'((ikev2 )?(local|remote)-authentication pre-shared-key) \K(\S+)', 4)],
    [(r'((\S )*pre-shared-key( remote| local)?( hex| hexadecimal| ascii-text| \d)?) \K(\S+)', 5)],
    [(r'((tacacs|radius)-server (\S+ )*key)( \d)? \K(\S+)', 5)],
    [(r'(key( \d)?) \K(\S+)', 3)],
    [(r'(ntp authentication-key \d+ md5) \K(\S+)', 2)],
    [(r'(syscon( password| address \S+)) \K(\S+)', 3)],
    [(r'(snmp-server user( \S+)+ (auth (md5|sha))) \K(\S+)', 5),
     (r'(snmp-server user( \S+)+ priv( 3des| aes( \d+)?| des)?) \K(\S+)', 5)],
    [(r'((crypto )?isakmp key( \d)?) \K(\S+)', 4)],
    [(r'(set session-key (in|out)bound ah \d+) \K(\S+)', 3)],
    [(r'(set session-key (in|out)bound esp \d+ cipher?) \K(\S+)', 3),
     (r'(set session-key (in|out)bound esp \d+(( cipher \S+)? authenticator)) \K(\S+)', 5)],
    # TODO(https://github.com/intentionet/netconan/issues/3):
    # Follow-up on these.  They were just copied from RANCID so currently:
    #   They are untested in general and need cases added for unit tests
    #   They do not specifically capture sensitive info
    #   They just identify lines where sensitive info exists
    [(r'(cable shared-secret) (.*)', None)],
    [(r'(wpa-psk ascii|hex \d) (.*)', None)],
    [(r'(ldap-login-password) \S+(.*)', None)],
    [(r'((ikev1 )?(pre-shared-key |key |failover key )(ascii-text |hexadecimal )?).*(.*)', None)],
    [(r'(vpdn username (\S+) password)(.*)', None)],
    [(r'(key-string \d?)(.*)', None)],
    [(r'(message-digest-key \d+ md5 (7|encrypted)) (.*)', None)],
    [(r'(.*?neighbor.*?) (\S*) password (.*)', None)],
    [(r'(wlccp \S+ username (\S+)( .*)? password( \d)?) (\S+)(.*)', None)],

    # These are regexes for JUNOS
    # TODO(https://github.com/intentionet/netconan/issues/4):
    # Follow-up on these.  They were modified from RANCID's regexes and currently:
    #   They do not have capture groups for sensitive info
    #   They just identify lines where sensitive info exists
    #   They need to be tested against config lines generated on a JUNOS router
    #     (to make sure the regex handles different syntaxes allowed in the line)
    [(r'(\S* )*authentication-key [^ ;]+(.*)', None)],
    [(r'(\S* )*md5 \d+ key [^ ;]+(.*)', None)],
    [(r'(\S* )*hello-authentication-key [^ ;]+(.*)', None)],
    [(r'(\S* )*(secret|simple-password) [^ ;]+(.*)', None)],
    [(r'(\S* )*encrypted-password [^ ;]+(.*)', None)],
    [(r'(\S* )*ssh-(rsa|dsa) \"(.*)', None)],
    [(r'(\S* )*((pre-shared-|)key (ascii-text|hexadecimal)) [^ ;]+(.*)', None)]
]
# Taken from RANCID community scrubbing regexes
default_com_line_regexes = [
    [(r'((snmp-server (\S+ )*community)( [08])?) \K(\S+)', 5)],
    # TODO(https://github.com/intentionet/netconan/issues/5):
    # Confirm this catches all community possibilities for snmp-server
    [(r'(snmp-server host (\S+)( informs| traps| version '
     r'(?:1|2c|3 \S+)| vrf \S+)*) \K(\S+)', 4)],
    # This is from JUNOS
    # TODO(https://github.com/intentionet/netconan/issues/4):
    # See if we need to make the snmp keyword optional for Juniper
    # Also, this needs to be tested against config lines generated on a JUNOS router
    #     (to make sure the regex handles different syntaxes allowed in the line)
    [(r'((\S* )*snmp( \S+)* (community|trap-group)) \K([^ ;]+)', 5)]
]
