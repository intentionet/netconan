"""Test removal of passwords and snmp communities."""
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

from netconan.sensitive_item_removal import (
    anonymize_as_numbers, anonymize_sensitive_words, AsNumberAnonymizer,
    replace_matching_item, generate_default_sensitive_item_regexes,
    generate_sensitive_word_regexes, _sensitive_item_formats,
    _anonymize_value, _check_sensitive_item_format, _extract_enclosing_text)
import pytest

# Tuple format is config_line, sensitive_text (should not be in output line)
# TODO(https://github.com/intentionet/netconan/issues/3):
# Add in additional test lines (these are just first pass from IOS)
cisco_password_lines = [
    ('     password   0      \t{}', 'RemoveMe'),
    (' password 7 {}', '122A00190102180D3C2E'),
    ('username Someone password 0 {}', 'RemoveMe'),
    ('username Someone password {}', 'RemoveMe'),
    ('username Someone password 7 {}', '122A00190102180D3C2E'),
    ('enable password level 12 {}', 'RemoveMe'),
    ('enable password 7 {}', '122A00190102180D3C2E'),
    ('enable secret 5 {}', '$1$wtHI$0rN7R8PKwC30AsCGA77vy.'),
    ('username Someone view Someview password 7 {}', '122A00190102180D3C2E'),
    ('username Someone password {}', 'RemoveMe'),
    ('username Someone secret 5 {}', '$1$wtHI$0rN7R8PKwC30AsCGA77vy.'),
    ('username Someone secret {}', 'RemoveMe'),
    ('username Someone view Someview secret {}', 'RemoveMe'),
    ('ip ftp password {}', 'RemoveMe'),
    ('ip ftp password 0 {}', 'RemoveMe'),
    ('ip ftp password 7 {}', '122A00190102180D3C2E'),
    (' ip ospf authentication-key {}', 'RemoveMe'),
    (' ip ospf authentication-key 0 {}', 'RemoveMe'),
    ('isis password {}', 'RemoveMe'),
    ('domain-password {}', 'RemoveMe'),
    ('domain-password {} authenticate snp validate', 'RemoveMe'),
    ('area-password {} authenticate snp send-only', 'RemoveMe'),
    ('ip ospf message-digest-key 123 md5 {}', 'RemoveMe'),
    ('ip ospf message-digest-key 124 md5 7 {}', '122A00190102180D3C2E'),
    ('standby authentication {}', 'RemoveMe'),
    ('standby authentication md5 key-string {} timeout 123', 'RemoveMe'),
    ('standby authentication md5 key-string 7 {}', 'RemoveMe'),
    ('standby authentication text {}', 'RemoveMe'),
    ('l2tp tunnel password 0 {}', 'RemoveMe'),
    ('l2tp tunnel password {}', 'RemoveMe'),
    ('digest secret {} hash MD5', 'RemoveMe'),
    ('digest secret {}', 'RemoveMe'),
    ('digest secret 0 {}', 'RemoveMe'),
    ('ppp chap password {}', 'RemoveMe'),
    ('ppp chap password 0 {}', 'RemoveMe'),
    ('ppp chap hostname {}', 'RemoveMe'),
    ('pre-shared-key {}', 'RemoveMe'),
    ('pre-shared-key 0 {}', 'RemoveMe'),
    ('pre-shared-key local 0 {}', 'RemoveMe'),
    ('pre-shared-key remote hex {}', '1234a'),
    ('pre-shared-key remote 6 {}', 'FLgBaJHXdYY_AcHZZMgQ_RhTDJXHUBAAB'),
    ('tacacs-server host 1.1.1.1 key {}', 'RemoveMe'),
    ('radius-server host 1.1.1.1 key 0 {}', 'RemoveMe'),
    ('tacacs-server key 7 {}', '122A00190102180D3C2E'),
    (' key 0 {}', 'RemoveMe'),
    ('ntp authentication-key 4294967295 md5 {}', 'RemoveMe'),
    ('ntp authentication-key 123 md5 {} 1', 'RemoveMe'),
    ('syscon address 1.1.1.1 {}', 'RemoveMe'),
    ('snmp-server user Someone Somegroup remote Crap v3 auth md5 {}', 'RemoveMe'),
    ('snmp-server user Someone Somegroup v3 auth sha {0} priv 3des {0}', 'RemoveMe'),
    # TODO: Figure out SHA format, this line throws: Error in Auth password
    ('snmp-server user Someone Somegroup v3 encrypted auth sha {}', 'RemoveMe'),
    ('crypto isakmp key {} address 1.1.1.1 255.255.255.0', 'RemoveMe'),
    ('crypto isakmp key 6 {} hostname Something', 'RemoveMe'),
    ('set session-key inbound ah 4294967295 {}', '1234abcdef'),
    ('set session-key outbound esp 256 authenticator {}', '1234abcdef'),
    ('set session-key outbound esp 256 cipher {0} authenticator {0}', '1234abcdef')
]

cisco_snmp_community_lines = [
    ('snmp-server community {} ro 1', 'RemoveMe'),
    ('snmp-server community {} Something', 'RemoveMe'),
    ('snmp-server host 1.1.1.1 vrf Something informs {} config', 'RemoveMe'),
    ('snmp-server host 1.1.1.1 informs version 1 {} ipsec', 'RemoveMe'),
    ('snmp-server host 1.1.1.1 traps version 2c {}', 'RemoveMe'),
    ('snmp-server host 1.1.1.1 informs version 3 auth {} ipsec', 'RemoveMe'),
    ('snmp-server host 1.1.1.1 traps version 3 noauth {}', 'RemoveMe'),
    ('snmp-server host 1.1.1.1 informs version 3 priv {} memory', 'RemoveMe'),
    ('snmp-server host 1.1.1.1 version 2c {}', 'RemoveMe'),
    ('snmp-server host 1.1.1.1 {} vrrp', 'RemoveMe')
]

# TODO(https://github.com/intentionet/netconan/issues/4):
# Add more Juniper config lines
juniper_password_lines = [
    ('secret "{}"', '$9$Be4EhyVb2GDkevYo'),
    ('set interfaces irb unit 5 family inet address 1.2.3.0/24 vrrp-group 5 authentication-key "{}"', '$9$i.m5OBEevLz3RSevx7-VwgZj5TFCA0Tz9p'),
    ('set system tacplus-server 1.2.3.4 secret "{}"', '$9$HqfQ1IcrK8n/t0IcvM24aZGi6/t'),
    ('set system tacplus-server 1.2.3.4 secret "{}"', '$9$YVgoZk.5n6AHq9tORlegoJGDkPfQCtOP5Qn9pRE'),
    ('set security ike policy test-ike-policy pre-shared-key ascii-text "{}"', '$9$/E6g9tO1IcSrvfTCu1hKv-VwgJD'),
    ('set system root-authentication encrypted-password "{}"', '$1$CXKwIUfL$6vLSvatE2TCaM25U4u9Bh1'),
    ('set system login user admin authentication encrypted-password "{}"', '$1$67Q0XA3z$YqiBW/xxKWr74oHPXEkIv1'),
    ('set system login user someone authenitcation "{}"', '$1$CNANTest$xAfu6Am1d5D/.6OVICuOu/'),
    ('set system license keys key "{}"', 'SOMETHING sensitive text here'),
    ('set snmp community {} authorization read-only', 'SECRETTEXT'),
    ('set snmp trap-group {} otherstuff', 'SECRETTEXT')
]

# TODO(https://github.com/intentionet/netconan/issues/3):
# Add more Arista config lines
arista_password_lines = [
    ('username noc secret sha512 {}', '$6$RMxgK5ALGIf.nWEC$tHuKCyfNtJMCY561P52dTzHUmYMmLxb/Mxik.j3vMUs8lMCPocM00/NAS.SN6GCWx7d/vQIgxnClyQLAb7n3x0')
]

misc_password_lines = [
    ('my password is ', '$1$salt$abcdefghijklmnopqrs'),
    ('set community {}', 'RemoveMe')
]

sensitive_lines = (cisco_password_lines +
                   cisco_snmp_community_lines + juniper_password_lines +
                   arista_password_lines + misc_password_lines)

sensitive_items_and_formats = [
    ('094F4107180B', _sensitive_item_formats.cisco_type7),
    ('00071C080555', _sensitive_item_formats.cisco_type7),
    ('1608030A2B25', _sensitive_item_formats.cisco_type7),
    ('070C2E424F072E04043A0E1E01', _sensitive_item_formats.cisco_type7),
    ('01999999', _sensitive_item_formats.numeric),
    ('987654321', _sensitive_item_formats.numeric),
    ('0000000000000000', _sensitive_item_formats.numeric),
    ('1234567890', _sensitive_item_formats.numeric),
    ('7', _sensitive_item_formats.numeric),
    ('A', _sensitive_item_formats.hexadecimal),
    ('0FFFFFFFFF', _sensitive_item_formats.hexadecimal),
    ('ABCDEF', _sensitive_item_formats.hexadecimal),
    ('7ab34c2fe31', _sensitive_item_formats.hexadecimal),
    ('deadBEEF', _sensitive_item_formats.hexadecimal),
    ('27a', _sensitive_item_formats.hexadecimal),
    ('$1$SALT$mutX1.3APXbr8JdR/Xi6t.', _sensitive_item_formats.md5),
    ('$1$SALT$X8i6w2OOpAaEMNBGfSoZC0', _sensitive_item_formats.md5),
    ('$1$SALT$ddio24/QfJatZkSKGuB4Z/', _sensitive_item_formats.md5),
    ('$1$salt$rwny14pmwbMjy1WTfxf4h/', _sensitive_item_formats.md5),
    ('$1$salt$BFdHEr6MVYydPmpY3FPXV/', _sensitive_item_formats.md5),
    ('$1$salt$jp6JinwkFEV.2OCDaXrmO1', _sensitive_item_formats.md5),
    ('$1$./4k$OVkG7VKh5GKt1/XjSO78.0', _sensitive_item_formats.md5),
    ('$1$CNANTest$xAfu6Am1d5D/.6OVICuOu/', _sensitive_item_formats.md5),
    ('$1$67Q0XA3z$YqiBW/xxKWr74oHPXEkIv1', _sensitive_item_formats.md5),
    ('thisIsATest', _sensitive_item_formats.text),
    ('netconan', _sensitive_item_formats.text),
    ('STRING', _sensitive_item_formats.text),
    ('text_here', _sensitive_item_formats.text),
    ('more-text-here0', _sensitive_item_formats.text),
    ('ABCDEFG', _sensitive_item_formats.text),
    ('$9$HqfQ1IcrK8n/t0IcvM24aZGi6/t', _sensitive_item_formats.juniper_type9),
    ('$9$YVgoZk.5n6AHq9tORlegoJGDkPfQCtOP5Qn9pRE', _sensitive_item_formats.juniper_type9),
    ('$6$RMxgK5ALGIf.nWEC$tHuKCyfNtJMCY561P52dTzHUmYMmLxb/Mxik.j3vMUs8lMCPocM00/NAS.SN6GCWx7d/vQIgxnClyQLAb7n3x0', _sensitive_item_formats.sha512)
]

unique_passwords = [
    '12345ABCDEF',
    'ABCDEF123456789',
    'F',
    'FF',
    '1A2B3C4D5E6F',
    '0000000A0000000',
    'DEADBEEF',
    '15260305170338051C362636',
    'ThisIsATest',
    'FLgBaJHXdYY_AcHZZMgQ_RhTDJXHUBAAB',
    '122A00190102180D3C2E',
    '$1$wtHI$0rN7R8PKwC30AsCGA77vy.',
    'JDYkqyIFWeBvzpljSfWmRZrmRSRE8syxKlOSjP9RCCkFinZbJI3GD5c6rckJR/Qju2PKLmOewbheAA==',
    'Password',
    '2ndPassword',
    'PasswordThree',
    '$9$HqfQ1IcrK8n/t0IcvM24aZGi6/t',
    '$1$CNANTest$xAfu6Am1d5D/.6OVICuOu/',
    '$6$NQJRTiqxZiNR0aWI$hU1EPleWl6wGcMtDxaMEqNhN8WnxEqmeFjWC5h8oh5USSn5P9ZgFXbf2giO8nEtM.yBXO3O6b.76LQ1zlmG3B0'
]

SALT = 'saltForTest'


@pytest.fixture(scope='module')
def regexes():
    """Compile regexes once for all tests in this module."""
    return generate_default_sensitive_item_regexes()


@pytest.mark.parametrize('raw_line, sensitive_as_numbers', [
    ('something {} something', ['123']),
    ('123-{}abc', ['65530']),
    ('asdf{0}_asdf{0}asdf', ['65530']),
    ('anonymize.{} and {}?', ['4567', '1234567']),
    ('{}', ['12345']),
    ('{} and other text', ['4567']),
    ('other text and {}', ['4567'])
])
def test_anonymize_as_numbers(raw_line, sensitive_as_numbers):
    """Test anonymization of lines with AS numbers."""
    anonymizer_as_number = AsNumberAnonymizer(sensitive_as_numbers, SALT)

    line = raw_line.format(*sensitive_as_numbers)
    anon_line = anonymize_as_numbers(anonymizer_as_number, line)

    # Anonymize each AS number individually & build another anon line
    anon_numbers = [anonymize_as_numbers(anonymizer_as_number, number) for number in sensitive_as_numbers]
    individually_anon_line = raw_line.format(*anon_numbers)

    # Make sure anonymizing each number individually gives the same result as anonymizing all at once
    assert(anon_line == individually_anon_line)

    for as_number in sensitive_as_numbers:
        # Make sure all AS numbers are removed from the line
        assert(as_number not in anon_line)


@pytest.mark.parametrize('raw_line, sensitive_as_numbers', [
    ('123{}890', ['65530']),
    ('{}{}', ['1234', '5678']),
    ('{}000', ['1234']),
    ('000{}', ['1234'])
])
def test_anonymize_as_numbers_ignore_sub_numbers(raw_line, sensitive_as_numbers):
    """Test that matching 'AS numbers' within other numbers are not replaced."""
    anonymizer_as_number = AsNumberAnonymizer(sensitive_as_numbers, SALT)

    line = raw_line.format(*sensitive_as_numbers)
    anon_line = anonymize_as_numbers(anonymizer_as_number, line)

    # Make sure substrings of other numbers are not affected
    assert(anon_line == line)


@pytest.mark.parametrize('as_number', [
    '0',
    '1234',
    '65534',
    '65535',
    '70000',
    '123456789',
    '4199999999',
    '4230000000',
    '4294967295'
])
def test_anonymize_as_num(as_number):
    """Test anonymization of AS numbers."""
    anonymizer = AsNumberAnonymizer([as_number], SALT)
    assert(anonymizer.anonymize(as_number) != as_number)


def get_as_number_block(as_number):
    """Determine which block a given AS number is in."""
    block = 0
    as_number = int(as_number)
    for upper_bound in AsNumberAnonymizer._AS_NUM_BOUNDARIES:
        if as_number < upper_bound:
            return block
        block += 1


@pytest.mark.parametrize('as_number', [
    '0', '64511',               # Original public block
    '64512', '65535',           # Original private block
    '65536', '4199999999',      # Expanded public block
    '4200000000', '4294967295'  # Expanded private block
])
def test_preserve_as_block(as_number):
    """Test that original AS number block is preserved after anonymization."""
    anonymizer = AsNumberAnonymizer([as_number], SALT)
    new_as_number = anonymizer.anonymize(as_number)
    assert(get_as_number_block(new_as_number) == get_as_number_block(as_number))


@pytest.mark.parametrize('invalid_as_number', [
    '-1', '4294967296'
])
def test_as_number_invalid(invalid_as_number):
    """Test that exception is thrown with invalid AS number."""
    with pytest.raises(ValueError):
        AsNumberAnonymizer([invalid_as_number], SALT)


@pytest.mark.parametrize('raw_line, sensitive_words', [
    ('something {} something', ['secret']),
    ('something{}something', ['secret']),
    ('{}', ['secret']),
    ('a{0}b{0}c{0}d', ['secret']),
    ('testing {} and {}.', ['SECRET', 'blah']),
    ('testing {}{}.', ['secret', 'blah'])
])
def test_anonymize_sensitive_words(raw_line, sensitive_words):
    """Test anonymization of specified sensitive words."""
    sens_word_regexes = generate_sensitive_word_regexes(sensitive_words)
    line = raw_line.format(*sensitive_words)
    anon_line = anonymize_sensitive_words(sens_word_regexes, line, SALT)

    # Now anonymize each sensitive word individually & build another anon line
    anon_words = [anonymize_sensitive_words(sens_word_regexes, word, SALT) for word in sensitive_words]
    individually_anon_line = raw_line.format(*anon_words)

    anon_line_lower = anonymize_sensitive_words(sens_word_regexes, line.lower(), SALT)
    anon_line_upper = anonymize_sensitive_words(sens_word_regexes, line.upper(), SALT)

    # Make sure reanonymizing each word individually gives the same result as
    # anonymizing all at once, the first time
    assert(anon_line == individually_anon_line)

    for sens_word in sensitive_words:
        # Make sure all sensitive words are removed from the anonymized line
        assert(sens_word not in anon_line)

        # Test for case insensitivity
        # Make sure all sensitive words are removed from the lowercase line
        assert(sens_word.lower() not in anon_line_lower)

        # Make sure all sensitive words are removed from the uppercase line
        assert(sens_word.upper() not in anon_line_upper)


@pytest.mark.parametrize('val', unique_passwords)
def test__anonymize_value(val):
    """Test sensitive item anonymization."""
    pwd_lookup = {}
    anon_val = _anonymize_value(val, pwd_lookup)
    val_format = _check_sensitive_item_format(val)
    anon_val_format = _check_sensitive_item_format(anon_val)

    # Confirm the anonymized value does not match the original value
    assert(anon_val != val)

    # Confirm format for anonmymized value matches format of the original value
    assert(anon_val_format == val_format)

    if (val_format == _sensitive_item_formats.md5):
        org_salt_size = len(val.split('$')[2])
        anon_salt_size = len(anon_val.split('$')[2])
        # Make sure salt size is preserved for md5 sensitive items
        # (Cisco should stay 4 character, Juniper 8 character, etc)
        assert(org_salt_size == anon_salt_size)

    # Confirm reanonymizing same source value results in same anonymized value
    assert(anon_val == _anonymize_value(val, pwd_lookup))


def test__anonymize_value_unique():
    """Test that unique sensitive items have unique anonymized values."""
    pwd_lookup = {}
    anon_vals = [_anonymize_value(pwd, pwd_lookup) for pwd in unique_passwords]
    unique_anon_vals = set()

    for anon_val in anon_vals:
        # Confirm unique source values have unique anonymized values
        assert(anon_val not in unique_anon_vals)
        unique_anon_vals.add(anon_val)


@pytest.mark.parametrize('val, format_', sensitive_items_and_formats)
def test__check_sensitive_item_format(val, format_):
    """Test sensitive item format detection."""
    item_format = _check_sensitive_item_format(val)
    assert(item_format == format_)


@pytest.mark.parametrize('val', unique_passwords)
@pytest.mark.parametrize('quote', [
    '\'',
    '"',
    '\\\'',
    '\\"'
])
def test__extract_enclosing_text(val, quote):
    """Test extraction of enclosing quotes."""
    enclosed_val = quote + val + quote
    enclosing_text, extracted_text = _extract_enclosing_text(enclosed_val)

    # Confirm the extracted text matches the original text
    assert(extracted_text == val)
    # Confirm the extracted enclosing text matches the original enclosing text
    assert (enclosing_text == quote)


@pytest.mark.parametrize('config_line,sensitive_text', sensitive_lines)
def test_pwd_removal(regexes, config_line, sensitive_text):
    """Test removal of passwords and communities from config lines."""
    config_line = config_line.format(sensitive_text)
    pwd_lookup = {}
    assert(sensitive_text not in replace_matching_item(regexes, config_line, pwd_lookup))


@pytest.mark.parametrize('whitespace', [
    '  ',
    '\t',
    '\n'
])
def test_pwd_removal_preserve_leading_whitespace(regexes, whitespace):
    """Test leading whitespace is preserved in config lines."""
    config_line = '{whitespace}{line}'.format(line='password secret',
                                              whitespace=whitespace)
    pwd_lookup = {}
    processed_line = replace_matching_item(regexes, config_line, pwd_lookup)
    assert(processed_line.startswith(whitespace))


@pytest.mark.parametrize('whitespace', [
    '  ',
    '\t',
    '\n'
])
def test_pwd_removal_preserve_trailing_whitespace(regexes, whitespace):
    """Test trailing whitespace is preserved in config lines."""
    config_line = '{line}{whitespace}'.format(line='password secret',
                                              whitespace=whitespace)
    pwd_lookup = {}
    processed_line = replace_matching_item(regexes, config_line, pwd_lookup)
    assert(processed_line.endswith(whitespace))


@pytest.mark.parametrize('config_line,sensitive_text', sensitive_lines)
@pytest.mark.parametrize('prepend_text', [
    '"',
    '\'',
    '{',
    ':',
    'something " ',
    'something \' ',
    'something { ',
    'something : '
])
def test_pwd_removal_prepend(regexes, config_line, sensitive_text, prepend_text):
    """Test that sensitive lines are still anonymized correctly if preceded by allowed text."""
    config_line = prepend_text + config_line.format(sensitive_text)
    pwd_lookup = {}
    assert(sensitive_text not in replace_matching_item(regexes, config_line, pwd_lookup))


@pytest.mark.parametrize('config_line,sensitive_text', sensitive_lines)
@pytest.mark.parametrize('append_text', [
    '"',
    '\'',
    '}',
    '" something',
    '\' something',
    '} something',
])
def test_pwd_removal_append(regexes, config_line, sensitive_text, append_text):
    """Test that sensitive lines are still anonymized correctly if followed by allowed text."""
    config_line = config_line.format(sensitive_text) + append_text
    pwd_lookup = {}
    assert(sensitive_text not in replace_matching_item(regexes, config_line, pwd_lookup))


@pytest.mark.parametrize('config_line', [
    'nothing in this string should be replaced',
    '      interface GigabitEthernet0/0',
    'ip address 1.2.3.4 255.255.255.0'
])
def test_pwd_removal_insensitive_lines(regexes, config_line):
    """Make sure benign lines are not affected by sensitive_item_removal."""
    pwd_lookup = {}
    # Collapse all whitespace in original config_line and add newline since
    # that will be done by replace_matching_item
    config_line = '{}\n'.format(' '.join(config_line.split()))
    assert(config_line == replace_matching_item(regexes, config_line, pwd_lookup))
