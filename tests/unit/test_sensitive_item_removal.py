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

import pytest

from netconan.sensitive_item_removal import (
    _LINE_SCRUBBED_MESSAGE,
    SensitiveWordAnonymizer,
    _anonymize_value,
    _check_sensitive_item_format,
    _extract_enclosing_text,
    _sensitive_item_formats,
    generate_default_sensitive_item_regexes,
    replace_matching_item,
)

# Tuple format is config_line, sensitive_text (should not be in output line)

# TODO(https://github.com/intentionet/netconan/issues/3):
# Add more Arista config lines
arista_password_lines = [
    (
        "username noc secret sha512 {}",
        "$6$RMxgK5ALGIf.nWEC$tHuKCyfNtJMCY561P52dTzHUmYMmLxb/Mxik.j3vMUs8lMCPocM00/NAS.SN6GCWx7d/vQIgxnClyQLAb7n3x0",
    ),
    ("   vrrp 2 authentication text {}", "RemoveMe"),
]
# TODO(https://github.com/intentionet/netconan/issues/3):
# Add in additional test lines (these are just first pass from IOS)
cisco_password_lines = [
    (" password 7 {}", "122A00190102180D3C2E"),
    ("username Someone password 0 {}", "RemoveMe"),
    ("username Someone password {}", "RemoveMe"),
    ("username Someone password 7 {}", "122A00190102180D3C2E"),
    ("enable password level 12 {}", "RemoveMe"),
    ("enable password 7 {}", "122A00190102180D3C2E"),
    ("enable password level 3 5 {}", "$1$wtHI$0rN7R8PKwC30AsCGA77vy."),
    ("enable secret 5 {}", "$1$wtHI$0rN7R8PKwC30AsCGA77vy."),
    ("username Someone view Someview password 7 {}", "122A00190102180D3C2E"),
    ("username Someone password {}", "RemoveMe"),
    ("username Someone secret 5 {}", "$1$wtHI$0rN7R8PKwC30AsCGA77vy."),
    ("username Someone secret {}", "RemoveMe"),
    ("username Someone view Someview secret {}", "RemoveMe"),
    ("ip ftp password {}", "RemoveMe"),
    ("ip ftp password 0 {}", "RemoveMe"),
    ("ip ftp password 7 {}", "122A00190102180D3C2E"),
    (" ip ospf authentication-key {}", "RemoveMe"),
    (" ip ospf authentication-key 0 {}", "RemoveMe"),
    (" ip ospf message-digest-key 1 md5 {}", "RemoveMe"),
    (" ip ospf message-digest-key 1 md5 3 {}", "RemoveMe"),
    ("isis password {}", "RemoveMe"),
    ("domain-password {}", "RemoveMe"),
    ("domain-password {} authenticate snp validate", "RemoveMe"),
    ("area-password {} authenticate snp send-only", "RemoveMe"),
    ("ip ospf message-digest-key 123 md5 {}", "RemoveMe"),
    ("ip ospf message-digest-key 124 md5 7 {}", "122A00190102180D3C2E"),
    ("standby authentication {}", "RemoveMe"),
    ("standby authentication md5 key-string {} timeout 123", "RemoveMe"),
    ("standby authentication md5 key-string 7 {}", "RemoveMe"),
    ("standby authentication text {}", "RemoveMe"),
    ("l2tp tunnel password 0 {}", "RemoveMe"),
    ("l2tp tunnel password {}", "RemoveMe"),
    ("digest secret {} hash MD5", "RemoveMe"),
    ("digest secret {}", "RemoveMe"),
    ("digest secret 0 {}", "RemoveMe"),
    ("ppp chap password {}", "RemoveMe"),
    ("ppp chap password 0 {}", "RemoveMe"),
    ("ppp chap hostname {}", "RemoveMe"),
    ("pre-shared-key {}", "RemoveMe"),
    ("pre-shared-key 0 {}", "RemoveMe"),
    ("pre-shared-key local 0 {}", "RemoveMe"),
    ("pre-shared-key remote hex {}", "1234a"),
    ("pre-shared-key remote 6 {}", "FLgBaJHXdYY_AcHZZMgQ_RhTDJXHUBAAB"),
    ("tacacs-server host 1.1.1.1 key {}", "RemoveMe"),
    ("radius-server host 1.1.1.1 key 0 {}", "RemoveMe"),
    ("tacacs-server key 7 {}", "122A00190102180D3C2E"),
    (" key 0 {}", "RemoveMe"),
    ("ntp authentication-key 4294967295 md5 {}", "RemoveMe"),
    ("ntp authentication-key 123 md5 {} 1", "RemoveMe"),
    ("syscon address 1.1.1.1 {}", "RemoveMe"),
    ("snmp-server user Someone Somegroup remote Crap v3 auth md5 {}", "RemoveMe"),
    ("snmp-server user Someone Somegroup v3 auth sha {0} priv 3des {0}", "RemoveMe"),
    ("snmp-server user Someone Somegroup v3 auth sha {0} priv {0}", "RemoveMe"),
    ("snmp-server user Someone Somegroup auth md5 {0} priv aes 128 {0}", "RemoveMe"),
    ("snmp-server user Someone Somegroup auth md5 {0} priv {0} something", "RemoveMe"),
    # TODO: Figure out SHA format, this line throws: Error in Auth password
    ("snmp-server user Someone Somegroup v3 encrypted auth sha {}", "RemoveMe"),
    ("crypto isakmp key {} address 1.1.1.1 255.255.255.0", "RemoveMe"),
    ("crypto isakmp key 6 {} hostname Something", "RemoveMe"),
    ("set session-key inbound ah 4294967295 {}", "1234abcdef"),
    ("set session-key outbound esp 256 authenticator {}", "1234abcdef"),
    ("set session-key outbound esp 256 cipher {0} authenticator {0}", "1234abcdef"),
    ("key-hash sha256 {}", "RemoveMe"),
    ("  authentication text {}", "RemoveMe"),  # HSRP
]

cisco_snmp_community_lines = [
    ("snmp-server community {} ro 1", "RemoveMe"),
    ("snmp-server community {} Something", "RemoveMe"),
    ("snmp-server host 1.1.1.1 vrf Something informs {} config", "RemoveMe"),
    ("snmp-server host 1.1.1.1 informs version 1 {} ipsec", "RemoveMe"),
    ("snmp-server host 1.1.1.1 traps version 2c {}", "RemoveMe"),
    ("snmp-server host 1.1.1.1 informs version 3 auth {} ipsec", "RemoveMe"),
    ("snmp-server host 1.1.1.1 traps version 3 noauth {}", "RemoveMe"),
    ("snmp-server host 1.1.1.1 informs version 3 priv {} memory", "RemoveMe"),
    ("snmp-server host 1.1.1.1 version 2c {}", "RemoveMe"),
    ("snmp-server host 1.1.1.1 {} vrrp", "RemoveMe"),
    ("snmp-server mib community-map {}:100 context public1", "RemoveMe"),
    ("snmp-server community {} RW 2", "secretcommunity"),
    ("rf-switch snmp-community {}", "RemoveMe"),
]

# TODO(https://github.com/intentionet/netconan/issues/3):
fortinet_password_lines = [
    (
        "set password ENC {}",
        "SH2nlSm9QL9tapcHPXIqAXvX7vBJuuqu22hpa0JX0sBuKIo7z2g0Kz/+0KyH4E=",
    ),
    (
        "set password {}",
        "mysecret",
    ),
    (
        "set pksecret ENC {}",
        "SH2nlSm9QL9tapcHPXIqAXvX7vBJuuqu22hpa0JX0sBuKIo7z2g0Kz/+0KyH4E=",
    ),
    (
        "set pksecret {}",
        "mysecret",
    ),
]

# TODO(https://github.com/intentionet/netconan/issues/4):
# Add more Juniper config lines
juniper_password_lines = [
    ('secret "{}"', "$9$Be4EhyVb2GDkevYo"),
    (
        'set interfaces irb unit 5 family inet address 1.2.3.0/24 vrrp-group 5 authentication-key "{}"',
        "$9$i.m5OBEevLz3RSevx7-VwgZj5TFCA0Tz9p",
    ),
    ('set system tacplus-server 1.2.3.4 secret "{}"', "$9$HqfQ1IcrK8n/t0IcvM24aZGi6/t"),
    (
        'set system tacplus-server 1.2.3.4 secret "{}"',
        "$9$YVgoZk.5n6AHq9tORlegoJGDkPfQCtOP5Qn9pRE",
    ),
    (
        'set security ike policy test-ike-policy pre-shared-key ascii-text "{}"',
        "$9$/E6g9tO1IcSrvfTCu1hKv-VwgJD",
    ),
    (
        'set system root-authentication encrypted-password "{}"',
        "$1$CXKwIUfL$6vLSvatE2TCaM25U4u9Bh1",
    ),
    (
        'set system login user admin authentication encrypted-password "{}"',
        "$1$67Q0XA3z$YqiBW/xxKWr74oHPXEkIv1",
    ),
    (
        'set system login user someone authenitcation "{}"',
        "$1$CNANTest$xAfu6Am1d5D/.6OVICuOu/",
    ),
    ('set system license keys key "{}"', "SOMETHING"),
    # Does not pass yet, see TODO(https://github.com/intentionet/netconan/issues/107)
    pytest.param(
        'set system license keys key "{}"',
        "SOMETHING sensitive",
        marks=pytest.mark.skip(),
    ),
    ("set snmp community {} authorization read-only", "SECRETTEXT"),
    ("set snmp trap-group {} otherstuff", "SECRETTEXT"),
    ("key hexadecimal {}", "ABCDEF123456"),
    ('authentication-key "{}";', "$9$i.m5OBEevLz3RSevx7-VwgZj5TFCA0Tz9p"),
    ("hello-authentication-key {}", "$9$i.m5OBEevLz3RSevx7-VwgZj5TFCA0Tz9p"),
]

misc_password_lines = [
    ("my password is ", "$1$salt$abcdefghijklmnopqrs"),
    ("set community {} trailing text", "RemoveMe"),
    ("set community {}", "1234a"),
    ("set community {}", "a1234"),
]

sensitive_lines = (
    arista_password_lines
    + cisco_password_lines
    + cisco_snmp_community_lines
    + fortinet_password_lines
    + juniper_password_lines
    + misc_password_lines
)

sensitive_items_and_formats = [
    ("094F4107180B", _sensitive_item_formats.cisco_type7),
    ("00071C080555", _sensitive_item_formats.cisco_type7),
    ("1608030A2B25", _sensitive_item_formats.cisco_type7),
    ("070C2E424F072E04043A0E1E01", _sensitive_item_formats.cisco_type7),
    ("01999999", _sensitive_item_formats.numeric),
    ("987654321", _sensitive_item_formats.numeric),
    ("0000000000000000", _sensitive_item_formats.numeric),
    ("1234567890", _sensitive_item_formats.numeric),
    ("7", _sensitive_item_formats.numeric),
    ("A", _sensitive_item_formats.hexadecimal),
    ("0FFFFFFFFF", _sensitive_item_formats.hexadecimal),
    ("ABCDEF", _sensitive_item_formats.hexadecimal),
    ("7ab34c2fe31", _sensitive_item_formats.hexadecimal),
    ("deadBEEF", _sensitive_item_formats.hexadecimal),
    ("27a", _sensitive_item_formats.hexadecimal),
    ("$1$SALT$mutX1.3APXbr8JdR/Xi6t.", _sensitive_item_formats.md5),
    ("$1$SALT$X8i6w2OOpAaEMNBGfSoZC0", _sensitive_item_formats.md5),
    ("$1$SALT$ddio24/QfJatZkSKGuB4Z/", _sensitive_item_formats.md5),
    ("$1$salt$rwny14pmwbMjy1WTfxf4h/", _sensitive_item_formats.md5),
    ("$1$salt$BFdHEr6MVYydPmpY3FPXV/", _sensitive_item_formats.md5),
    ("$1$salt$jp6JinwkFEV.2OCDaXrmO1", _sensitive_item_formats.md5),
    ("$1$./4k$OVkG7VKh5GKt1/XjSO78.0", _sensitive_item_formats.md5),
    ("$1$CNANTest$xAfu6Am1d5D/.6OVICuOu/", _sensitive_item_formats.md5),
    ("$1$67Q0XA3z$YqiBW/xxKWr74oHPXEkIv1", _sensitive_item_formats.md5),
    ("thisIsATest", _sensitive_item_formats.text),
    ("netconan", _sensitive_item_formats.text),
    ("STRING", _sensitive_item_formats.text),
    ("text_here", _sensitive_item_formats.text),
    ("more-text-here0", _sensitive_item_formats.text),
    ("ABCDEFG", _sensitive_item_formats.text),
    ("$9$HqfQ1IcrK8n/t0IcvM24aZGi6/t", _sensitive_item_formats.juniper_type9),
    (
        "$9$YVgoZk.5n6AHq9tORlegoJGDkPfQCtOP5Qn9pRE",
        _sensitive_item_formats.juniper_type9,
    ),
    (
        "$6$RMxgK5ALGIf.nWEC$tHuKCyfNtJMCY561P52dTzHUmYMmLxb/Mxik.j3vMUs8lMCPocM00/NAS.SN6GCWx7d/vQIgxnClyQLAb7n3x0",
        _sensitive_item_formats.sha512,
    ),
]

unique_passwords = [
    "12345ABCDEF",
    "ABCDEF123456789",
    "F",
    "FF",
    "1A2B3C4D5E6F",
    "0000000A0000000",
    "DEADBEEF",
    "15260305170338051C362636",
    "ThisIsATest",
    "FLgBaJHXdYY_AcHZZMgQ_RhTDJXHUBAAB",
    "122A00190102180D3C2E",
    "$1$wtHI$0rN7R8PKwC30AsCGA77vy.",
    "JDYkqyIFWeBvzpljSfWmRZrmRSRE8syxKlOSjP9RCCkFinZbJI3GD5c6rckJR/Qju2PKLmOewbheAA==",
    "Password",
    "2ndPassword",
    "PasswordThree",
    "$9$HqfQ1IcrK8n/t0IcvM24aZGi6/t",
    "$1$CNANTest$xAfu6Am1d5D/.6OVICuOu/",
    "$6$NQJRTiqxZiNR0aWI$hU1EPleWl6wGcMtDxaMEqNhN8WnxEqmeFjWC5h8oh5USSn5P9ZgFXbf2giO8nEtM.yBXO3O6b.76LQ1zlmG3B0",
]

SALT = "saltForTest"


@pytest.fixture(scope="module")
def regexes():
    """Compile regexes once for all tests in this module."""
    return generate_default_sensitive_item_regexes()


@pytest.mark.parametrize(
    "raw_line, sensitive_words",
    [
        ("something {} something", ["secret"]),
        ("something{}something", ["secret"]),
        ("{}", ["secret"]),
        ("a{0}b{0}c{0}d", ["secret"]),
        ("testing {} and {}.", ["SECRET", "blah"]),
        ("testing {}{}.", ["secret", "blah"]),
    ],
)
def test_anonymize_sensitive_words(raw_line, sensitive_words):
    """Test anonymization of specified sensitive words."""
    sens_word_anonymizer = SensitiveWordAnonymizer(sensitive_words, SALT, [])
    line = raw_line.format(*sensitive_words)
    anon_line = sens_word_anonymizer.anonymize(line)

    # Now anonymize each sensitive word individually & build another anon line
    anon_words = [sens_word_anonymizer.anonymize(word) for word in sensitive_words]
    individually_anon_line = raw_line.format(*anon_words)

    anon_line_lower = sens_word_anonymizer.anonymize(line.lower())
    anon_line_upper = sens_word_anonymizer.anonymize(line.upper())

    # Make sure reanonymizing each word individually gives the same result as
    # anonymizing all at once, the first time
    assert anon_line == individually_anon_line

    for sens_word in sensitive_words:
        # Make sure all sensitive words are removed from the anonymized line
        assert sens_word not in anon_line

        # Test for case insensitivity
        # Make sure all sensitive words are removed from the lowercase line
        assert sens_word.lower() not in anon_line_lower

        # Make sure all sensitive words are removed from the uppercase line
        assert sens_word.upper() not in anon_line_upper


def test_anonymize_sensitive_words_preserve_reserved_word():
    """Test preservation of reserved words when anonymizing sensitive words."""
    reserved_word = "search"
    # Intentionally use different case than reserved word
    keyword = "SEA"
    keyword_plural = "seas"
    line = "{reserved_word} {keyword} {keyword_plural}".format(
        reserved_word=reserved_word, keyword=keyword, keyword_plural=keyword_plural
    )

    anonymizer = SensitiveWordAnonymizer([keyword], SALT, [reserved_word])
    anon_line = anonymizer.anonymize(line)

    # Confirm keyword and plural keyword are removed from the line
    assert keyword not in anon_line.split()
    assert keyword_plural not in anon_line.split()

    # Confirm the reserved word was not replaced
    assert reserved_word in anon_line.split()


@pytest.mark.parametrize("val", unique_passwords)
def test__anonymize_value(val):
    """Test sensitive item anonymization."""
    pwd_lookup = {}
    anon_val = _anonymize_value(val, pwd_lookup, {})
    val_format = _check_sensitive_item_format(val)
    anon_val_format = _check_sensitive_item_format(anon_val)

    # Confirm the anonymized value does not match the original value
    assert anon_val != val

    # Confirm format for anonmymized value matches format of the original value
    assert anon_val_format == val_format

    if val_format == _sensitive_item_formats.md5:
        org_salt_size = len(val.split("$")[2])
        anon_salt_size = len(anon_val.split("$")[2])
        # Make sure salt size is preserved for md5 sensitive items
        # (Cisco should stay 4 character, Juniper 8 character, etc)
        assert org_salt_size == anon_salt_size

    # Confirm reanonymizing same source value results in same anonymized value
    assert anon_val == _anonymize_value(val, pwd_lookup, {})


def test__anonymize_value_unique():
    """Test that unique sensitive items have unique anonymized values."""
    pwd_lookup = {}
    anon_vals = [_anonymize_value(pwd, pwd_lookup, {}) for pwd in unique_passwords]
    unique_anon_vals = set()

    for anon_val in anon_vals:
        # Confirm unique source values have unique anonymized values
        assert anon_val not in unique_anon_vals
        unique_anon_vals.add(anon_val)


@pytest.mark.parametrize("val, format_", sensitive_items_and_formats)
def test__check_sensitive_item_format(val, format_):
    """Test sensitive item format detection."""
    item_format = _check_sensitive_item_format(val)
    assert item_format == format_


@pytest.mark.parametrize("raw_val", unique_passwords)
@pytest.mark.parametrize(
    "head_text",
    [
        "'",
        '"',
        "\\'",
        '\\"',
        "[",
        "[ ",
        "\"['[",
        '" [',
        "{",
    ],
)
def test__extract_enclosing_text_head(raw_val, head_text):
    """Test extraction of leading text."""
    val = head_text + raw_val
    head, extracted_text, tail = _extract_enclosing_text(val)

    # Confirm the extracted text matches the original text
    assert extracted_text == raw_val
    # Confirm the leading text matches the prepended text
    assert head == head_text
    assert not tail


@pytest.mark.parametrize("raw_val", unique_passwords)
@pytest.mark.parametrize(
    "tail_text",
    [
        "'",
        '"',
        "\\'",
        '\\"',
        "]",
        " ]",
        ";",
        ",",
        '"],',
        "] ;",
        "}",
    ],
)
def test__extract_enclosing_text_tail(raw_val, tail_text):
    """Test extraction of trailing text."""
    val = raw_val + tail_text
    head, extracted_text, tail = _extract_enclosing_text(val)

    # Confirm the extracted text matches the original text
    assert extracted_text == raw_val
    # Confirm the trailing text matches the appended text
    assert tail == tail_text
    assert not head


@pytest.mark.parametrize("val", unique_passwords)
@pytest.mark.parametrize("quote", ["'", '"', "\\'", '\\"'])
def test__extract_enclosing_text(val, quote):
    """Test extraction of enclosing quotes."""
    enclosed_val = quote + val + quote
    head, extracted_text, tail = _extract_enclosing_text(enclosed_val)

    # Confirm the extracted text matches the original text
    assert extracted_text == val
    # Confirm the extracted enclosing text matches the original enclosing text
    assert head == tail
    assert head == quote


@pytest.mark.parametrize("raw_config_line,sensitive_text", sensitive_lines)
def test_pwd_removal(regexes, raw_config_line, sensitive_text):
    """Test removal of passwords and communities from config lines."""
    config_line = raw_config_line.format(sensitive_text)
    pwd_lookup = {}
    anon_line = replace_matching_item(regexes, config_line, pwd_lookup)
    # Make sure the output line does not contain the sensitive text
    assert sensitive_text not in anon_line

    if _LINE_SCRUBBED_MESSAGE not in anon_line:
        # If the line wasn't "completely scrubbed",
        # make sure context was preserved
        anon_val = _anonymize_value(sensitive_text, pwd_lookup, {})
        assert anon_line == raw_config_line.format(anon_val)


def test_pwd_removal_with_whitespace(regexes):
    """Test removal of password when a sensitive line contains extra whitespace."""
    sensitive_text = "RemoveMe"
    sensitive_line = "     password   0      \t{}".format(sensitive_text)
    assert sensitive_text not in replace_matching_item(regexes, sensitive_line, {})


@pytest.mark.parametrize(
    "config_line, sensitive_text",
    [
        (
            "snmp-server user Someone Somegroup auth md5 ipaddress priv {0} something",
            "RemoveMe",
        ),
        (
            "snmp-server user Someone Somegroup auth md5 {0} priv ipaddress something",
            "RemoveMe",
        ),
    ],
)
def test_pwd_removal_and_preserve_reserved_word(regexes, config_line, sensitive_text):
    """Test removal of passwords when reserved words must be skipped."""
    config_line = config_line.format(sensitive_text)
    pwd_lookup = {}
    assert sensitive_text not in replace_matching_item(regexes, config_line, pwd_lookup)


@pytest.mark.parametrize(
    "config_line",
    [
        "password ipaddress",
        "set community p2p",
        "digest secret snmp",
        "password {",
        'password "ip"',
    ],
)
def test_pwd_removal_preserve_reserved_word(regexes, config_line):
    """Test that reserved words are preserved even if they appear in password lines."""
    pwd_lookup = {}
    assert config_line == replace_matching_item(regexes, config_line, pwd_lookup)


@pytest.mark.parametrize(
    "config_line, anon_line",
    [
        ('"key": "password FOOBAR",', '"key": "password netconanRemoved0",'),
        (
            '{"key": "cable shared-secret FOOBAR"}',
            '{"key": "! Sensitive line SCRUBBED by netconan"}',
        ),
        ('password "FOOBAR";', 'password "netconanRemoved0";'),
    ],
)
def test_pwd_removal_preserve_context(regexes, config_line, anon_line):
    """Test that context is preserved replacing/removing passwords."""
    pwd_lookup = {}
    assert anon_line == replace_matching_item(regexes, config_line, pwd_lookup)


@pytest.mark.parametrize("whitespace", [" ", "\t", "\n", " \t\n"])
def test_pwd_removal_preserve_leading_whitespace(regexes, whitespace):
    """Test leading whitespace is preserved in config lines."""
    config_line = "{whitespace}{line}".format(
        line="password secret", whitespace=whitespace
    )
    pwd_lookup = {}
    processed_line = replace_matching_item(regexes, config_line, pwd_lookup)
    assert processed_line.startswith(whitespace)


@pytest.mark.parametrize("whitespace", [" ", "\t", "\n", " \t\n"])
def test_pwd_removal_preserve_trailing_whitespace(regexes, whitespace):
    """Test trailing whitespace is preserved in config lines."""
    config_line = "{line}{whitespace}".format(
        line="password secret", whitespace=whitespace
    )
    pwd_lookup = {}
    processed_line = replace_matching_item(regexes, config_line, pwd_lookup)
    assert processed_line.endswith(whitespace)


@pytest.mark.parametrize("config_line,sensitive_text", sensitive_lines)
@pytest.mark.parametrize(
    "prepend_text",
    [
        '"',
        "'",
        "{",
        ":",
        'something " ',
        "something ' ",
        "something { ",
        "something : ",
    ],
)
def test_pwd_removal_prepend(regexes, config_line, sensitive_text, prepend_text):
    """Test that sensitive lines are still anonymized correctly if preceded by allowed text."""
    config_line = prepend_text + config_line.format(sensitive_text)
    pwd_lookup = {}
    assert sensitive_text not in replace_matching_item(regexes, config_line, pwd_lookup)


@pytest.mark.parametrize("config_line,sensitive_text", sensitive_lines)
@pytest.mark.parametrize(
    "append_text",
    [
        '"',
        "'",
        "}",
        '" something',
        "' something",
        "} something",
    ],
)
def test_pwd_removal_append(regexes, config_line, sensitive_text, append_text):
    """Test that sensitive lines are still anonymized correctly if followed by allowed text."""
    config_line = config_line.format(sensitive_text) + append_text
    pwd_lookup = {}
    assert sensitive_text not in replace_matching_item(regexes, config_line, pwd_lookup)


@pytest.mark.parametrize(
    "config_line",
    [
        "nothing in this string should be replaced",
        "      interface GigabitEthernet0/0",
        "ip address 1.2.3.4 255.255.255.0",
        "set community 12345",
        "set community 1234:5678",
        "set community (1234:5678)",
        "set community 1234:5678 additive",
        "set community (1234:5678) additive",
        "set community gshut",
        "set community internet",
        "set community local-AS",
        "set community no-advertise",
        "set community no-export",
        "set community (no-export)",
        "set community none",
        "set community (12345 123:456 $foo:$bar no-export)",
        "set community (12345 123:456 $foo:$bar no-export) additive",
        "set community $foo:123",
        "set community $foo:$bar",
        "set community 123:$bar",
        "set community blah additive",
        "set community no-export additive",
        "set community peeras:24",
    ],
)
def test_pwd_removal_insensitive_lines(regexes, config_line):
    """Make sure benign lines are not affected by sensitive_item_removal."""
    pwd_lookup = {}
    # Collapse all whitespace in original config_line and add newline since
    # that will be done by replace_matching_item
    config_line = "{}\n".format(" ".join(config_line.split()))
    assert config_line == replace_matching_item(regexes, config_line, pwd_lookup)
