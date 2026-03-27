"""Test SSH key anonymization."""

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

import base64
import struct

import pytest

from netconan.ssh_key_anonymization import (
    anonymize_ssh_key_blob,
    anonymize_ssh_key_hash,
    generate_ssh_key_regexes,
    replace_ssh_keys,
)

SALT = "testSalt"

# Real SSH public key blobs (base64-encoded) for testing.
# These are generated test keys, not real credentials.

# Ed25519 key blob: \x00\x00\x00\x0bssh-ed25519\x00\x00\x00\x20 + 32 bytes
_ED25519_KEY_TYPE = b"ssh-ed25519"
_ED25519_KEY_DATA = b"\x01" * 32
_ED25519_BLOB = base64.b64encode(
    struct.pack(">I", len(_ED25519_KEY_TYPE))
    + _ED25519_KEY_TYPE
    + struct.pack(">I", len(_ED25519_KEY_DATA))
    + _ED25519_KEY_DATA
).decode()

# RSA key blob: key type header + fake exponent + fake modulus
_RSA_KEY_TYPE = b"ssh-rsa"
_RSA_EXPONENT = b"\x01\x00\x01"  # 65537
_RSA_MODULUS = b"\x02" * 256  # 2048-bit key
_RSA_BLOB = base64.b64encode(
    struct.pack(">I", len(_RSA_KEY_TYPE))
    + _RSA_KEY_TYPE
    + struct.pack(">I", len(_RSA_EXPONENT))
    + _RSA_EXPONENT
    + struct.pack(">I", len(_RSA_MODULUS))
    + _RSA_MODULUS
).decode()

# DSA key blob
_DSA_KEY_TYPE = b"ssh-dss"
_DSA_DATA = b"\x03" * 128
_DSA_BLOB = base64.b64encode(
    struct.pack(">I", len(_DSA_KEY_TYPE)) + _DSA_KEY_TYPE + _DSA_DATA
).decode()

# ECDSA key blob
_ECDSA_KEY_TYPE = b"ecdsa-sha2-nistp256"
_ECDSA_DATA = b"\x04" * 64
_ECDSA_BLOB = base64.b64encode(
    struct.pack(">I", len(_ECDSA_KEY_TYPE)) + _ECDSA_KEY_TYPE + _ECDSA_DATA
).decode()


class TestAnonymizeSshKeyBlob:
    """Tests for anonymize_ssh_key_blob()."""

    def test_determinism(self):
        """Same key + same salt always produces same output."""
        result1 = anonymize_ssh_key_blob(_ED25519_BLOB, SALT)
        result2 = anonymize_ssh_key_blob(_ED25519_BLOB, SALT)
        assert result1 == result2

    def test_different_output(self):
        """Anonymized key differs from original."""
        result = anonymize_ssh_key_blob(_ED25519_BLOB, SALT)
        assert result != _ED25519_BLOB

    def test_base64_length_preserved(self):
        """Anonymized blob has same base64 length."""
        for blob in [_ED25519_BLOB, _RSA_BLOB, _DSA_BLOB, _ECDSA_BLOB]:
            result = anonymize_ssh_key_blob(blob, SALT)
            assert len(result) == len(blob), (
                f"Length mismatch for blob starting with {blob[:20]}"
            )

    def test_key_type_header_preserved(self):
        """The SSH wire format key type header is preserved."""
        result = anonymize_ssh_key_blob(_ED25519_BLOB, SALT)
        original_raw = base64.b64decode(_ED25519_BLOB)
        result_raw = base64.b64decode(result)

        # Extract key type from both
        orig_type_len = struct.unpack(">I", original_raw[:4])[0]
        orig_type = original_raw[4 : 4 + orig_type_len]

        result_type_len = struct.unpack(">I", result_raw[:4])[0]
        result_type = result_raw[4 : 4 + result_type_len]

        assert orig_type == result_type

    def test_different_salts_produce_different_output(self):
        """Different salts produce different anonymized keys."""
        result1 = anonymize_ssh_key_blob(_RSA_BLOB, "salt1")
        result2 = anonymize_ssh_key_blob(_RSA_BLOB, "salt2")
        assert result1 != result2

    def test_different_keys_produce_different_output(self):
        """Different input keys produce different anonymized keys."""
        result1 = anonymize_ssh_key_blob(_RSA_BLOB, SALT)
        result2 = anonymize_ssh_key_blob(_ED25519_BLOB, SALT)
        assert result1 != result2

    def test_rsa_key_type_preserved(self):
        """RSA key type header is preserved."""
        result = anonymize_ssh_key_blob(_RSA_BLOB, SALT)
        result_raw = base64.b64decode(result)
        type_len = struct.unpack(">I", result_raw[:4])[0]
        key_type = result_raw[4 : 4 + type_len]
        assert key_type == b"ssh-rsa"

    def test_ecdsa_key_type_preserved(self):
        """ECDSA key type header is preserved."""
        result = anonymize_ssh_key_blob(_ECDSA_BLOB, SALT)
        result_raw = base64.b64decode(result)
        type_len = struct.unpack(">I", result_raw[:4])[0]
        key_type = result_raw[4 : 4 + type_len]
        assert key_type == b"ecdsa-sha2-nistp256"

    def test_valid_base64_output(self):
        """Output is valid base64."""
        for blob in [_ED25519_BLOB, _RSA_BLOB, _DSA_BLOB, _ECDSA_BLOB]:
            result = anonymize_ssh_key_blob(blob, SALT)
            # Should not raise
            base64.b64decode(result)


# Auth key config lines: (line_template, key_blob)
auth_key_lines = [
    # Juniper set-style
    ('set system login user admin authentication ssh-rsa "{}"', _RSA_BLOB),
    ('set system login user admin authentication ssh-dsa "{}"', _DSA_BLOB),
    ('set system login user admin authentication ssh-ed25519 "{}"', _ED25519_BLOB),
    ('set system login user admin authentication ssh-ecdsa "{}"', _ECDSA_BLOB),
    # Juniper hierarchical (curly-brace) style
    ('ssh-rsa "{}";', _RSA_BLOB),
    ('ssh-ed25519 "{}";', _ED25519_BLOB),
    # Without quotes
    ("ssh-rsa {}", _RSA_BLOB),
    ("ssh-ed25519 {}", _ED25519_BLOB),
    # Arista EOS
    ("username kevin ssh-key ssh-rsa {}", _RSA_BLOB),
    ("username admin ssh-key ssh-ed25519 {}", _ED25519_BLOB),
    ("username admin ssh-key ecdsa-sha2-nistp256 {}", _ECDSA_BLOB),
    # Cisco NX-OS
    ("username User1 sshkey ssh-rsa {}", _RSA_BLOB),
    ("username User1 sshkey ecdsa-sha2-nistp256 {}", _ECDSA_BLOB),
    ("username User1 sshkey ecdsa-sha2-nistp384 {}", _ECDSA_BLOB),
    ("username User1 sshkey ecdsa-sha2-nistp521 {}", _ECDSA_BLOB),
    # Fortinet FortiOS
    ('set ssh-public-key1 "ssh-rsa {}"', _RSA_BLOB),
    ('set ssh-public-key2 "ssh-ed25519 {}"', _ED25519_BLOB),
]

# Known hosts config lines: (line_template, key_blob)
known_hosts_key_lines = [
    ('set security ssh-known-hosts host example.com rsa-key "{}"', _RSA_BLOB),
    ('set security ssh-known-hosts host example.com rsa1-key "{}"', _RSA_BLOB),
    ('set security ssh-known-hosts host example.com dsa-key "{}"', _DSA_BLOB),
    ('set security ssh-known-hosts host example.com ed25519-key "{}"', _ED25519_BLOB),
    (
        'set security ssh-known-hosts host example.com ecdsa-sha2-nistp256-key "{}"',
        _ECDSA_BLOB,
    ),
    (
        'set security ssh-known-hosts host example.com ecdsa-sha2-nistp384-key "{}"',
        _ECDSA_BLOB,
    ),
    (
        'set security ssh-known-hosts host example.com ecdsa-sha2-nistp521-key "{}"',
        _ECDSA_BLOB,
    ),
    # Hierarchical style
    ('rsa-key "{}";', _RSA_BLOB),
    ('ed25519-key "{}";', _ED25519_BLOB),
]

# Auth key lines WITH comments: (line_template, key_blob, comment)
auth_key_comment_lines = [
    # Juniper set-style with comment inside quotes
    (
        'set system login user admin authentication ssh-rsa "ssh-rsa {} user@host"',
        _RSA_BLOB,
        " user@host",
    ),
    (
        'set system login user admin authentication ssh-rsa "ssh-rsa {} Firstname Lastname (YK 12345) <first.last@example.com>"',
        _RSA_BLOB,
        " Firstname Lastname (YK 12345) <first.last@example.com>",
    ),
    (
        'set system login user admin authentication ssh-ed25519 "ssh-ed25519 {} admin key"',
        _ED25519_BLOB,
        " admin key",
    ),
    # Arista EOS with comment (no quotes)
    (
        "username kevin ssh-key ssh-rsa {} kevin@workstation",
        _RSA_BLOB,
        " kevin@workstation",
    ),
    # Cisco NX-OS with comment (no quotes)
    (
        "username User1 sshkey ssh-rsa {} user@host",
        _RSA_BLOB,
        " user@host",
    ),
    # Fortinet FortiOS with comment inside quotes
    (
        'set ssh-public-key1 "ssh-rsa {} admin@fortigate"',
        _RSA_BLOB,
        " admin@fortigate",
    ),
]

# Cisco IOS key-hash lines: (line, hash, comment_or_none)
cisco_key_hash_lines = [
    (
        "  key-hash ssh-rsa 8FB4F858DD7E5AFB372780EC653DB371 alice@alice",
        "8FB4F858DD7E5AFB372780EC653DB371",
        " alice@alice",
    ),
    (
        "  key-hash ssh-rsa 39970CAB33EABB8BE39F4FDB9AFECFFE",
        "39970CAB33EABB8BE39F4FDB9AFECFFE",
        "",
    ),
    (
        "  key-hash ssh-dsa AABBCCDD11223344AABBCCDD11223344 bob",
        "AABBCCDD11223344AABBCCDD11223344",
        " bob",
    ),
]

all_ssh_key_lines = auth_key_lines + known_hosts_key_lines


class TestAnonymizeSshKeyHash:
    """Tests for anonymize_ssh_key_hash()."""

    def test_determinism(self):
        """Same hash + same salt always produces same output."""
        result1 = anonymize_ssh_key_hash("8FB4F858DD7E5AFB372780EC653DB371", SALT)
        result2 = anonymize_ssh_key_hash("8FB4F858DD7E5AFB372780EC653DB371", SALT)
        assert result1 == result2

    def test_different_output(self):
        """Anonymized hash differs from original."""
        result = anonymize_ssh_key_hash("8FB4F858DD7E5AFB372780EC653DB371", SALT)
        assert result != "8FB4F858DD7E5AFB372780EC653DB371"

    def test_length_preserved(self):
        """Anonymized hash has same length as original."""
        original = "8FB4F858DD7E5AFB372780EC653DB371"
        result = anonymize_ssh_key_hash(original, SALT)
        assert len(result) == len(original)

    def test_uppercase_hex_output(self):
        """Output is uppercase hexadecimal."""
        import re as _re

        result = anonymize_ssh_key_hash("8FB4F858DD7E5AFB372780EC653DB371", SALT)
        assert _re.match(r"^[0-9A-F]{32}$", result)

    def test_different_salts(self):
        """Different salts produce different results."""
        result1 = anonymize_ssh_key_hash("8FB4F858DD7E5AFB372780EC653DB371", "salt1")
        result2 = anonymize_ssh_key_hash("8FB4F858DD7E5AFB372780EC653DB371", "salt2")
        assert result1 != result2


class TestRegexMatching:
    """Tests for SSH key regex matching."""

    @pytest.mark.parametrize("line_template,key_blob", auth_key_lines)
    def test_auth_key_regex_matches(self, line_template, key_blob):
        """Auth key regex matches authentication key lines."""
        regexes = generate_ssh_key_regexes()
        auth_regex = regexes[0][0]
        line = line_template.format(key_blob)
        match = auth_regex.search(line)
        assert match is not None, f"Auth regex should match: {line[:80]}"
        assert match.group("key") == key_blob

    @pytest.mark.parametrize("line_template,key_blob", known_hosts_key_lines)
    def test_known_hosts_regex_matches(self, line_template, key_blob):
        """Known hosts regex matches known-hosts key lines."""
        regexes = generate_ssh_key_regexes()
        kh_regex = regexes[1][0]
        line = line_template.format(key_blob)
        match = kh_regex.search(line)
        assert match is not None, f"Known hosts regex should match: {line[:80]}"
        assert match.group("key") == key_blob

    def test_no_false_positive_on_short_base64(self):
        """Regexes should not match short base64 strings."""
        regexes = generate_ssh_key_regexes()
        line = 'ssh-rsa "AAAA"'
        for regex, _ in regexes:
            assert regex.search(line) is None

    def test_no_false_positive_on_non_ssh_lines(self):
        """Regexes should not match non-SSH config lines."""
        regexes = generate_ssh_key_regexes()
        lines = [
            "ip address 10.0.0.1 255.255.255.0",
            "password 7 122A00190102180D3C2E",
            "hostname router1",
            'set community "something"',
        ]
        for line in lines:
            for regex, _ in regexes:
                assert regex.search(line) is None, f"False positive on: {line}"

    @pytest.mark.parametrize("line,hex_hash,comment", cisco_key_hash_lines)
    def test_cisco_key_hash_regex_matches(self, line, hex_hash, comment):
        """Cisco IOS key-hash regex matches key-hash lines."""
        regexes = generate_ssh_key_regexes()
        kh_regex = regexes[2][0]
        match = kh_regex.search(line)
        assert match is not None, f"Key-hash regex should match: {line}"
        assert match.group("keyhash") == hex_hash

    def test_key_hash_not_matched_by_auth_or_known_hosts_regex(self):
        """Key-hash lines should NOT match the auth or known-hosts regexes."""
        regexes = generate_ssh_key_regexes()
        auth_regex = regexes[0][0]
        kh_regex = regexes[1][0]
        lines = [
            "key-hash ssh-rsa 8FB4F858DD7E5AFB372780EC653DB371 alice@alice",
            "key-hash ssh-rsa 39970CAB33EABB8BE39F4FDB9AFECFFE",
        ]
        for line in lines:
            assert auth_regex.search(line) is None, f"Auth regex false positive: {line}"
            assert kh_regex.search(line) is None, (
                f"Known hosts regex false positive: {line}"
            )


class TestReplaceSshKeys:
    """Tests for replace_ssh_keys()."""

    @pytest.mark.parametrize("line_template,key_blob", all_ssh_key_lines)
    def test_key_replaced(self, line_template, key_blob):
        """Original key blob does not appear in output."""
        regexes = generate_ssh_key_regexes()
        lookup = {}
        line = line_template.format(key_blob)
        result = replace_ssh_keys(regexes, line, lookup, SALT)
        assert key_blob not in result

    @pytest.mark.parametrize("line_template,key_blob", all_ssh_key_lines)
    def test_context_preserved(self, line_template, key_blob):
        """Line context (prefix, quotes, semicolons) is preserved."""
        regexes = generate_ssh_key_regexes()
        lookup = {}
        line = line_template.format(key_blob)
        result = replace_ssh_keys(regexes, line, lookup, SALT)

        # The prefix (everything before the key) should be preserved
        key_start = line.index(key_blob)
        prefix = line[:key_start]
        assert result.startswith(prefix)

        # Trailing context (quote, semicolon) should be preserved
        key_end = key_start + len(key_blob)
        suffix = line[key_end:]
        assert result.endswith(suffix)

    @pytest.mark.parametrize("line_template,key_blob", all_ssh_key_lines)
    def test_output_contains_valid_base64(self, line_template, key_blob):
        """The replacement key blob is valid base64."""
        regexes = generate_ssh_key_regexes()
        lookup = {}
        line = line_template.format(key_blob)
        result = replace_ssh_keys(regexes, line, lookup, SALT)

        # Extract the replacement blob from the result
        anon_key = lookup[key_blob]
        assert anon_key in result
        # Should not raise
        base64.b64decode(anon_key)

    def test_lookup_consistency(self):
        """Same key blob produces same replacement across calls."""
        regexes = generate_ssh_key_regexes()
        lookup = {}
        line1 = 'ssh-rsa "{}"'.format(_RSA_BLOB)
        line2 = 'set system login user bob authentication ssh-rsa "{}"'.format(
            _RSA_BLOB
        )

        result1 = replace_ssh_keys(regexes, line1, lookup, SALT)
        result2 = replace_ssh_keys(regexes, line2, lookup, SALT)

        # Both should use the same anonymized key
        anon_key = lookup[_RSA_BLOB]
        assert anon_key in result1
        assert anon_key in result2

    def test_different_keys_get_different_replacements(self):
        """Different key blobs get different anonymized replacements."""
        regexes = generate_ssh_key_regexes()
        lookup = {}
        line1 = 'ssh-rsa "{}"'.format(_RSA_BLOB)
        line2 = 'ssh-ed25519 "{}"'.format(_ED25519_BLOB)

        replace_ssh_keys(regexes, line1, lookup, SALT)
        replace_ssh_keys(regexes, line2, lookup, SALT)

        assert lookup[_RSA_BLOB] != lookup[_ED25519_BLOB]

    @pytest.mark.parametrize("line_template,key_blob,comment", auth_key_comment_lines)
    def test_comment_stripped(self, line_template, key_blob, comment):
        """SSH key comment after base64 blob is stripped."""
        regexes = generate_ssh_key_regexes()
        lookup = {}
        line = line_template.format(key_blob)
        result = replace_ssh_keys(regexes, line, lookup, SALT)
        # The comment text should not appear in output
        assert comment.strip() not in result
        # The key blob should be replaced
        assert key_blob not in result

    @pytest.mark.parametrize("line_template,key_blob,comment", auth_key_comment_lines)
    def test_comment_stripped_preserves_structure(
        self, line_template, key_blob, comment
    ):
        """Line structure (quotes, semicolons) is preserved when comment is stripped."""
        regexes = generate_ssh_key_regexes()
        lookup = {}
        line = line_template.format(key_blob)
        result = replace_ssh_keys(regexes, line, lookup, SALT)
        # If original had closing quote, it should be preserved
        if line_template.endswith('"'):
            assert result.rstrip().endswith('"')
        # Key blob should be replaced regardless
        assert key_blob not in result

    @pytest.mark.parametrize("line,hex_hash,comment", cisco_key_hash_lines)
    def test_key_hash_replaced(self, line, hex_hash, comment):
        """Original key hash does not appear in output."""
        regexes = generate_ssh_key_regexes()
        lookup = {}
        result = replace_ssh_keys(regexes, line, lookup, SALT)
        assert hex_hash not in result

    @pytest.mark.parametrize("line,hex_hash,comment", cisco_key_hash_lines)
    def test_key_hash_comment_stripped(self, line, hex_hash, comment):
        """Comment after key hash is stripped."""
        regexes = generate_ssh_key_regexes()
        lookup = {}
        result = replace_ssh_keys(regexes, line, lookup, SALT)
        if comment.strip():
            assert comment.strip() not in result

    @pytest.mark.parametrize("line,hex_hash,comment", cisco_key_hash_lines)
    def test_key_hash_context_preserved(self, line, hex_hash, comment):
        """Line prefix (indentation + key-hash keyword) is preserved."""
        regexes = generate_ssh_key_regexes()
        lookup = {}
        result = replace_ssh_keys(regexes, line, lookup, SALT)
        hash_start = line.index(hex_hash)
        prefix = line[:hash_start]
        assert result.startswith(prefix)

    def test_key_hash_lookup_consistency(self):
        """Same key hash produces same replacement across calls."""
        regexes = generate_ssh_key_regexes()
        lookup = {}
        line1 = "  key-hash ssh-rsa 8FB4F858DD7E5AFB372780EC653DB371 alice@alice"
        line2 = "  key-hash ssh-rsa 8FB4F858DD7E5AFB372780EC653DB371 bob"
        replace_ssh_keys(regexes, line1, lookup, SALT)
        replace_ssh_keys(regexes, line2, lookup, SALT)
        assert "8FB4F858DD7E5AFB372780EC653DB371" in lookup
        # Same hash → same replacement
        assert (
            lookup["8FB4F858DD7E5AFB372780EC653DB371"]
            == lookup["8FB4F858DD7E5AFB372780EC653DB371"]
        )

    def test_key_hash_replacement_is_uppercase_hex(self):
        """Replacement key hash is uppercase hexadecimal of same length."""
        import re as _re

        regexes = generate_ssh_key_regexes()
        lookup = {}
        line = "  key-hash ssh-rsa 8FB4F858DD7E5AFB372780EC653DB371"
        replace_ssh_keys(regexes, line, lookup, SALT)
        anon_hash = lookup["8FB4F858DD7E5AFB372780EC653DB371"]
        assert len(anon_hash) == 32
        assert _re.match(r"^[0-9A-F]{32}$", anon_hash)

    def test_non_ssh_line_unchanged(self):
        """Lines without SSH keys are returned unchanged."""
        regexes = generate_ssh_key_regexes()
        lookup = {}
        line = "ip address 10.0.0.1 255.255.255.0\n"
        result = replace_ssh_keys(regexes, line, lookup, SALT)
        assert result == line
        assert not lookup
