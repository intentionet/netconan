"""Tests for encrypted-password anonymization (hash verification)."""

import pytest

from netconan.sensitive_item_removal import _anonymize_value

SALT = "saltForTest"


@pytest.mark.parametrize(
    "original_val, hash_module",
    [
        (
            # Hash of "netconanExamplePassword" using sha256_crypt
            "$5$dyjYlf.RKgW5cjA5$5OmkZF/RpklPYw8oC9k8nxKIh0RzyNmx74zPJ1CRuz8",
            "sha256_crypt",
        ),
        (
            # Hash of "netconanExamplePassword" using sha512_crypt
            "$6$DOphiwNHNVLzCXmR$4sS7hYY6UPAnX6oXU9rIbCqKgTJBf9wJ4Hf2sz7HYPjH7Wrn9II1vS0wdHtirRHv1YACC.E.YDlaUb9U8ysvk0",
            "sha512_crypt",
        ),
        (
            "$1$CNANTest$xAfu6Am1d5D/.6OVICuOu/",
            "md5_crypt",
        ),
    ],
)
def test__anonymize_value_produces_verifiable_hash(original_val, hash_module):
    """Test that anonymized crypt hashes are verifiable against their plaintext."""
    from passlib.hash import md5_crypt, sha256_crypt, sha512_crypt

    hash_modules = {
        "md5_crypt": md5_crypt,
        "sha256_crypt": sha256_crypt,
        "sha512_crypt": sha512_crypt,
    }
    pwd_lookup = {}
    anon_val = _anonymize_value(original_val, pwd_lookup, {}, SALT)

    # _anonymize_value generates "netconanRemoved0" as the plaintext (first
    # entry in an empty lookup) and hashes it. Verify the hash is valid.
    plaintext = "netconanRemoved0"
    hasher = hash_modules[hash_module]
    assert hasher.verify(plaintext, anon_val)
