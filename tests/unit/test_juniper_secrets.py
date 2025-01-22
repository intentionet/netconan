"""Tests Juniper secret encryption/decryption methods."""

from unittest.mock import MagicMock

import pytest

from netconan.utils import juniper_secrets


@pytest.mark.parametrize(
    "plain_text, expected",
    [
        ("abc", "$9$aaZGiq.5zF/"),
        ("123", "$9$aaZikmfTF69"),
        ("netconan", "$9$aaGi.-QnAu1Di6Au1yrevWXds"),
        (
            "QjEf.WloKY4IBVGik9xeIO9xWN5F7S13",
            "$9$aaZiq3nCOBRqmApBIyrdbs4ZjQzn/t0zFuBRErlJZUHqP6/tO1h0Ob24aiHQz39pOrevMXdfT01RhrlLX7b4aUjk.fTGU",
        ),
    ],
)
def test_juniper_encrypt(plain_text, expected):
    """Test encryption of secrets."""
    juniper_secrets._randc = MagicMock(return_value="a")
    assert juniper_secrets.juniper_encrypt(plain_text) == expected


@pytest.mark.parametrize(
    "encrypted, expected",
    [
        ("$9$aaZGiq.5zF/", "abc"),
        ("$9$aaZikmfTF69", "123"),
        ("$9$aaGi.-QnAu1Di6Au1yrevWXds", "netconan"),
        (
            "$9$aaZiq3nCOBRqmApBIyrdbs4ZjQzn/t0zFuBRErlJZUHqP6/tO1h0Ob24aiHQz39pOrevMXdfT01RhrlLX7b4aUjk.fTGU",
            "QjEf.WloKY4IBVGik9xeIO9xWN5F7S13",
        ),
    ],
)
def test_juniper_decrypt(encrypted, expected):
    """Test decryption of secrets."""
    assert juniper_secrets.juniper_decrypt(encrypted) == expected


@pytest.mark.parametrize("encrypted", [("abcd"), ("$9$aaGi.Qz6t0IDi/t0IrlKM8x,s")])
def test_invalid_juniper_decrypt(encrypted):
    """Test raising errors when decrypting invalid secrets."""
    with pytest.raises(ValueError):
        juniper_secrets.juniper_decrypt(encrypted)
