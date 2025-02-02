"""Tests Juniper secret encryption/decryption methods."""

import pytest

from netconan.utils import juniper_secrets


@pytest.mark.parametrize(
    "plain_text, expected",
    [
        ("abc", "$9$nnet/9pOBEyrv"),
        ("123", "$9$nnet/p01RhrKM"),
        ("netconan", "$9$nnet9pBcSe8xdApK8xdg4aZUi.5"),
        (
            "QjEf.WloKY4IBVGik9xeIO9xWN5F7S13",
            "$9$nnet/pOleWN-bO18X-Vg4.P5F/tSyevL7yrx-bw4o6/CuOIKvLNds7NPQFnpuSylMXN4aZGi.Rh7dbs4ojikPFnCt0BRh9C",
        ),
    ],
)
def test_juniper_encrypt(plain_text, expected):
    """Test encryption of secrets."""
    assert juniper_secrets.juniper_nonrandom_encrypt(plain_text) == expected


@pytest.mark.parametrize(
    "encrypted, expected",
    [
        (
            "$9$Ly.x7VYgJH.5SraGiH5TFn/CO1cylW8xs23/Ap1Ibs24aGf5F/A0EcNVs4Dj5QF6/AlKWdsg-VQ3n/tp-Vbs4JTQnCp0Lx",
            "asvWWcb54DGWFvEjsENnhB__xY49Mn3R",
        ),
        ("$9$CSxptpBREyKvL", "abc"),
        ("$9$-pV24JGDkmf", "123"),
        ("$9$sSgJD.mTn9poJQn9pREcylvLN", "netconan"),
        (
            "$9$hzrSKWws4UDHWLoJDiPftuORSedVs2aGVbZDHkf5cSrvWXY2aUjqGUu1RhKvdVwgJUfTzF/txNGjHqf56/CuRhreM8xNyr",
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


def test_encryption_decryption():
    """Test a large set of inputs to detect any possible encrypting/decrypting issues."""
    for i in range(0, 1000):
        plaintext = str(i)
        decrypted = juniper_secrets.juniper_decrypt(
            juniper_secrets.juniper_nonrandom_encrypt(plaintext, "t")
        )
        assert decrypted == plaintext
