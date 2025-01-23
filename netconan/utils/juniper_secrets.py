"""Encrypts and decryptes Juniper Type 9 hashes.

This module is a derivative work based on the perl module Crypt-Juniper by Kevin Brintnall.
https://metacpan.org/dist/Crypt-Juniper/view/lib/Crypt/Juniper.pm
Used under the Artistic License https://dev.perl.org/licenses/artistic.html

This work was modified from the original in the following ways:
2025-01-21: Rob Ankeny(ankeny at gmail.com): Translated from perl to python.
"""

import random
import re
from typing import List, Tuple

MAGIC = "$9$"

FAMILY = [
    "QzF3n6/9CAtpu0O",
    "B1IREhcSyrleKvMW8LXx",
    "7N-dVbwsY2g4oaJZGUDj",
    "iHkq.mPf5T",
]

EXTRA = {c: (3 - fam) for fam, chars in enumerate(FAMILY) for c in chars}

NUM_ALPHA = list("".join(FAMILY))
ALPHA_NUM = {char: idx for idx, char in enumerate(NUM_ALPHA)}


ENCODING = [
    [1, 4, 32],
    [1, 16, 32],
    [1, 8, 32],
    [1, 64],
    [1, 32],
    [1, 4, 16, 128],
    [1, 32, 64],
]

VALID = rf"^{re.escape(MAGIC)}[{re.escape(''.join(NUM_ALPHA))}]{{4,}}$"


def juniper_decrypt(crypt: str) -> str:
    """Decrypts a Juniper $9 encrypted secret.

    Args:
      crypt: String containing the secret to decrypt.

    Returns:
      String representing the decrypted secret.
    """
    if not crypt or not re.search(VALID, crypt):
        raise ValueError("Invalid Juniper crypt string!")

    chars = crypt[len(MAGIC) :]
    first, chars = _nibble(chars, 1)
    _, chars = _nibble(chars, EXTRA[first])

    prev = first
    decrypt = ""

    while chars:
        decode = ENCODING[len(decrypt) % len(ENCODING)]
        nibble_len = len(decode)
        nibble, chars = _nibble(chars, nibble_len)
        gaps = []
        for i, _ in enumerate(nibble):
            gaps.append(_gap(prev, nibble[i]))
            prev = nibble[i]
        decrypt += _gap_decode(gaps, decode)
    return decrypt


def _nibble(chars: str, length: int) -> Tuple[str, str]:
    nib = chars[:length]
    chars = chars[length:]
    return nib, chars


def _gap(c1: str, c2: str) -> int:
    diff = ALPHA_NUM[c2] - ALPHA_NUM[c1]
    pos_diff = diff + len(NUM_ALPHA)
    return pos_diff % len(NUM_ALPHA) - 1


def _gap_decode(gaps: List[int] , dec: List[int]) -> chr:
    if len(gaps) != len(dec):
        raise ValueError("Nibble and decode size not the same!")
    num = sum(g * d for g, d in zip(gaps, dec))
    return chr(num % 256)


def juniper_encrypt(plain: str, salt: str=None ) -> str:
    """Encrypts a Juniper $9 encrypted secret.

    Args:
      plain: String containing the plaintext secret to be encrypted.
      salt: Optional salt to be used when encrypting the secret.

    Returns:
      String representing the encrypted secret.
    """
    if salt is None:
        salt = _randc(1)
    salt = salt[0]
    rand = _randc(EXTRA[salt])

    pos = 0
    prev = salt
    crypt = f"{MAGIC}{salt}{rand}"
    for p in plain:
        encode = ENCODING[pos % len(ENCODING)]
        crypt += _gap_encode(p, prev, encode)
        prev = crypt[-1]
        pos += 1
    return crypt


def _randc(count: int) -> str:
    return "".join(random.choice(NUM_ALPHA) for _ in range(count))


def _gap_encode(pc: str, prev: str, enc: List[int]) -> str:
    ord_val = ord(pc)
    crypt = ""
    gaps = []
    for mod in reversed(enc):
        gaps.insert(0, ord_val // mod)
        ord_val %= mod
    for gap in gaps:
        gap += ALPHA_NUM[prev] + 1
        prev = NUM_ALPHA[gap % len(NUM_ALPHA)]
        crypt += prev
    return crypt
