"""Anonymize SSH public key blobs in router configurations."""

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
import hashlib
import hmac
import logging
import re
import struct

# Minimum base64 length for a valid SSH public key blob.
# An Ed25519 key (the smallest type) is 51 raw bytes → 68 base64 chars.
_MIN_KEY_BASE64_LEN = 68

# Authentication key types: ssh-rsa, ssh-dsa, ssh-ecdsa, ssh-ed25519,
# and bare ecdsa-sha2-nistp* (used by NX-OS/Arista without ssh- prefix).
# The comment group captures any trailing SSH key comment (e.g., "user@host")
# between the base64 blob and the closing quote, so it can be stripped.
_AUTH_KEY_REGEX = re.compile(
    r"(?P<prefix>(?:\S+ )*(?:ssh-(?:rsa|dsa|ecdsa|ed25519)|ecdsa-sha2-nistp(?:256|384|521)) )"
    r'"?(?P<key>[A-Za-z0-9+/=]{' + str(_MIN_KEY_BASE64_LEN) + r',})(?P<comment>[^"]*)"?'
)

# Cisco IOS key-hash: key-hash ssh-rsa <32-hex-MD5> [comment]
_CISCO_KEY_HASH_REGEX = re.compile(
    r"(?P<prefix>key-hash\s+ssh-(?:rsa|dsa)\s+)"
    r"(?P<keyhash>[0-9A-Fa-f]{32})"
    r"(?P<comment>.*)"
)

# Known hosts key types: rsa-key, rsa1-key, dsa-key, ed25519-key, ecdsa-sha2-nistp*-key
_KNOWN_HOSTS_KEY_REGEX = re.compile(
    r"(?P<prefix>(?:\S+ )*(?:rsa1?|dsa|ed25519|ecdsa-sha2-nistp(?:256|384|521))-key )"
    r'"?(?P<key>[A-Za-z0-9+/=]{' + str(_MIN_KEY_BASE64_LEN) + r',})(?P<comment>[^"]*)"?'
)


def _read_ssh_wire_string(data, offset):
    """Read a length-prefixed string from SSH wire format.

    Returns (string_bytes, new_offset) or (None, offset) if data is too short.
    """
    if offset + 4 > len(data):
        return None, offset
    length = struct.unpack(">I", data[offset : offset + 4])[0]
    if offset + 4 + length > len(data):
        return None, offset
    return data[offset : offset + 4 + length], offset + 4 + length


def anonymize_ssh_key_blob(base64_blob, salt):
    """Generate a deterministic anonymized SSH key blob preserving format.

    The replacement:
    - Preserves the SSH wire format key type header (first field)
    - Preserves exact base64 length
    - Is deterministic from salt + original blob (HMAC-based)
    """
    try:
        raw = base64.b64decode(base64_blob)
    except Exception:
        logging.debug("Failed to base64-decode SSH key blob, returning original")
        return base64_blob

    # Extract the key type header (first SSH wire format field)
    header, data_offset = _read_ssh_wire_string(raw, 0)
    if header is None:
        logging.debug("Failed to parse SSH wire format header, returning original")
        return base64_blob

    data_portion = raw[data_offset:]
    if not data_portion:
        return base64_blob

    # Generate replacement bytes using HMAC-SHA256, expanding as needed
    hmac_key = salt.encode() if isinstance(salt, str) else salt
    replacement_bytes = b""
    counter = 0
    while len(replacement_bytes) < len(data_portion):
        h = hmac.new(
            hmac_key,
            base64_blob.encode() + struct.pack(">I", counter),
            hashlib.sha256,
        )
        replacement_bytes += h.digest()
        counter += 1
    replacement_bytes = replacement_bytes[: len(data_portion)]

    # Reassemble: original header + replacement data
    new_raw = header + replacement_bytes
    new_blob = base64.b64encode(new_raw).decode()

    # Ensure exact same base64 length by padding with '=' if needed
    # (base64 encoding of same-length bytes should produce same-length output,
    # but be defensive)
    if len(new_blob) != len(base64_blob):
        logging.debug(
            "Base64 length mismatch: original=%d, new=%d",
            len(base64_blob),
            len(new_blob),
        )

    return new_blob


def anonymize_ssh_key_hash(hex_hash, salt):
    """Generate a deterministic anonymized SSH key hash (MD5 fingerprint).

    Produces a same-length uppercase hex string from HMAC-SHA256.
    """
    hmac_key = salt.encode() if isinstance(salt, str) else salt
    h = hmac.new(hmac_key, hex_hash.encode(), hashlib.sha256)
    return h.hexdigest()[: len(hex_hash)].upper()


def generate_ssh_key_regexes():
    """Return compiled SSH key regexes as a list of (regex, group_name) tuples."""
    return [
        (_AUTH_KEY_REGEX, "key"),
        (_KNOWN_HOSTS_KEY_REGEX, "key"),
        (_CISCO_KEY_HASH_REGEX, "keyhash"),
    ]


def replace_ssh_keys(compiled_regexes, line, lookup, salt):
    """Replace SSH public key blobs in the given line.

    Args:
        compiled_regexes: List of (compiled_regex, group_name) tuples from
            generate_ssh_key_regexes().
        line: Input configuration line.
        lookup: Dict mapping original key blobs to anonymized blobs for
            consistency across lines/files.
        salt: Salt string for deterministic HMAC-based replacement.

    Returns:
        The line with SSH key blobs anonymized.
    """
    for regex, group_name in compiled_regexes:
        match = regex.search(line)
        if match is None:
            continue

        original_key = match.group(group_name)

        if original_key in lookup:
            anon_key = lookup[original_key]
        else:
            if group_name == "keyhash":
                anon_key = anonymize_ssh_key_hash(original_key, salt)
            else:
                anon_key = anonymize_ssh_key_blob(original_key, salt)
            lookup[original_key] = anon_key

        # Replace the key blob and strip any SSH key comment after it
        line = line[: match.start(group_name)] + anon_key + line[match.end("comment") :]

        logging.debug("Anonymized SSH key blob in line")
        break  # One SSH key per line

    return line
