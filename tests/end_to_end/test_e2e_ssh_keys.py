"""End-to-end tests for SSH key anonymization."""

import base64
import re
import struct

from netconan.netconan import main

# Test key blobs


def _make_ssh_key_blob(key_type_str, data_bytes):
    """Build a base64-encoded SSH public key blob."""
    key_type = key_type_str.encode()
    return base64.b64encode(
        struct.pack(">I", len(key_type)) + key_type + data_bytes
    ).decode()


_ED25519_BLOB = _make_ssh_key_blob("ssh-ed25519", struct.pack(">I", 32) + b"\x01" * 32)
_RSA_BLOB = _make_ssh_key_blob(
    "ssh-rsa",
    struct.pack(">I", 3) + b"\x01\x00\x01" + struct.pack(">I", 256) + b"\x02" * 256,
)

SSH_KEY_INPUT = (
    'set system login user admin authentication ssh-ed25519 "{}"\n'
    'set system login user admin authentication ssh-rsa "{}"\n'
    'set security ssh-known-hosts host example.com ed25519-key "{}"\n'
    'set security ssh-known-hosts host example.com rsa-key "{}"\n'
    # SSH key with comment (OpenSSH format: key-type blob comment)
    'set system login user admin authentication ssh-rsa "ssh-rsa {} Admin User <admin@example.com>"\n'
    # Cisco IOS key-hash lines
    "  key-hash ssh-rsa 8FB4F858DD7E5AFB372780EC653DB371 alice@alice\n"
    "  key-hash ssh-rsa 39970CAB33EABB8BE39F4FDB9AFECFFE\n"
    "ip address 10.0.0.1 255.255.255.0\n"
).format(_ED25519_BLOB, _RSA_BLOB, _ED25519_BLOB, _RSA_BLOB, _RSA_BLOB)


def test_end_to_end_ssh_key_anonymization(tmpdir):
    """Test SSH key anonymization preserves context and removes original keys."""
    filename = "ssh_keys.txt"
    input_dir = tmpdir.mkdir("input")
    input_dir.join(filename).write(SSH_KEY_INPUT)

    output_dir = tmpdir.mkdir("output")
    args = [
        "-i",
        str(input_dir),
        "-o",
        str(output_dir),
        "-s",
        "TESTSALT",
        "--anonymize-ssh-keys",
    ]
    main(args)

    with open(str(output_dir.join(filename))) as f:
        output = f.read()

    output_lines = output.strip().split("\n")

    # Original key blobs should not appear in output
    assert _ED25519_BLOB not in output
    assert _RSA_BLOB not in output

    # Line context should be preserved
    assert output_lines[0].startswith(
        "set system login user admin authentication ssh-ed25519"
    )
    assert output_lines[1].startswith(
        "set system login user admin authentication ssh-rsa"
    )
    assert output_lines[2].startswith(
        "set security ssh-known-hosts host example.com ed25519-key"
    )
    assert output_lines[3].startswith(
        "set security ssh-known-hosts host example.com rsa-key"
    )

    # SSH key comment should be stripped (line 4 had "Admin User <admin@example.com>")
    assert "Admin User" not in output
    assert "admin@example.com" not in output
    assert output_lines[4].startswith(
        "set system login user admin authentication ssh-rsa"
    )
    assert output_lines[4].rstrip().endswith('"')

    # Cisco IOS key-hash lines (lines 5-6)
    assert "8FB4F858DD7E5AFB372780EC653DB371" not in output
    assert "39970CAB33EABB8BE39F4FDB9AFECFFE" not in output
    assert "alice@alice" not in output  # comment stripped
    assert output_lines[5].startswith("  key-hash ssh-rsa ")
    assert output_lines[6].startswith("  key-hash ssh-rsa ")
    # Replacement hashes should be 32-char uppercase hex
    key_hash_match5 = re.search(r"key-hash ssh-rsa ([0-9A-F]{32})", output_lines[5])
    key_hash_match6 = re.search(r"key-hash ssh-rsa ([0-9A-F]{32})", output_lines[6])
    assert key_hash_match5 is not None
    assert key_hash_match6 is not None
    # Different original hashes should produce different replacements
    assert key_hash_match5.group(1) != key_hash_match6.group(1)

    # Non-SSH line should pass through unchanged
    assert output_lines[7] == "ip address 10.0.0.1 255.255.255.0"

    # Replacement blobs should be valid base64
    # Lines 0-3 have "BLOB", line 4 has "ssh-rsa BLOB" (OpenSSH format)
    for line in output_lines[:5]:
        match = re.search(r'"(?:ssh-\S+ )?([A-Za-z0-9+/=]+)"', line)
        assert match is not None, f"No base64 blob found in: {line}"
        base64.b64decode(match.group(1))  # Should not raise

    # Same original key should produce same anonymized key (determinism)
    ed25519_blobs = []
    rsa_blobs = []
    for line in output_lines[:5]:
        match = re.search(r'"(?:ssh-\S+ )?([A-Za-z0-9+/=]+)"', line)
        blob = match.group(1)
        if "ed25519" in line:
            ed25519_blobs.append(blob)
        else:
            rsa_blobs.append(blob)

    assert len(ed25519_blobs) == 2
    assert ed25519_blobs[0] == ed25519_blobs[1]
    assert len(rsa_blobs) == 3
    assert rsa_blobs[0] == rsa_blobs[1] == rsa_blobs[2]


def test_end_to_end_ssh_key_anonymization_deterministic(tmpdir):
    """Test that SSH key anonymization is deterministic with same salt."""
    filename = "ssh_keys.txt"
    input_dir = tmpdir.mkdir("input")
    input_dir.join(filename).write(SSH_KEY_INPUT)

    output_dir1 = tmpdir.mkdir("output1")
    output_dir2 = tmpdir.mkdir("output2")

    args_base = ["-s", "TESTSALT", "--anonymize-ssh-keys"]

    main(args_base + ["-i", str(input_dir), "-o", str(output_dir1)])
    main(args_base + ["-i", str(input_dir), "-o", str(output_dir2)])

    with (
        open(str(output_dir1.join(filename))) as f1,
        open(str(output_dir2.join(filename))) as f2,
    ):
        assert f1.read() == f2.read()
