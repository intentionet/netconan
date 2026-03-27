"""End-to-end tests for encrypted-password anonymization."""

import re

from netconan.netconan import main


def test_end_to_end_encrypted_password_sha512(tmpdir):
    """Test that encrypted-password with $6$ hash is anonymized, not scrubbed."""
    filename = "test.txt"
    # Hash of "netconanExamplePassword" using sha512_crypt
    original_hash = "$6$DOphiwNHNVLzCXmR$4sS7hYY6UPAnX6oXU9rIbCqKgTJBf9wJ4Hf2sz7HYPjH7Wrn9II1vS0wdHtirRHv1YACC.E.YDlaUb9U8ysvk0"
    input_line = 'set system root-authentication encrypted-password "{}"\n'.format(
        original_hash
    )

    input_dir = tmpdir.mkdir("input")
    input_dir.join(filename).write(input_line)

    output_dir = tmpdir.mkdir("output")
    args = ["-s", "TESTSALT", "-p", "-i", str(input_dir), "-o", str(output_dir)]
    main(args)

    with open(str(output_dir.join(filename))) as f:
        output = f.read()

    # Original hash must not appear in output
    assert original_hash not in output
    # Line must not be scrubbed
    assert "SCRUBBED" not in output
    # Context must be preserved and output must contain a $6$ hash
    assert "encrypted-password" in output
    assert re.search(r'\$6\$[^\s"]+\$[^\s"]+', output)
