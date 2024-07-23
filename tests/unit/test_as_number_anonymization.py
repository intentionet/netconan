"""Test removal of AS numbers."""

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

from netconan.sensitive_item_removal import AsNumberAnonymizer, anonymize_as_numbers

SALT = "saltForTest"


@pytest.mark.parametrize(
    "raw_line, sensitive_as_numbers",
    [
        ("something {} something", ["123"]),
        ("123-{}abc", ["65530"]),
        ("asdf{0}_asdf{0}asdf", ["65530"]),
        ("anonymize.{} and {}?", ["4567", "1234567"]),
        ("{}", ["12345"]),
        ("{} and other text", ["4567"]),
        ("other text and {}", ["4567"]),
    ],
)
def test_anonymize_as_numbers(raw_line, sensitive_as_numbers):
    """Test anonymization of lines with AS numbers."""
    anonymizer_as_number = AsNumberAnonymizer(sensitive_as_numbers, SALT)

    line = raw_line.format(*sensitive_as_numbers)
    anon_line = anonymize_as_numbers(anonymizer_as_number, line)

    # Anonymize each AS number individually & build another anon line
    anon_numbers = [
        anonymize_as_numbers(anonymizer_as_number, number)
        for number in sensitive_as_numbers
    ]
    individually_anon_line = raw_line.format(*anon_numbers)

    # Make sure anonymizing each number individually gives the same result as anonymizing all at once
    assert anon_line == individually_anon_line

    for as_number in sensitive_as_numbers:
        # Make sure all AS numbers are removed from the line
        assert as_number not in anon_line


@pytest.mark.parametrize(
    "raw_line, sensitive_as_numbers",
    [
        ("123{}890", ["65530"]),
        ("{}{}", ["1234", "5678"]),
        ("{}000", ["1234"]),
        ("000{}", ["1234"]),
    ],
)
def test_anonymize_as_numbers_ignore_sub_numbers(raw_line, sensitive_as_numbers):
    """Test that matching 'AS numbers' within other numbers are not replaced."""
    anonymizer_as_number = AsNumberAnonymizer(sensitive_as_numbers, SALT)

    line = raw_line.format(*sensitive_as_numbers)
    anon_line = anonymize_as_numbers(anonymizer_as_number, line)

    # Make sure substrings of other numbers are not affected
    assert anon_line == line


@pytest.mark.parametrize(
    "as_number",
    [
        "0",
        "1234",
        "65534",
        "65535",
        "70000",
        "123456789",
        "4199999999",
        "4230000000",
        "4294967295",
    ],
)
def test_anonymize_as_num(as_number):
    """Test anonymization of AS numbers."""
    anonymizer = AsNumberAnonymizer([as_number], SALT)
    assert anonymizer.anonymize(as_number) != as_number


def get_as_number_block(as_number):
    """Determine which block a given AS number is in."""
    block = 0
    as_number = int(as_number)
    for upper_bound in AsNumberAnonymizer._AS_NUM_BOUNDARIES:
        if as_number < upper_bound:
            return block
        block += 1


@pytest.mark.parametrize(
    "as_number",
    [
        "0",
        "64511",  # Original public block
        "64512",
        "65535",  # Original private block
        "65536",
        "4199999999",  # Expanded public block
        "4200000000",
        "4294967295",  # Expanded private block
    ],
)
def test_preserve_as_block(as_number):
    """Test that original AS number block is preserved after anonymization."""
    anonymizer = AsNumberAnonymizer([as_number], SALT)
    new_as_number = anonymizer.anonymize(as_number)
    assert get_as_number_block(new_as_number) == get_as_number_block(as_number)


@pytest.mark.parametrize("invalid_as_number", ["-1", "4294967296"])
def test_as_number_invalid(invalid_as_number):
    """Test that exception is thrown with invalid AS number."""
    with pytest.raises(ValueError):
        AsNumberAnonymizer([invalid_as_number], SALT)
