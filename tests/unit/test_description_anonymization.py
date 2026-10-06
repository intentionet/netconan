"""Tests for description anonymization module."""

import pytest

from netconan.description_anonymization import (
    anonymize_description,
    generate_description_regexes,
    replace_descriptions,
)


class TestAnonymizeDescription:
    """Tests for the anonymize_description function."""

    def test_deterministic(self):
        """Same input+salt always produces the same output."""
        lookup = {}
        result1 = anonymize_description("server.example.net", lookup, "salt1")
        lookup2 = {}
        result2 = anonymize_description("server.example.net", lookup2, "salt1")
        assert result1 == result2

    def test_format_prefix(self):
        """Output starts with 'descr_'."""
        lookup = {}
        result = anonymize_description("test value", lookup, "salt1")
        assert result.startswith("descr_")

    def test_format_length(self):
        """Output has 8 chars after the prefix."""
        lookup = {}
        result = anonymize_description("test value", lookup, "salt1")
        suffix = result[len("descr_") :]
        assert len(suffix) == 8

    def test_format_lowercase_alphanumeric(self):
        """Output suffix is lowercase alphanumeric (base32)."""
        lookup = {}
        result = anonymize_description("test value", lookup, "salt1")
        suffix = result[len("descr_") :]
        assert suffix == suffix.lower()
        assert suffix.isalnum()

    def test_caching_in_lookup(self):
        """Once computed, the result is cached in the lookup dict."""
        lookup = {}
        result = anonymize_description("cached value", lookup, "salt1")
        assert "cached value" in lookup
        assert lookup["cached value"] == result

    def test_different_salt_different_result(self):
        """Different salts produce different results."""
        result1 = anonymize_description("same value", {}, "salt_a")
        result2 = anonymize_description("same value", {}, "salt_b")
        assert result1 != result2

    def test_different_values_different_result(self):
        """Different description values produce different results."""
        result1 = anonymize_description("value_one", {}, "salt1")
        result2 = anonymize_description("value_two", {}, "salt1")
        assert result1 != result2


class TestRegexMatching:
    """Tests for description regex patterns."""

    @pytest.fixture
    def regexes(self):
        """Return compiled description regexes."""
        return generate_description_regexes()

    @pytest.mark.parametrize(
        "line,expected_desc",
        [
            (
                'description "server.example.net (port14)"',
                "server.example.net (port14)",
            ),
            ('description "Core Router - Site A"', "Core Router - Site A"),
            (' description "indented quoted"', "indented quoted"),
        ],
        ids=["quoted-basic", "quoted-spaces", "quoted-indented"],
    )
    def test_quoted_regex_matches(self, regexes, line, expected_desc):
        """Quoted description regex captures the description content."""
        match = regexes[0].search(line)
        assert match is not None
        assert match.group("desc") == expected_desc

    @pytest.mark.parametrize(
        "line,expected_desc",
        [
            ("description server.example.net", "server.example.net"),
            ("description Link-to-upstream;", "Link-to-upstream"),
            ("description multi word value", "multi word value"),
            (" description indented-value", "indented-value"),
            ("description trailing-semi ;", "trailing-semi"),
        ],
        ids=[
            "unquoted-simple",
            "unquoted-semicolon",
            "unquoted-multiword",
            "unquoted-indented",
            "unquoted-space-before-semi",
        ],
    )
    def test_unquoted_regex_matches(self, regexes, line, expected_desc):
        """Unquoted description regex captures the description content."""
        match = regexes[1].search(line)
        assert match is not None
        assert match.group("desc") == expected_desc

    @pytest.mark.parametrize(
        "line",
        [
            "hostname router1",
            "interface GigabitEthernet0/0",
            "ip address 10.0.0.1 255.255.255.0",
            "set description-limit 100",
        ],
        ids=[
            "hostname",
            "interface",
            "ip-address",
            "set-description-limit",
        ],
    )
    def test_no_false_positives(self, regexes, line):
        """Lines that are not descriptions should not match."""
        for regex in regexes:
            assert regex.search(line) is None


class TestReplaceDescriptions:
    """Tests for the replace_descriptions function."""

    @pytest.fixture
    def regexes(self):
        """Return compiled description regexes."""
        return generate_description_regexes()

    def test_quoted_replacement(self, regexes):
        """Quoted description content is replaced, quotes preserved."""
        lookup = {}
        line = 'description "server.example.net (port14)"'
        result = replace_descriptions(regexes, line, lookup, "salt1")
        assert result.startswith('description "descr_')
        assert result.endswith('"')
        assert "server.example.net" not in result

    def test_unquoted_replacement(self, regexes):
        """Unquoted description content is replaced."""
        lookup = {}
        line = "description server.example.net"
        result = replace_descriptions(regexes, line, lookup, "salt1")
        assert result.startswith("description descr_")
        assert "server.example.net" not in result

    def test_semicolon_preserved(self, regexes):
        """Trailing semicolons are preserved after replacement."""
        lookup = {}
        line = "description Link-to-upstream;"
        result = replace_descriptions(regexes, line, lookup, "salt1")
        assert result.endswith(";")
        assert "Link-to-upstream" not in result

    def test_quoted_semicolon_preserved(self, regexes):
        """Quoted description with trailing semicolon preserved."""
        lookup = {}
        line = 'description "Core Router - Site A";'
        result = replace_descriptions(regexes, line, lookup, "salt1")
        assert result.endswith('";')
        assert "Core Router" not in result

    def test_non_matching_unchanged(self, regexes):
        """Lines that don't match are returned unchanged."""
        lookup = {}
        line = "ip address 10.0.0.1 255.255.255.0"
        result = replace_descriptions(regexes, line, lookup, "salt1")
        assert result == line

    def test_deterministic_replacement(self, regexes):
        """Same description produces the same replacement."""
        lookup1 = {}
        lookup2 = {}
        line = 'description "test value"'
        result1 = replace_descriptions(regexes, line, lookup1, "salt1")
        result2 = replace_descriptions(regexes, line, lookup2, "salt1")
        assert result1 == result2

    def test_context_preserved(self, regexes):
        """Leading whitespace/context is preserved."""
        lookup = {}
        line = '  description "indented value"'
        result = replace_descriptions(regexes, line, lookup, "salt1")
        assert result.startswith("  description ")

    def test_set_style_description(self, regexes):
        """Set description ... style lines are handled."""
        lookup = {}
        line = "set interfaces ge-0/0/0 description upstream-link"
        result = replace_descriptions(regexes, line, lookup, "salt1")
        assert "descr_" in result
        assert "upstream-link" not in result
