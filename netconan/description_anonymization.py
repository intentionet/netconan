"""Anonymize description fields in network configuration files."""

import hashlib
import re

# Matches: description "some text here"
_DESCRIPTION_QUOTED_REGEX = re.compile(
    r'(?P<pre>description\s+")(?P<desc>[^"]+)(?P<post>")'
)

# Matches: description some text here (with optional trailing semicolon)
_DESCRIPTION_UNQUOTED_REGEX = re.compile(
    r"(?P<pre>description\s+)(?P<desc>[^\";\s].+?)\s*(?P<post>;?\s*)$"
)


def anonymize_description(value: str, lookup: dict[str, str], salt: str) -> str:
    """Return a deterministic anonymized replacement for a description value.

    Uses SHA-256 hashing with the given salt to produce a stable 8-character
    base32-encoded identifier prefixed with 'descr_'.
    """
    if value in lookup:
        return lookup[value]
    hash_input = (salt + value).encode("utf-8")
    digest = hashlib.sha256(hash_input).digest()
    # Use first 5 bytes -> 8 base32 chars, strip padding, lowercase
    anon = "descr_" + _base32_encode(digest[:5]).lower()
    lookup[value] = anon
    return anon


def _base32_encode(data: bytes) -> str:
    """Base32 encode bytes and strip padding."""
    import base64

    return base64.b32encode(data).decode("ascii").rstrip("=")


def generate_description_regexes() -> list[re.Pattern[str]]:
    """Return list of compiled regexes for matching description lines."""
    return [_DESCRIPTION_QUOTED_REGEX, _DESCRIPTION_UNQUOTED_REGEX]


def replace_descriptions(
    regexes: list[re.Pattern[str]], line: str, lookup: dict[str, str], salt: str
) -> str:
    """Replace description content in a line if it matches any regex.

    First match wins. Returns the line with description content replaced,
    preserving surrounding context (quotes, semicolons, whitespace).
    """
    for regex in regexes:
        match = regex.search(line)
        if match:
            desc_value = match.group("desc")
            anon_value = anonymize_description(desc_value, lookup, salt)
            return (
                line[: match.start()]
                + match.group("pre")
                + anon_value
                + match.group("post")
                + line[match.end() :]
            )
    return line
