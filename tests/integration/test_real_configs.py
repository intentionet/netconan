"""Integration tests that run netconan against real-world config files.

Discovers configs in two directories:
  - tests/test_data/{vendor}/{source}/  — downloaded by the download script
  - tests/test_data_local/{vendor}/{source}/  — your own local configs

Runs netconan against each file and verifies:
  - No crashes (no unhandled exceptions)
  - Output file is produced and non-empty
  - Password-like patterns are anonymized when present in input
  - IP addresses are changed when present in input

Requires test data to be downloaded or placed manually:
    python tools/download_test_configs.py      # downloaded data
    tests/test_data_local/{vendor}/{source}/   # your own configs

The entire suite is skipped if neither directory contains config files.
"""

import os
import re
from pathlib import Path

import pytest

from netconan.netconan import main

# Test data directories (both are scanned for configs)
TEST_DATA_DIR = Path(__file__).parent.parent / "test_data"
TEST_DATA_LOCAL_DIR = Path(__file__).parent.parent / "test_data_local"

# Regex for detecting password-like patterns in input configs.
# Intentionally conservative — only match patterns that netconan's password
# regexes would actually anonymize, to avoid false positives from Juniper
# policy "community" statements or "authentication-order password" lines.
_PASSWORD_PATTERNS = re.compile(
    r"(?i)("
    r"\bpassword\s+['\"\$\d]\S*"
    r"|\bsecret\s+['\"\$\d]\S*"
    r"|\bsnmp\S*\s+.*\bcommunity\s+\S"
    r"|\bpre-shared-key\s+\S"
    r"|\bset password ENC\s+\S"
    r"|\bset psksecret\s+\S"
    r"|\bmd5\s+\d"
    r")"
)

# Regex for extracting IPv4 addresses
_IP_PATTERN = re.compile(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b")

# Extensions to skip (binary or non-config files)
_SKIP_EXTENSIONS = {".png", ".jpg", ".jpeg", ".gif", ".pdf", ".gz", ".tar", ".zip"}

# Max file size to process (10 MB)
_MAX_FILE_SIZE = 10 * 1024 * 1024


def _scan_data_dir(data_dir):
    """Scan a test data directory and return (vendor, source, filepath) tuples."""
    if not data_dir.is_dir():
        return []
    configs = []
    for vendor_dir in sorted(data_dir.iterdir()):
        if not vendor_dir.is_dir() or vendor_dir.name.startswith("."):
            continue
        vendor = vendor_dir.name
        for source_dir in sorted(vendor_dir.iterdir()):
            if not source_dir.is_dir() or source_dir.name.startswith("."):
                continue
            source = source_dir.name
            for config_file in sorted(source_dir.iterdir()):
                if not config_file.is_file():
                    continue
                if config_file.suffix.lower() in _SKIP_EXTENSIONS:
                    continue
                if config_file.name.startswith("."):
                    continue
                if config_file.stat().st_size > _MAX_FILE_SIZE:
                    continue
                configs.append((vendor, source, config_file))
    return configs


def discover_test_configs():
    """Scan test_data/ and test_data_local/ for config files."""
    return _scan_data_dir(TEST_DATA_DIR) + _scan_data_dir(TEST_DATA_LOCAL_DIR)


def has_password_patterns(content):
    """Check if content contains password-like patterns."""
    return bool(_PASSWORD_PATTERNS.search(content))


def extract_ip_addresses(content):
    """Extract all IPv4 addresses from content."""
    return set(_IP_PATTERN.findall(content))


def _is_readable_text(filepath):
    """Check if a file is readable as text."""
    try:
        with open(filepath, "r", encoding="utf-8", errors="strict") as f:
            f.read(1024)
        return True
    except (UnicodeDecodeError, PermissionError):
        return False


# Collect test configs at import time for parametrize
_TEST_CONFIGS = discover_test_configs()

# Skip the entire module if no test data exists
pytestmark = pytest.mark.skipif(
    not _TEST_CONFIGS,
    reason="No test configs found — run: python tools/download_test_configs.py",
)


def _config_id(param):
    """Generate readable test ID from parametrize tuple."""
    vendor, source, filepath = param
    return f"{vendor}/{source}/{filepath.name}"


@pytest.fixture
def output_dir(tmp_path):
    """Provide a temporary output directory."""
    return tmp_path / "output"


@pytest.mark.parametrize(
    "vendor,source,config_path",
    _TEST_CONFIGS,
    ids=[_config_id(c) for c in _TEST_CONFIGS],
)
def test_no_crash(vendor, source, config_path, output_dir):
    """Netconan should process the file without raising exceptions."""
    if not _is_readable_text(config_path):
        pytest.skip("Not a readable text file")

    output_file = output_dir / config_path.name
    os.makedirs(output_dir, exist_ok=True)

    main(
        [
            "-i",
            str(config_path),
            "-o",
            str(output_file),
            "-a",
            "-p",
            "-s",
            "TESTSALT",
        ]
    )

    assert output_file.exists(), f"Output file was not created: {output_file}"
    assert output_file.stat().st_size > 0, f"Output file is empty: {output_file}"


@pytest.mark.parametrize(
    "vendor,source,config_path",
    _TEST_CONFIGS,
    ids=[_config_id(c) for c in _TEST_CONFIGS],
)
def test_passwords_anonymized(vendor, source, config_path, output_dir):
    """If input has password patterns, output should show anonymization markers."""
    if not _is_readable_text(config_path):
        pytest.skip("Not a readable text file")

    try:
        input_text = config_path.read_text(encoding="utf-8", errors="replace")
    except Exception:
        pytest.skip("Could not read input file")

    if not has_password_patterns(input_text):
        pytest.skip("No password patterns detected in input")

    output_file = output_dir / config_path.name
    os.makedirs(output_dir, exist_ok=True)

    main(
        [
            "-i",
            str(config_path),
            "-o",
            str(output_file),
            "-a",
            "-p",
            "-s",
            "TESTSALT",
        ]
    )

    output_text = output_file.read_text(encoding="utf-8", errors="replace")

    # At minimum, the output should differ from input when passwords are present
    assert (
        output_text != input_text
    ), f"Output is identical to input despite password patterns in {config_path.name}"


@pytest.mark.parametrize(
    "vendor,source,config_path",
    _TEST_CONFIGS,
    ids=[_config_id(c) for c in _TEST_CONFIGS],
)
def test_ips_anonymized(vendor, source, config_path, output_dir):
    """If input has IP addresses, some should be changed in output."""
    if not _is_readable_text(config_path):
        pytest.skip("Not a readable text file")

    try:
        input_text = config_path.read_text(encoding="utf-8", errors="replace")
    except Exception:
        pytest.skip("Could not read input file")

    input_ips = extract_ip_addresses(input_text)
    # Filter out common non-routable/mask IPs that netconan preserves by default
    trivial_ips = {"0.0.0.0", "255.255.255.255", "255.255.255.0", "127.0.0.1"}
    meaningful_ips = input_ips - trivial_ips
    if len(meaningful_ips) < 2:
        pytest.skip("Not enough non-trivial IP addresses in input")

    output_file = output_dir / config_path.name
    os.makedirs(output_dir, exist_ok=True)

    main(
        [
            "-i",
            str(config_path),
            "-o",
            str(output_file),
            "-a",
            "-p",
            "-s",
            "TESTSALT",
        ]
    )

    output_text = output_file.read_text(encoding="utf-8", errors="replace")
    output_ips = extract_ip_addresses(output_text)

    # At least some IPs should have changed
    assert (
        input_ips != output_ips
    ), f"IP addresses unchanged in {config_path.name}: {meaningful_ips}"
