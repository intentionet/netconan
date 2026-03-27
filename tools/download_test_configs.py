#!/usr/bin/env python3
"""Download real-world network configs from public GitHub repos for testing.

Downloads configs into tests/test_data/{vendor}/{source}/ for use with
the integration test suite in tests/integration/test_real_configs.py.

Usage:
    python tools/download_test_configs.py              # all vendors
    python tools/download_test_configs.py --vendors cisco arista
    python tools/download_test_configs.py --force       # re-download all
"""

import argparse
import json
import logging
import os
import shutil
import subprocess
import sys
import tempfile
import urllib.request

logging.basicConfig(
    format="%(levelname)s %(message)s",
    level=logging.INFO,
)
logger = logging.getLogger(__name__)

# Root of the netconan project
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TEST_DATA_DIR = os.path.join(PROJECT_ROOT, "tests", "test_data")
METADATA_FILE = os.path.join(TEST_DATA_DIR, ".download_metadata.json")

# Batfish base paths inside the repo
_BF_GRAMMAR = "projects/batfish/src/test/resources/org/batfish/grammar"
_BF_VENDOR = "projects/batfish/src/test/resources/org/batfish/vendor"

SOURCES = {
    "cisco": [
        {
            "name": "batfish",
            "type": "git_sparse",
            "repo": "https://github.com/batfish/batfish.git",
            "paths": [f"{_BF_GRAMMAR}/cisco/testconfigs"],
            "src_dir": f"{_BF_GRAMMAR}/cisco/testconfigs",
        },
        {
            "name": "ciscoconfparse",
            "type": "git_sparse",
            "repo": "https://github.com/mpenning/ciscoconfparse.git",
            "paths": ["tests/fixtures/configs"],
            "src_dir": "tests/fixtures/configs",
            "glob": "*.ios",
        },
    ],
    "arista": [
        {
            "name": "batfish",
            "type": "git_sparse",
            "repo": "https://github.com/batfish/batfish.git",
            "paths": [f"{_BF_VENDOR}/arista/grammar/testconfigs"],
            "src_dir": f"{_BF_VENDOR}/arista/grammar/testconfigs",
        },
    ],
    "juniper_flat": [
        {
            "name": "jcoeder",
            "type": "git_clone",
            "repo": "https://github.com/jcoeder/juniper-configurations.git",
            "glob": "*.conf",
        },
    ],
    "juniper_hierarchical": [
        {
            "name": "batfish",
            "type": "git_sparse",
            "repo": "https://github.com/batfish/batfish.git",
            "paths": [f"{_BF_GRAMMAR}/juniper/testconfigs"],
            "src_dir": f"{_BF_GRAMMAR}/juniper/testconfigs",
        },
    ],
    "fortinet": [
        {
            "name": "batfish",
            "type": "git_sparse",
            "repo": "https://github.com/batfish/batfish.git",
            "paths": [f"{_BF_GRAMMAR}/fortios/testconfigs"],
            "src_dir": f"{_BF_GRAMMAR}/fortios/testconfigs",
        },
        {
            "name": "azure",
            "type": "url",
            "url": (
                "https://raw.githubusercontent.com/Azure/"
                "Azure-vpn-config-samples/master/Fortinet/Current/"
                "fortigate_show%20full-configuration.txt"
            ),
            "filename": "fortigate_full.txt",
        },
    ],
}


def load_metadata():
    """Load download metadata from disk."""
    if os.path.exists(METADATA_FILE):
        with open(METADATA_FILE) as f:
            return json.load(f)
    return {}


def save_metadata(metadata):
    """Save download metadata to disk."""
    os.makedirs(os.path.dirname(METADATA_FILE), exist_ok=True)
    with open(METADATA_FILE, "w") as f:
        json.dump(metadata, f, indent=2, sort_keys=True)


def source_key(vendor, source):
    """Return a unique key for a vendor/source pair."""
    return f"{vendor}/{source['name']}"


def is_downloaded(metadata, vendor, source):
    """Check if a source has already been downloaded."""
    key = source_key(vendor, source)
    return key in metadata


def copy_files(src_dir, dest_dir, glob_pattern=None):
    """Copy files from src_dir to dest_dir, optionally filtering by glob."""
    os.makedirs(dest_dir, exist_ok=True)
    count = 0
    for entry in os.listdir(src_dir):
        src_path = os.path.join(src_dir, entry)
        if not os.path.isfile(src_path):
            continue
        if glob_pattern and not _matches_glob(entry, glob_pattern):
            continue
        shutil.copy2(src_path, os.path.join(dest_dir, entry))
        count += 1
    return count


def _matches_glob(filename, pattern):
    """Simple glob matching for *.ext patterns."""
    if pattern.startswith("*."):
        return filename.endswith(pattern[1:])
    return True


def download_git_sparse(source, tmp_dir, dest_dir):
    """Download files using git sparse checkout."""
    repo_dir = os.path.join(tmp_dir, "repo")
    subprocess.run(
        [
            "git",
            "clone",
            "--depth",
            "1",
            "--filter=blob:none",
            "--sparse",
            source["repo"],
            repo_dir,
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    subprocess.run(
        ["git", "sparse-checkout", "set"] + source["paths"],
        cwd=repo_dir,
        check=True,
        capture_output=True,
        text=True,
    )
    src_dir = os.path.join(repo_dir, source["src_dir"])
    if not os.path.isdir(src_dir):
        raise FileNotFoundError(f"Source directory not found: {src_dir}")
    return copy_files(src_dir, dest_dir, source.get("glob"))


def download_git_clone(source, tmp_dir, dest_dir):
    """Download files by cloning a full repo (shallow)."""
    repo_dir = os.path.join(tmp_dir, "repo")
    subprocess.run(
        ["git", "clone", "--depth", "1", source["repo"], repo_dir],
        check=True,
        capture_output=True,
        text=True,
    )
    return copy_files(repo_dir, dest_dir, source.get("glob"))


def download_url(source, dest_dir):
    """Download a single file from a URL."""
    os.makedirs(dest_dir, exist_ok=True)
    dest_path = os.path.join(dest_dir, source["filename"])
    urllib.request.urlretrieve(source["url"], dest_path)
    return 1


def download_source(vendor, source, force=False):
    """Download a single source. Returns (count, error_or_None)."""
    key = source_key(vendor, source)
    dest_dir = os.path.join(TEST_DATA_DIR, vendor, source["name"])

    if not force and os.path.isdir(dest_dir) and os.listdir(dest_dir):
        logger.info("  [skip] %s — already exists", key)
        return 0, None

    logger.info("  [download] %s ...", key)

    if source["type"] == "url":
        count = download_url(source, dest_dir)
        return count, None

    with tempfile.TemporaryDirectory(prefix="netconan_dl_") as tmp_dir:
        if source["type"] == "git_sparse":
            count = download_git_sparse(source, tmp_dir, dest_dir)
        elif source["type"] == "git_clone":
            count = download_git_clone(source, tmp_dir, dest_dir)
        else:
            raise ValueError(f"Unknown source type: {source['type']}")
    return count, None


def main(argv=None):
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Download real-world network configs for testing."
    )
    parser.add_argument(
        "--vendors",
        nargs="+",
        choices=sorted(SOURCES.keys()),
        default=None,
        help="Only download configs for these vendors (default: all)",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Re-download even if files already exist",
    )
    args = parser.parse_args(argv)

    vendors = args.vendors or sorted(SOURCES.keys())
    metadata = load_metadata()
    total_files = 0
    errors = []

    for vendor in vendors:
        sources = SOURCES.get(vendor, [])
        if not sources:
            logger.warning("No sources defined for vendor: %s", vendor)
            continue
        logger.info("Vendor: %s", vendor)
        for src in sources:
            try:
                count, err = download_source(vendor, src, force=args.force)
                if err:
                    errors.append((source_key(vendor, src), err))
                else:
                    total_files += count
                    metadata[source_key(vendor, src)] = {
                        "type": src["type"],
                        "repo": src.get("repo", src.get("url", "")),
                    }
            except Exception as e:
                key = source_key(vendor, src)
                logger.error("  [error] %s: %s", key, e)
                errors.append((key, str(e)))

    save_metadata(metadata)

    logger.info("")
    logger.info("Done: %d files downloaded", total_files)
    if errors:
        logger.error("%d source(s) failed:", len(errors))
        for key, err in errors:
            logger.error("  %s: %s", key, err)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
