# Tests

## Test Structure

```
tests/
  unit/                  # Fast unit tests (always run)
  end_to_end/            # End-to-end tests with inline data
  integration/           # Real-config integration tests (need downloaded data)
  test_data/             # Downloaded configs (git-ignored)
  test_data_local/       # Your own configs (git-ignored)
  TEST_DATA_SOURCES.md   # Detailed list of public config sources
```

## Running Tests

```bash
# Unit + end-to-end tests only (no downloads needed)
python -m pytest --override-ini="addopts=" -x -q

# Integration tests only
python -m pytest --override-ini="addopts=" tests/integration/ -v

# Everything together
python -m pytest --override-ini="addopts=" -v
```

Integration tests skip automatically if no test data is present.

## Downloading Test Data

The download script fetches real-world configs from public GitHub repos:

```bash
# Download all vendors (~600 files)
python tools/download_test_configs.py

# Download specific vendors only
python tools/download_test_configs.py --vendors cisco juniper_flat

# Force re-download (overwrite existing files)
python tools/download_test_configs.py --force
```

Files go into `tests/test_data/{vendor}/{source}/`. This directory is
git-ignored.

## Using Your Own Local Configs

Place your own config files in `tests/test_data_local/` using the same
`{vendor}/{source}/` structure:

```bash
mkdir -p tests/test_data_local/cisco/my_lab
cp ~/my-router.cfg tests/test_data_local/cisco/my_lab/

mkdir -p tests/test_data_local/juniper_flat/office
cp ~/srx-config.txt tests/test_data_local/juniper_flat/office/
```

The integration tests scan both `test_data/` and `test_data_local/`
automatically. The vendor and source names are free-form — use whatever
makes sense for your files. Both directories are git-ignored so your
configs are never committed.

## Adding a Download Source

Edit the `SOURCES` dict in `tools/download_test_configs.py`. Each vendor
maps to a list of source entries. Three types are supported:

```python
# git sparse checkout (for large repos where you only need one directory)
{
    "name": "my_source",
    "type": "git_sparse",
    "repo": "https://github.com/org/repo.git",
    "paths": ["path/to/configs"],       # sparse-checkout paths
    "src_dir": "path/to/configs",       # directory to copy files from
    "glob": "*.cfg",                    # optional file filter
},

# git clone (for small repos)
{
    "name": "my_source",
    "type": "git_clone",
    "repo": "https://github.com/org/repo.git",
    "glob": "*.conf",                   # optional file filter
},

# single file URL
{
    "name": "my_source",
    "type": "url",
    "url": "https://example.com/config.txt",
    "filename": "config.txt",           # name for the saved file
},
```

After adding, run `python tools/download_test_configs.py --force` to fetch.

## Removing a Download Source

Delete the source entry from the `SOURCES` dict in
`tools/download_test_configs.py`, then delete its local directory:

```bash
rm -rf tests/test_data/{vendor}/{source}
```

The metadata file (`tests/test_data/.download_metadata.json`) will be
updated on the next download run.
