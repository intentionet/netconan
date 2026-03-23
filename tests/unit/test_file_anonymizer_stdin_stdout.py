"""Test stdin/stdout pipe mode for file anonymization."""

import io
import os

import pytest

from netconan.anonymize_files import anonymize_files

_INPUT_CONTENTS = """
# Intentionet's sensitive test file
ip address 192.168.2.1 255.255.255.255
my hash is $1$salt$ABCDEFGHIJKLMNOPQRS
password foobar

"""
_REF_CONTENTS = """
# a4daba's fd8607 test file
ip address 192.168.139.13 255.255.255.255
my hash is $1$0000$CxUUGIrqPb7GaB5midrQZ.
password netconanRemoved1

"""
_SALT = "TESTSALT"
_SENSITIVE_WORDS = [
    "intentionet",
    "sensitive",
]


def test_anonymize_files_stdin_stdout(monkeypatch):
    """Test anonymize_files with stdin and stdout (pipe mode)."""
    monkeypatch.setattr("sys.stdin", io.StringIO(_INPUT_CONTENTS))
    fake_stdout = io.StringIO()
    monkeypatch.setattr("sys.stdout", fake_stdout)

    anonymize_files(
        "-",
        "-",
        True,
        True,
        salt=_SALT,
        sensitive_words=_SENSITIVE_WORDS,
    )

    assert fake_stdout.getvalue() == _REF_CONTENTS


def test_anonymize_files_stdin_to_file(monkeypatch, tmpdir):
    """Test anonymize_files with stdin input and file output."""
    monkeypatch.setattr("sys.stdin", io.StringIO(_INPUT_CONTENTS))

    output_file = tmpdir.mkdir("out").join("test.txt")

    anonymize_files(
        "-",
        str(output_file),
        True,
        True,
        salt=_SALT,
        sensitive_words=_SENSITIVE_WORDS,
    )

    assert os.path.isfile(str(output_file))
    with open(str(output_file), "r") as f:
        assert f.read() == _REF_CONTENTS


def test_anonymize_files_file_to_stdout(monkeypatch, tmpdir):
    """Test anonymize_files with file input and stdout output."""
    input_file = tmpdir.join("test.txt")
    input_file.write(_INPUT_CONTENTS)

    fake_stdout = io.StringIO()
    monkeypatch.setattr("sys.stdout", fake_stdout)

    anonymize_files(
        str(input_file),
        "-",
        True,
        True,
        salt=_SALT,
        sensitive_words=_SENSITIVE_WORDS,
    )

    assert fake_stdout.getvalue() == _REF_CONTENTS


def test_anonymize_files_dir_to_stdout_raises(tmpdir):
    """Test that directory input with stdout output raises ValueError."""
    input_dir = tmpdir.mkdir("input")
    input_dir.join("test.txt").write(_INPUT_CONTENTS)

    with pytest.raises(ValueError, match="Cannot write directory output to stdout"):
        anonymize_files(
            str(input_dir),
            "-",
            True,
            True,
            salt=_SALT,
            sensitive_words=_SENSITIVE_WORDS,
        )
