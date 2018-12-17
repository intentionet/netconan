"""Test file anonymization."""
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

import os

import pytest

from testfixtures import LogCapture

from netconan.anonymize_files import anonymize_file, anonymize_files

_INPUT_CONTENTS = """
# Intentionet's sensitive test file
ip address 192.168.2.1 255.255.255.255
my hash is $1$salt$ABCDEFGHIJKLMNOPQRS
password foobar

"""
_REF_CONTENTS = """
# 1cbbc2's fd8607 test file
ip address 201.235.139.13 255.255.255.255
my hash is $1$0000$CxUUGIrqPb7GaB5midrQZ.
password netconanRemoved1

"""
_SALT = "TESTSALT"
_SENSITIVE_WORDS = [
    "intentionet",
    "sensitive",
]


def test_anonymize_files_bad_input_empty(tmpdir):
    """Test anonymize_files with empty input dir."""
    input_dir = tmpdir.mkdir("input")
    output_dir = tmpdir.mkdir("output")

    with pytest.raises(ValueError, match='Input directory is empty'):
        anonymize_files(str(input_dir), str(output_dir), True, True, salt=_SALT,
                        sensitive_words=_SENSITIVE_WORDS)


def test_anonymize_files_bad_input_missing(tmpdir):
    """Test anonymize_files with non-existent input."""
    filename = "test.txt"
    input_file = tmpdir.join(filename)

    output_file = tmpdir.mkdir("out").join(filename)

    with pytest.raises(ValueError, match='Input does not exist'):
        anonymize_files(str(input_file), str(output_file), True, True,
                        salt=_SALT,
                        sensitive_words=_SENSITIVE_WORDS)


def test_anonymize_files_bad_output_file(tmpdir):
    """Test anonymize_files when output 'file' already exists but is a dir."""
    filename = "test.txt"
    input_file = tmpdir.join(filename)
    input_file.write(_INPUT_CONTENTS)

    output_file = tmpdir.mkdir("out").mkdir(filename)

    with pytest.raises(ValueError, match='Cannot write output file.*'):
        anonymize_file(str(input_file), str(output_file))

    # Anonymizing files should complete okay, because it skips the errored file
    with LogCapture() as log_capture:
        anonymize_files(str(input_file), str(output_file), True, True,
                        salt=_SALT,
                        sensitive_words=_SENSITIVE_WORDS)
        log_capture.check_present(
            ('root', 'ERROR', 'Failed to anonymize file {}'.format(str(input_file)))
        )


def test_anonymize_files_bad_output_dir(tmpdir):
    """Test anonymize_files when output 'dir' already exists but is a file."""
    filename = "test.txt"
    input_dir = tmpdir.mkdir("input")
    input_dir.join(filename).write(_INPUT_CONTENTS)

    output_file = tmpdir.join("out")
    output_file.write('blah')

    with pytest.raises(ValueError, match='Output path must be a directory.*'):
        anonymize_files(str(input_dir), str(output_file), True, True,
                        salt=_SALT,
                        sensitive_words=_SENSITIVE_WORDS)


def test_anonymize_files_dir(tmpdir):
    """Test anonymize_files with a file in root of input dir."""
    filename = "test.txt"
    input_dir = tmpdir.mkdir("input")
    input_dir.join(filename).write(_INPUT_CONTENTS)

    output_dir = tmpdir.mkdir("output")
    output_file = output_dir.join(filename)

    anonymize_files(str(input_dir), str(output_dir), True, True, salt=_SALT,
                    sensitive_words=_SENSITIVE_WORDS)

    # Make sure output file exists and matches the ref
    assert(os.path.isfile(str(output_file)))
    assert(read_file(str(output_file)) == _REF_CONTENTS)


def test_anonymize_files_dir_skip_hidden(tmpdir):
    """Test that file starting with '.' is skipped."""
    filename = ".test.txt"
    input_dir = tmpdir.mkdir("input")
    input_file = input_dir.join(filename)
    input_file.write(_INPUT_CONTENTS)

    output_dir = tmpdir.mkdir("output")
    output_file = output_dir.join(filename)

    anonymize_files(str(input_dir), str(output_dir), True, True, salt=_SALT,
                    sensitive_words=_SENSITIVE_WORDS)

    # Make sure output file does not exist
    assert(not os.path.exists(str(output_file)))


def test_anonymize_files_dir_nested(tmpdir):
    """Test anonymize_files with files in nested dirs i.e. not at root of input dir."""
    filename = "test.txt"
    input_dir = tmpdir.mkdir("input")
    input_dir.mkdir("subdir1").join(filename).write(_INPUT_CONTENTS)
    input_dir.mkdir("subdir2").mkdir("subsubdir").join(filename).write(_INPUT_CONTENTS)

    output_dir = tmpdir.mkdir("output")
    output_file_1 = output_dir.join("subdir1").join(filename)
    output_file_2 = output_dir.join("subdir2").join("subsubdir").join(filename)

    anonymize_files(str(input_dir), str(output_dir), True, True, salt=_SALT,
                    sensitive_words=_SENSITIVE_WORDS)

    # Make sure both output files exists and match the ref
    assert(os.path.isfile(str(output_file_1)))
    assert(read_file(str(output_file_1)) == _REF_CONTENTS)

    assert(os.path.isfile(str(output_file_2)))
    assert(read_file(str(output_file_2)) == _REF_CONTENTS)


def test_anonymize_files_file(tmpdir):
    """Test anonymize_files with input file instead of dir."""
    filename = "test.txt"
    input_file = tmpdir.join(filename)
    input_file.write(_INPUT_CONTENTS)

    output_file = tmpdir.mkdir("out").join(filename)

    anonymize_files(str(input_file), str(output_file), True, True, salt=_SALT,
                    sensitive_words=_SENSITIVE_WORDS)

    # Make sure output file exists and matches the ref
    assert(os.path.isfile(str(output_file)))
    assert(read_file(str(output_file)) == _REF_CONTENTS)


def read_file(file_path):
    """Read and return contents of file at specified path."""
    with open(file_path, 'r') as f:
        return f.read()
