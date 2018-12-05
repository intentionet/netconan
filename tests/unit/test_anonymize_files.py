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

from netconan.anonymize_files import anonymize_files


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
    """Test anonymize_files with a file in a nested dir i.e. not at root of input dir."""
    filename = "test.txt"
    input_dir = tmpdir.mkdir("input")
    input_dir.mkdir("subdir").join(filename).write(_INPUT_CONTENTS)

    output_dir = tmpdir.mkdir("output")
    output_file = output_dir.join("subdir").join(filename)

    anonymize_files(str(input_dir), str(output_dir), True, True, salt=_SALT,
                    sensitive_words=_SENSITIVE_WORDS)

    # Make sure output file exists and matches the ref
    assert(os.path.isfile(str(output_file)))
    assert(read_file(str(output_file)) == _REF_CONTENTS)


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
