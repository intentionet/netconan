"""Test Netconan from end to end."""

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

import os.path

import pytest

from netconan import __version__
from netconan.netconan import main

INPUT_CONTENTS = """
# Intentionet's sensitive test file
ip address 192.168.2.1 255.255.255.255
ip address 111.111.111.111
ip address 1.2.3.4 0.0.0.0
my hash is $1$salt$ABCDEFGHIJKLMNOPQRS
AS num 12345 and 65432 should be changed
password foobar
password reservedword
ip address 11.11.11.11 0.0.0.0
ip address 11.11.197.79 0.0.0.0
# Sensitive word Addr here

"""

ANON_REF_CONTENTS = """
# a4daba's fd8607 test file
ip address 192.168.2.1 255.255.255.255
ip address 111.111.111.111
ip address 5.86.3.4 0.0.0.0
my hash is $1$0000$CxUUGIrqPb7GaB5midrQZ.
AS num 8625 and 64818 should be changed
password netconanRemoved1
password reservedword
ip address 11.11.11.11 0.0.0.0
ip address 11.11.197.79 0.0.0.0
# 3b836f word 10b348 here

"""

DEANON_REF_CONTENTS = """
# a4daba's fd8607 test file
ip address 192.168.2.1 255.255.255.255
ip address 111.111.111.111
ip address 1.2.3.4 0.0.0.0
my hash is $1$0000$CxUUGIrqPb7GaB5midrQZ.
AS num 8625 and 64818 should be changed
password netconanRemoved1
password reservedword
ip address 11.11.11.11 0.0.0.0
ip address 11.11.197.79 0.0.0.0
# 3b836f word 10b348 here

"""


def run_test(input_dir, output_dir, filename, ref, args):
    """Executes a test that the given filename is netconan-ified to ref."""
    used_args = args + ["-i", str(input_dir), "-o", str(output_dir)]
    main(used_args)

    # Compare lines for more readable failed assertion message
    t_ref = ref.split("\n")
    with open(str(output_dir.join(filename))) as f_out:
        t_out = f_out.read().split("\n")

    # Make sure output file lines match ref lines
    assert t_ref == t_out


def test_end_to_end(tmpdir):
    """Test Netconan main with simulated input file and commandline args."""
    filename = "test.txt"
    args = [
        "-s",
        "TESTSALT",
        "-p",
        "-w",
        "intentionet,sensitive,ADDR",
        "-r",
        "reservedword",
        "-n",
        "65432,12345",
        "--preserve-addresses",
        "11.11.0.0/16,111.111.111.111",
        "--preserve-prefixes",
        "192.168.2.0/24",
        "--preserve-host-bits",
        "17",
    ]

    input_dir = tmpdir.mkdir("input")
    input_dir.join(filename).write(INPUT_CONTENTS)

    anon_dir = tmpdir.mkdir("anon")
    run_test(input_dir, anon_dir, filename, ANON_REF_CONTENTS, args + ["-a"])

    deanon_dir = tmpdir.mkdir("deanon")
    run_test(anon_dir, deanon_dir, filename, DEANON_REF_CONTENTS, args + ["-u"])


def test_end_to_end_no_anonymization(tmpdir):
    """Test Netconan main with simulated input file and no anonymization args."""
    filename = "test.txt"
    input_dir = tmpdir.mkdir("input")
    input_dir.join(filename).write(INPUT_CONTENTS)

    output_dir = tmpdir.mkdir("output")
    output_file = output_dir.join(filename)

    args = [
        "-i",
        str(input_dir),
        "-o",
        str(output_dir),
        "-s",
        "TESTSALT",
        "-r",
        "reservedword",
    ]
    main(args)

    # Make sure no output file was generated
    # when no anonymization args are supplied
    assert not os.path.exists(str(output_file))


def test_version(capsys):
    """Test that version info is printed."""
    with pytest.raises(SystemExit):
        main(["--version"])
    captured = capsys.readouterr()
    assert __version__ in captured.out
