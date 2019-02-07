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

import filecmp
import os.path

from netconan.netconan import main

INPUT_CONTENTS = """
# Intentionet's sensitive test file
ip address 192.168.2.1 255.255.255.255
my hash is $1$salt$ABCDEFGHIJKLMNOPQRS
AS num 12345 and 65432 should be changed
password foobar
password reservedword

"""

REF_CONTENTS = """
# 1cbbc2's fd8607 test file
ip address 201.235.139.13 255.255.255.255
my hash is $1$0000$CxUUGIrqPb7GaB5midrQZ.
AS num 8625 and 64818 should be changed
password netconanRemoved1
password reservedword

"""


def test_end_to_end(tmpdir):
    """Test Netconan main with simulated input file and commandline args."""
    filename = "test.txt"
    input_dir = tmpdir.mkdir("input")
    input_dir.join(filename).write(INPUT_CONTENTS)

    output_dir = tmpdir.mkdir("output")
    output_file = output_dir.join(filename)

    ref_file = tmpdir.join(filename)
    ref_file.write(REF_CONTENTS)

    args = [
        '-i', str(input_dir),
        '-o', str(output_dir),
        '-s', 'TESTSALT',
        '-a',
        '-p',
        '-w', 'intentionet,sensitive',
        '-r', 'reservedword',
        '-n', '65432,12345',
    ]
    main(args)

    # Make sure output file matches the ref
    assert(filecmp.cmp(str(ref_file), str(output_file)))


def test_end_to_end_no_anonymization(tmpdir):
    """Test Netconan main with simulated input file and no anonymization args."""
    filename = "test.txt"
    input_dir = tmpdir.mkdir("input")
    input_dir.join(filename).write(INPUT_CONTENTS)

    output_dir = tmpdir.mkdir("output")
    output_file = output_dir.join(filename)

    args = [
        '-i', str(input_dir),
        '-o', str(output_dir),
        '-s', 'TESTSALT',
        '-r', 'reservedword',
    ]
    main(args)

    # Make sure no output file was generated
    # when no anonymization args are supplied
    assert(not os.path.exists(str(output_file)))
