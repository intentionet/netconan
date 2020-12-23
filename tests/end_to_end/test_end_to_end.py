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
import six

from netconan.netconan import main
from netconan import __version__

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

REF_CONTENTS = """
# 1cbbc2's fd8607 test file
ip address 192.168.2.13 255.255.255.255
ip address 111.111.111.111
ip address 5.86.28.249 0.0.0.0
my hash is $1$0000$CxUUGIrqPb7GaB5midrQZ.
AS num 8625 and 64818 should be changed
password netconanRemoved1
password reservedword
ip address 11.11.11.11 0.0.0.0
ip address 11.11.197.79 0.0.0.0
# fd8607 word e77b71 here

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
        '-w', 'intentionet,sensitive,ADDR',
        '-r', 'reservedword',
        '-n', '65432,12345',
        '--preserve-addresses', '11.11.0.0/16,111.111.111.111',
        '--preserve-prefixes', '192.168.2.0/24',
    ]
    main(args)

    with open(str(ref_file)) as f_ref, open(str(output_file)) as f_out:
        # Compare lines for more readable failed assertion message
        t_ref = f_ref.read().split('\n')
        t_out = f_out.read().split('\n')

    # Make sure output file lines match ref lines
    assert t_ref == t_out


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


def test_version(capsys):
    """Test that version info is printed."""
    with pytest.raises(SystemExit):
        main(['--version'])
    captured = capsys.readouterr()
    # Python2 prints version info in err instead of out
    if six.PY2:
        assert __version__ in captured.err
    else:
        assert __version__ in captured.out
