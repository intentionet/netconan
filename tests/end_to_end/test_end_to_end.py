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

from netconan.netconan import main
from os import path

def test_end_to_end(tmpdir):
    input_contents = """
# Intentionet's sensitive test file
ip address 192.168.2.1 255.255.255.255
my password is $1$salt$ABCDEFGHIJKLMNOPQRS
AS num 12345 and 65432 should be changed

"""
    ref_contents = """
# 1cbbc2's fd8607 test file
ip address 201.235.139.13 255.255.255.255
my password is $1$0000$CxUUGIrqPb7GaB5midrQZ.
AS num 8625 and 64818 should be changed

"""

    filename = "test.txt"
    input_dir = str(tmpdir.mkdir("input"))
    input_file = path.join(input_dir, filename)
    with open(input_file, 'w') as f_tmp:
        f_tmp.write(input_contents)

    output_dir = str(tmpdir.mkdir("output"))
    output_file = path.join(output_dir, filename)

    ref_file = path.join(tmpdir, filename)
    with open(ref_file, 'w') as f_tmp:
        f_tmp.write(ref_contents)

    args = [
        '-i', input_dir,
        '-o', output_dir,
        '-s', 'TESTSALT',
        '-a',
        '-p',
        '-w', 'intentionet,sensitive',
        '-n', '65432,12345'
    ]
    main(args)

    # Make sure output file matches the ref
    assert(filecmp.cmp(ref_file, output_file))

