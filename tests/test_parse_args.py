"""Test netconan argument parsing."""
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

from __future__ import unicode_literals

from netconan.netconan import _parse_args


def test_defaults():
    args = _parse_args(["--input=in", "--output=out"])
    assert "in" == args.input
    assert "out" == args.output
    assert not args.anonymize_passwords
    assert not args.anonymize_ips
    assert args.dump_ip_map is None
    assert 'INFO' == args.log_level
    assert args.salt is None
    assert not args.undo
    assert args.sensitive_words is None


def test_no_config_file():
    args = _parse_args([
        "--input=in",
        "--output=out",
        "--anonymize-passwords=True",
        "--anonymize-ips=true",
        "--dump-ip-map=dump",
        "--log-level=CRITICAL",
        "--salt=salty",
        "--undo=true",
        "--sensitive-words=secret,password",
    ])

    assert "in" == args.input
    assert "out" == args.output
    assert args.anonymize_passwords
    assert args.anonymize_ips
    assert "dump" == args.dump_ip_map
    assert "CRITICAL" == args.log_level
    assert "salty" == args.salt
    assert args.undo
    assert ["secret,password"] == args.sensitive_words


def test_config_file(tmpdir):
    cfg_file = tmpdir.mkdir('config_file').join('config.cfg')
    with open(cfg_file, 'w') as f:
        f.write("""[Defaults]
        input=in
        output=out
        log_level=CRITICAL""")
    args = _parse_args(["-c={}".format(cfg_file)])

    assert "in" == args.input
    assert "out" == args.output
    assert not args.anonymize_passwords
    assert not args.anonymize_ips
    assert args.dump_ip_map is None
    assert "CRITICAL" == args.log_level
    assert args.salt is None
    assert not args.undo
    assert args.sensitive_words is None


def test_config_file_and_override(tmpdir):
    cfg_file = tmpdir.mkdir('config_file').join('config.cfg')
    with open(cfg_file, 'w') as f:
        f.write("""[Defaults]
        input=in
        output=out
        log_level=CRITICAL""")
    args = _parse_args(["-c={}".format(cfg_file), "--input=override"])

    assert "override" == args.input
