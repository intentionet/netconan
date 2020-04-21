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
    """Test default parameters."""
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
    assert args.keyword_remover is None


def test_no_config_file():
    """Test command line args are parsed."""
    args = _parse_args([
        "--input=in",
        "--output=out",
        "--anonymize-passwords",
        "--anonymize-ips",
        "--dump-ip-map=dump",
        "--log-level=CRITICAL",
        "--salt=salty",
        "--undo",
        "--sensitive-words=secret,password",
        "--keyword-remover=BGP neighbors,interface decriptions",
    ])

    assert "in" == args.input
    assert "out" == args.output
    assert args.anonymize_passwords
    assert args.anonymize_ips
    assert "dump" == args.dump_ip_map
    assert "CRITICAL" == args.log_level
    assert "salty" == args.salt
    assert args.undo
    assert "secret,password" == args.sensitive_words
    assert "BGP neighbors,interface decriptions" == args.keyword_remover


def test_config_file(tmpdir):
    """Test config file args are parsed."""
    cfg_file = str(tmpdir.mkdir('config_file').join('config.cfg'))
    with open(cfg_file, 'w') as f:
        f.write("""[Defaults]
        input=in
        output=out
        log-level=CRITICAL""")
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
    assert args.keyword_remover is None


def test_config_file_and_override(tmpdir):
    """Test command line args override config file args."""
    cfg_file = str(tmpdir.mkdir('config_file').join('config.cfg'))
    with open(cfg_file, 'w') as f:
        f.write("""[Defaults]
        input=in
        output=out
        log-level=CRITICAL""")
    args = _parse_args(["-c={}".format(cfg_file), "--input=override"])

    assert "override" == args.input
