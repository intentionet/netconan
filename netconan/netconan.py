"""Handle invoking netconan from the command line."""
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

from __future__ import absolute_import
import argparse
import logging
import os
import yaml

from .anonymize_files import anonymize_files_in_dir

DEFAULT_ARGS = {}
DEFAULT_ARGS["anonymize_passwords"] = False
DEFAULT_ARGS["anonymize_ips"] = False
DEFAULT_ARGS["dump_ip_map"] = None
DEFAULT_ARGS["input"] = None
DEFAULT_ARGS["log_level"] = 'INFO'
DEFAULT_ARGS["output"] = None
DEFAULT_ARGS["salt"] = None
DEFAULT_ARGS["sensitive_words"] = None
DEFAULT_ARGS["undo"] = False


def main(args=None):
    """Netconan tool entry point."""
    parser = argparse.ArgumentParser()
    parser.add_argument('-a', '--anonymize-ips',
                        help='Anonymize IP addresses')
    parser.add_argument('-c', '--config-file',
                        help='YAML formatted configuration file')
    parser.add_argument('-d', '--dump-ip-map',
                        help='Dump IP address anonymization map to specified file')
    parser.add_argument('-i', '--input',
                        help='Directory containing files to anonymize')
    parser.add_argument('-l', '--log-level',
                        help='Determines what level of logs to display',
                        choices=['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'])
    parser.add_argument('-o', '--output',
                        help='Directory to place anonymized files')
    parser.add_argument('-p', '--anonymize-passwords',
                        help='Anonymize password and snmp community lines')
    parser.add_argument('-s', '--salt',
                        help='Salt for IP and sensitive keyword anonymization')
    parser.add_argument('-u', '--undo',
                        help='Undo reversible anonymization (must specify salt)')
    parser.add_argument('-w', '--sensitive-words', nargs="+",
                        help='One or more keywords to anonymize')
    cmd_args = vars(parser.parse_args(args))

    config_args = {}
    if cmd_args.get("config_file"):
        with open(cmd_args.get("config_file"), 'r') as stream:
            try:
                config_args = yaml.load(stream)
            except yaml.YAMLError as exc:
                print(exc)

    final_args = {}
    for arg in cmd_args:
        try:
            final_args[arg] = next(
                val for val in [cmd_args.get(arg), config_args.get(arg), DEFAULT_ARGS.get(arg)] if val is not None)
        except StopIteration as e:
            final_args[arg] = None

    loglevel = logging.getLevelName(final_args.get("log_level"))
    logging.basicConfig(format='%(levelname)s %(message)s', level=loglevel)

    if not final_args.get("input"):
        raise ValueError("Input directory must be specified")

    if not os.path.exists(final_args.get("input")):
        raise ValueError("Input directory does not exist")

    if len(os.listdir(final_args.get("input"))) == 0:
        raise ValueError("Input directory is empty")

    if not final_args.get("output"):
        raise ValueError("Output directory must be specified")

    if not os.path.exists(final_args.get("output")):
        os.makedirs(final_args["output"])

    if final_args.get("undo"):
        if final_args.get("anonymize_ips"):
            raise ValueError('Cannot anonymize and undo anonymization, select '
                             'only one.')
        if final_args.get("salt") is None:
            raise ValueError('Salt used for anonymization must be specified in '
                             'order to undo anonymization.')

    if final_args.get("dump_ip_map") is not None:
        if not final_args.get("anonymize_ips"):
            raise ValueError('Can only dump IP address map when anonymizing IP '
                             'addresses.')

    anonymize_files_in_dir(final_args.get("input"), final_args.get("output"),
                           final_args.get("anonymize_passwords"), final_args.get("anonymize_ips"),
                           final_args.get("salt"), final_args.get("dump_ip_map"), final_args.get("sensitive_words"),
                           final_args.get("undo"))


if __name__ == '__main__':
    main()
