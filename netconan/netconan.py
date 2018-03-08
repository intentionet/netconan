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
import configparser
import logging
import os
import sys

from .anonymize_files import anonymize_files_in_dir


def _parse_bool(v):
    if v.lower() in ('true',):
        return True
    elif v.lower() in ('false',):
        return False
    else:
        raise argparse.ArgumentTypeError('Boolean value expected.')


def _parse_args(argv):
    """Parse arguments from the given list."""

    conf_parser = argparse.ArgumentParser(
        description=__doc__,  # printed with -h/--help
        # Don't mess with format of description
        formatter_class=argparse.RawDescriptionHelpFormatter,
        # Turn off help, so that the parser below prints help for all options.
        add_help=False
    )
    conf_parser.add_argument("-c", "--conf_file", type=argparse.FileType('r'),
                             help="Specify config file", metavar="FILE")
    args, remaining_argv = conf_parser.parse_known_args(argv)

    defaults = {"anonymize_passwords": False,
                "anonymize_ips": False,
                "dump_ip_map": None,
                "input": None,
                "log_level": 'INFO',
                "output": None,
                "salt": None,
                "sensitive_words": None,
                "undo": False}

    if args.conf_file:
        config = configparser.ConfigParser()
        config.read_file(args.conf_file)
        defaults.update(dict(config.items("Defaults")))

    # Parse rest of arguments
    # Don't suppress add_help here so it will handle -h
    parser = argparse.ArgumentParser(
        # Inherit options from config_parser
        parents=[conf_parser]
    )
    parser.set_defaults(**defaults)
    parser.add_argument('-a', '--anonymize-ips', type=_parse_bool,
                        help='Anonymize IP addresses')
    parser.add_argument('-d', '--dump-ip-map',
                        help='Dump IP address anonymization map to specified file')
    parser.add_argument('-i', '--input',
                        help='Directory containing files to anonymize')
    parser.add_argument('-l', '--log-level',
                        help='Determines what level of logs to display',
                        choices=['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'])
    parser.add_argument('-o', '--output',
                        help='Directory to place anonymized files')
    parser.add_argument('-p', '--anonymize-passwords', type=_parse_bool,
                        help='Anonymize password and snmp community lines')
    parser.add_argument('-s', '--salt',
                        help='Salt for IP and sensitive keyword anonymization')
    parser.add_argument('-u', '--undo', type=_parse_bool,
                        help='Undo reversible anonymization (must specify salt)')
    parser.add_argument('-w', '--sensitive-words', nargs="+",
                        help='One or more keywords to anonymize')

    return parser.parse_args(remaining_argv)


def main(argv=sys.argv):
    """Netconan tool entry point."""

    # Parse any conf_file specification
    args = _parse_args(argv[1:])

    if not args.input:
        raise ValueError("Input directory must be specified")

    if not os.path.exists(args.input):
        raise ValueError("Input directory does not exist")

    log_level = logging.getLevelName(args.log_level)
    logging.basicConfig(format='%(levelname)s %(message)s', level=log_level)

    if len(os.listdir(args.input)) == 0:
        raise ValueError("Input directory is empty")

    if not args.output:
        raise ValueError("Output directory must be specified")

    if not os.path.exists(args.output):
        os.makedirs(args["output"])

    if args.undo:
        if args.anonymize_ips:
            raise ValueError('Cannot anonymize and undo anonymization, select '
                             'only one.')
        if args.salt is None:
            raise ValueError('Salt used for anonymization must be specified in '
                             'order to undo anonymization.')

    if args.dump_ip_map is not None:
        if not args.anonymize_ips:
            raise ValueError('Can only dump IP address map when anonymizing IP '
                             'addresses.')

    anonymize_files_in_dir(args.input, args.output, args.anonymize_passwords, args.anonymize_ips, args.salt,
                           args.dump_ip_map, args.sensitive_words, args.undo)


if __name__ == '__main__':
    main()
