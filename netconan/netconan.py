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


def str2bool(v):
    if v.lower() in ('true'):
        return True
    elif v.lower() in ('false'):
        return False
    else:
        raise argparse.ArgumentTypeError('Boolean value expected.')


def main(argv=None):
    """Netconan tool entry point."""
    if argv is None:
        argv = sys.argv

    # Parse any conf_file specification
    # We make this parser with add_help=False so that it doesn't parse -h and print help.
    conf_parser = argparse.ArgumentParser(
        description=__doc__,  # printed with -h/--help
        # Don't mess with format of description
        formatter_class=argparse.RawDescriptionHelpFormatter,
        # Turn off help, so we print all options in response to -h
        add_help=False
    )
    conf_parser.add_argument("-c", "--conf_file",
                             help="Specify config file", metavar="FILE")
    args, remaining_argv = conf_parser.parse_known_args()

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
        if not os.path.exists(args.conf_file):
            raise ValueError("Config file does not exist")
        config = configparser.ConfigParser()
        config.read([args.conf_file])
        defaults.update(dict(config.items("Defaults")))

    # Parse rest of arguments
    # Don't suppress add_help here so it will handle -h
    parser = argparse.ArgumentParser(
        # Inherit options from config_parser
        parents=[conf_parser]
    )
    parser.set_defaults(**defaults)
    parser.add_argument('-a', '--anonymize-ips', type=str2bool,
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
    parser.add_argument('-p', '--anonymize-passwords', type=str2bool,
                        help='Anonymize password and snmp community lines')
    parser.add_argument('-s', '--salt',
                        help='Salt for IP and sensitive keyword anonymization')
    parser.add_argument('-u', '--undo', type=str2bool,
                        help='Undo reversible anonymization (must specify salt)')
    parser.add_argument('-w', '--sensitive-words', nargs="+",
                        help='One or more keywords to anonymize')
    args = parser.parse_args(remaining_argv)

    print(args)

    loglevel = logging.getLevelName(args.log_level)
    logging.basicConfig(format='%(levelname)s %(message)s', level=loglevel)

    if not args.input:
        raise ValueError("Input directory must be specified")

    if not os.path.exists(args.input):
        raise ValueError("Input directory does not exist")

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
