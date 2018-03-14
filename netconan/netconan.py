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
import configargparse
import logging
import os
import sys

from .anonymize_files import anonymize_files_in_dir


def _parse_args(argv):
    """Parse arguments from the given list."""
    parser = configargparse.ArgParser(
        # Replace the default config file help with custom message
        # To fix some syntax issues
        add_config_file_help=False,
        description="""
        Args that can start with '--' can also be set in a config file (specified
        via -c). If an arg is specified in more than one place, then command line
        values override config file values which override defaults. Config file
        syntax allows: key=value, flag=true, stuff=[a,b,c] (for more details, see
        here https://goo.gl/R74nmi).
        """
    )

    parser.add_argument('-a', '--anonymize-ips', action='store_true', default=False,
                        help='Anonymize IP addresses')
    parser.add_argument('-c', '--config', is_config_file=True,
                        help='Config file specifying params')
    parser.add_argument('-d', '--dump-ip-map', default=None,
                        help='Dump IP address anonymization map to specified file')
    parser.add_argument('-i', '--input', required=True,
                        help='Directory containing files to anonymize')
    parser.add_argument('-l', '--log-level', default='INFO',
                        choices=['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'],
                        help='Determines what level of logs to display')
    parser.add_argument('-n', '--as-numbers', default=None,
                        help='List of comma separated AS numbers to anonymize')
    parser.add_argument('-o', '--output', required=True,
                        help='Directory to place anonymized files')
    parser.add_argument('-p', '--anonymize-passwords', action='store_true', default=False,
                        help='Anonymize password and snmp community lines')
    parser.add_argument('-s', '--salt', default=None,
                        help='Salt for IP and sensitive keyword anonymization')
    parser.add_argument('-u', '--undo', action='store_true', default=False,
                        help='Undo reversible anonymization (must specify salt)')
    parser.add_argument('-w', '--sensitive-words', default=None,
                        help='List of comma separated keywords to anonymize')
    return parser.parse_args(argv)


def main(argv=sys.argv[1:]):
    """Netconan tool entry point."""
    args = _parse_args(argv)

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
        os.makedirs(args.output)

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

    sensitive_words = None
    if args.sensitive_words is not None:
        sensitive_words = args.sensitive_words.split(',')

    as_numbers = None
    if args.as_numbers is not None:
        as_numbers = args.as_numbers.split(',')

    anonymize_files_in_dir(args.input, args.output, args.anonymize_passwords, args.anonymize_ips, args.salt,
                           args.dump_ip_map, sensitive_words, args.undo, as_numbers)


if __name__ == '__main__':
    main()
