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
import sys

from .ip_anonymization import IpAnonymizer
from .anonymize_files import anonymize_files
from . import __version__


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

    parser.add_argument('--version', action='version', version=__version__,
                        help='Print version number and exit')
    parser.add_argument('-a', '--anonymize-ips', action='store_true', default=False,
                        help='Anonymize IP addresses')
    parser.add_argument('-c', '--config', is_config_file=True,
                        help='Netconan configuration file with defaults for these CLI parameters')
    parser.add_argument('-d', '--dump-ip-map', default=None,
                        help='Dump IP address anonymization map to specified file')
    parser.add_argument('-i', '--input', required=True,
                        help='Input file or directory containing files to anonymize')
    parser.add_argument('-l', '--log-level', default='INFO',
                        choices=['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'],
                        help='Determines what level of logs to display')
    parser.add_argument('-n', '--as-numbers', default=None,
                        help='List of comma separated AS numbers to anonymize')
    parser.add_argument('-o', '--output', required=True,
                        help='Output file or directory where anonymized files are placed')
    parser.add_argument('-p', '--anonymize-passwords', action='store_true', default=False,
                        help='Anonymize password and snmp community lines')
    parser.add_argument('-r', '--reserved-words', default=None,
                        help='List of comma separated words that should not be anonymized')
    parser.add_argument('-s', '--salt', default=None,
                        help='Salt for IP and sensitive keyword anonymization')
    parser.add_argument('-u', '--undo', action='store_true', default=False,
                        help='Undo reversible anonymization (must specify salt)')
    parser.add_argument('-w', '--sensitive-words', default=None,
                        help='List of comma separated keywords to anonymize')
    parser.add_argument('--preserve-prefixes',
                        default=','.join(IpAnonymizer.DEFAULT_PRESERVED_PREFIXES),
                        help='List of comma separated IP prefixes to preserve. Specified prefixes are preserved, but the host bits within those prefixes are still anonymized. To preserve prefixes and host bits in specified blocks, use --preserve-addresses instead')
    parser.add_argument('--preserve-addresses', default=None,
                        help='List of comma separated IP addresses or networks to preserve. Prefixes and host bits within those networks are preserved.  To preserve just prefixes and anonymize host bits, use --preserve-prefixes')
    parser.add_argument('--preserve-private-addresses',
                        action='store_true', default=False,
                        help='Preserve private-use IP addresses. Prefixes and host bits within the private-use IP networks are preserved. To preserve specific addresses or networks, use --preserve-addresses instead. To preserve just prefixes and anonymize host bits, use --preserve-prefixes')
    parser.add_argument('--preserve-host-bits',
                        type=int, default=8,
                        help='Preserve the trailing bits of IP addresses, aka the host bits of a network. Set this value large enough to represent the largest interface network (e.g., 8 for a /24 or 12 for a /20) or NAT pool.')
    return parser.parse_args(argv)


def main(argv=sys.argv[1:]):
    """Netconan tool entry point."""
    args = _parse_args(argv)

    if not args.input:
        raise ValueError("Input must be specified")

    log_level = logging.getLevelName(args.log_level)
    logging.basicConfig(format='%(levelname)s %(message)s', level=log_level)

    if not args.output:
        raise ValueError("Output must be specified")

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

    as_numbers = None
    if args.as_numbers is not None:
        as_numbers = args.as_numbers.split(',')

    reserved_words = None
    if args.reserved_words is not None:
        reserved_words = args.reserved_words.split(',')

    sensitive_words = None
    if args.sensitive_words is not None:
        sensitive_words = args.sensitive_words.split(',')

    preserve_prefixes = None
    if args.preserve_prefixes is not None:
        preserve_prefixes = args.preserve_prefixes.split(',')

    preserve_addresses = None
    if args.preserve_addresses is not None:
        preserve_addresses = args.preserve_addresses.split(',')

    if args.preserve_private_addresses:
        addrs = list(IpAnonymizer.RFC_1918_NETWORKS)
        # Merge private addresses with explicitly preserved addresses
        preserve_addresses = addrs if preserve_addresses is None else (
            preserve_addresses + addrs
        )

    if not any([
        as_numbers,
        sensitive_words,
        args.anonymize_passwords,
        args.anonymize_ips,
        args.undo
    ]):
        logging.warning('No anonymization options turned on, '
                        'no output file(s) will be generated.')
    else:
        anonymize_files(args.input, args.output, args.anonymize_passwords,
                        args.anonymize_ips, args.salt, args.dump_ip_map,
                        sensitive_words, args.undo, as_numbers, reserved_words,
                        preserve_prefixes, preserve_addresses,
                        preserve_suffix_v4=args.preserve_host_bits,
                        preserve_suffix_v6=args.preserve_host_bits)


if __name__ == '__main__':
    main()
