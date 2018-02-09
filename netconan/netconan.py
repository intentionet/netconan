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

from .anonymize_files import anonymize_files_in_dir


def main(args=None):
    """Netconan tool entry point."""
    parser = argparse.ArgumentParser()
    parser.add_argument('-i', '--input-dir', required=True,
                        help='Directory containing files to anonymize')
    parser.add_argument('-o', '--output-dir', required=True,
                        help='Directory to place anonymized files')
    parser.add_argument('-p', '--anonymize-pwd',
                        help='Anonymize password and snmp community lines',
                        action='store_true', default=False)
    parser.add_argument('-a', '--anonymize-ip-addr',
                        help='Anonymize IP addresses',
                        action='store_true', default=False)
    parser.add_argument('-s', '--salt',
                        help='Salt for IP and sensitive keyword anonymization',
                        default=None)
    parser.add_argument('-d', '--dump-ip-map',
                        help='Dump IP address anonymization map to specified file',
                        default=None)
    parser.add_argument('-u', '--undo',
                        help='Undo reversible anonymization (must specify salt)',
                        action='store_true', default=False)
    parser.add_argument('-w', '--sensitive-words', help='Comma separated list of '
                        'keywords to anonymize', default=None)
    loglevel_choices = ['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL']
    parser.add_argument('-l', '--log-level',
                        help='Determines what level of logs to display',
                        choices=loglevel_choices, default='INFO')
    options = parser.parse_args(args)
    input_dir = options.input_dir
    output_dir = options.output_dir

    loglevel = logging.getLevelName(options.log_level)
    logging.basicConfig(format='%(levelname)s %(message)s', level=loglevel)

    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    sensitive_words = None
    if options.sensitive_words is not None:
        sensitive_words = options.sensitive_words.split(',')

    if options.undo:
        if options.anonymize_ip_addr:
            raise ValueError('Cannot anonymize and undo anonymization, select '
                             'only one.')
        if options.salt is None:
            raise ValueError('Salt used for anonymization must be specified in '
                             'order to undo anonymization.')

    if options.dump_ip_map is not None:
        if not options.anonymize_ip_addr:
            raise ValueError('Can only dump IP address map when anonymizing IP '
                             'addresses.')

    anonymize_files_in_dir(input_dir, output_dir, options.anonymize_pwd,
                           options.anonymize_ip_addr, options.salt,
                           options.dump_ip_map, sensitive_words,
                           options.undo)


if __name__ == '__main__':
    main()
