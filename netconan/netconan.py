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
#
#   This product uses regexes modified from RANCID, which is available under a
#   "3-clause BSD" license.  For details, see LICENSE.RANCID

from __future__ import absolute_import
import argparse
import logging
import os

from netconan.anonymize_files import anonymize_files_in_dir


def main(args=None):
    """Netconan tool entry point."""
    parser = argparse.ArgumentParser()
    parser.add_argument('-i', '--inputdirectory',
                        help='Directory containing configurtions to anonymize',
                        default='./configs/')
    parser.add_argument('-o', '--outputdirectory',
                        help='Directory to place anonymized configs',
                        default='./anon_configs/')
    parser.add_argument('-p', '--anonymizepwdandcomm',
                        help='Remove password and snmp community lines',
                        action='store_true', default=False)
    parser.add_argument('-a', '--anonymizeipaddr',
                        help='Anonymize IP addresses',
                        action='store_true', default=False)
    parser.add_argument('-s', '--salt',
                        help='Salt for IP and sensitive keyword anonymization',
                        default=None)
    parser.add_argument('-d', '--dumpipaddrmap',
                        help='Dump IP address anonymization map to specified file',
                        default=None)
    parser.add_argument('-u', '--undoanonymizeipaddr',
                        help='Undo IP address anonymization (must specify salt)',
                        action='store_true', default=False)
    parser.add_argument('--sensitivewords', help='Comma separated list of '
                        'keywords to anonymize', default=None)
    loglevel_choices = ['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL']
    parser.add_argument('-l', '--loglevel',
                        help='Determines what level of logs to display',
                        choices=loglevel_choices, default='INFO')
    options = parser.parse_args(args)
    input_dir = options.inputdirectory
    output_dir = options.outputdirectory

    loglevel = logging.getLevelName(options.loglevel)
    logging.basicConfig(format='%(levelname)s %(message)s', level=loglevel)

    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    sensitive_words = None
    if options.sensitivewords is not None:
        sensitive_words = options.sensitivewords.split(',')

    if options.undoanonymizeipaddr:
        if options.anonymizeipaddr:
            raise ValueError('Cannot anonymize and undo anonymization, select '
                             'only one.')
        if options.salt is None:
            raise ValueError('Salt used for anonymization must be specified in '
                             'order to undo anonymization.')

    if options.dumpipaddrmap is not None:
        if not options.anonymizeipaddr:
            raise ValueError('Can only dump IP address map when anonymizing IP '
                             'addresses.')

    anonymize_files_in_dir(input_dir, output_dir, options.anonymizepwdandcomm,
                           options.anonymizeipaddr, options.salt,
                           options.dumpipaddrmap, sensitive_words,
                           options.undoanonymizeipaddr)


if __name__ == '__main__':
    main()
