"""Handle invoking Conan from the command line."""

import argparse
import logging
import os

from anonymize_files import anonymize_files_in_dir


if __name__ == '__main__':
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
    parser.add_argument('-r', '--randomseed',
                        help='Random seed for IP anonymization',
                        type=int, default=None)
    loglevel_choices = ['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL']
    parser.add_argument('-l', '--loglevel',
                        help='Determines what level of logs to display \
                        (DEBUG|INFO|WARNING|ERROR|CRITICAL)',
                        choices=loglevel_choices, default='INFO')
    options = parser.parse_args()
    input_dir = options.inputdirectory
    output_dir = options.outputdirectory

    loglevel = logging.getLevelName(options.loglevel)
    logging.basicConfig(format='%(levelname)s %(message)s', level=loglevel)

    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    # If compiled_regexes is None,
    # then passwd removal is skipped in anonymize_files_in_dir
    compiled_regexes = None

    anonymize_files_in_dir(input_dir, output_dir, options.anonymizepwdandcomm,
                           options.anonymizeipaddr, options.randomseed)
