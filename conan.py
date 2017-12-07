from sensitive_item_removal import generate_default_sensitive_item_regexes
from anonymize_files import anonymize_files_in_dir
import argparse
import os
import logging

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-i', '--inputdirectory', help='Directory containing configurtions to anonymize', default='./configs/')
    parser.add_argument('-o', '--outputdirectory', help='Directory to place anonymized configs', default='./anon_configs/')
    parser.add_argument('-p', '--anonymizepwdandcomm', help='Remove password and snmp community lines', action='store_true', default=False)
    parser.add_argument('-l', '--loglevel', help='Determines what level of logs to display (DEBUG|INFO|WARNING|ERROR|CRITICAL)',
                        choices=['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'], default='INFO')
    options = parser.parse_args()
    input_dir = options.inputdirectory
    output_dir = options.outputdirectory

    numeric_level = getattr(logging, options.loglevel.upper(), None)
    logging.basicConfig(format='%(levelname)s %(message)s', level=numeric_level)

    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    # If compiled_regexes is None, then passwd removal is skipped in anonymize_files_in_dir
    compiled_regexes = None
    if options.anonymizepwdandcomm:
        compiled_regexes = generate_default_sensitive_item_regexes()

    anonymize_files_in_dir(input_dir, output_dir, compiled_regexes)
