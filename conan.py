from sensitive_item_removal import *
import argparse
import os
import logging

def anonymize_files_in_dir(input_dir_path, output_dir_path, compiled_regexes=None):
    for cur_dir, dir_list, file_list in os.walk(input_dir_path):
        logging.debug("Input dir " + cur_dir)
        for f in file_list:
            if f.endswith(".cfg"):
                logging.info("Anonymizing " + f)
                anonymize_file(input_dir_path + "/" + f,
                                output_dir_path + "/" + f,
                                compiled_regexes)
        break
    return

def anonymize_file(filename_in, filename_out, compiled_regexes=None):
    logging.debug("File in " + filename_in)
    logging.debug("File out " + filename_out)
    with open(filename_out, 'w') as file_out:
        with open(filename_in, 'r') as file_in:
            for line in file_in:
                output_line = line
                if compiled_regexes is not None:
                    output_line = replace_matching_item(compiled_regexes, output_line)
                if line != output_line:
                    logging.debug("Input line:  " + line.rstrip())
                    logging.debug("Output line: " + output_line.rstrip())
                file_out.write(output_line)
    return

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-i', '--inputdirectory', help='Directory containing configurtions to anonymize', default='./configs/')
    parser.add_argument('-o', '--outputdirectory', help='Directory to place anonymized configs', default='./anon_configs/')
    parser.add_argument('-p', '--anonymizepwdandcomm', help='Remove password and snmp community lines', action='store_true', default=False)
    parser.add_argument('-l', '--loglevel', help='Determines what level of logs to display (DEBUG|INFO|WARNING|ERROR|CRITICAL)', default='INFO')
    options = parser.parse_args()
    input_dir = options.inputdirectory
    output_dir = options.outputdirectory

    numeric_level = getattr(logging, options.loglevel.upper(), None)
    if not isinstance(numeric_level, int):
        raise ValueError('Invalid log level: %s' % options.loglevel)
    logging.basicConfig(format='%(levelname)s %(message)s', level=numeric_level)

    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    # If compiled_regexes is None, then passwd removal is skipped in anonymize_files_in_dir
    compiled_regexes = None
    if options.anonymizepassword:
        compiled_regexes = generate_default_sensitive_item_regexes()

    anonymize_files_in_dir(input_dir, output_dir, compiled_regexes)
