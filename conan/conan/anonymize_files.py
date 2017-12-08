"""Anonymize configuration file(s)."""

from sensitive_item_removal import replace_matching_item
import logging
import os


def anonymize_files_in_dir(input_dir_path,
                           output_dir_path,
                           compiled_regexes=None):
    """Anonymize each file in the input directory and save to the output directory.

    This only applies sensitive line removal if compiled_regexes is not None.
    """
    for file_name in os.listdir(input_dir_path):
        input_file = os.path.join(input_dir_path, file_name)
        output_file = os.path.join(output_dir_path, file_name)
        if os.path.isfile(input_file) and not file_name.startswith('.'):
            logging.info("Anonymizing " + file_name)
            anonymize_file(input_file, output_file, compiled_regexes)


def anonymize_file(filename_in, filename_out, compiled_regexes=None):
    """Anonymize contents of input file and save to the output file.

    This only applies sensitive line removal if compiled_regexes is not None.
    """
    logging.debug("File in " + filename_in)
    logging.debug("File out " + filename_out)
    with open(filename_out, 'w') as f_out, open(filename_in, 'r') as f_in:
        for line in f_in:
            output_line = line
            if compiled_regexes is not None:
                output_line = replace_matching_item(compiled_regexes,
                                                    output_line)
            if line != output_line:
                logging.debug("Input line:  " + line.rstrip())
                logging.debug("Output line: " + output_line.rstrip())
            f_out.write(output_line)
