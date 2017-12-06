from sensitive_item_removal import replace_matching_item
import logging
import os

def anonymize_files_in_dir(input_dir_path, output_dir_path, compiled_regexes=None):
    """Anonymize each file in the input directory and save to the output directory.
    This only applies sensitive line removal if compiled_regexes is not None.
    """
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
    """Anonymize contents of input file and save to the output file.
    This only applies sensitive line removal if compiled_regexes is not None.
    """
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
