"""Anonymize configuration file(s)."""

from __future__ import absolute_import
import logging
import os
import random
import string

from conan.ip_anonymization import tree_node, anonymize_ip_addr
from conan.sensitive_item_removal import anonymize_sensitive_words, \
    replace_matching_item, generate_default_sensitive_item_regexes

_DEFAULT_SALT_LENGTH = 16


def anonymize_files_in_dir(input_dir_path, output_dir_path, anon_pwd, anon_ip,
                           salt=None, iptree_filename=None, sensitive_words=None):
    """Anonymize each file in input directory and save to output directory."""
    compiled_regexes = None
    ip_tree = None
    pwd_lookup = None
    if anon_pwd:
        compiled_regexes = generate_default_sensitive_item_regexes()
        pwd_lookup = {}
    if anon_ip:
        ip_tree = tree_node(None)
        ip_tree.preserve_ipv4_class()
    # The salt is only used for IP and sensitive word anonymization:
    if salt is None:
        char_choices = string.ascii_letters + string.digits
        salt = ''.join(random.choice(char_choices) for i in range(_DEFAULT_SALT_LENGTH))
    logging.debug('Using random salt: "{}"'.format(salt))

    for file_name in os.listdir(input_dir_path):
        input_file = os.path.join(input_dir_path, file_name)
        output_file = os.path.join(output_dir_path, file_name)
        if os.path.isfile(input_file) and not file_name.startswith('.'):
            logging.info("Anonymizing {}".format(file_name))
            anonymize_file(input_file, output_file, salt, compiled_regexes,
                           ip_tree, pwd_lookup, sensitive_words)

    if iptree_filename is not None:
        with open(iptree_filename, 'w') as f_out:
            ip_tree.dump_to_file(f_out)


def anonymize_file(filename_in, filename_out, salt, compiled_regexes=None,
                   ip_tree=None, pwd_lookup=None, sensitive_words=None):
    """Anonymize contents of input file and save to the output file.

    This only applies sensitive line removal if compiled_regexes and pwd_lookup
    are not None.  This only applies ip anonymization if ip_tree is not None.
    """
    logging.debug("File in  {}".format(filename_in))
    logging.debug("File out {}".format(filename_out))
    with open(filename_out, 'w') as f_out, open(filename_in, 'r') as f_in:
        for line in f_in:
            output_line = line
            if compiled_regexes is not None and pwd_lookup is not None:
                output_line = replace_matching_item(compiled_regexes,
                                                    output_line, pwd_lookup)
            if ip_tree is not None:
                output_line = anonymize_ip_addr(ip_tree, output_line, salt)
            if sensitive_words is not None:
                output_line = anonymize_sensitive_words(sensitive_words,
                                                        output_line, salt)
            if line != output_line:
                logging.debug("Input line:  {}".format(line.rstrip()))
                logging.debug("Output line: {}".format(output_line.rstrip()))
            f_out.write(output_line)
