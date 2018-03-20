"""Anonymize configuration file(s)."""
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
import logging
import os
import random
import string

from .ip_anonymization import (
    IpAnonymizer, IpV6Anonymizer, anonymize_ip_addr)
from .sensitive_item_removal import (
    anonymize_as_numbers, anonymize_sensitive_words, AsNumberAnonymizer, replace_matching_item,
    generate_default_sensitive_item_regexes, generate_sensitive_word_regexes)

_DEFAULT_SALT_LENGTH = 16
_CHAR_CHOICES = string.ascii_letters + string.digits


def anonymize_files_in_dir(input_dir_path, output_dir_path, anon_pwd, anon_ip,
                           salt=None, dumpfile=None, sensitive_words=None,
                           undo_ip_anon=False, as_numbers=None):
    """Anonymize each file in input directory and save to output directory."""
    anonymizer4 = None
    anonymizer6 = None
    anonymizer_as_num = None
    compiled_regexes = None
    pwd_lookup = None
    sensitive_word_regexes = None
    # The salt is only used for IP and sensitive word anonymization:
    if salt is None:
        salt = ''.join(random.choice(_CHAR_CHOICES) for _ in range(_DEFAULT_SALT_LENGTH))
        logging.warning('No salt was provided; using randomly generated "%s"', salt)
    logging.debug('Using salt: "%s"', salt)
    if anon_pwd:
        compiled_regexes = generate_default_sensitive_item_regexes()
        pwd_lookup = {}
    if sensitive_words is not None:
        sensitive_word_regexes = generate_sensitive_word_regexes(sensitive_words)
    if anon_ip or undo_ip_anon:
        anonymizer4 = IpAnonymizer(salt)
        anonymizer6 = IpV6Anonymizer(salt)
    if as_numbers is not None:
        anonymizer_as_num = AsNumberAnonymizer(as_numbers, salt)

    for file_name in os.listdir(input_dir_path):
        input_file = os.path.join(input_dir_path, file_name)
        output_file = os.path.join(output_dir_path, file_name)
        if os.path.isfile(input_file) and not file_name.startswith('.'):
            logging.info("Anonymizing %s", file_name)
            anonymize_file(input_file, output_file, salt,
                           compiled_regexes=compiled_regexes,
                           pwd_lookup=pwd_lookup,
                           sensitive_word_regexes=sensitive_word_regexes,
                           anonymizer_as_num=anonymizer_as_num,
                           undo_ip_anon=undo_ip_anon,
                           anonymizer4=anonymizer4,
                           anonymizer6=anonymizer6)

    if dumpfile is not None:
        with open(dumpfile, 'w') as f_out:
            anonymizer4.dump_to_file(f_out)
            anonymizer6.dump_to_file(f_out)


def anonymize_file(filename_in, filename_out, salt, compiled_regexes=None,
                   anonymizer4=None, anonymizer6=None, pwd_lookup=None,
                   sensitive_word_regexes=None, anonymizer_as_num=None,
                   undo_ip_anon=False):
    """Anonymize contents of input file and save to the output file.

    This only applies sensitive line removal if compiled_regexes and pwd_lookup
    are not None.  This only applies ip anonymization if anonymizer is not None.
    """
    logging.debug("File in  %s", filename_in)
    logging.debug("File out %s", filename_out)
    with open(filename_out, 'w') as f_out, open(filename_in, 'r') as f_in:
        for line in f_in:
            output_line = line
            if compiled_regexes is not None and pwd_lookup is not None:
                output_line = replace_matching_item(compiled_regexes,
                                                    output_line, pwd_lookup)

            if anonymizer6 is not None:
                output_line = anonymize_ip_addr(anonymizer6, output_line, undo_ip_anon)
            if anonymizer4 is not None:
                output_line = anonymize_ip_addr(anonymizer4, output_line, undo_ip_anon)

            if sensitive_word_regexes is not None:
                output_line = anonymize_sensitive_words(sensitive_word_regexes,
                                                        output_line, salt)

            if anonymizer_as_num is not None:
                output_line = anonymize_as_numbers(anonymizer_as_num, output_line)

            if line != output_line:
                logging.debug("Input line:  %s", line.rstrip())
                logging.debug("Output line: %s", output_line.rstrip())
            f_out.write(output_line)
