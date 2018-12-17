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
import errno
import logging
import os
import random
import string

from .default_reserved_words import default_reserved_words
from .ip_anonymization import (
    IpAnonymizer, IpV6Anonymizer, anonymize_ip_addr)
from .sensitive_item_removal import (
    anonymize_as_numbers, AsNumberAnonymizer, replace_matching_item,
    SensitiveWordAnonymizer, generate_default_sensitive_item_regexes)

_DEFAULT_SALT_LENGTH = 16
_CHAR_CHOICES = string.ascii_letters + string.digits


def anonymize_files(input_path, output_path, anon_pwd, anon_ip,
                    salt=None, dumpfile=None, sensitive_words=None,
                    undo_ip_anon=False, as_numbers=None, reserved_words=None):
    """Anonymize each file in input and save to output."""
    anonymizer4 = None
    anonymizer6 = None
    anonymizer_as_num = None
    anonymizer_sensitive_word = None
    compiled_regexes = None
    pwd_lookup = None
    # The salt is only used for IP and sensitive word anonymization:
    if salt is None:
        salt = ''.join(random.choice(_CHAR_CHOICES) for _ in range(_DEFAULT_SALT_LENGTH))
        logging.warning('No salt was provided; using randomly generated "%s"', salt)
    logging.debug('Using salt: "%s"', salt)
    if anon_pwd:
        compiled_regexes = generate_default_sensitive_item_regexes()
        pwd_lookup = {}
    if reserved_words is not None:
        default_reserved_words.update(reserved_words)

    if sensitive_words is not None:
        anonymizer_sensitive_word = SensitiveWordAnonymizer(sensitive_words, salt)
    if anon_ip or undo_ip_anon:
        anonymizer4 = IpAnonymizer(salt)
        anonymizer6 = IpV6Anonymizer(salt)
    if as_numbers is not None:
        anonymizer_as_num = AsNumberAnonymizer(as_numbers, salt)

    if not os.path.exists(input_path):
        raise ValueError("Input does not exist")

    # Generate list of file tuples: (input file path, output file path)
    file_list = []
    if os.path.isfile(input_path):
        file_list = [(input_path, output_path)]
    else:
        if not os.listdir(input_path):
            raise ValueError("Input directory is empty")
        if os.path.isfile(output_path):
            raise ValueError("Output path must be a directory if input path is "
                             "a directory")

        for root, dirs, files in os.walk(input_path):
            rel_root = os.path.relpath(root, input_path)
            file_list.extend([(
                os.path.join(input_path, rel_root, f),
                os.path.join(output_path, rel_root, f)
            ) for f in files if not f.startswith('.')])

    for in_path, out_path in file_list:
        try:
            anonymize_file(in_path,
                           out_path,
                           compiled_regexes=compiled_regexes,
                           pwd_lookup=pwd_lookup,
                           anonymizer_sensitive_word=anonymizer_sensitive_word,
                           anonymizer_as_num=anonymizer_as_num,
                           undo_ip_anon=undo_ip_anon,
                           anonymizer4=anonymizer4,
                           anonymizer6=anonymizer6)
        except Exception:
            logging.error('Failed to anonymize file %s', in_path, exc_info=True)

    if dumpfile is not None:
        with open(dumpfile, 'w') as f_out:
            anonymizer4.dump_to_file(f_out)
            anonymizer6.dump_to_file(f_out)


def anonymize_file(filename_in, filename_out, compiled_regexes=None,
                   anonymizer4=None, anonymizer6=None, pwd_lookup=None,
                   anonymizer_sensitive_word=None, anonymizer_as_num=None,
                   undo_ip_anon=False):
    """Anonymize contents of input file and save to the output file.

    This only applies sensitive line removal if compiled_regexes and pwd_lookup
    are not None.  This only applies ip anonymization if anonymizer is not None.
    """
    logging.debug("File in  %s", filename_in)
    logging.debug("File out %s", filename_out)

    # Make parent dirs for output file if they don't exist
    _mkdirs(filename_out)

    if os.path.isdir(filename_out):
        raise ValueError('Cannot write output file; '
                         'output file is a directory ({})'
                         .format(filename_out))

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

            if anonymizer_sensitive_word is not None:
                output_line = anonymizer_sensitive_word.anonymize(output_line)

            if anonymizer_as_num is not None:
                output_line = anonymize_as_numbers(anonymizer_as_num, output_line)

            if line != output_line:
                logging.debug("Input line:  %s", line.rstrip())
                logging.debug("Output line: %s", output_line.rstrip())
            f_out.write(output_line)


def _mkdirs(file_path):
    """Make parent directories for the specified file if they don't exist."""
    dir_path = os.path.dirname(file_path)
    if len(dir_path) > 0:
        try:
            os.makedirs(dir_path)
        except OSError as e:
            if e.errno == errno.EEXIST and os.path.isdir(dir_path):
                pass
            else:
                raise
