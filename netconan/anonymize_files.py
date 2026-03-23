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
import sys
from collections.abc import Sequence
from typing import IO

from .default_reserved_words import default_reserved_words
from .ip_anonymization import IpAnonymizer, IpV6Anonymizer, anonymize_ip_addr
from .sensitive_item_removal import (
    AsNumberAnonymizer,
    CompiledRegexRule,
    SensitiveWordAnonymizer,
    anonymize_as_numbers,
    generate_default_sensitive_item_regexes,
    replace_matching_item,
)

_DEFAULT_SALT_LENGTH = 16
_CHAR_CHOICES = string.ascii_letters + string.digits


class FileAnonymizer:
    """Class that handles anonymization of files and corresponding configuraiton."""

    def __init__(
        self,
        anon_pwd: bool,
        anon_ip: bool,
        salt: str | None = None,
        sensitive_words: Sequence[str] | None = None,
        undo_ip_anon: bool = False,
        as_numbers: Sequence[str] | None = None,
        reserved_words: Sequence[str] | None = None,
        preserve_prefixes: Sequence[str] | None = None,
        preserve_networks: Sequence[str] | None = None,
        preserve_suffix_v4: int | None = None,
        preserve_suffix_v6: int | None = None,
    ) -> None:
        """Creates anonymizer classes."""
        self.undo_ip_anon = undo_ip_anon

        self.anonymizer4: IpAnonymizer | None = None
        self.anonymizer6: IpV6Anonymizer | None = None
        self.anonymizer_as_num: AsNumberAnonymizer | None = None
        self.anonymizer_sensitive_word: SensitiveWordAnonymizer | None = None
        self.compiled_regexes: list[list[CompiledRegexRule]] | None = None
        self.pwd_lookup: dict[str, str] | None = None

        # The salt is only used for IP and sensitive word anonymization
        if salt is None:
            salt = "".join(
                random.choice(_CHAR_CHOICES) for _ in range(_DEFAULT_SALT_LENGTH)
            )
            logging.warning('No salt was provided; using randomly generated "%s"', salt)
        self.salt: str = salt
        logging.debug('Using salt: "%s"', self.salt)

        if anon_pwd:
            self.compiled_regexes = generate_default_sensitive_item_regexes()
            self.pwd_lookup = {}
        if reserved_words is not None:
            default_reserved_words.update(reserved_words)
        if sensitive_words is not None:
            self.anonymizer_sensitive_word = SensitiveWordAnonymizer(
                sensitive_words, self.salt
            )
        if anon_ip or undo_ip_anon:
            self.anonymizer4 = IpAnonymizer(
                self.salt,
                preserve_prefixes,
                preserve_networks,
                preserve_suffix=preserve_suffix_v4,
            )
            self.anonymizer6 = IpV6Anonymizer(
                self.salt, preserve_suffix=preserve_suffix_v6
            )
        if as_numbers is not None:
            self.anonymizer_as_num = AsNumberAnonymizer(as_numbers, self.salt)

    def anonymize_io(self, in_io: IO[str], out_io: IO[str]) -> None:
        """Reads from the in_io buffer, writing anonymized configuration into the out_io buffer.

        Both in_io and out_io can either be
        - an actual file (`io.TextIOWrapper` as returned by 'open')
        - in memory (`io.StringIO`)
        """
        for line in in_io.readlines():
            output_line = line
            if self.compiled_regexes is not None and self.pwd_lookup is not None:
                output_line = replace_matching_item(
                    self.compiled_regexes, output_line, self.pwd_lookup, self.salt
                )

            if self.anonymizer6 is not None:
                output_line = anonymize_ip_addr(
                    self.anonymizer6, output_line, self.undo_ip_anon
                )
            if self.anonymizer4 is not None:
                output_line = anonymize_ip_addr(
                    self.anonymizer4, output_line, self.undo_ip_anon
                )

            if self.anonymizer_sensitive_word is not None:
                output_line = self.anonymizer_sensitive_word.anonymize(output_line)

            if self.anonymizer_as_num is not None:
                output_line = anonymize_as_numbers(self.anonymizer_as_num, output_line)

            if line != output_line:
                logging.debug("Input line:  %s", line.rstrip())
                logging.debug("Output line: %s", output_line.rstrip())
            out_io.write(output_line)


def anonymize_files(
    input_path: str,
    output_path: str,
    anon_pwd: bool,
    anon_ip: bool,
    salt: str | None = None,
    dumpfile: str | None = None,
    sensitive_words: Sequence[str] | None = None,
    undo_ip_anon: bool = False,
    as_numbers: Sequence[str] | None = None,
    reserved_words: Sequence[str] | None = None,
    preserve_prefixes: Sequence[str] | None = None,
    preserve_networks: Sequence[str] | None = None,
    preserve_suffix_v4: int | None = None,
    preserve_suffix_v6: int | None = None,
) -> None:
    """Anonymize each file in input and save to output."""
    use_stdin = input_path == "-"
    use_stdout = output_path == "-"

    if not use_stdin and not os.path.exists(input_path):
        raise ValueError("Input does not exist")

    # Build list of (input, output) pairs to process.
    # Pipe paths use "-" as a sentinel for stdin/stdout.
    if use_stdin or os.path.isfile(input_path):
        file_list = [(input_path, output_path)]
    elif use_stdout:
        raise ValueError(
            "Cannot write directory output to stdout; "
            "use a file input with -o - or specify an output directory"
        )
    else:
        if not os.listdir(input_path):
            raise ValueError("Input directory is empty")
        if os.path.isfile(output_path):
            raise ValueError(
                "Output path must be a directory if input path is a directory"
            )
        file_list = []
        for root, dirs, files in os.walk(input_path):
            rel_root = os.path.relpath(root, input_path)
            file_list.extend(
                [
                    (
                        os.path.join(input_path, rel_root, f),
                        os.path.join(output_path, rel_root, f),
                    )
                    for f in files
                    if not f.startswith(".")
                ]
            )

    file_anonymizer = FileAnonymizer(
        anon_ip=anon_ip,
        anon_pwd=anon_pwd,
        as_numbers=as_numbers,
        preserve_networks=preserve_networks,
        preserve_prefixes=preserve_prefixes,
        preserve_suffix_v4=preserve_suffix_v4,
        preserve_suffix_v6=preserve_suffix_v6,
        reserved_words=reserved_words,
        salt=salt,
        sensitive_words=sensitive_words,
        undo_ip_anon=undo_ip_anon,
    )

    for in_path, out_path in file_list:
        logging.debug("File in  %s", in_path)
        logging.debug("File out %s", out_path)
        try:
            _process_one(file_anonymizer, in_path, out_path)
        except Exception:
            logging.error("Failed to anonymize file %s", in_path, exc_info=True)

    if dumpfile is not None:
        # dumpfile requires anon_ip, which guarantees both anonymizers exist
        assert file_anonymizer.anonymizer4 is not None
        assert file_anonymizer.anonymizer6 is not None
        with open(dumpfile, "w") as f_out:
            file_anonymizer.anonymizer4.dump_to_file(f_out)
            file_anonymizer.anonymizer6.dump_to_file(f_out)


def _process_one(file_anonymizer: FileAnonymizer, in_path: str, out_path: str) -> None:
    """Anonymize a single input/output pair. A path of "-" means stdin/stdout."""
    use_stdin = in_path == "-"
    use_stdout = out_path == "-"

    if not use_stdout:
        _mkdirs(out_path)
        if os.path.isdir(out_path):
            raise ValueError(
                "Cannot write output file; "
                "output file is a directory ({})".format(out_path)
            )

    in_io: IO[str] = sys.stdin if use_stdin else open(in_path, "r")
    out_io: IO[str] = sys.stdout if use_stdout else open(out_path, "w")
    try:
        file_anonymizer.anonymize_io(in_io, out_io)
    finally:
        if not use_stdin:
            in_io.close()
        if not use_stdout:
            out_io.close()


def _mkdirs(file_path: str) -> None:
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
