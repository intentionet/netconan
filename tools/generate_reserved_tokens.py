"""Script used to generate reserved words/tokens used by Netconan, from Batfish token files."""
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
import os
import re
from pathlib import Path

from rules_python.python.runfiles import runfiles

DEFAULT_PREFIX = "    "
TOKEN_REGEX = re.compile(r"'([^']+)'=\d+")
PREAMBLE = """\"\"\"Default reserved words that should not be anonymized by sensitive word anonymization.\"\"\"
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

# THIS IS AN AUTOMATICALLY GENERATED FILE. TO REGENERATE, RUN:
#
#    bazel run //tools:generate_reserved_tokens
#
# YOU MAY ALSO NEED TO UPDATE the `srcs` attribute for //tools:tokens

# These are important tokens in network device configs and should not be modified by keyword anonymization
default_reserved_words = {
"""
POSTAMBLE = "}\n"


def get_token(line):
    """Return the token from the specified line. If no token is found, returns None."""
    match = TOKEN_REGEX.match(line)
    if match:
        return match.group(1).lower()
    return None


def write_reserved_words_file(filename, token_set):
    """Writes a reserved words file with the given token set."""
    with open(filename, "w") as file:
        file.write(PREAMBLE)
        for token in sorted(token_set):
            file.write("{}'{}',\n".format(DEFAULT_PREFIX, token))
        file.write(POSTAMBLE)


if __name__ == "__main__":
    workspace_dir = os.getenv("BUILD_WORKSPACE_DIRECTORY")
    if not workspace_dir:
        raise RuntimeError("Must be run inside bazel")
    output_path = Path(workspace_dir) / "netconan" / "default_reserved_words.py"

    rf = runfiles.Create()
    tokens_path = rf.Rlocation("netconan/tools/concatenated.tokens")
    if not tokens_path:
        raise RuntimeError("Cannot resolve tokens file")

    tokens = set()
    with open(tokens_path, "r") as f_in:
        for line in f_in:
            token = get_token(line)
            if token:
                tokens.add(token)
    write_reserved_words_file(output_path, tokens)
