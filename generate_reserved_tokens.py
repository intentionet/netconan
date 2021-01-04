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
import regex
import argparse

DEFAULT_PREFIX = "    "
TOKEN_REGEX = regex.compile(r"'([^']+)'=\d+")


def get_token(line):
    """Return the token from the specified line. If no token is found, returns None."""
    match = TOKEN_REGEX.match(line)
    if match:
        return match.group(1).lower()
    return None


def write_tokens_to_file(filename, token_set, prefix):
    """Write specified token set to the specified file.

    Each token is quote enclosed on a separate line with specified prefix prepended."""
    with open(filename, 'w') as file:
        for token in sorted(token_set):
            file.write('{}"{}",\n'.format(prefix, token))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Generate list of reserved words/tokens for Netconan to ignore, from Batfish token files."
    )

    parser.add_argument(
        "--token-dir",
        required=True,
        help="Path to directory containing Batfih token files (e.g. `<batfish_repo_root>/projects/batfish/target/generated-sources/antlr4`).",
    )
    parser.add_argument(
        "--output", required=True,
        help="Path to output file."
    )
    parser.add_argument(
        "--prefix",
        default=DEFAULT_PREFIX,
        help="Prefix to append to each token line.",
    )
    args = parser.parse_args()

    tokens = set()
    for file_name in os.listdir(args.token_dir):
        input_file = os.path.join(args.token_dir, file_name)
        if os.path.isfile(input_file):
            with open(input_file, 'r') as f_in:
                for line in f_in:
                    token = get_token(line)
                    if token:
                        tokens.add(token)
    write_tokens_to_file(args.output, tokens, args.prefix)
