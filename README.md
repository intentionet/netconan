# conan
Configuration Anonymizer

## Installing conan
In the directory with setup.py, run:

`pip install .`

## Running conan
Conan processes all files not starting with `.` housed in the top level of the specified input directory and saves processed files in the specified output directory.  Use the help flag `-h` to learn more about accepted parameters.

### Anonymizing sensitive items
With the `anonymizepwdandcomm` flag (`-p`), conan will anonymize any line matching its sensitive item regexes.  Where possible, any password, secret, or snmp community will be replaced by an arbitrary value of the same format (e.g. text, hexadecimal, ...).  In other situations, where conan may identify a sensitive line but is not sure how to preserve all non-sensitive information, the entire line will be replaced with a generic comment indicating that line was scrubbed from the config file.

### Anonymizing IP addresses
With the `anonymizeipaddr` flag (`-a`), conan will replace all IPv4 addresses that do not look like masks with a randomly generated IPv4 address.  Any addresses that originally shared prefixes will share prefixes after anonymization.

### Example usage
To anonymize sensitive lines and IP addresses on all configs in `~/config` and save the anonymized versions in `~/anon_configs`:

`conan -p -a -i ~/configs -o ~/anon_configs`

For development/debugging purposes, `loglevel DEBUG`, `randomseed ######` (for consistent anonymization outputs), and `dumpipaddrmap` (to save original-to-anonymized IP mapping) may be set:

`conan -p -a -i ~/configs -o ~/anon_configs -l DEBUG -r 4913368284060515126 -d ~/ip_mapping.txt`
