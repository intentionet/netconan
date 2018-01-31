# conan
Configuration Anonymizer

## Installing conan
In the directory with setup.py, run:

`pip install .`

## Running conan
Conan processes all files not starting with `.` housed in the top level of the specified input directory and saves processed files in the specified output directory.  Use the help flag `-h` to learn more about accepted parameters.

### Anonymizing sensitive items
With the `anonymizepwdandcomm` flag (`-p`), conan will anonymize any line matching its sensitive item regexes.  Where possible, any password, secret, or snmp community will be replaced by an arbitrary value of the same format (e.g. text, hexadecimal, ...).  In other situations, where conan may identify a sensitive line but is not sure how to preserve all non-sensitive information, the entire line will be replaced with a generic comment indicating that line was scrubbed from the config file.

### Anonymizing sensitive words
If the `sensitivewords` parameter is specified with a comma separated list of sensitive words, any occurrences of the sensitive words (case ignored) are replaced with anonymized hexadecimal strings.  If there are multiple occurrences of a sensitive word, the same anonymized value is used to replace all occurrences.

### Anonymizing IP addresses
With the `anonymizeipaddr` flag (`-a`), conan will replace all IPv4 addresses that do not look like masks with an anonymized IPv4 address.  Any addresses that originally shared prefixes will share prefixes after anonymization, and IP classes are preserved.

### Example usage
To anonymize sensitive lines and IP addresses on all configs in `~/config` and save the anonymized versions in `~/anon_configs`:

`conan -p -a -i ~/configs -o ~/anon_configs`

To anonymize sensitive lines, IP addresses, and any occurrences of `ConanSecret` and `SensitiveText`:

`conan -p -a --sensitivewords=ConanSecret,SensitiveText -i ~/configs -o ~/anon_configs`

For development/debugging purposes, `loglevel DEBUG`, `salt ######` (specify salt string for consistent IP and sensitive word anonymization outputs), and `dumpipaddrmap` (to save original-to-anonymized IP mapping) may be set:

`conan -p -a --sensitivewords=ConanSecret,SensitiveText -i ~/configs -o ~/anon_configs -l DEBUG -s ConanSalt1234 -d ~/ip_mapping.txt`

For development/debugging purposes, IP anonymization can be undone if the original salt value is saved.  To unanonymize IP addresses in files in the `~/anon_configs` directory that were anonymized with salt `ConanSalt1234` and save to the output directory `~/unanon_configs`:

`conan -i ~/anon_configs -o ~/unanon_configs -s ConanSalt1234 -u`
