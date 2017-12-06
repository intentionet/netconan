# conan
Configuration anonymizer

## Running conan
Conan processes all .cfg files housed in the top level of the specified input directory and saves processed .cfg files in the specified output directory.  Use the help flag `-h` to learn more about accepted parameters.

### Removing sensitive lines from config files
With the `anonymizepwdandcomm` flag (`-p`), conan will replace any line matching its password and community regexes with a comment indicating that line was scrubbed from the config file.

Example usage: `python conan.py -p -i ~/configs -o ~/anon_configs`
