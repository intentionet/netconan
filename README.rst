Netconan
========

Netconan (network configuration anonymizer) is used to anonymize sensitive network information (IP addresses, passwords, etc.) from files.

Installing netconan
===================

To install netconan, run:

``pip install netconan``

Running netconan
================

Netconan processes all files not starting with ``.`` housed in the top level of the specified input directory and saves processed files in the specified output directory.  Use the help flag ``-h`` to learn more about accepted parameters.

Anonymizing sensitive items
---------------------------

With the ``anonymizepwdandcomm`` flag (``-p``), netconan will anonymize any line matching its sensitive item regexes.  Where possible, any password, secret, or snmp community will be replaced by an arbitrary value of the same format (e.g. text, hexadecimal, ...).  In other situations, where netconan may identify a sensitive line but is not sure how to preserve all non-sensitive information, the entire line will be replaced with a generic comment indicating that line was scrubbed from the config file.

Anonymizing sensitive words
---------------------------

If the ``sensitivewords`` parameter is specified with a comma separated list of sensitive words, any occurrences of the sensitive words (case ignored) are replaced with anonymized hexadecimal strings.  If there are multiple occurrences of a sensitive word, the same anonymized value is used to replace all occurrences.

Anonymizing IP addresses
------------------------

With the ``anonymizeipaddr`` flag (``-a``), netconan will replace each IPv4 and IPv6 address with an anonymized address.  Any addresses that originally shared prefixes will share prefixes after anonymization, and IPv4 classes are preserved.

Example usage
-------------

To anonymize sensitive lines and IP addresses on all files in ``~/config`` and save the anonymized versions in ``~/anon_configs``:

``netconan -p -a -i ~/configs -o ~/anon_configs``

To anonymize sensitive lines, IP addresses, and any occurrences of ``netconanSecret`` and ``SensitiveText``:

``netconan -p -a --sensitivewords=netconanSecret,SensitiveText -i ~/configs -o ~/anon_configs``

For development/debugging purposes, ``loglevel DEBUG``, ``salt ######`` (specify salt string for consistent IP and sensitive word anonymization outputs), and ``dumpipaddrmap`` (to save original-to-anonymized IP mapping) may be set:

``netconan -p -a --sensitivewords=netconanSecret,SensitiveText -i ~/configs -o ~/anon_configs -l DEBUG -s netconanSalt1234 -d ~/ip_mapping.txt``

For development/debugging purposes, IP anonymization can be undone if the original salt value is saved.  To unanonymize IP addresses in files in the ``~/anon_configs`` directory that were anonymized with salt ``netconanSalt1234`` and save to the output directory ``~/unanon_configs``:

``netconan -i ~/anon_configs -o ~/unanon_configs -s netconanSalt1234 -u``

Updating netconan on Python Package Index
=========================================

Prerequisites
-------------

#. Make an account on `pypi <https://pypi.python.org>`_ if you do not already have one
#. Ask an existing netconan developer for maintaner access to the project on pypi
#. Install twine if you do not already have it: ``pip install twine``

Building and Uploading
----------------------

#. Make sure the version number in ``__version__.py`` is updated
#. Navigate to the root directory of the project
#. Remove previously built distributions: ``rm dist/*``
#. To build the source and wheel distributions, run: ``python setup.py sdist bdist_wheel``
#. Upload the newly generated ``.tar.gz`` and ``.whl`` files from the ``dist/`` folder: ``twine upload dist/*``
