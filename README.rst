Netconan
========

Netconan (network configuration anonymizer) anonymizes text files that contain sensitive network information.

With Netconan, a sensitive input file

.. code-block:: bash

    $ cat sensitive/cisco.cfg 
    ! This is intentionet's sensitive comment
    username admin password 7 122A001901
    !
    tacacs-server host 10.10.10.10 key pwd1234

can be anonymized

.. code-block:: bash

    $ netconan --sensitivewords intentionet --anonymizepwdandcomm --anonymizeipaddr -i sensitive -o anonymized
    WARNING No salt was provided; using randomly generated "WNo5pX28MJOrqxfv"
    INFO Anonymizing cisco.cfg

to produce an output file you can feel comfortable sharing.

.. code-block:: bash

    $ cat anonymized/cisco.cfg 
    ! This is db1792's sensitive comment
    username admin password 7 09424B1D1A0A1913053E012724322D3765
    !
    tacacs-server host 119.72.192.224 key netconanRemoved1

Installing Netconan
===================

Install Netconan using ``pip``:

.. code-block:: bash

    $ pip install netconan

Features
========

Netconan can anonymize *many types of sensitive information*:

* Sensitive strings like passwords or SNMP community strings (``--anonymizepwdandcomm``, ``-p``), for many common network vendors.
* IPv4 and IPv6 addresses (``--anonymizeipaddr``, ``-a``).
* User-specified sensitive words (``--sensitivewords``).

Netconan attempts to *preserve useful structure*. For example,

* Netconan preserves prefixes when anonymizing IPv4 and IPv6 addresses: IP addresses with a common prefix before anonymization will share the same prefix length after anonymization. For more information, see J. Xu et al., *On the Design and Performance of Prefix-Preserving IP Traffic Trace Anonymization*, ACM SIGCOMM Workshop on Internet Measurement, 2001 [`link <https://smartech.gatech.edu/bitstream/handle/1853/6573/GIT-CC-01-22.pdf>`_].

* IPv4 classes are preserved.

* Standard password and hash formats (salted md5, Cisco Type 7, Juniper Type 9) are recognized and substituted with format-compliant replacements.

Netconan is *deterministic* when provided the same user-controllable salt (``--salt``, ``-s``). Files processed using the same salt are compatible (e.g., IP addresses anonymized the same way) whether anonymized together or separately.

For *reversible operations* (specifically, IP address anonymization), Netconan can produce a de-anonymized file (``--undoanonymizeipaddr``, ``-u``) when provided with the same salt used in anonymization (``--salt``, ``-s``).

Running netconan
================

Netconan processes all files not starting with ``.`` housed in the top level of the specified input directory and saves processed files in the specified output directory.

For more information about less commonly-used features, see the Netconan help (``-h``).

.. code-block:: bash

    usage: netconan [-h] [-i INPUTDIRECTORY] [-o OUTPUTDIRECTORY] [-p] [-a]
                    [-s SALT] [-d DUMPIPADDRMAP] [-u]
                    [--sensitivewords SENSITIVEWORDS]
                    [-l {DEBUG,INFO,WARNING,ERROR,CRITICAL}]
    
    optional arguments:
      -h, --help            show this help message and exit
      -i INPUTDIRECTORY, --inputdirectory INPUTDIRECTORY
                            Directory containing configurtions to anonymize
      -o OUTPUTDIRECTORY, --outputdirectory OUTPUTDIRECTORY
                            Directory to place anonymized configs
      -p, --anonymizepwdandcomm
                            Remove password and snmp community lines
      -a, --anonymizeipaddr
                            Anonymize IP addresses
      -s SALT, --salt SALT  Salt for IP and sensitive keyword anonymization
      -d DUMPIPADDRMAP, --dumpipaddrmap DUMPIPADDRMAP
                            Dump IP address anonymization map to specified file
      -u, --undoanonymizeipaddr
                            Undo IP address anonymization (must specify salt)
      --sensitivewords SENSITIVEWORDS
                            Comma separated list of keywords to anonymize
      -l {DEBUG,INFO,WARNING,ERROR,CRITICAL}, --loglevel {DEBUG,INFO,WARNING,ERROR,CRITICAL}
                            Determines what level of logs to display


