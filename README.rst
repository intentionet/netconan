Netconan
========

Netconan (network configuration anonymizer) anonymizes text files that contain sensitive network information.

With Netconan, a sensitive input file

.. code-block:: bash

    $ cat sensitive/cisco.cfg 
    ! This is intentionet's sensitive comment
    username admin password 7 122A001901
    enable secret 5 $1$wtHI$0rN7R8PKwC30AsCGA77vy.
    !
    tacacs-server host 1.2.3.4 key pwd1234
    ip address 10.10.20.30/24
    ip address 2001:2002::9d3b:1
    !
    route-map sea-to-lax ...
    route-map sea-to-atl ...

can be anonymized

.. code-block:: bash

    $ netconan -i sensitive -o anonymized \
        --sensitive-words intentionet,sea,lax,atl \
        --anonymize-passwords \
        --anonymize-ips 
    WARNING No salt was provided; using randomly generated "WNo5pX28MJOrqxfv"
    INFO Anonymizing cisco.cfg

to produce an output file you can feel comfortable sharing.

.. code-block:: bash

    $ cat anonymized/cisco.cfg 
    ! This is db1792's sensitive comment
    username admin password 7 09424B1D1A0A1913053E012724322D3765
    enable secret 5 $1$0000$EhfXcDfB7iiakW6mwMy1i.
    !
    tacacs-server host 7.227.130.88 key netconanRemoved2
    ip address 10.72.218.183/24
    ip address cd7e:83e:1eaf:2ada:7535:591e:6d47:a4b8
    !
    route-map e69ceb-to-880ac2 ...
    route-map e69ceb-to-5d37ad ...

Installing Netconan
===================

Install Netconan using ``pip``:

.. code-block:: bash

    $ pip install netconan

Features
========

Netconan can anonymize *many types of sensitive information*:

* Sensitive strings like passwords or SNMP community strings (``--anonymize-passwords``, ``-p``), for many common network vendors.
* IPv4 and IPv6 addresses (``--anonymize-ips``, ``-a``).
* User-specified sensitive words (``--sensitive-words``, ``-w``).  *Note that any occurrence of a specified sensitive word will be replaced regardless of context, even if it is part of a larger string.*
* User-specified AS numbers (``--as-numbers``, ``-n``).  *Note that any number matching a specified AS number will be anonymized.*


Netconan attempts to *preserve useful structure*. For example,

* Netconan preserves prefixes when anonymizing IPv4 and IPv6 addresses: IP addresses with a common prefix before anonymization will share the same prefix length after anonymization. For more information, see J. Xu et al., *On the Design and Performance of Prefix-Preserving IP Traffic Trace Anonymization*, ACM SIGCOMM Workshop on Internet Measurement, 2001 [`link <https://smartech.gatech.edu/bitstream/handle/1853/6573/GIT-CC-01-22.pdf>`_].

* IPv4 classes and private-use prefixes (see `IANA IPv4 assignments <https://www.iana.org/assignments/iana-ipv4-special-registry/iana-ipv4-special-registry.xhtml>`_) are preserved by default, but can be overriden (with ``--preserve-prefixes`` e.g. ``--preserve-prefixes 12.0.0.0/8`` will preserve a leading octet ``12`` of IP addresses encountered but anonymize octets after the ``12``).

* Specific addresses can optionally be preserved, e.g.

  - ``--preserve-addresses`` skips anonymizing the specified network or address e.g. ``--preserve-addresses 12.0.0.0/8,13.12.11.10`` will skip anonymization for any address in the ``12.0.0.0/8`` network and skip anonymizing ``13.12.11.10``.

  - ``--preserve-private-addresses`` skips anonymizing addresses that fall under private-use blocks.

* AS number blocks are preserved (i.e. an anonymized public AS number will still be in the public AS number range after anonymization).

* Standard password and hash formats (salted md5, Cisco Type 7, Juniper Type 9) are recognized and substituted with format-compliant replacements.

Netconan is *deterministic* when provided the same user-controllable salt (``--salt``, ``-s``). Files processed using the same salt are compatible (e.g., IP addresses anonymized the same way) whether anonymized together or separately.

For *reversible operations* (specifically, IP address anonymization), Netconan can produce a de-anonymized file (``--undo``, ``-u``) when provided with the same salt used in anonymization (``--salt``, ``-s``).

Running netconan
================

Netconan processes the ``input`` file or recursively processes files in the ``input`` directory (skipping files starting with ``.``) and saves processed files at the specified ``output``.

For more information about less commonly-used features, see the Netconan help (``-h``).  For more information on config file syntax, see `here <https://goo.gl/R74nmi>`_.

.. code-block:: bash

    usage: netconan [-h] [-a] [-c CONFIG] [-d DUMP_IP_MAP] -i INPUT
                    [-l {DEBUG,INFO,WARNING,ERROR,CRITICAL}] [-n AS_NUMBERS] -o
                    OUTPUT [-p] [-r RESERVED_WORDS] [-s SALT] [-u]
                    [-w SENSITIVE_WORDS] [--preserve-prefixes PRESERVE_PREFIXES]

    Args that can start with '--' can also be set in a config file (specified via
    -c). If an arg is specified in more than one place, then command line values
    override config file values which override defaults. Config file syntax
    allows: key=value, flag=true, stuff=[a,b,c] (for more details, see here
    https://goo.gl/R74nmi).

    optional arguments:
      -h, --help            show this help message and exit
      -a, --anonymize-ips   Anonymize IP addresses
      -c CONFIG, --config CONFIG
                            Netconan configuration file with defaults for these
                            CLI parameters
      -d DUMP_IP_MAP, --dump-ip-map DUMP_IP_MAP
                            Dump IP address anonymization map to specified file
      -i INPUT, --input INPUT
                            Input file or directory containing files to anonymize
      -l {DEBUG,INFO,WARNING,ERROR,CRITICAL}, --log-level {DEBUG,INFO,WARNING,ERROR,CRITICAL}
                            Determines what level of logs to display
      -n AS_NUMBERS, --as-numbers AS_NUMBERS
                            List of comma separated AS numbers to anonymize
      -o OUTPUT, --output OUTPUT
                            Output file or directory where anonymized files are
                            placed
      -p, --anonymize-passwords
                            Anonymize password and snmp community lines
      -r RESERVED_WORDS, --reserved-words RESERVED_WORDS
                            List of comma separated words that should not be
                            anonymized
      -s SALT, --salt SALT  Salt for IP and sensitive keyword anonymization
      -u, --undo            Undo reversible anonymization (must specify salt)
      -w SENSITIVE_WORDS, --sensitive-words SENSITIVE_WORDS
                            List of comma separated keywords to anonymize
      --preserve-prefixes PRESERVE_PREFIXES
                            List of comma separated IP prefixes to preserve.
                            Specified prefixes are preserved, but the host bits
                            within those prefixes are still anonymized. To
                            preserve prefixes and host bits in specified blocks,
                            use --preserve-addresses instead
      --preserve-addresses PRESERVE_ADDRESSES
                            List of comma separated IP addresses or networks to
                            preserve. Prefixes and host bits within those networks
                            are preserved. To preserve just prefixes and anonymize
                            host bits, use --preserve-prefixes
      --preserve-private-addresses
                            Preserve private-use IP addresses. Prefixes and host
                            bits within the private-use IP networks are preserved.
                            To preserve specific addresses or networks, use
                            --preserve-addresses instead. To preserve just
                            prefixes and anonymize host bits, use --preserve-
                            prefixes
