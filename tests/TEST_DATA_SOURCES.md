# Test Data Sources

Where to find real-world network configuration files for testing netconan.

Netconan's regex-based anonymization works across many vendor formats. Testing against
real configs (beyond the inline test strings in `tests/unit/`) helps validate coverage
and catch edge cases.

## Directory Setup

Downloaded configs should go in `tests/test_data/`, which is git-ignored to avoid
accidentally committing sensitive material.

```bash
mkdir -p tests/test_data/{cisco,arista,juniper,fortinet,aws,snmp}
```

## Vendor Sources

### Cisco IOS

Cisco IOS has the broadest regex coverage in netconan (75+ password patterns).

**GitHub repos:**

- [Batfish Cisco test configs](https://github.com/batfish/batfish/tree/master/projects/batfish/src/test/resources/org/batfish/grammar/cisco/testconfigs)
  — Hundreds of minimal IOS/IOS-XE configs covering edge cases. Clone the repo
  and copy files from the path above.
- [NTC Templates](https://github.com/networktocode/ntc-templates)
  — TextFSM templates with sample `show` command outputs for many Cisco platforms.
  Look under `tests/` for fixture data.

**Download example (Batfish):**

```bash
git clone --depth 1 --filter=blob:none --sparse \
  https://github.com/batfish/batfish.git /tmp/batfish
cd /tmp/batfish
git sparse-checkout set projects/batfish/src/test/resources/org/batfish/grammar/cisco/testconfigs
cp projects/batfish/src/test/resources/org/batfish/grammar/cisco/testconfigs/* \
  /path/to/netconan/tests/test_data/cisco/
```

**Vendor docs:**

- [Cisco IOS-XE Configuration Guides](https://www.cisco.com/c/en/us/support/ios-nx-os-software/ios-xe-17/products-installation-and-configuration-guides-list.html)
  — Official config examples for every IOS-XE feature.

### Arista EOS

Arista EOS uses Cisco-like syntax. Netconan covers SHA-512 passwords and VRRP
authentication for EOS (see `default_pwd_regexes.py`, Issue #3 tracks expanding this).

**GitHub repos:**

- [Batfish Arista test configs](https://github.com/batfish/batfish/tree/master/projects/batfish/src/test/resources/org/batfish/grammar/arista/testconfigs)
  — Arista-specific test configs in the Batfish grammar suite.
- [Arista NetDevOps Community](https://github.com/arista-netdevops-community)
  — Multiple repos with EOS config examples and automation scripts.
- [Ansible Arista EOS Collection](https://github.com/ansible-collections/arista.eos)
  — Ansible modules with EOS config snippets in the docs and test fixtures.

**Download example (Batfish):**

```bash
git clone --depth 1 --filter=blob:none --sparse \
  https://github.com/batfish/batfish.git /tmp/batfish
cd /tmp/batfish
git sparse-checkout set projects/batfish/src/test/resources/org/batfish/grammar/arista/testconfigs
cp projects/batfish/src/test/resources/org/batfish/grammar/arista/testconfigs/* \
  /path/to/netconan/tests/test_data/arista/
```

### Juniper JunOS (Set-Style)

Set-style (`set system host-name ...`) is one of two JunOS config formats. Netconan
has strong Juniper support including Type 9 encryption handling.

**GitHub repos:**

- [Batfish Flat Juniper test configs](https://github.com/batfish/batfish/tree/master/projects/batfish/src/test/resources/org/batfish/grammar/flatjuniper/testconfigs)
  — Set-style ("flat") Juniper configs used in Batfish parsing tests.

**Download example:**

```bash
git clone --depth 1 --filter=blob:none --sparse \
  https://github.com/batfish/batfish.git /tmp/batfish
cd /tmp/batfish
git sparse-checkout set projects/batfish/src/test/resources/org/batfish/grammar/flatjuniper/testconfigs
cp projects/batfish/src/test/resources/org/batfish/grammar/flatjuniper/testconfigs/* \
  /path/to/netconan/tests/test_data/juniper/
```

**Vendor docs:**

- [Juniper TechLibrary — CLI Configuration](https://www.juniper.net/documentation/us/en/software/junos/cli/topics/topic-map/cli-configuration.html)
  — Official reference covering both set and hierarchical formats.

### Juniper JunOS (Hierarchical)

Hierarchical format uses curly braces (`system { host-name router1; }`). Both formats
should be tested since netconan's regexes may behave differently with indented blocks.

**GitHub repos:**

- [Batfish Juniper test configs](https://github.com/batfish/batfish/tree/master/projects/batfish/src/test/resources/org/batfish/grammar/juniper/testconfigs)
  — Hierarchical (brace-style) Juniper configs.

**Download example:**

```bash
git clone --depth 1 --filter=blob:none --sparse \
  https://github.com/batfish/batfish.git /tmp/batfish
cd /tmp/batfish
git sparse-checkout set projects/batfish/src/test/resources/org/batfish/grammar/juniper/testconfigs
cp projects/batfish/src/test/resources/org/batfish/grammar/juniper/testconfigs/* \
  /path/to/netconan/tests/test_data/juniper/
```

### Fortinet FortiOS

FortiOS uses `config`/`set`/`end` block syntax. Netconan has basic support for ENC
passwords and pksecret fields (4 regex patterns).

**GitHub repos:**

- [Azure VPN Config Samples — FortiGate](https://github.com/Azure/Azure-vpn-config-samples/tree/master/Fortinet/Current)
  — Full `show full-configuration` output from a FortiGate device.
- [Batfish Fortinet test configs](https://github.com/batfish/batfish/tree/master/projects/batfish/src/test/resources/org/batfish/grammar/fortios/testconfigs)
  — FortiOS test configs in the Batfish grammar suite.

**Download example (Azure VPN samples):**

```bash
curl -o tests/test_data/fortinet/fortigate_full.txt \
  "https://raw.githubusercontent.com/Azure/Azure-vpn-config-samples/master/Fortinet/Current/fortigate_show%20full-configuration.txt"
```

**Vendor docs:**

- [Fortinet Documentation Library](https://docs.fortinet.com/document/fortigate/7.6.0/administration-guide)
  — Official FortiOS administration guide with config examples.

### AWS VPN Configs

AWS VPN configs use XML (`<pre_shared_key>`) and JSON (`PreSharedKey`) formats.
Netconan has 4 regex patterns for these.

**GitHub repos:**

- [AWS VPN Gateway strongSwan](https://github.com/aws-samples/vpn-gateway-strongswan)
  — CloudFormation templates with VPN connection configs.
- [Terraform AWS VPN Gateway](https://github.com/terraform-aws-modules/terraform-aws-vpn-gateway)
  — Terraform module with VPN config examples in `examples/`.

**Vendor docs:**

- [AWS Site-to-Site VPN User Guide](https://docs.aws.amazon.com/vpn/latest/s2svpn/VPNTunnels.html)
  — Official documentation with XML/JSON config download examples.

**Creating test data manually:**

AWS VPN configs follow a predictable XML structure. A minimal test file:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<vpn_connection>
  <ipsec_tunnel>
    <ike>
      <pre_shared_key>ExamplePreSharedKey123</pre_shared_key>
    </ike>
  </ipsec_tunnel>
</vpn_connection>
```

### SNMP Configs

SNMP community strings and SNMPv3 user/group definitions appear across all vendors.
Netconan covers `snmp-server community` and `snmp-server user` patterns (14+ regexes).

**Vendor docs (Cisco — most comprehensive examples):**

- [Cisco SNMPv3 Configuration Guide](https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/snmp/configuration/xe-3se/3850/snmp-xe-3se-3850-book/nm-snmp-snmpv3.html)
  — Complete SNMPv3 user/group/view config examples with all security levels.

**Creating test data manually:**

SNMP config lines follow standard patterns across vendors:

```
snmp-server community public RO
snmp-server community private RW
snmp-server group MYGROUP v3 priv read MYVIEW write MYVIEW
snmp-server user MYUSER MYGROUP v3 auth sha AuthPass123 priv aes 128 PrivPass456
```

## Using Test Data for Development

### Running netconan against downloaded configs

```bash
# Anonymize a single file
netconan -i tests/test_data/cisco/example.cfg -o /tmp/anon_output.cfg -a -p

# Anonymize a whole directory
netconan -i tests/test_data/cisco/ -o /tmp/anon_cisco/ -a -p

# Check what gets anonymized (diff original vs output)
diff tests/test_data/cisco/example.cfg /tmp/anon_output.cfg
```

### Adding configs as test fixtures

If a downloaded config exposes a bug or an unhandled pattern, add it as a test case:

1. **Extract the relevant lines** — isolate just the config lines that need testing.
2. **Add to the appropriate test** — add inline test data to
   `tests/unit/test_sensitive_item_removal.py` (for password/community patterns) or
   create a new test file.
3. **Never commit raw downloaded configs** — they may contain real credentials or
   proprietary content. Always sanitize first.

### Tips for creating test cases from real configs

- Look for lines that netconan **should** anonymize but doesn't (false negatives).
- Look for lines that netconan anonymizes **incorrectly** (false positives or mangled output).
- Juniper Type 9 encrypted passwords and Cisco Type 7 passwords are especially good
  test targets since netconan has dedicated handling for them.
- Test both `show running-config` style output and startup-config file format — some
  vendors include extra headers/timestamps that can affect regex matching.
