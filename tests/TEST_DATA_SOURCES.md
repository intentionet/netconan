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

## Multi-Vendor Sources

These repositories contain configs for multiple vendors in one place.

- [Batfish](https://github.com/batfish/batfish)
  — The single best source. Test configs for Cisco, Arista, Juniper (flat and
  hierarchical), Fortinet, Palo Alto, and more under
  `projects/batfish/src/test/resources/org/batfish/grammar/`. Hundreds of files.
- [CiscoConfParse test fixtures](https://github.com/mpenning/ciscoconfparse/tree/master/tests/fixtures/configs)
  — Parser test fixtures covering Cisco IOS/NXOS/ASA/IOS-XR, Juniper JunOS, F5,
  Arista EOS, Palo Alto, Brocade, HP, and more.
- [NTC Templates](https://github.com/networktocode/ntc-templates)
  — TextFSM templates with sample `show` command outputs for many vendors. Look
  under `tests/` for fixture data.
- [Azure VPN Config Samples](https://github.com/Azure/Azure-vpn-config-samples)
  — Microsoft-maintained. Full running configs for Cisco ASA/ISR/ASR, Juniper SRX,
  FortiGate, and others. Contains encrypted passwords and pre-shared keys.
- [Oxidized](https://github.com/ytti/oxidized)
  — RANCID replacement supporting 90+ vendor OS types. The tool itself is useful for
  collecting configs from lab devices.
- [Containerlab topologies (holo-routing)](https://github.com/holo-routing/containerlab-topologies)
  — 25+ protocol lab topologies with configs for FRRouting, Nokia SR Linux, Arista
  cEOS. Covers BGP, OSPF, IS-IS, MPLS-LDP, VRRP, and more.

## Vendor Sources

### Cisco IOS

Cisco IOS has the broadest regex coverage in netconan (75+ password patterns).

**GitHub repos:**

- [Batfish Cisco test configs](https://github.com/batfish/batfish/tree/master/projects/batfish/src/test/resources/org/batfish/grammar/cisco/testconfigs)
  — Hundreds of minimal IOS/IOS-XE configs covering edge cases.
- [CiscoConfParse test fixtures](https://github.com/mpenning/ciscoconfparse/tree/master/tests/fixtures/configs)
  — Multiple `sample_NN.ios` files with diverse IOS syntax (interfaces, routing,
  ACLs, HSRP, etc.). Also includes ASA, NXOS, IOS-XR samples.
- [tireland1985/cisco-config-examples](https://github.com/tireland1985/cisco-config-examples)
  — 5 sanitized lab configs: AP1141N, C2811-CUCME, C2911 router, C3560G L3 switch.
  Contains enable secrets, TACACS+, SNMP community strings.
- [NTC Templates](https://github.com/networktocode/ntc-templates)
  — TextFSM templates with sample `show` command outputs under `tests/`.
- [frostbits-security/ccat](https://github.com/frostbits-security/ccat)
  — Cisco Config Analysis Tool with test configs in `example/` directory.
- [bbartik/cisco-cfg](https://github.com/bbartik/cisco-cfg)
  — 6 router config files including Jinja2 templates.

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
- [HPENetworking/HPEIMCUtils — Arista sample config](https://github.com/HPENetworking/HPEIMCUtils/blob/master/DeviceAdapters/Arista%20Networks/arista%20sample%20config.txt)
  — Complete Arista config with enable secret, username admin secret, SNMP
  community strings ("public"/"private"), MLAG, VLANs, NTP, AAA.
- [networkop/arista-network-ci](https://github.com/networkop/arista-network-ci)
  — Generated configs for lab and production topologies. BGP, interfaces, VLANs,
  SVIs, route-maps. Configs intentionally contain bugs for testing Batfish.
- [arista-netdevops-community/ceos_lab_demo](https://github.com/arista-netdevops-community/ceos_lab_demo)
  — 3 cEOS startup configs for an EBGP triangle topology.
- [arista-netdevops-community/avd-evpn-webinar-june-11](https://github.com/arista-netdevops-community/avd-evpn-webinar-june-11)
  — EVPN/VXLAN fabric configs in `intended/configs/` directory.
- [Ansible Arista EOS Collection](https://github.com/ansible-collections/arista.eos)
  — Ansible modules with EOS config snippets in the docs and test fixtures.
- [JulioPDX/multi-vendor-python](https://github.com/JulioPDX/multi-vendor-python)
  — Running/startup configs from Cisco vIOS, Arista vEOS, and Aruba CX.

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
- [jcoeder/juniper-configurations](https://github.com/jcoeder/juniper-configurations)
  — 28 production-style set-style config snippets: BGP (communities, policies, bogon
  filtering), OSPF, firewall rules (QFX5100 RE protection), HA (chassis redundancy,
  MC-LAG), SRX dynamic VPN, SNMPv3, TACACS, EVPN/VXLAN, IPFIX.
- [flightlesstux/juniper-srx-config](https://github.com/flightlesstux/juniper-srx-config)
  — SRX110H-VA set-style config for VDSL2 internet connectivity. System setup,
  interfaces, security zones, NAT.

**Download example (jcoeder):**

```bash
git clone https://github.com/jcoeder/juniper-configurations.git /tmp/juniper-configs
cp /tmp/juniper-configs/*.conf tests/test_data/juniper/
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
- [Azure VPN Config Samples — Juniper SRX](https://github.com/Azure/Azure-vpn-config-samples/tree/master/Juniper/Current/SRX)
  — Full hierarchical SRX configs for site-to-site VPNs with security zones,
  policies, IPsec, IKE. Contains `encrypted-password "$1$..."` entries.
- [jtkristoff/junos](https://github.com/jtkristoff/junos)
  — 10+ hierarchical config templates: BFD, BGP Monitoring Protocol, firewall
  filters, iBGP, route origin validation, BGP route sanitization.
- [codeout/junoser](https://github.com/codeout/junoser)
  — PEG parser for JunOS configs with test fixtures in both set and hierarchical
  format.

**Download example (Batfish):**

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
  — Full `show full-configuration` output from a FortiGate device. Contains
  `set password ENC SH2...` and `set psksecret ENC ...` entries.
- [Batfish Fortinet test configs](https://github.com/batfish/batfish/tree/master/projects/batfish/src/test/resources/org/batfish/grammar/fortios/testconfigs)
  — FortiOS test configs in the Batfish grammar suite.
- [vansteenk/FortiLab-VPN-IPSEC](https://github.com/vansteenk/FortiLab-VPN-IPSEC)
  — Lab environment with complete FortiGate `.conf` backup files. Contains VPN
  IPsec phase1 configs with PSK, admin passwords (ENC format), user credentials,
  certificate private keys.
- [fortinet/fortigate-terraform-deploy](https://github.com/fortinet/fortigate-terraform-deploy)
  — Terraform deployment templates with FortiGate configs. See
  `aws/6.2/ha/config-active.conf` for HA example.
- [cgustave/fgtconfig](https://github.com/cgustave/fgtconfig)
  — FortiGate configuration analysis tool, may contain test fixture configs.

**Download example (Azure VPN samples):**

```bash
curl -o tests/test_data/fortinet/fortigate_full.txt \
  "https://raw.githubusercontent.com/Azure/Azure-vpn-config-samples/master/Fortinet/Current/fortigate_show%20full-configuration.txt"
```

**Download example (FortiLab):**

```bash
git clone https://github.com/vansteenk/FortiLab-VPN-IPSEC.git /tmp/fortilab
cp /tmp/fortilab/*.conf tests/test_data/fortinet/
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
- [PackeTsar/AWS_IPv6_VPN](https://github.com/PackeTsar/AWS_IPv6_VPN)
  — Guide for building IPv6 site-to-site VPN to AWS with IKEv1 pre-shared-key
  config examples.
- [cloudposse/terraform-aws-vpn-connection](https://github.com/cloudposse/terraform-aws-vpn-connection)
  — Terraform module supporting `tunnel1_preshared_key` / `tunnel2_preshared_key`.
- [asantos2000/aws_vpn_config](https://github.com/asantos2000/aws_vpn_config)
  — Tool to download VPN configs from AWS and convert to vendor-specific formats.
  Uses `describe_vpn_connections` API to get the XML.
- [Azure VPN Config Samples — Cisco ASA](https://github.com/Azure/Azure-vpn-config-samples/tree/master/Cisco/Current/ASA)
  — ASA running-config with `ikev1 pre-shared-key` entries; useful for testing
  Cisco VPN pre-shared key regexes too.

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

**GitHub repos:**

- [LibreNMS — SNMP Configuration Examples](https://github.com/librenms/librenms/blob/master/doc/Support/SNMP-Configuration-Examples.md)
  — Comprehensive multi-vendor SNMP guide covering Cisco (ASA, IOS), Juniper,
  Extreme, Linux, Windows. Uses placeholders like `<YOUR-COMMUNITY>`.
- [JunOS SNMPv3 example (Gist)](https://gist.github.com/rendoaw/541c41527d9c576305dd)
  — Complete Juniper JunOS SNMPv3 config with `## SECRET-DATA` markers, MD5/SHA
  auth, DES/AES128 privacy, community strings.
- [jcoeder/juniper-configurations](https://github.com/jcoeder/juniper-configurations)
  — Includes SNMPv3 set-style config snippets among its 28 files.
- [net-snmp/net-snmp — EXAMPLE.conf](https://github.com/net-snmp/net-snmp/blob/master/EXAMPLE.conf.def)
  — Example `snmpd.conf` with community string configuration.
- [colin-mccarthy/ansible-playbooks-for-cisco-ios](https://github.com/colin-mccarthy/ansible-playbooks-for-cisco-ios)
  — SNMP configuration playbooks with `snmp-server` command examples.

**Vendor docs:**

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

## Automated Testing

An automated download script and integration test suite are provided to streamline
testing against real-world configs.

### Downloading configs

```bash
# Download all vendors
python tools/download_test_configs.py

# Download specific vendors only
python tools/download_test_configs.py --vendors cisco arista

# Force re-download (overwrite existing)
python tools/download_test_configs.py --force
```

Configs are downloaded into `tests/test_data/{vendor}/{source}/`. The directory is
git-ignored so downloaded configs are never committed.

**Current sources (7 across 5 vendors):**

| Vendor | Source | Method | Files |
|--------|--------|--------|-------|
| cisco | batfish | git sparse | Cisco IOS/IOS-XE test configs |
| cisco | ciscoconfparse | git sparse | `*.ios` parser test fixtures |
| arista | batfish | git sparse | Arista EOS test configs |
| juniper_flat | jcoeder | git clone | 28 production-style set-style snippets |
| juniper_hierarchical | batfish | git sparse | Hierarchical (brace-style) Juniper configs |
| fortinet | batfish | git sparse | FortiOS test configs |
| fortinet | azure | curl | FortiGate `show full-configuration` |

### Running integration tests

```bash
# Run integration tests (skips if test_data/ not present)
python -m pytest tests/integration/test_real_configs.py -v

# Run only crash tests (fastest)
python -m pytest tests/integration/test_real_configs.py -v -k test_no_crash

# Run only password anonymization checks
python -m pytest tests/integration/test_real_configs.py -v -k test_passwords_anonymized
```

The integration tests verify three things per config file:
1. **No crash** — netconan processes the file without exceptions
2. **Passwords anonymized** — if the input contains password patterns, the output differs
3. **IPs anonymized** — if the input contains IP addresses, some change in the output

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
