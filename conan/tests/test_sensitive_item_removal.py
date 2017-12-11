"""Test removal of passwords and snmp communities."""

from conan.sensitive_item_removal import replace_matching_item, generate_default_sensitive_item_regexes
import pytest

# Tuple format is config_line, sensitive_text (should not be in output line)
# TODO: Add in additional test lines (these are just first pass from IOS)
cisco_password_lines = [
    (' password 0 {}', 'RemoveMe'),
    (' password 7 {}', '122A00190102180D3C2E'),
    ('username Someone password 0 {}', 'RemoveMe'),
    ('username Someone password {}', 'RemoveMe'),
    ('username Someone password 7 {}', '122A00190102180D3C2E'),
    ('enable password level 12 {}', 'RemoveMe'),
    ('enable password 7 {}', '122A00190102180D3C2E'),
    ('enable secret 5 {}', '$1$wtHI$0rN7R8PKwC30AsCGA77vy.'),
    ('username Someone view Someview password 7 {}', '122A00190102180D3C2E'),
    ('username Someone password {}', 'RemoveMe'),
    ('username Someone secret 5 {}', '$1$wtHI$0rN7R8PKwC30AsCGA77vy.'),
    ('username Someone secret {}', 'RemoveMe'),
    ('username Someone view Someview secret {}', 'RemoveMe'),
    ('ip ftp password {}', 'RemoveMe'),
    ('ip ftp password 0 {}', 'RemoveMe'),
    ('ip ftp password 7 {}', '122A00190102180D3C2E'),
    (' ip ospf authentication-key {}', 'RemoveMe'),
    (' ip ospf authentication-key 0 {}', 'RemoveMe'),
    ('isis password {}', 'RemoveMe'),
    ('domain-password {}', 'RemoveMe'),
    ('domain-password {} authenticate snp validate', 'RemoveMe'),
    ('area-password {} authenticate snp send-only', 'RemoveMe'),
    ('ip ospf message-digest-key 123 md5 {}', 'RemoveMe'),
    ('ip ospf message-digest-key 124 md5 7 {}', '122A00190102180D3C2E'),
    ('standby authentication {}', 'RemoveMe'),
    ('standby authentication md5 key-string {} timeout 123', 'RemoveMe'),
    ('standby authentication md5 key-string 7 {}', 'RemoveMe'),
    ('standby authentication text {}', 'RemoveMe'),
    ('l2tp tunnel password 0 {}', 'RemoveMe'),
    ('l2tp tunnel password {}', 'RemoveMe'),
    ('digest secret {} hash MD5', 'RemoveMe'),
    ('digest secret {}', 'RemoveMe'),
    ('digest secret 0 {}', 'RemoveMe'),
    ('ppp chap password {}', 'RemoveMe'),
    ('ppp chap password 0 {}', 'RemoveMe'),
    ('ppp chap hostname {}', 'RemoveMe'),
    ('pre-shared-key {}', 'RemoveMe'),
    ('pre-shared-key 0 {}', 'RemoveMe'),
    ('pre-shared-key local 0 {}', 'RemoveMe'),
    ('pre-shared-key remote hex {}', '1234a'),
    ('pre-shared-key remote 6 {}', 'FLgBaJHXdYY_AcHZZMgQ_RhTDJXHUBAAB'),
    ('tacacs-server host 1.1.1.1 key {}', 'RemoveMe'),
    ('radius-server host 1.1.1.1 key 0 {}', 'RemoveMe'),
    ('tacacs-server key 7 {}', '122A00190102180D3C2E'),
    (' key 0 {}', 'RemoveMe'),
    ('ntp authentication-key 4294967295 md5 {}', 'RemoveMe'),
    ('ntp authentication-key 123 md5 {} 1', 'RemoveMe'),
    ('syscon address 1.1.1.1 {}', 'RemoveMe'),
    ('snmp-server user Someone Somegroup remote Crap v3 auth md5 {}', 'RemoveMe'),
    ('snmp-server user Someone Somegroup v3 auth sha {0} priv 3des {0}', 'RemoveMe'),
    # TODO: Figure out SHA format, this line throws: Error in Auth password
    ('snmp-server user Someone Somegroup v3 encrypted auth sha {}', 'RemoveMe'),
    ('crypto isakmp key {} address 1.1.1.1 255.255.255.0', 'RemoveMe'),
    ('crypto isakmp key 6 {} hostname Something', 'RemoveMe'),
    ('set session-key inbound ah 4294967295 {}', '1234abcdef'),
    ('set session-key outbound esp 256 authenticator {}', '1234abcdef'),
    ('set session-key outbound esp 256 cipher {0} authenticator {0}', '1234abcdef')
]

cisco_snmp_community_lines = [
    ('snmp-server community {} ro 1', 'RemoveMe'),
    ('snmp-server community {} Something', 'RemoveMe'),
    ('snmp-server host 1.1.1.1 vrf Something informs {} config', 'RemoveMe'),
    ('snmp-server host 1.1.1.1 informs version 3 auth {} ipsec', 'RemoveMe'),
    ('snmp-server host 1.1.1.1 traps version 2c noauth {}', 'RemoveMe'),
    ('snmp-server host 1.1.1.1 informs version 1 priv {} memory', 'RemoveMe'),
    ('snmp-server host 1.1.1.1 {} vrrp', 'RemoveMe')
]

# TODO: Add Juniper config lines


@pytest.fixture(scope='module')
def regexes():
    """Compile regexes once for all tests in this module."""
    return generate_default_sensitive_item_regexes()


@pytest.mark.parametrize('config_line,sensitive_text', cisco_password_lines + cisco_snmp_community_lines)
def test_pwd_and_com_removal_cisco(regexes, config_line, sensitive_text):
    """Test removal of passwords and communities from Cisco style config lines."""
    config_line = config_line.format(sensitive_text)
    assert(sensitive_text not in replace_matching_item(regexes, config_line))


@pytest.mark.parametrize('config_line', [
                         'nothing in this string should be replaced',
                         'interface GigabitEthernet0/0',
                         'ip address 1.2.3.4 255.255.255.0'
                         ])
def test_pwd_and_com_removal_insensitive_lines(regexes, config_line):
    """Make sure benign lines are not affected by sensitive_item_removal."""
    assert(config_line == replace_matching_item(regexes, config_line))
