"""Test removal of passwords and snmp communities."""

from conan.sensitive_item_removal import replace_matching_item, generate_default_sensitive_item_regexes

# Tuple format is config_line, sensitive_text (should not be in output line)
# TODO: Add in additional test lines (these are just first pass from IOS)
cisco_password_lines = [
    (' password 0 RemoveMe', 'RemoveMe'),
    (' password 7 122A00190102180D3C2E', '122A00190102180D3C2E'),
    ('username Someone password 0 RemoveMe', 'RemoveMe'),
    ('username Someone password RemoveMe', 'RemoveMe'),
    ('username Someone password 7 122A00190102180D3C2E', '122A00190102180D3C2E'),
    ('enable password level 12 RemoveMe', 'RemoveMe'),
    ('enable password 7 122A00190102180D3C2E', '122A00190102180D3C2E'),
    ('enable secret 5 $1$wtHI$0rN7R8PKwC30AsCGA77vy.', '$1$wtHI$0rN7R8PKwC30AsCGA77vy.'),
    ('username Someone view Someview password 7 122A00190102180D3C2E', '122A00190102180D3C2E'),
    ('username Someone password RemoveMe', 'RemoveMe'),
    ('username Someone secret 5 $1$wtHI$0rN7R8PKwC30AsCGA77vy.', '$1$wtHI$0rN7R8PKwC30AsCGA77vy.'),
    ('username Someone secret RemoveMe', 'RemoveMe'),
    ('username Someone view Someview secret RemoveMe', 'RemoveMe'),
    ('ip ftp password RemoveMe', 'RemoveMe'),
    ('ip ftp password 0 RemoveMe', 'RemoveMe'),
    ('ip ftp password 7 122A00190102180D3C2E', '122A00190102180D3C2E'),
    (' ip ospf authentication-key RemoveMe', 'RemoveMe'),
    (' ip ospf authentication-key 0 RemoveMe', 'RemoveMe'),
    ('isis password RemoveMe', 'RemoveMe'),
    ('domain-password RemoveMe', 'RemoveMe'),
    ('domain-password RemoveMe authenticate snp validate', 'RemoveMe'),
    ('area-password RemoveMe authenticate snp send-only', 'RemoveMe'),
    ('ip ospf message-digest-key 123 md5 RemoveMe', 'RemoveMe'),
    ('ip ospf message-digest-key 124 md5 7 122A00190102180D3C2E', '122A00190102180D3C2E'),
    ('standby authentication RemoveMe', 'RemoveMe'),
    ('standby authentication md5 key-string RemoveMe timeout 123', 'RemoveMe'),
    ('standby authentication md5 key-string 7 122A00190102180D3C2E', 'RemoveMe'),
    ('standby authentication text RemoveMe', 'RemoveMe'),
    ('l2tp tunnel password 0 RemoveMe', 'RemoveMe'),
    ('l2tp tunnel password RemoveMe', 'RemoveMe'),
    ('digest secret RemoveMe hash MD5', 'RemoveMe'),
    ('digest secret RemoveMe', 'RemoveMe'),
    ('digest secret 0 RemoveMe', 'RemoveMe'),
    ('ppp chap password RemoveMe', 'RemoveMe'),
    ('ppp chap password 0 RemoveMe', 'RemoveMe'),
    ('ppp chap hostname RemoveMe', 'RemoveMe'),
    ('pre-shared-key RemoveMe', 'RemoveMe'),
    ('pre-shared-key 0 RemoveMe', 'RemoveMe'),
    ('pre-shared-key local 0 RemoveMe', 'RemoveMe'),
    ('pre-shared-key remote hex 1234a', '1234a'),
    ('pre-shared-key remote 6 FLgBaJHXdYY_AcHZZMgQ_RhTDJXHUBAAB', 'FLgBaJHXdYY_AcHZZMgQ_RhTDJXHUBAAB'),
    ('tacacs-server host 1.1.1.1 key RemoveMe', 'RemoveMe'),
    ('radius-server host 1.1.1.1 key 0 RemoveMe', 'RemoveMe'),
    ('tacacs-server key 7 122A00190102180D3C2E', '122A00190102180D3C2E'),
    (' key 0 RemoveMe', 'RemoveMe'),
    ('ntp authentication-key 4294967295 md5 RemoveMe', 'RemoveMe'),
    ('ntp authentication-key 123 md5 RemoveMe 1', 'RemoveMe'),
    ('syscon address 1.1.1.1 RemoveMe', 'RemoveMe'),
    ('snmp-server user Someone Somegroup remote Crap v3 auth md5 RemoveMe', 'RemoveMe'),
    ('snmp-server user Someone Somegroup v3 auth sha RemoveMe priv 3des RemoveMe', 'RemoveMe'),
    # TODO: Figure out SHA format, this line throws: Error in Auth password
    ('snmp-server user Someone Somegroup v3 encrypted auth sha RemoveMe', 'RemoveMe'),
    ('crypto isakmp key RemoveMe address 1.1.1.1 255.255.255.0', 'RemoveMe'),
    ('crypto isakmp key 6 RemoveMe hostname Something', 'RemoveMe'),
    ('set session-key inbound ah 4294967295 1234abcdef', '1234abcdef'),
    ('set session-key outbound esp 256 authenticator 1234abcdef', '1234abcdef'),
    ('set session-key outbound esp 256 cipher 1234abcdef authenticator 1234abcdef', '1234abcdef')
]

cisco_snmp_community_lines = [
    ('snmp-server community RemoveMe ro 1', 'RemoveMe'),
    ('snmp-server community RemoveMe Something', 'RemoveMe'),
    ('snmp-server host 1.1.1.1 vrf Something informs RemoveMe config', 'RemoveMe'),
    ('snmp-server host 1.1.1.1 informs version 3 auth RemoveMe ipsec', 'RemoveMe'),
    ('snmp-server host 1.1.1.1 traps version 2c noauth RemoveMe', 'RemoveMe'),
    ('snmp-server host 1.1.1.1 informs version 1 priv RemoveMe memory', 'RemoveMe'),
    ('snmp-server host 1.1.1.1 RemoveMe vrrp', 'RemoveMe')
]

# TODO: Add Juniper config lines


def test_cisco_pwd_and_com_removal():
    """Test removal of passwords and communities from Cisco style config lines."""
    regexes = generate_default_sensitive_item_regexes()

    sensitive_lines = cisco_password_lines + cisco_snmp_community_lines
    for (line, sensitive_text) in sensitive_lines:
        assert(sensitive_text not in replace_matching_item(regexes, line))

    line = 'this is a test'
    assert(line == replace_matching_item(regexes, line))
