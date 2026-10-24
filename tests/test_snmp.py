"""SNMP credentials, host visibility and collector scope remain independent."""

import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock
from types import SimpleNamespace
import stat

from lanrith import authoritative, bindings, build, config, snmp
from lanrith.release import ReleaseError
from test_intent import minimal


HELPERS = Path(__file__).resolve().parents[1]/'mkosi/base/mkosi.extra/usr/lib/lanrith'
sys.path.insert(0, str(HELPERS))
import snmp_service
import snmp_credentials
from snmp_credentials import SNMPError


def fixture():
    value = minimal()
    value['services'] = {'dns': {'enabled': False}, 'ntp': {'enabled': False}}
    value['networks']['home']['ipv6'] = {'subnet_id': 16, 'ra': False, 'gua': False}
    value['observability'] = {'snmp': {'enabled': True, 'username': 'synthetic-monitor',
        'credential': 'monitor_user', 'clients': [{'network': 'home', 'addresses': 'fd42:1234:5678:10::50/128'}]}}
    return value


class SNMPTests(unittest.TestCase):
    def test_private_custody_rejects_renameable_ancestor_directories(self):
        root = Path('/var/lib/example-private/snmp')
        trusted = SimpleNamespace(st_uid=0, st_mode=stat.S_IFDIR | 0o755)
        with mock.patch.object(Path, 'stat', return_value=trusted):
            snmp_service.protected_ancestors(root)
        for uid, mode in ((1000, stat.S_IFDIR | 0o755), (0, stat.S_IFDIR | 0o775),
                          (0, stat.S_IFDIR | 0o777), (0, stat.S_IFREG | 0o600)):
            for parent in root.parents:
                def observed(path, *, target=parent, owner=uid, permissions=mode):
                    return SimpleNamespace(st_uid=owner, st_mode=permissions) if path == target else trusted
                with self.subTest(parent=parent, uid=uid, mode=mode), \
                        mock.patch.object(Path, 'stat', autospec=True, side_effect=observed), self.assertRaises(SNMPError):
                    snmp_service.protected_ancestors(root)

    def test_authoritative_dns_generates_only_the_enabled_ipv6_listener(self):
        value = fixture()
        value['services']['dns'] = {'authoritative': {'enabled': True, 'primary_zone': 'home.arpa',
                                                     'zones': {'home.arpa': {}}}}
        records = authoritative.zone_records(config.normalize(value))['home.arpa']
        self.assertEqual(records['snmp'], {'AAAA': 'fd42:1234:5678:fe02::1'})
        value['observability']['snmp']['enabled'] = False
        self.assertNotIn('snmp', authoritative.zone_records(config.normalize(value))['home.arpa'])

    def test_host_listener_requires_authpriv_and_only_the_declared_collectors(self):
        value = fixture()
        files = config.render(value)
        self.assertIn('agentAddress udp6:[fd42:1234:5678:fe02::1]:161', files['etc/snmp/snmpd.conf'])
        self.assertIn('rouser synthetic-monitor priv -V lanrith', files['etc/snmp/snmpd.conf'])
        self.assertNotIn('createUser', files['etc/snmp/snmpd.conf'])
        self.assertNotIn('community', files['etc/snmp/snmpd.conf'])
        firewall = files['etc/nftables.conf']
        self.assertIn('iifname "lan" ip6 saddr { fd42:1234:5678:10::50/128 } '
                      'ip6 daddr fd42:1234:5678:fe02::1 udp dport 161 accept', firewall)
        unit = files['usr/lib/systemd/system/snmpd.service']
        self.assertIn('PrivateNetwork=no\nNetworkNamespacePath=\n', unit)
        self.assertIn('-u Debian-snmp -g Debian-snmp', unit)
        self.assertNotIn('-c /etc/snmp/snmpd.conf', unit)
        self.assertIn('IPAddressDeny=any', unit)
        self.assertIn('IPAddressAllow=fd42:1234:5678:10::50/128', unit)
        self.assertNotIn('IPAddressAllow=fd42:1234:5678:10::/64', unit)
        self.assertIn('CapabilityBoundingSet=', unit)
        input_chain = firewall[firewall.index(' chain input '):firewall.index(' chain forward ')]
        self.assertLess(input_chain.index('udp dport 161 drop'), input_chain.index('ct state established,related accept'))
        output_chain = firewall[firewall.index(' chain output '):]
        self.assertLess(output_chain.index('udp sport 161 drop'), output_chain.index('ct state established,related accept'))

    def test_snmp_alone_has_service_addresses_without_dns_ntp_or_identity(self):
        files = config.render(fixture())
        self.assertNotIn('etc/chrony/chrony.conf', files)
        self.assertNotIn('etc/unbound/unbound.conf.d/lanrith.conf', files)
        plane = json.loads(files['usr/share/lanrith/service-plane.json'])
        self.assertEqual(plane['endpoints'], {})
        self.assertEqual(len(plane['default_sources']), len(plane['defaults']))
        self.assertIn('iifname "lr-services" ip6 saddr !=', files['etc/nftables.conf'])
        self.assertIn('snmpd.service', json.loads(files['usr/share/lanrith/health.json'])['units'])
        self.assertNotIn('udp dport 161', files['etc/lanrith/services.nft'])

    def test_custom_ranges_gua_and_on_link_delivery_preserve_the_host_endpoint(self):
        value = fixture()
        value['addressing']['services'] = {'ipv4': '172.30.40.0/24', 'ipv6': 'fd42:1234:5678:700::/64'}
        value['uplink']['ipv6'] = {'address': '2001:db8:20::2/48', 'gateway': '2001:db8:20::1',
                                  'downstream_prefix': '2001:db8:20::/48', 'delivery': 'on_link'}
        files = config.render(value)
        policy = json.loads(files['etc/lanrith/integrations/snmp-runtime-policy.json'])
        self.assertEqual(policy['server'], '2001:db8:20:700::1')
        plane = json.loads(files['usr/share/lanrith/service-plane.json'])
        self.assertIn('2001:db8:20:700::1', plane['proxy'])
        self.assertIn('2001:db8:20:700::1/64', plane['host_addresses'])

    def test_disabling_snmp_removes_the_listener_policy_and_attachment(self):
        value = fixture()
        value['observability']['snmp']['enabled'] = False
        files = config.render(value)
        self.assertFalse(any('snmp' in name for name in files))
        self.assertNotIn('udp dport 161', files['etc/nftables.conf'])
        self.assertNotIn('usr/share/lanrith/service-plane.json', files)

    def test_wrong_family_attachment_and_internal_identities_do_not_gain_access(self):
        for selector in ({'network': 'uplink', 'addresses': 'fd42:1234:5678:10::50'},
                         {'network': 'home', 'addresses': '192.168.10.50'},
                         {'network': 'home', 'addresses': 'fd42:1234:5678:fe02::10'},
                         {'addresses': '::/0'}, {'addresses': 'fe80::1'},
                         {'network': 'home', 'addresses': 'fd42:1234:5678:11::50'},
                         {'network': 'home', 'mac': '02:00:00:00:00:01'}):
            with self.subTest(selector=selector), self.assertRaises(ReleaseError):
                value = fixture()
                value['observability']['snmp']['clients'] = [selector]
                config.normalize(value)
        value = fixture()
        value['networks']['home']['role'] = 'management'
        with self.assertRaises(ReleaseError):
            config.normalize(value)

    def test_on_link_extra_collector_gets_only_the_selected_listener(self):
        value = fixture()
        value['routing'] = {'static_routes': [{'to': 'fd42:1234:5678:ffff::/64', 'network': 'home', 'on_link': True}]}
        value['observability']['snmp']['clients'] = [{'addresses': 'fd42:1234:5678:ffff::56/128'}]
        normalized = config.normalize(value)
        rules = snmp.client_rules(normalized, ingress=True)
        self.assertEqual(len(rules), 2)
        self.assertIn('iifname "lan" ip6 saddr { fd42:1234:5678:ffff::56/128 }', rules[0])
        self.assertIn('udp dport 161 return', rules[0])
        self.assertIn('ip6 hoplimit 255', rules[1])
        self.assertNotIn('ffff::/64', '\n'.join(rules))

    def test_custom_custody_path_reaches_only_the_compiled_runtime_policy(self):
        value = fixture()
        value['runtime'] = {'credentials': {'monitor_user': '/var/lib/router-monitoring/snmpd.conf'}}
        files = config.render(value)
        policy = json.loads(files['etc/lanrith/integrations/snmp-runtime-policy.json'])
        self.assertEqual(policy, snmp_service.policy_value(policy))
        self.assertEqual(policy['state_directory'], '/var/lib/router-monitoring')
        self.assertIn('/var/lib/router-monitoring/snmpd.conf', files['usr/lib/systemd/system/snmpd.service'])
        self.assertEqual(bindings.credential_path(config.normalize(fixture()), 'monitor_user'),
                         '/var/lib/lanrith/snmp/snmpd.conf')
        old = {key: policy[key] for key in ('schema', 'server', 'username')}
        self.assertEqual(snmp_service.policy_value(old)['state_directory'], '/var/lib/lanrith/snmp')

    def test_explicit_credential_format_preserves_the_existing_file_bytes(self):
        value = fixture()
        header = '# Managed by a previous example router runtime.\n'
        value['runtime'] = {'credential_headers': {'monitor_user': header}}
        files = config.render(value)
        policy = json.loads(files['etc/lanrith/integrations/snmp-runtime-policy.json'])
        self.assertEqual(policy, snmp_service.policy_value(policy))
        request = {'username': 'synthetic-monitor', 'auth_protocol': 'SHA-256', 'priv_protocol': 'AES',
                   'auth_password': 'Synthetic-Authentication-1', 'priv_password': 'Synthetic-Encryption-1'}
        original = snmp_credentials.configuration(request, header)
        self.assertEqual(snmp_service.State(header=policy['credential_header']).validate(original), original)
        with self.assertRaises(SNMPError):
            snmp_service.State().validate(original)
        with self.assertRaises(SNMPError):
            snmp_credentials.validate({**request, 'credential_header': header})
        for bad in ('createUser injected\n', '# note\ncreateUser injected\n', '# note\r\n', '# '+('x'*126)+'\n'):
            with self.subTest(header=bad), self.assertRaises(ReleaseError):
                value['runtime']['credential_headers']['monitor_user'] = bad
                config.normalize(value)
            with self.subTest(runtime_header=bad), self.assertRaises(SNMPError):
                snmp_service.policy_value({**policy, 'credential_header': bad})
        value['runtime']['credential_headers'] = {'undeclared': header}
        with self.assertRaises(ReleaseError):
            config.normalize(value)

    def test_invalid_username_and_credential_custody_fail_before_assembly(self):
        for username in ('bad user', '0user', 'a', 'x'*33, 'user\ninclude /tmp/other'):
            with self.subTest(username=username), self.assertRaises(ReleaseError):
                value = fixture()
                value['observability']['snmp']['username'] = username
                config.normalize(value)
        for path in ('/var/lib/snmp/snmpd.conf', '/var/lib/snmpd.conf', '/var/cache/monitor/snmpd.conf',
                     '/var/lib/monitor/other.conf', '/var/lib/monitor/../snmpd.conf'):
            with self.subTest(path=path), self.assertRaises(ReleaseError):
                value = fixture()
                value['runtime'] = {'credentials': {'monitor_user': path}}
                config.normalize(value)
        policy = snmp.manifest(config.normalize(fixture()))
        for root in ('/etc/snmp', '/var/lib', '/var/lib/snmp', '/var/lib/snmp/other',
                     '/var/lib/a/../b', '/var/lib/a\nother'):
            with self.subTest(root=root), self.assertRaises(SNMPError):
                snmp_service.policy_value({**policy, 'state_directory': root})
        for alteration in ({'username': 'x; exec'}, {'schema': True}, {'unknown': 1}):
            with self.subTest(alteration=alteration), self.assertRaises(SNMPError):
                snmp_service.policy_value({**policy, **alteration})

    def test_assembly_installs_the_policy_consumer_without_the_owner_configuration(self):
        value = fixture()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            base = root/'base.tar'
            base.write_bytes(b'synthetic assembly input')
            build.assembly(value, base, root/'image', version='0.1.0', sequence=9)
            overlay = root/'image/mkosi.extra'
            self.assertTrue((overlay/'etc/systemd/system/snmpd.service').is_symlink())
            self.assertIn('snmpd.service', (overlay/'usr/lib/systemd/system/lanrith-health.service').read_text())
            for name in ('snmp_service.py', 'snmp_credentials.py', 'snmp-runtime', 'credential_runtime.py', 'systemd_service.py'):
                self.assertEqual((overlay/'usr/lib/lanrith'/name).read_bytes(), (HELPERS/name).read_bytes())
            self.assertFalse((overlay/'usr/lib/lanrith/lanrith/config.py').exists())
            self.assertFalse((overlay/'usr/share/lanrith/resolved.json').exists())
            self.assertFalse((overlay/'var/lib/lanrith/snmp/snmpd.conf').exists())


if __name__ == '__main__':
    unittest.main()
