"""RADIUS is compiled as bounded connectivity, never embedded credentials."""

import copy
import ipaddress
import json
from pathlib import Path
import tempfile
import unittest

from lanrith import build, config, credential_config, policy_agent, radius
from lanrith.release import ReleaseError
from test_policy_agent import declaration as policy_declaration


def declaration():
    value = policy_declaration()
    value['networks']['home']['vlan'] = 1
    value['networks']['devices']['dhcp4'] = {'pools': ['192.168.22.100-192.168.22.150']}
    value['identity']['radius'] = {
        'enabled': True,
        'network': 'home',
        'clients': {
            'wired-switch': {'address': '192.168.10.40', 'kind': 'wired_mab', 'port': 5,
                             'credential': 'radius_wired'},
            'wireless': {'address': '192.168.10.48/28', 'kind': 'wireless_mac',
                         'credential': 'radius_wireless'},
        },
        'admission': {'directory': 'directory', 'group_dn': 'cn=devices,dc=example,dc=test',
                      'network': 'devices'},
        'proxy': {'address': '192.168.10.30', 'credential': 'radius_upstream'},
        'fallback': {'enabled': True, 'clients': ['wired-switch']},
    }
    return value


class RadiusContractTests(unittest.TestCase):
    def test_host_boundary_admits_only_configured_nas_udp_to_radius(self):
        value = config.normalize(declaration())
        files = config.render(value)
        policy = radius.manifest(value)
        nas = sorted(str(ipaddress.ip_network(c['address'])) for c in policy['clients'])
        network = value['networks'][value['identity']['radius']['network']]['name']
        rules = [line.strip() for line in files['etc/nftables.conf'].splitlines()
                 if 'dport { 1812, 1813 }' in line]
        target = next(a for a in policy['listeners'] if ':' not in a)
        self.assertEqual(rules, [f'iifname "{network}" oifname "lr-services" '
            f'ip saddr {{ {", ".join(nas)} }} ip daddr {{ {target} }} udp dport {{ 1812, 1813 }} accept'])
        forward = files['etc/nftables.conf'].split('chain forward', 1)[1]
        self.assertLess(forward.index('ct state invalid,untracked drop'), forward.index(rules[0]))
        self.assertLess(forward.index(rules[0]), forward.index('oifname "lr-services" drop'))
        value['identity']['radius'] = {'enabled': False}
        self.assertNotIn('dport { 1812, 1813 }', config.render(value)['etc/nftables.conf'])

    def test_transport_controls_the_shared_secret_requirement(self):
        value = declaration()
        for client in value['identity']['radius']['clients'].values():
            client['transport'] = 'udp'
        value['identity']['radius']['proxy']['transport'] = 'udp'
        self.assertEqual(radius.manifest(config.normalize(value)), radius.manifest(config.normalize(declaration())))
        client = value['identity']['radius']['clients']['wired-switch']
        client.pop('credential')
        with self.assertRaisesRegex(ReleaseError, 'UDP NAS client requires a shared-secret'):
            config.normalize(value)
        client['transport'] = 'tls'
        with self.assertRaisesRegex(ReleaseError, 'currently supports UDP'):
            config.normalize(value)

    def test_proxy_admission_does_not_require_a_directory_or_bind_password(self):
        from test_credential_image import fixture
        value = declaration()
        value['identity'] = {'radius': value['identity']['radius']}
        value['identity']['radius']['admission'] = {'network': 'devices'}
        value['access']['rules'] = []
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            value = fixture(root, value)
            self.assertEqual(set(value['credentials']), {'radius_wired', 'radius_wireless', 'radius_upstream'})
            base = root/'base.tar'; base.write_bytes(b'synthetic')
            build.assembly(value, base, root/'image', version='0.1.0', sequence=1)
            tree = root/'image/mkosi.extra'
            self.assertTrue((tree/'etc/systemd/system/freeradius.service.d/60-lanrith.conf').exists())
            helper = tree/'etc/systemd/system/lanrith-radius-runtime.service'
            self.assertTrue(helper.is_symlink())
            self.assertEqual(helper.readlink(), Path('/usr/lib/systemd/system/lanrith-radius-runtime.service'))
            self.assertFalse((tree/'etc/router-policy-agent').exists())
            self.assertFalse((tree/'usr/lib/lanrith/credentials/core/directory_bind').exists())
            self.assertNotIn('control-socket', json.loads((tree/'etc/kea/kea-dhcp4.conf').read_bytes())['Dhcp4'])
            self.assertNotIn('lanrith-policy-reader.service',
                             json.loads((tree/'usr/share/lanrith/health.json').read_bytes())['units'])

    def test_proxy_and_directory_policy_can_be_selected_independently(self):
        value = declaration()
        value['identity']['radius']['admission'] = {'network': 'devices'}
        value['networks']['devices'].pop('dhcp4')
        value = config.normalize(value)
        self.assertIsNone(policy_agent.runtime_contract(value)['binding_collector'])
        files = config.render(value)
        self.assertNotIn('control-socket', json.loads(files['etc/kea/kea-dhcp4.conf'])['Dhcp4'])
        self.assertIn('etc/systemd/system/freeradius.service.d/60-lanrith.conf', files)

    def test_selected_directory_admission_still_requires_complete_policy(self):
        for change in ('group', 'directory', 'policy', 'different-directory', 'proxy'):
            value = declaration()
            if change in ('group', 'directory'):
                value['identity']['radius']['admission'].pop('group_dn' if change == 'group' else 'directory')
            elif change == 'policy':
                value['identity']['policy']['enabled'] = False
                value['access']['rules'] = []
            elif change == 'different-directory':
                value['identity']['directories']['other'] = copy.deepcopy(value['identity']['directories']['directory'])
                value['identity']['radius']['admission']['directory'] = 'other'
            else:
                value['identity']['radius'].pop('proxy')
            with self.subTest(change=change), self.assertRaises(ReleaseError):
                config.normalize(value)

    def test_render_uses_only_compiled_policy_and_systemd_credentials(self):
        value = config.normalize(declaration())
        files = config.render(value)
        policy = json.loads(files['usr/share/lanrith/radius.json'])
        self.assertEqual(policy['authentication_port'], 1812)
        self.assertEqual(policy['accounting_port'], 1813)
        self.assertEqual(policy['admission_vlan'], 22)
        self.assertEqual(policy['fallback_clients'], ['wired-switch'])
        unit = files['etc/systemd/system/freeradius.service.d/60-lanrith.conf']
        stage = files['usr/lib/systemd/system/lanrith-radius-runtime.service']
        for reference in ('radius_wired', 'radius_wireless', 'radius_upstream'):
            self.assertIn('LoadCredential='+reference+':/var/lib/lanrith/credentials/'+reference, stage)
        self.assertNotIn('LoadCredential=', unit)
        self.assertNotIn('radius-runtime stage', unit)
        self.assertIn('Requires=lanrith-services.service lanrith-radius-runtime.service', unit)
        self.assertIn('ExecStartPre=\nExecStartPre=/usr/sbin/freeradius', unit)
        self.assertIn('User=root\nGroup=freerad', stage)
        self.assertIn('RuntimeDirectoryPreserve=yes', stage)
        self.assertNotIn('RemainAfterExit', stage)
        self.assertIn('CapabilityBoundingSet=\n', stage)
        self.assertNotIn('BindReadOnlyPaths', stage)
        self.assertIn('NetworkNamespacePath=/run/netns/lanrith-services', unit)
        self.assertIn('/run/lanrith-radius/clients.conf:/etc/freeradius/3.0/clients.conf', unit)
        self.assertNotIn('shared_secret', ''.join(files.values()))
        self.assertEqual(files['etc/freeradius/3.0/mods-enabled/eap'],
                         '# EAP is intentionally disabled by the Lanrith MAB policy.\n')
        self.assertEqual(files['etc/freeradius/3.0/sites-enabled/inner-tunnel'],
                         '# The EAP inner tunnel is intentionally disabled by the Lanrith MAB policy.\n')
        self.assertIn('radius-policy-accounting-v1', files[
            'etc/freeradius/3.0/mods-enabled/lanrith_accounting'])
        self.assertIn('dport 1813 accept', files['etc/lanrith/services.nft'])
        self.assertEqual(json.loads(files['etc/kea/kea-dhcp4.conf'])['Dhcp4']['control-socket'],
                         {'socket-type': 'unix', 'socket-name': '/run/kea/kea4-ctrl-socket'})
        self.assertEqual(json.loads(files['etc/kea/kea-dhcp4.conf'])['Dhcp4']['hooks-libraries'],
                         [{'library': '/usr/lib/x86_64-linux-gnu/kea/hooks/libdhcp_lease_cmds.so'}])
        self.assertIn('kea_runtime.py $MAINPID\n', files[
            'etc/systemd/system/kea-dhcp4-server.service.d/60-lanrith-control.conf'])

    def test_disabled_radius_removes_its_kea_control_dependency(self):
        value = declaration()
        value['identity']['radius'] = {'enabled': False}
        files = config.render(config.normalize(value))
        native = json.loads(files['etc/kea/kea-dhcp4.conf'])['Dhcp4']
        self.assertNotIn('control-socket', native)
        self.assertNotIn('hooks-libraries', native)
        self.assertNotIn('etc/systemd/system/kea-dhcp4-server.service.d/60-lanrith-control.conf', files)

    def test_policy_binding_projection_is_exact_and_not_source_intent(self):
        value = config.normalize(declaration())
        runtime = policy_agent.runtime_contract(value)
        collector = runtime['binding_collector']
        self.assertEqual(collector, {
            'radius_user': 'freerad', 'nas_prefixes': ['192.168.10.40/32', '192.168.10.48/28'],
            'kea_user': '_kea', 'kea_socket': '/run/kea/kea4-ctrl-socket',
            'subnet_id': 2, 'ipv4_prefix': '192.168.22.0/24', 'vlan': 22,
            'maximum_devices': 256, 'interface': 'lan.22', 'parent': 'lan',
        })
        encoded = json.dumps(runtime)
        for forbidden in ('group_dn', 'access', 'groups', 'dhcp4', 'radius_wired'):
            self.assertNotIn(forbidden, encoded)
        model = policy_agent.baseline(value)['network_model']
        service = next(item for item in model['core_services'] if item['kind'] == 'radius')
        self.assertEqual(service['clients'], [{'interface': 'lan.1', 'addresses': [
            '192.168.10.40/32', '192.168.10.48/28']}])
        self.assertEqual(next(item for item in model['core_egress'] if item['kind'] == 'radius_proxy'), {
            'kind': 'radius_proxy', 'interface': 'lr-services', 'address': '10.255.254.30',
            'destinations': ['192.168.10.30/32'], 'masquerade': False,
            'destination_interface': 'lan.1'})

    def test_unsafe_radius_attachments_and_fallbacks_are_rejected(self):
        cases = []
        outside_nas = declaration()
        outside_nas['identity']['radius']['clients']['wired-switch']['address'] = '198.51.100.40'
        cases.append(outside_nas)
        outside_proxy = declaration()
        outside_proxy['identity']['radius']['proxy']['address'] = '198.51.100.30'
        cases.append(outside_proxy)
        untagged = declaration()
        untagged['networks']['devices'].pop('vlan')
        cases.append(untagged)
        no_dhcp = declaration()
        no_dhcp['networks']['devices'].pop('dhcp4', None)
        cases.append(no_dhcp)
        wireless_fallback = declaration()
        wireless_fallback['identity']['radius']['fallback']['clients'] = ['wireless']
        cases.append(wireless_fallback)
        unmanaged = declaration()
        unmanaged['identity']['policy']['networks'] = []
        cases.append(unmanaged)
        for value in cases:
            with self.subTest(value=copy.deepcopy(value)), self.assertRaises(ReleaseError):
                config.normalize(value)


if __name__ == '__main__':
    unittest.main()
