"""RADIUS is compiled as bounded connectivity, never embedded credentials."""

import copy
import json
import unittest

from lanrith import config, policy_agent, radius
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
    def test_render_uses_only_compiled_policy_and_systemd_credentials(self):
        value = config.normalize(declaration())
        files = config.render(value)
        policy = json.loads(files['usr/share/lanrith/radius.json'])
        self.assertEqual(policy['authentication_port'], 1812)
        self.assertEqual(policy['accounting_port'], 1813)
        self.assertEqual(policy['admission_vlan'], 22)
        self.assertEqual(policy['fallback_clients'], ['wired-switch'])
        unit = files['etc/systemd/system/freeradius.service.d/60-lanrith.conf']
        for reference in ('radius_wired', 'radius_wireless', 'radius_upstream'):
            self.assertIn('LoadCredential='+reference+':/var/lib/lanrith/credentials/'+reference, unit)
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
