"""Host DHCP construction shares native geometry and admitted account identity."""

import copy
import hashlib
import json
from pathlib import Path
import unittest

from lanrith import config, dhcp4, policy_agent
from lanrith.release import ReleaseError, canonical
from test_intent import minimal
from test_policy_agent import declaration


ROOT = Path(__file__).resolve().parents[1]
ACCOUNTS = {
    'passwd': b'root:x:0:0:root:/root:/bin/bash\n_kea:x:3218:3219:DHCP:/var/lib/kea:/usr/sbin/nologin\n',
    'group': b'root:x:0:\n_kea:x:3219:\n',
}


def static_minimal():
    value = minimal()
    value['uplink']['ipv4'] = {'address': '10.243.0.2/24', 'gateway': '10.243.0.1'}
    value['uplink']['ipv6'] = 'disabled'
    return value


class HostServiceBuildTests(unittest.TestCase):
    def test_minimal_candidate_has_no_directory_dependency(self):
        value = config.normalize(static_minimal())
        result = policy_agent.bounded_baseline(value, ACCOUNTS)
        self.assertEqual(result['network_model']['managed_networks'], [])
        self.assertEqual(result['network_model']['host_dhcp4'], [{
            'uid': 3218, 'interface': value['networks']['home']['name'],
            'server_address': '192.168.10.1', 'subnet': '192.168.10.0/24'}])
        self.assertNotIn('directory', result)
        generation = result['generation']
        result['generation'] = 'pending'
        self.assertEqual(generation, hashlib.sha256(canonical(result)).hexdigest())
        # The installed legacy profile still requires directory selection and
        # does not accidentally select the unqualified candidate backend.
        with self.assertRaises(ReleaseError):
            policy_agent.baseline(value)
        self.assertNotIn('usr/lib/lanrith-build/policy-baseline.json', config.render(value))

    def test_native_kea_and_host_scope_use_the_same_custom_gateway_and_interface(self):
        raw = static_minimal()
        raw['hardware']['interfaces']['lan']['name'] = 'trunk0'
        raw['networks']['home'].update(vlan=1, ipv4={'subnet': '192.168.10.0/24', 'address': '192.168.10.11'})
        raw['networks']['home']['dhcp4']['id'] = 615
        value = config.normalize(raw)
        native = json.loads(config.render(value)['etc/kea/kea-dhcp4.conf'])['Dhcp4']['subnet4']
        self.assertEqual(native, dhcp4.scopes(value))
        host = dhcp4.host_scopes(value, ACCOUNTS)
        self.assertEqual(host, [{'uid': 3218, 'interface': native[0]['interface'],
                                'server_address': '192.168.10.11', 'subnet': native[0]['subnet']}])
        self.assertEqual(native[0]['id'], 615)
        self.assertEqual(host[0]['interface'], 'trunk0.1')

    def test_disabled_or_absent_dhcp_needs_no_account_or_host_declaration(self):
        for selection in ('global', 'network', 'absent', 'IPv6-only'):
            raw = static_minimal()
            if selection == 'global':
                raw['services'] = {'dhcp4': {'enabled': False}}
            elif selection == 'network':
                raw['networks']['home']['dhcp4']['enabled'] = False
            else:
                del raw['networks']['home']['dhcp4']
                if selection == 'IPv6-only':
                    del raw['networks']['home']['ipv4']
                    raw['networks']['home']['ipv6'] = {'subnet_id': 10, 'gua': False}
            value = config.normalize(raw)
            with self.subTest(selection=selection):
                self.assertEqual(dhcp4.host_scopes(value, None), [])
                self.assertNotIn('host_dhcp4', policy_agent.bounded_baseline(value, None)['network_model'])

    def test_uid_is_from_registry_and_changes_the_candidate_identity_only(self):
        value = config.normalize(declaration())
        before = copy.deepcopy(value)
        first = policy_agent.bounded_baseline(value, ACCOUNTS)
        accounts = copy.deepcopy(ACCOUNTS)
        accounts['passwd'] = accounts['passwd'].replace(b':3218:', b':4218:')
        second = policy_agent.bounded_baseline(value, accounts)
        self.assertEqual(first['network_model']['host_dhcp4'][0]['uid'], 3218)
        self.assertEqual(second['network_model']['host_dhcp4'][0]['uid'], 4218)
        self.assertNotEqual(first['generation'], second['generation'])
        self.assertEqual(value, before)
        self.assertNotIn('host_dhcp4', policy_agent.baseline(value)['network_model'])
        first['network_model']['host_dhcp4'][0]['uid'] = 1
        self.assertEqual(dhcp4.host_scopes(value, ACCOUNTS)[0]['uid'], 3218)

    def test_no_owner_uid_override_is_accepted(self):
        raw = static_minimal()
        raw['networks']['home']['dhcp4']['uid'] = 3218
        with self.assertRaises(ReleaseError):
            config.normalize(raw)

    def test_unsafe_or_ambiguous_account_registries_reject(self):
        value = config.normalize(static_minimal())
        invalid = [None, {}, {'passwd': ACCOUNTS['passwd']},
                   {**ACCOUNTS, 'extra': b''}]
        for content in (b'', b'\x00', b'\xff', b'x'*1048577,
                        b'root:x:0:0:root:/root:/bin/bash\n',
                        ACCOUNTS['passwd'].replace(b':3218:', b':0:'),
                        ACCOUNTS['passwd'].replace(b':3218:', b':2147483647:'),
                        ACCOUNTS['passwd'].replace(b':3218:', b':-1:'),
                        ACCOUNTS['passwd']+b'other:x:3218:3220:other:/nonexistent:/usr/sbin/nologin\n',
                        ACCOUNTS['passwd']+b'_kea:x:4218:4219:other:/nonexistent:/usr/sbin/nologin\n'):
            invalid.append({**ACCOUNTS, 'passwd': content})
        invalid.append({**ACCOUNTS, 'group': b'wrong'})
        for accounts in invalid:
            with self.subTest(case=invalid.index(accounts)), self.assertRaises(ReleaseError):
                dhcp4.host_scopes(value, accounts)

    def test_all_public_native_dhcp_projections_match(self):
        for path in sorted((ROOT/'examples').glob('*.yaml')):
            value = config.load(path)
            files = config.render(value)
            with self.subTest(example=path.name):
                if 'etc/kea/kea-dhcp4.conf' in files:
                    native = json.loads(files['etc/kea/kea-dhcp4.conf'])['Dhcp4']['subnet4']
                    self.assertEqual(native, dhcp4.scopes(value))
                    self.assertEqual({entry['interface'] for entry in native},
                                     {entry['interface'] for entry in dhcp4.host_scopes(value, ACCOUNTS)})
                else:
                    self.assertEqual(dhcp4.host_scopes(value, None), [])


if __name__ == '__main__':
    unittest.main()
