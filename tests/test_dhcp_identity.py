"""DHCP lease identities agree across native configuration and policy admission."""

import copy
import json
import os
from pathlib import Path
import tempfile
import unittest

from lanrith import config, intent, policy_agent, policy_runtime
from lanrith.release import ReleaseError
from test_radius import declaration


class DhcpIdentityTests(unittest.TestCase):
    def scopes(self, value):
        return json.loads(config.render(value)['etc/kea/kea-dhcp4.conf'])['Dhcp4']['subnet4']

    def test_defaults_keep_existing_numbers_and_are_part_of_the_normalized_identity(self):
        value = config.normalize(declaration())
        self.assertEqual(intent.dhcp4_ids(value), {'home': 1, 'devices': 2})
        self.assertEqual([scope['id'] for scope in self.scopes(value)], [1, 2])
        self.assertEqual(value, config.normalize(value))
        # Hosted owner snapshots sort keys. An already normalized lease
        # identity must survive that serialization without being renumbered.
        reordered = json.loads(json.dumps(value, sort_keys=True))
        self.assertEqual(intent.dhcp4_ids(config.normalize(reordered)), {'devices': 2, 'home': 1})
        self.assertEqual(config.effective_digest(value, {}), config.effective_digest(config.normalize(reordered), {}))

    def test_explicit_numbers_survive_network_order_and_name_changes(self):
        value = declaration()
        value['networks']['home']['dhcp4']['id'] = 1024
        value['networks']['devices']['dhcp4']['id'] = 79
        normalized = config.normalize(value)
        for selected in (normalized, {**normalized, 'networks': dict(reversed(list(normalized['networks'].items())))}):
            scopes = {scope['subnet']: scope['id'] for scope in self.scopes(selected)}
            self.assertEqual(scopes, {'192.168.10.0/24': 1024, '192.168.22.0/24': 79})
            self.assertEqual(policy_agent.runtime_contract(selected)['binding_collector']['subnet_id'], 79)
        changed = copy.deepcopy(normalized)
        changed['networks']['home']['name'] = 'renamed-home'
        self.assertEqual(intent.dhcp4_ids(config.normalize(changed))['home'], 1024)

    def test_implicit_numbers_skip_all_explicit_reservations(self):
        value = declaration()
        value['networks']['devices']['dhcp4']['id'] = 1
        normalized = config.normalize(value)
        self.assertEqual(intent.dhcp4_ids(normalized), {'home': 2, 'devices': 1})
        self.assertEqual(policy_agent.runtime_contract(normalized)['binding_collector']['subnet_id'], 1)

    def test_native_bounds_and_duplicate_ids_fail_before_render(self):
        for identifier in (0, -1, True, '79', 1.0, None, [], 4294967295, 4294967296):
            with self.subTest(identifier=identifier), self.assertRaises(ReleaseError):
                value = declaration()
                value['networks']['devices']['dhcp4']['id'] = identifier
                config.normalize(value)
        value = declaration()
        for network in value['networks'].values():
            network['dhcp4']['id'] = 1024
        with self.assertRaisesRegex(ReleaseError, 'duplicate DHCPv4'):
            config.normalize(value)

    def test_highest_supported_id_is_preserved_in_native_and_policy_output(self):
        value = declaration()
        value['networks']['devices']['dhcp4']['id'] = 4294967294
        normalized = config.normalize(value)
        self.assertEqual(self.scopes(normalized)[1]['id'], 4294967294)
        self.assertEqual(policy_agent.runtime_contract(normalized)['binding_collector']['subnet_id'], 4294967294)

    def test_runtime_collector_accepts_pinned_ids_and_rejects_the_reserved_global_id(self):
        value = declaration()
        value['networks']['devices']['dhcp4']['id'] = 4294967294
        contract = policy_agent.runtime_contract(config.normalize(value))
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary)/'runtime.json'
            path.write_text(json.dumps(contract))
            path.chmod(0o600)
            self.assertEqual(policy_runtime.load_contract(path, owner=os.geteuid())['binding_collector']['subnet_id'],
                             4294967294)
            contract['binding_collector']['subnet_id'] = 4294967295
            path.write_text(json.dumps(contract))
            with self.assertRaises(policy_runtime.PolicyRuntimeError):
                policy_runtime.load_contract(path, owner=os.geteuid())

    def test_disabled_scopes_do_not_reserve_or_reject_an_active_identity(self):
        value = declaration()
        value['identity']['radius'] = {'enabled': False}
        value['networks']['devices']['dhcp4'] = {'enabled': False, 'id': 1}
        normalized = config.normalize(value)
        self.assertEqual(intent.dhcp4_ids(normalized), {'home': 1})

    def test_changed_subnet_id_changes_configuration_identity_without_changing_access(self):
        value = config.normalize(declaration())
        changed = copy.deepcopy(value)
        changed['networks']['devices']['dhcp4']['id'] = 79
        changed = config.normalize(changed)
        self.assertNotEqual(config.effective_digest(value, {}), config.effective_digest(changed, {}))
        self.assertEqual(config.render(value)['etc/nftables.conf'], config.render(changed)['etc/nftables.conf'])


if __name__ == '__main__':
    unittest.main()
