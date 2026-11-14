"""Build-time translation geometry retains output addresses and exact scope."""

import copy
import hashlib
import unittest

from lanrith import config, firewall, intent, policy_agent
from lanrith.release import canonical
from test_host_services import ACCOUNTS, static_minimal
from test_policy_agent import declaration


def translated():
    value = static_minimal()
    value['translation'] = {'nat64': {'enabled': True}}
    return value


class NAT64EgressContractTests(unittest.TestCase):
    def test_disabled_and_nat46_only_emit_no_nat64_egress(self):
        value = static_minimal()
        for translation in ({}, {'nat64': {'enabled': False}},
                            {'nat46': {'enabled': True, 'mappings': {
                                'example': {'ipv4': '10.255.200.2',
                                            'ipv6': 'fd42:1234:5678:10::50'}}}}):
            with self.subTest(translation=translation):
                value['translation'] = translation
                normalized = config.normalize(value)
                self.assertEqual(policy_agent.nat64_egress(normalized), [])
                self.assertNotIn('nat64_egress', policy_agent.bounded_baseline(
                    normalized, ACCOUNTS)['network_model'])

    def test_custom_gateways_interfaces_and_pools_are_retained(self):
        raw = translated()
        raw['hardware']['interfaces']['wan']['name'] = 'outside0'
        raw['hardware']['interfaces']['lan']['name'] = 'trunk0'
        raw['uplink']['ipv4'] = {'address': '172.28.64.27/24', 'gateway': '172.28.64.1'}
        raw['networks']['home'].update(vlan=37, ipv4={
            'subnet': '192.168.10.0/24', 'address': '192.168.10.254'})
        raw['translation']['nat64'].update(internet_pool='10.77.224.0/20',
                                          private_pool='10.77.208.0/20')
        paths = policy_agent.nat64_egress(config.normalize(raw))
        self.assertEqual(paths, [
            {'interface': component, **output}
            for component in ('nat64', 'nat64-internal')
            for output in (
                {'destination_interface': 'trunk0.37', 'destinations': ['192.168.10.0/24'],
                 'addresses': ['192.168.10.254']},
                {'destination_interface': 'outside0', 'destinations': ['0.0.0.0/0'],
                 'addresses': ['172.28.64.27']})])
        self.assertNotIn('source_pool', paths[0])
        self.assertTrue(all(set(path) == {'interface', 'destination_interface',
                                         'destinations', 'addresses'} for path in paths))

    def test_management_and_ipv6_only_attachments_are_excluded(self):
        raw = translated()
        raw['hardware']['interfaces']['oob'] = {'name': 'recovery0',
                                              'match': {'mac': '02:00:00:00:99:01'}}
        raw['networks']['management'] = {'interface': 'oob', 'role': 'management',
                                        'ipv4': '10.99.0.0/24'}
        raw['networks']['v6'] = {'interface': 'lan', 'vlan': 61,
                                'ipv6': {'subnet_id': 61, 'gua': False}}
        paths = policy_agent.nat64_egress(config.normalize(raw))
        self.assertEqual({p['destination_interface'] for p in paths}, {'lan', 'wan'})
        self.assertEqual(len(paths), 4)

    def test_extra_attachment_scopes_match_existing_masquerade(self):
        raw = translated()
        raw['networks']['home']['ipv6'] = {'subnet_id': 16, 'gua': False}
        raw['networks']['home']['additional_subnets'] = ['172.30.44.0/24',
                                                       'fd42:1234:5678:ffff::60/124']
        value = config.normalize(raw)
        paths = policy_agent.nat64_egress(value)
        lan = next(p for p in paths if p['interface'] == 'nat64-internal'
                   and p['destination_interface'] == 'lan')
        self.assertEqual(lan['destinations'], ['172.30.44.0/24', '192.168.10.0/24'])
        self.assertEqual(lan['addresses'], ['172.30.44.1', '192.168.10.1'])
        text = firewall.render(value)
        components = {p['interface']: p for p in intent.translations(value).values()
                      if p['component'] == 'nat64'}
        for path in paths:
            for prefix in path['destinations']:
                suffix = '' if prefix == '0.0.0.0/0' else ' ip daddr '+prefix
                self.assertIn('iifname "'+path['interface']+'" ip saddr '+
                              components[path['interface']]['pool']+' oifname "'+
                              path['destination_interface']+'"'+suffix+' masquerade', text)

    def test_ordinary_client_masquerade_does_not_disable_translation_geometry(self):
        raw = translated()
        enabled = policy_agent.nat64_egress(config.normalize(raw))
        raw['uplink']['masquerade'] = False
        value = config.normalize(raw)
        self.assertEqual(policy_agent.nat64_egress(value), enabled)
        self.assertEqual(policy_agent.bounded_baseline(value, ACCOUNTS)[
            'network_model']['uplink_nat'], [])

    def test_disabled_ipv4_wan_retains_private_attachment_paths(self):
        raw = translated()
        raw['uplink']['ipv4'] = 'disabled'
        paths = policy_agent.nat64_egress(config.normalize(raw))
        self.assertEqual({p['destination_interface'] for p in paths}, {'lan'})
        self.assertEqual(len(paths), 2)

    def test_dynamic_wan_never_invents_a_source_address(self):
        raw = translated()
        raw['uplink']['ipv4'] = 'dhcp'
        paths = policy_agent.nat64_egress(config.normalize(raw))
        wan = [p for p in paths if p['destination_interface'] == 'wan']
        self.assertEqual(len(wan), 2)
        self.assertTrue(all(p['addresses'] == [] for p in wan))
        self.assertTrue(all(p['addresses'] == ['192.168.10.1']
                            for p in paths if p['destination_interface'] == 'lan'))

    def test_only_candidate_contract_changes_and_generation_binds_addresses(self):
        raw = declaration()
        raw['translation'] = {'nat64': {'enabled': True}}
        value = config.normalize(raw)
        old = policy_agent.baseline(value)
        candidate = policy_agent.bounded_baseline(value, ACCOUNTS)
        self.assertNotIn('nat64_egress', old['network_model'])
        self.assertEqual(candidate['network_model']['nat64_egress'],
                         policy_agent.nat64_egress(value))
        self.assertEqual(candidate['network_model']['rules'], old['network_model']['rules'])
        generation = candidate['generation']
        candidate['generation'] = 'pending'
        self.assertEqual(generation, hashlib.sha256(canonical(candidate)).hexdigest())
        changed = copy.deepcopy(raw)
        changed['uplink']['ipv4']['address'] = '10.243.0.3/24'
        second = policy_agent.bounded_baseline(config.normalize(changed), ACCOUNTS)
        self.assertNotEqual(generation, second['generation'])
        self.assertTrue(all(path['addresses'] == ['10.243.0.3']
                            for path in second['network_model']['nat64_egress']
                            if path['destination_interface'] == 'wan'))
