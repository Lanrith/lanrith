"""Exercise portable access selectors, ordering and fail-closed validation."""

import copy
import json
from pathlib import Path
import unittest

from lanrith import config
from lanrith.release import ReleaseError


ROOT = Path(__file__).resolve().parents[1]


class AccessTests(unittest.TestCase):
    def setUp(self):
        self.value = config.load(ROOT/'examples/segmented.yaml')

    def firewall(self, rules, **settings):
        value = copy.deepcopy(self.value)
        value['access'] = {'default': 'deny', 'rules': rules, **settings}
        return config.render(value)['etc/nftables.conf']

    def test_network_and_uplink_rules_need_no_component_roles(self):
        text = self.firewall([{'action': 'allow', 'from': ['home', 'guest'], 'to': 'uplink'}])
        for name in ('lan.10', 'lan.20'):
            self.assertIn(f'iifname "{name}" oifname "wan"', text)
        self.assertIn('policy drop;', text)
        self.assertNotIn('chain forward { type filter hook forward priority filter; policy accept;', text)

    def test_host_ports_and_interface_must_all_match(self):
        text = self.firewall([{'action': 'allow', 'from': 'home',
            'to': {'network': 'guest', 'addresses': '172.20.20.7'},
            'protocol': 'tcp', 'ports': [443, 80]}])
        self.assertIn('iifname "lan.10" oifname "lan.20" ip daddr { 172.20.20.7/32 }', text)
        self.assertIn('meta l4proto tcp tcp dport { 80, 443 }', text)
        self.assertNotIn('ip daddr { 172.20.20.0/24 }', text)

    def test_explicit_denies_keep_list_order_and_precede_return_shortcut(self):
        text = self.firewall([
            {'action': 'deny', 'from': 'home', 'to': {'network': 'uplink', 'addresses': '203.0.113.9'}},
            {'action': 'allow', 'from': 'home', 'to': 'uplink'},
        ])
        deny = text.index('ip daddr { 203.0.113.9/32 }')
        allow = text.index('iifname "lan.10" oifname "wan" ct state')
        established = text.index('ct state established,related accept', text.index('chain forward'))
        self.assertLess(deny, allow)
        self.assertLess(allow, established)

    def test_address_family_is_explicit_or_derived_without_cross_family_matches(self):
        text = self.firewall([{'action': 'allow', 'from': ['192.0.2.7', '2001:db8:1::7'],
            'to': ['198.51.100.8', '2001:db8:2::8']}])
        rules = [line for line in text.splitlines() if 'saddr {' in line and 'ct state' in line]
        self.assertEqual(len(rules), 2)
        self.assertTrue(any('meta nfproto ipv4' in line for line in rules))
        self.assertTrue(any('meta nfproto ipv6' in line for line in rules))

    def test_mac_state_direction_and_return_flags_are_generic_optional_selectors(self):
        text = self.firewall([{'action': 'allow',
            'from': {'interface': 'transit0', 'addresses': '198.51.100.0/24', 'mac': '02:00:00:00:00:07'},
            'to': 'home', 'protocol': 'tcp', 'tcp_flags': ['ack'],
            'states': ['established'], 'direction': 'reply'}])
        self.assertIn('ether saddr 02:00:00:00:00:07', text)
        self.assertIn('tcp flags & (ack) == (ack) ct state { established } ct direction reply accept', text)
        self.assertLess(text.index('ct state invalid,untracked drop'), text.index('tcp flags & (ack)'))

    def test_icmp_types_and_non_transport_protocols_are_supported(self):
        text = self.firewall([
            {'action': 'allow', 'from': 'home', 'to': 'guest', 'protocol': 'icmpv6', 'icmp_types': ['echo-reply', 2], 'icmp_codes': [0]},
            {'action': 'allow', 'from': 'home', 'to': 'uplink', 'protocol': 'esp'},
        ])
        self.assertIn('meta nfproto ipv6', text)
        self.assertIn('meta l4proto ipv6-icmp icmpv6 type { echo-reply, 2 }', text)
        self.assertIn('icmpv6 code { 0 }', text)
        self.assertIn('meta l4proto esp', text)

    def test_default_rules_exclude_invalid_connections(self):
        text = self.firewall([{'action': 'allow', 'from': 'home', 'to': 'guest'}])
        self.assertIn('ct state { new, established, related } accept', text)

    def test_optional_names_survive_compilation_without_changing_firewall_permissions(self):
        rule = {'action': 'allow', 'from': 'home', 'to': 'guest', 'protocol': 'tcp', 'ports': [443]}
        unnamed = self.firewall([rule])
        value = copy.deepcopy(self.value)
        for name in ('Home access to guest web service', 'Lab "web"; accept — café'):
            with self.subTest(name=name):
                value['access'] = {'rules': [{'name': name, **rule}]}
                compiled = config.render(value)
                resolved = config.normalize(value)
                self.assertEqual(resolved['access']['rules'][0]['name'], name)
                self.assertEqual(compiled['etc/nftables.conf'], unnamed)

    def test_names_are_bounded_printable_labels_and_unique_ignoring_case(self):
        rule = {'action': 'allow', 'from': 'home', 'to': 'guest'}
        for name in (None, False, 7, [], {}, '', ' ', ' Leading', 'Trailing ',
                     'private-value\nnew rule', 'private-value\t', 'private-value\x00',
                     'private-value\x1b[31m', 'private-value\u202e', 'x'*97):
            with self.subTest(name=name), self.assertRaises(ReleaseError) as caught:
                self.firewall([{'name': name, **rule}])
            self.assertNotIn('private-value', str(caught.exception))
        self.firewall([{'name': 'x'*96, **rule}])
        with self.assertRaises(ReleaseError):
            self.firewall([{'name': 'Web access', **rule}, {'name': 'web ACCESS', **rule}])

    def test_masquerading_is_independent_of_access_permissions(self):
        value = copy.deepcopy(self.value)
        value['access'] = {'rules': []}
        value['uplink']['masquerade'] = True
        text = config.render(value)['etc/nftables.conf']
        self.assertIn('ip saddr 192.168.10.0/24 oifname "wan" masquerade', text)
        self.assertNotIn('iifname "lan.10" oifname "wan"', text)
        value['uplink']['masquerade'] = False
        self.assertNotIn('ip saddr 192.168.10.0/24 oifname "wan" masquerade', config.render(value)['etc/nftables.conf'])
        self.assertIn('iifname "lr-services"', config.render(value)['etc/nftables.conf'])

    def test_existing_internet_and_connection_files_still_render(self):
        value = copy.deepcopy(self.value)
        value['access'] = {'internet': ['home'], 'between_networks': [
            {'from': 'home', 'to': 'guest', 'protocol': 'tcp', 'ports': [443]}]}
        value['uplink'].pop('masquerade', None)
        text = config.render(value)['etc/nftables.conf']
        self.assertIn('iifname "lan.10" oifname "wan" accept', text)
        self.assertIn('iifname "lan.10" oifname "lan.20" tcp dport { 443 } accept', text)
        self.assertIn('ip saddr 192.168.10.0/24 oifname "wan" masquerade', text)

    def test_invalid_and_injectable_selectors_are_rejected_without_echoing_values(self):
        base = {'action': 'allow', 'from': 'home', 'to': 'guest'}
        changes = (
            {'action': 'accept'}, {'action': True}, {'protocol': 'any', 'ports': [443]},
            {'protocol': 'tcp', 'ports': [True]}, {'protocol': 'udp', 'ports': [53, 53]},
            {'protocol': 'tcp', 'ports': []}, {'protocol': 'icmp', 'family': 'ipv6'},
            {'family': None}, {'direction': None}, {'states': ['arbitrary']}, {'states': []},
            {'states': ['invalid']}, {'states': ['untracked']},
            {'from': []}, {'from': {}}, {'from': {'network': 'home', 'interface': 'tap0'}},
            {'from': {'addresses': '192.0.2.7/24'}}, {'from': {'addresses': []}},
            {'from': {'addresses': 'fe80::1%eth0'}}, {'from': {'mac': 'bad'}},
            {'to': {'mac': '02:00:00:00:00:01'}}, {'protocol': 'udp', 'tcp_flags': ['ack']},
            {'protocol': 'icmp', 'icmp_types': ['nd-router-advert']},
            {'protocol': 'tcp', 'icmp_codes': [0]}, {'protocol': 'icmp', 'icmp_codes': [True]},
            {'from': {'interface': 'private-value\nflush ruleset'}},
            {'to': 'private-value; accept'}, {'description': 'private-value\nnew rule'},
            {'from': '192.0.2.1', 'to': '2001:db8::1'},
        )
        for change in changes:
            with self.subTest(change=change), self.assertRaises(ReleaseError) as caught:
                self.firewall([{**base, **change}])
            self.assertNotIn('private-value', str(caught.exception))

    def test_default_allow_unknown_fields_and_mixed_policy_models_are_rejected(self):
        for change in ({'default': 'allow'}, {'internet': ['home']}, {'kubernetes': {}}):
            with self.subTest(change=change), self.assertRaises(ReleaseError):
                self.firewall([], **change)

    def test_expansion_is_bounded_before_configuration_is_admitted(self):
        rules = [{'action': 'allow', 'from': ['home']*16, 'to': ['guest']*16}]*17
        with self.assertRaises(ReleaseError):
            self.firewall(rules)


if __name__ == '__main__':
    unittest.main()
