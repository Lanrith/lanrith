"""NAT64 policy projection retains logical destinations and source identity."""

import json
import unittest

from lanrith import config, firewall, nat64, nat64_packets
from nat64_native import declaration


class Nat64Tests(unittest.TestCase):
    def test_encoded_destination_keeps_address_with_its_attachment(self):
        value = config.normalize(declaration())
        for manifest in nat64.manifests(value):
            encoded = manifest['prefix']
            for selected, expected in (
                    ({'interface': manifest['interface'], 'addresses': encoded}, True),
                    ({'network': 'servers', 'addresses': '192.0.2.2'}, True),
                    ({'interface': manifest['interface'], 'addresses': '192.0.2.2'}, False),
                    ({'network': 'servers', 'addresses': encoded}, False)):
                with self.subTest(component=manifest['interface'], selected=selected):
                    rule = {'action': 'allow', 'from': 'home', 'to': selected}
                    self.assertEqual(bool(nat64.targets(value, rule, manifest, 'servers')), expected)


    def test_ipv4_destination_deny_precedes_translation_permission_for_each_egress(self):
        value = config.normalize(declaration())
        for manifest in nat64.manifests(value):
            for destination in nat64.attachments(value):
                rules = nat64.original_rules(value, manifest, destination)
                self.assertIn('fd42:1234:5678:10::90/128', rules[0])
                self.assertTrue(rules[0].endswith('drop'))
                self.assertEqual(len(rules), 4)
                self.assertIn('oifname "'+manifest['interface']+'"', rules[0])
                self.assertTrue(rules[-1].endswith('accept'))

    def test_partial_cross_family_rule_keeps_interface_mac_destination_and_port(self):
        raw = declaration()
        raw['access']['rules'] = [{
            'action': 'allow', 'authorization': 'owner', 'protocol': 'tcp', 'ports': [443],
            'from': {'network': 'home', 'addresses': 'fd42:1234:5678:10::2', 'mac': '02:00:00:00:01:02'},
            'to': {'network': 'servers', 'addresses': '192.0.2.2'}}]
        value = config.normalize(raw)
        for manifest in nat64.manifests(value):
            self.assertEqual(nat64.original_rules(value, manifest, 'wan'), [])
            rules = nat64.original_rules(value, manifest, 'servers')
            self.assertEqual(len(rules), 1)
            for scope in ('iifname "lan"', 'fd42:1234:5678:10::2/128',
                          'ether saddr 02:00:00:00:01:02', 'tcp dport { 443 }'):
                self.assertIn(scope, rules[0])

    def test_first_match_is_terminal_and_old_proofs_do_not_admit_an_original_packet(self):
        value = config.normalize(declaration())
        text = firewall.render(value)
        self.assertIn('goto n64_first_a0', text)
        self.assertNotIn('_eligible', text)
        self.assertNotIn('meta mark', text)
        self.assertLess(text.index('iifname "nat64" drop'),
                        text.index('ct state established,related accept'))
        self.assertLess(text.index('ct state invalid,untracked drop'), text.index('jump n64_output'))
        self.assertIn('ip6 saddr . @nh,288,32', text)
        self.assertIn('flags dynamic,timeout; timeout 2s', text)

    def test_allocation_map_carries_literal_identity_without_changing_packet_marks(self):
        manifest = nat64.manifests(config.normalize(declaration()))[0]
        rules = nat64_packets.client_chains(manifest, {'fd42:1234:5678:10::2': '10.255.224.4'})
        self.assertIn('fd42:1234:5678:10::2 . @nh,128,32 . tcp sport . tcp dport @n64_tcp_forward_0', rules)
        self.assertIn('ip saddr 10.255.224.4 ct protocol udp', rules)
        self.assertIn('10.255.224.4 : jump n64_c0affe004', rules)
        self.assertNotIn('meta mark', rules)

    def test_translator_accounts_and_state_are_independent_of_nat46(self):
        value = config.normalize(declaration())
        files = nat64.render(value)
        self.assertIn('etc/tayga.conf', files)
        self.assertIn('etc/tayga-nat64-internal.conf', files)
        self.assertNotIn('etc/tayga-nat46.conf', files)
        for manifest in nat64.manifests(value):
            name = manifest['interface']
            self.assertIn('ReadWritePaths='+manifest['state_directory'],
                          files['usr/lib/systemd/system/lanrith-'+name+'.service'])
            self.assertIn('u lanrith-'+name, files['usr/lib/sysusers.d/80-lanrith-'+name+'.conf'])
        runtime = json.loads(files['etc/router-policy-agent/nat64-runtime/runtime.json'])
        self.assertEqual(runtime, {'schema_version': 1, 'components': [
            {'id': 'nat64', 'status_directory': '/run/lanrith-nat64',
             'configuration_file': '/run/lanrith-nat64/tayga.conf', 'executable': '/usr/sbin/tayga',
             'username': 'lanrith-nat64'},
            {'id': 'nat64-internal', 'status_directory': '/run/lanrith-nat64-internal',
             'configuration_file': '/run/lanrith-nat64-internal/tayga.conf',
             'executable': '/usr/lib/lanrith/tayga-internal', 'username': 'lanrith-nat64-internal'}]})
        raw = declaration()
        raw['translation']['nat64']['enabled'] = False
        raw['access']['rules'] = []
        disabled = config.normalize(raw)
        self.assertEqual(nat64.render(disabled), {})
        self.assertNotIn('n64', firewall.render(disabled))

    def test_names_are_metadata_and_translators_can_be_enabled_together(self):
        raw = declaration()
        expected = firewall.render(config.normalize(raw))
        for index, rule in enumerate(raw['access']['rules']):
            rule['name'] = 'Owner intent '+str(index)
        self.assertEqual(firewall.render(config.normalize(raw)), expected)
        self.assertIn('usr/share/lanrith/nat64.json', config.render(raw))
        raw['translation']['nat46'] = {'enabled': True, 'mappings': {
            'example': {'ipv4': '10.255.200.2', 'ipv6': 'fd42:1234:5678:10::20'}}}
        files = config.render(raw)
        for name in ('nat46', 'nat64', 'nat64-internal'):
            self.assertIn('usr/share/lanrith/'+name+'.json', files)
        self.assertIn('iifname { "nat64", "nat64-internal", "nat46" } '
                      'oifname { "nat64", "nat64-internal", "nat46" } drop', files['etc/nftables.conf'])


if __name__ == '__main__':
    unittest.main()
