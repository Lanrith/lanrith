"""NAT64 policy projection retains logical destinations and source identity."""

import ipaddress as ip
import json
import unittest

from lanrith import config, firewall, nat64, nat64_packets, translation_runtime
from nat64_native import declaration


class Nat64Tests(unittest.TestCase):
    def test_private_route_samples_scale_with_fixed_allocations_and_peer_ranges(self):
        manifest = next(m for m in nat64.manifests(config.normalize(declaration()))
                        if m['interface'] == 'nat64-internal')
        pool = ip.ip_network(manifest['pool'])
        prefix = ip.ip_network(manifest['prefix']).network_address
        active = {str(ip.IPv6Address('fd42::100')+i): str(pool.broadcast_address-1-i) for i in range(255)}
        clients = [('v'+str(i), f'fd43:{i:x}::2') for i in range(64)]
        clients.extend(('v0', source) for source in active)
        peers = [('v'+str(i), f'10.64.{i}.2') for i in range(64)]
        manifest['source_allocations'] = {'active': active, 'reserved': active}
        manifest['route_contexts'] = {'clients': clients, 'peers': peers}
        cases = set(translation_runtime.forwarding_cases(manifest))
        # Each later peer expands only by the fixed identities and one sample.
        self.assertEqual(len(cases), 2+len(clients)+63*256+64*257)
        for attachment, peer in peers:
            synthesized = str(prefix+int(ip.ip_address(peer)))
            for source, alias in active.items():
                self.assertIn((synthesized, 'v0', source, 'forward'), cases)
                self.assertIn((alias, attachment, peer, 'return'), cases)

        del manifest['route_contexts']
        older = list(translation_runtime.forwarding_cases(manifest))
        self.assertTrue(all(case[1:3] == (None, None) for case in older))
        self.assertEqual({case[0] for case in older if case[-1] == 'return'},
                         set(active.values()) | {str(pool.network_address+2),
                                                 str(pool.network_address+pool.num_addresses//4)})

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
        text = firewall.render(value, access_backend='legacy')
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
            self.assertIn('MemoryMax=256M\nMemorySwapMax=0\nTasksMax=32\nLimitNOFILE=1024\n',
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
