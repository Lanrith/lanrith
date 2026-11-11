"""TUN compilation retains selector conjunctions, ordering and bounded code."""

import copy
import ipaddress as ip
import unittest

from lanrith import config, firewall, intent, tun_policy
from lanrith.release import ReleaseError
from nat64_native import declaration as nat64_declaration
from test_nat46 import declaration as nat46_declaration
from test_policy_agent import declaration as directory_declaration


class TunPolicyTests(unittest.TestCase):
    def test_nat64_partial_permission_keeps_interface_address_mac_and_port(self):
        raw = nat64_declaration()
        raw['access']['rules'] = [{'action': 'allow', 'authorization': 'owner', 'protocol': 'tcp',
            'ports': [443], 'from': {'network': 'home', 'addresses': 'fd42:1234:5678:10::2',
                                    'mac': '02:00:00:00:01:02'},
            'to': {'network': 'servers', 'addresses': '192.0.2.2'}}]
        value = config.normalize(raw)
        program = tun_policy.compile(value)
        self.assertEqual(program['access_rules'], 1)
        self.assertIn('ether saddr', program['rules'][0])
        self.assertIn('tcp dport { 443 }', program['rules'][0])
        data = '\n'.join(program['declarations'])
        self.assertIn('"lan" . fd42:1234:5678:10::2/128 . 02:00:00:00:01:02', data)
        self.assertIn('"nat64-internal" . fd42:1234:5678:fd65::c000:202/128', data)
        self.assertNotIn('"nat64-internal" . fd42:1234:5678:fd65::/96', data)

    def test_source_group_alternatives_do_not_mix_attachment_and_address(self):
        value = config.normalize(nat64_declaration())
        compiler = tun_policy.Compiler(value)
        rows = set().union(*(compiler.sources(compiler.endpoint(endpoint, True), 6) for endpoint in (
            {'network': 'home', 'addresses': 'fd42:1234:5678:10::2'},
            {'network': 'guest', 'addresses': 'fd42:1234:5678:20::2'})))
        self.assertIn(('lan', ip.ip_network('fd42:1234:5678:10::2'), None), rows)
        self.assertNotIn(('lan', ip.ip_network('fd42:1234:5678:20::2'), None), rows)

    def test_ipv4_source_to_wan_does_not_emit_an_unreachable_ipv6_callback(self):
        raw = nat64_declaration()
        raw['access']['rules'] = [{'action': 'deny', 'from': {'network': 'servers', 'addresses': '192.0.2.2'},
                                   'to': 'uplink'}]
        program = tun_policy.compile(config.normalize(raw))
        self.assertEqual(program['access_rules'], 1)
        self.assertIn('meta nfproto ipv4', program['rules'][0])

    def test_mapping_count_changes_data_instead_of_copying_policy(self):
        counts = []
        for size in (1, 6, 60):
            raw = nat46_declaration()
            raw['access']['rules'] = [raw['access']['rules'][1]]
            raw['translation']['nat46']['mappings'] = {
                'service'+str(i): {'ipv4': '10.255.200.'+str(i+2),
                                   'ipv6': 'fd42:1234:5678:20::'+format(i+10, 'x')} for i in range(size)}
            program = tun_policy.compile(config.normalize(raw))
            counts.append(program['access_rules'])
        self.assertEqual(counts, [3, 3, 3])

    def test_address_lists_and_network_groups_do_not_copy_transport_clauses(self):
        raw = nat64_declaration()
        raw['groups'] = {'sources': [{'network': 'home', 'addresses': [
            'fd42:1234:5678:10::'+format(i+2, 'x') for i in range(60)]}]}
        raw['access']['rules'] = [{'action': 'allow', 'from': {'group': 'sources'},
            'to': {'translation': 'nat64'}, 'protocol': ['tcp', 'udp', 'icmp'], 'authorization': 'owner'}]
        self.assertEqual(tun_policy.compile(config.normalize(raw))['access_rules'], 3)

    def test_ordered_deny_and_terminal_directory_survive_a_later_owner_allow(self):
        value = config.normalize(directory_declaration())
        program = tun_policy.compile(value)
        self.assertTrue(program['rules'][0].endswith('drop'))
        directory = next(i for i, line in enumerate(program['rules']) if line.endswith('goto tp_directory'))
        self.assertGreater(directory, 0)
        code = '\n'.join(tun_policy.definitions(value))
        self.assertIn(f'chain tp_directory {{ ct mark set {tun_policy.DIRECTORY} goto tp_fresh;', code)
        self.assertIn('ct original proto-dst @tp_grants6 accept\n  drop\n }', code)

    def test_rule_names_and_descriptions_leave_enforcement_unchanged(self):
        raw = nat64_declaration()
        before = tun_policy.definitions(config.normalize(raw))
        for i, rule in enumerate(raw['access']['rules']):
            rule.update(name='Description '+str(i), description='Owner metadata')
        self.assertEqual(tun_policy.definitions(config.normalize(raw)), before)

    def test_inherit_recognizes_a_managed_peer_after_nat64(self):
        raw = directory_declaration()
        raw['translation'] = {'nat64': {'enabled': True}}
        value = config.normalize(raw)
        text = '\n'.join(tun_policy.definitions(value))
        self.assertIn('iifname "nat64-internal" ip6 saddr fd42:1234:5678:fd65::c0a8:1600/120 goto tp_directory', text)
        self.assertIn('oifname "nat64-internal" ip6 daddr fd42:1234:5678:fd65::c0a8:1600/120 goto tp_directory', text)
        self.assertLess(tun_policy.forward().index('  ct status & 512 != 0 drop'),
                        tun_policy.forward().index(f'  ct state established,related ct direction reply ct mark {tun_policy.OWNER} accept'))

    def test_retained_source_assignments_bound_both_tayga_and_callback_guards(self):
        raw = nat64_declaration()
        raw['access']['rules'].append({'action': 'allow', 'from': 'fd42:1234:5678:10::2',
                                      'to': {'translation': 'nat64'}, 'authorization': 'owner'})
        value = config.normalize(raw)
        retained = {'fd42:1234:5678:10::2': '10.255.223.200'}
        text = '\n'.join(tun_policy.definitions(value, retained))
        self.assertIn('oifname "nat64-internal" ip daddr { 10.255.223.200 }', text)
        self.assertIn('ip6 daddr != { fd42:1234:5678:10::2 } drop', text)
        self.assertIn('oifname "nat64" meta nfproto ipv4 drop', text)
        self.assertNotIn('dynamic.map', text)

    def test_each_enablement_combination_removes_disabled_components(self):
        for nat64 in (False, True):
            for nat46 in (False, True):
                raw = nat64_declaration()
                raw['translation']['nat64']['enabled'] = nat64
                raw['translation']['nat46'] = nat46_declaration()['translation']['nat46']
                raw['translation']['nat46']['enabled'] = nat46
                raw['access']['rules'] = []
                text = '\n'.join(tun_policy.definitions(config.normalize(raw)))
                with self.subTest(nat64=nat64, nat46=nat46):
                    self.assertEqual('oifname "nat64"' in text, nat64)
                    self.assertEqual('oifname "nat46"' in text, nat46)
                    self.assertEqual('map tp_routes4' in text, nat64)
                    self.assertEqual('map tp_routes6' in text, nat46)

    def test_declared_route_partition_excludes_lans_from_wan(self):
        value = config.normalize(nat64_declaration())
        routes = tun_policy.route_scopes(value, 4)
        for address, expected in (('192.0.2.2', 'servers'), ('93.184.216.2', 'wan')):
            matches = [interface for prefix, interface in routes if ip.ip_address(address) in prefix]
            self.assertEqual(matches, [expected])

    def test_longest_prefix_static_route_retains_its_attachment(self):
        value = config.normalize(nat64_declaration())
        value['routing'] = {'static_routes': [
            {'to': '198.51.100.0/24', 'network': 'servers', 'on_link': True}]}
        routes = tun_policy.route_scopes(value, 4)
        self.assertEqual([interface for prefix, interface in routes
                          if ip.ip_address('198.51.100.9') in prefix], ['servers'])

    def test_unknown_backend_is_rejected_and_tun_is_the_default(self):
        value = config.normalize(nat64_declaration())
        self.assertEqual(firewall.render(value), firewall.render(value, access_backend='tun'))
        with self.assertRaises(ReleaseError):
            firewall.render(value, access_backend='unknown')
        text = firewall.render(value, access_backend='tun')
        for retired in ('timeout 2s', 'meta mark & 0xff000000', 'chain n64_first', '_pending'):
            self.assertNotIn(retired, text)
        self.assertIn('oifname "nat64" meta nfproto ipv6', text)
        self.assertIn('iifname "nat64-internal" meta nfproto ipv6', text)
        self.assertIn('iifname "nat46" meta nfproto ipv4',
                      firewall.render(config.normalize(nat46_declaration()), access_backend='tun'))

    def test_build_selector_emits_native_services_and_strict_runtime_contract(self):
        import json
        raw = directory_declaration()
        raw['networks']['home']['vlan'] = 1
        raw['translation'] = {'nat64': {'enabled': True}}
        files = config.render(raw, access_backend='tun')
        self.assertIn('jump tp_identity', files['etc/nftables.conf'])
        self.assertEqual(files['usr/lib/lanrith-build/policy-backend'], 'tun\n')
        contract = json.loads(files['etc/router-policy-agent/runtime/runtime.json'])
        self.assertEqual(contract['backend'], 'tun')
        for name in ('nat64', 'nat64-internal'):
            unit = files['usr/lib/systemd/system/lanrith-'+name+'.service']
            self.assertIn('User=lanrith-'+name, unit)
            self.assertIn('CapabilityBoundingSet=\n', unit)
            self.assertIn('ExecStart=/usr/lib/lanrith/tayga-internal --nodetach --config /etc/', unit)
        text = '\n'.join(files.values())
        self.assertNotIn('lanrith.nat64_runtime', text)
        self.assertNotIn('nat64-runtime/runtime.json', files)

    def test_identity_guards_precede_owner_reply_shortcut_and_are_optional(self):
        value = config.normalize(directory_declaration())
        self.assertEqual(tun_policy.forward(value)[0], '  jump tp_identity')
        text = '\n'.join(tun_policy.definitions(value))
        self.assertIn('iifname . ether saddr . ip saddr @tp_bound4 return', text)
        self.assertIn('oifname . ip6 daddr @tp_dest6 return', text)
        self.assertIn('numgen inc mod 1 != @tp_started drop', text)
        value['identity']['policy']['enabled'] = False
        self.assertNotIn('tp_identity', '\n'.join(tun_policy.definitions(value)))
        self.assertNotIn('tp_started', '\n'.join(tun_policy.definitions(value)))

    def test_asymmetric_replies_are_ipv6_scoped_and_keep_identity_checks(self):
        raw = directory_declaration()
        raw['routing'] = {'asymmetric_replies': [
            {'mode': mode, 'from': {'network': 'home', 'addresses': 'fd42:1234:5678:10::2'},
             'to': {'network': 'home', 'addresses': 'fd42:1234:5678:10::3'}}
            for mode in ('tcp_dsr', 'icmp_echo_reply')]}
        value = config.normalize(raw)
        text = firewall.render(value, access_backend='tun')
        self.assertLess(text.index('  jump tp_asymmetric'), text.index('  ct state invalid,untracked drop'))
        code = '\n'.join(tun_policy.asymmetric_definitions(value))
        self.assertIn('tcp flags & (syn | ack | rst) == ack goto tp_asymmetric_allow', code)
        self.assertIn('icmpv6 type echo-reply goto tp_asymmetric_allow', code)
        self.assertIn('chain tp_asymmetric_allow {\n  jump tp_identity\n  accept', code)
        self.assertNotIn('ipv4_addr', code)

    def test_unrecoverable_callback_mac_is_rejected_rather_than_ignored(self):
        value = config.normalize(nat64_declaration())
        value['access']['rules'] = [{'action': 'deny',
            'from': {'network': 'servers', 'addresses': '192.0.2.2', 'mac': '02:00:00:00:01:02'},
            'to': {'network': 'home', 'addresses': 'fd42:1234:5678:10::2'}}]
        with self.assertRaisesRegex(ReleaseError, 'physical ingress evidence'):
            tun_policy.compile(value)


if __name__ == '__main__':
    unittest.main()
