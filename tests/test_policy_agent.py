"""The policy helper consumes the same ordered model as the packet compiler."""

import unittest

from lanrith import config, policy_agent
from lanrith.release import ReleaseError
from test_intent import minimal


def declaration():
    value = minimal()
    value['networks']['home']['ipv6'] = {'subnet_id': 16, 'gua': False}
    value['networks']['devices'] = {'interface': 'lan', 'vlan': 22, 'ipv4': '192.168.22.0/24',
                                   'ipv6': {'subnet_id': 22, 'gua': False}}
    value['identity'] = {'directories': {'directory': {'enabled': True,
        'url': 'ldaps://[fd42:1234:5678:10::30]:636', 'base_dn': 'dc=example,dc=test',
        'bind_dn': 'cn=router,dc=example,dc=test', 'credential': 'directory_bind',
        'ca_file': 'trust/directory.pem'}},
        'policy': {'enabled': True, 'directory': 'directory', 'networks': ['devices']}}
    value['groups'] = {'automation': ['fd42:1234:5678:10::84', 'fd42:1234:5678:10::85']}
    value['access'] = {'default': 'deny', 'rules': [
        {'action': 'deny', 'from': 'devices', 'to': {'network': 'home', 'addresses': '192.168.10.90'}},
        {'action': 'allow', 'from': {'network': 'home', 'group': 'automation'},
         'to': 'devices', 'protocol': ['tcp', 'udp'], 'ports': [6053], 'authorization': 'owner'},
        {'action': 'allow', 'from': {'group': 'automation'}, 'to': 'any', 'authorization': 'directory'},
        {'action': 'allow', 'from': 'devices', 'to': 'uplink'}]}
    return value


class PolicyAgentContractTests(unittest.TestCase):
    def test_base_firewall_bridges_only_agent_admission_marks(self):
        from lanrith import firewall
        value = config.normalize(declaration())
        text = firewall.render(value)
        self.assertIn('chain source_guard { type filter hook prerouting priority -310; policy accept;', text)
        self.assertIn('meta mark & 0xff000000 { 0xb1000000, 0xb2000000, 0xb3000000, 0xd1000000', text)
        self.assertIn('0xf6000000 } accept', text)
        self.assertNotIn('jump directory_grants', text)
        self.assertNotIn('ct state established,related accept\n }\n chain output', text)
        self.assertNotIn('chain n64_', text)
        self.assertNotIn('chain nat46_input', text)
        self.assertNotIn('flags dynamic,timeout', text)

        unmanaged = config.normalize(minimal())
        static = firewall.render(unmanaged)
        self.assertIn('chain source_guard { type filter hook prerouting priority -300; policy accept;', static)
        self.assertNotIn('meta mark & 0xff000000 { 0xb1000000', static)

    def test_service_source_allocations_are_not_inferred_from_delegation_ceilings(self):
        raw = declaration()
        raw['access']['delegation_limits'] = {'networks': ['172.31.0.0/16']}
        raw['addressing']['services'] = {'ipv4': '172.30.40.0/24',
                                       'ipv6': 'fd42:1234:5678:700::/64'}
        model = policy_agent.baseline(config.normalize(raw))['network_model']
        self.assertEqual(model['service_prefixes'], ['172.30.40.0/24',
                                                    'fd42:1234:5678:700::/64'])
        self.assertNotIn('172.31.0.0/16', model['service_prefixes'])
        raw['services'] = {'dns': {'enabled': False}, 'ntp': {'enabled': False}}
        disabled = policy_agent.baseline(config.normalize(raw))['network_model']
        self.assertEqual(disabled['service_prefixes'], [])
        self.assertEqual(disabled['rules'], model['rules'])

    def test_named_networks_and_partial_rules_do_not_become_controller_capabilities(self):
        value = config.normalize(declaration())
        result = policy_agent.baseline(value)
        self.assertNotIn('controller_initiators', result)
        self.assertEqual(result['network_model']['managed_networks'], ['devices'])
        self.assertEqual([(n['role'], n['vlan']) for n in result['zones']], [('home', 0), ('devices', 22)])
        rules = result['network_model']['rules']
        self.assertEqual(len(rules), 5)
        self.assertEqual(rules[0]['action'], 'deny')
        self.assertEqual(rules[1]['authorization'], 'owner')
        self.assertEqual(rules[1]['protocol'], 'tcp')
        self.assertEqual(rules[1]['ports'], [6053])
        self.assertEqual(rules[1]['from'], [
            {'interface': 'lan', 'addresses': ['fd42:1234:5678:10::84/128']},
            {'interface': 'lan', 'addresses': ['fd42:1234:5678:10::85/128']}])
        self.assertEqual(rules[1]['to'], [{'interface': 'lan.22'}])
        self.assertEqual(rules[2]['protocol'], 'udp')
        self.assertEqual(rules[3]['authorization'], 'directory')
        self.assertEqual(rules[4]['authorization'], 'inherit')
        # The runtime is compiled from the same model. Use an all-tagged trunk
        # for the render fixture; the baseline-only fixture above deliberately
        # retains its legacy untagged attachment.
        rendered = declaration()
        rendered['networks']['home']['vlan'] = 1
        files = config.render(rendered)
        runtime = files['etc/router-policy-agent/runtime/runtime.json']
        self.assertNotIn('access', runtime)
        self.assertNotIn('networks', runtime)
        self.assertIn('usr/lib/systemd/system/lanrith-policy-helper.service', files)
        self.assertEqual(files['usr/lib/sysctl.d/60-lanrith-policy-netlink.conf'],
                         'net.core.wmem_max = 16777216\nnet.core.rmem_max = 16777216\n')
        self.assertIn('After=nftables.service systemd-networkd.service systemd-sysctl.service',
                      files['usr/lib/systemd/system/lanrith-policy-guards.service'])

    def test_core_contract_tracks_service_ranges_families_and_network_switches(self):
        raw = declaration()
        raw['addressing']['services'] = {'ipv4': '172.30.40.0/24',
                                        'ipv6': 'fd42:1234:5678:700::/64'}
        raw['networks']['home'].update(dns=False)
        result = policy_agent.baseline(config.normalize(raw))['network_model']['core_services']
        self.assertEqual([entry['kind'] for entry in result], ['dns', 'ntp'])
        dns, ntp = result
        self.assertEqual(dns['interface'], 'lr-services')
        self.assertEqual(dns['addresses'], ['172.30.40.10', 'fd42:1234:5678:700::10'])
        self.assertEqual(dns['clients'], [{'interface': 'lan.22', 'addresses': [
            '192.168.22.0/24', 'fd42:1234:5678:16::/64']}])
        self.assertEqual({entry['interface'] for entry in ntp['clients']}, {'lan', 'lan.22'})
        raw['services'] = {'ntp': {'enabled': False}}
        self.assertEqual([entry['kind'] for entry in policy_agent.baseline(
            config.normalize(raw))['network_model']['core_services']], ['dns'])
        raw['networks']['devices']['dns'] = False
        self.assertEqual(policy_agent.baseline(config.normalize(raw))['network_model']['core_services'], [])

    def test_core_contract_retains_explicit_vpn_dns_without_ntp_or_other_routes(self):
        from test_routing import declaration as routing_declaration
        raw = declaration()
        routes = routing_declaration()
        raw['groups'].update(routes['groups'])
        raw['routing'] = routes['routing']
        result = policy_agent.baseline(config.normalize(raw))['network_model']['core_services']
        scopes = {entry['kind']: {prefix for client in entry['clients'] for prefix in client['addresses']}
                  for entry in result}
        self.assertIn('fd42:9876:5432::/48', scopes['dns'])
        self.assertNotIn('fd42:9876:5432::/48', scopes['ntp'])
        self.assertNotIn('fd42:1234:5678:400::/56', scopes['dns'])
        self.assertNotIn('fd42:1234:5678:500::/64', scopes['dns'])

    def test_core_dependency_contract_pins_source_nat_and_disabled_uplink_families(self):
        raw = declaration()
        raw['uplink']['ipv4'] = {'address': '10.243.0.2/24', 'gateway': '10.243.0.1'}
        raw['uplink']['ipv6'] = {'address': '2001:db8:100::2/48', 'gateway': '2001:db8:100::1',
                                  'downstream_prefix': '2001:db8:100::/48', 'delivery': 'on_link'}
        paths = policy_agent.baseline(config.normalize(raw))['network_model']['core_egress']
        self.assertEqual({path['kind'] for path in paths}, {'dns', 'ntp'})
        protected = policy_agent.baseline(config.normalize(raw))['protected_networks'][0]['networks']
        self.assertIn('10.243.0.2/32', protected)
        self.assertIn('2001:db8:100::2/128', protected)
        for path in paths:
            if ':' in path['address']:
                self.assertFalse(path['masquerade'])
                self.assertNotIn('translated_addresses', path)
            else:
                self.assertTrue(path['masquerade'])
                self.assertEqual(path['translated_addresses'], ['10.243.0.2'])
        raw['uplink']['ipv4'] = 'disabled'
        self.assertTrue(all(':' in path['address'] for path in
            policy_agent.baseline(config.normalize(raw))['network_model']['core_egress']))
        raw['uplink']['ipv4'] = 'dhcp'
        dynamic = policy_agent.baseline(config.normalize(raw))['network_model']['core_egress']
        self.assertTrue(all(path['masquerade'] and not path.get('translated_addresses')
                            for path in dynamic if ':' not in path['address']))

    def test_ntp_numeric_dns_dependency_is_exact_and_disappears_with_ntp(self):
        raw = declaration()
        raw['services'] = {'dns': {'enabled': False, 'upstreams': ['9.9.9.9', '2620:fe::fe']}}
        paths = policy_agent.baseline(config.normalize(raw))['network_model']['core_egress']
        self.assertEqual({path['kind'] for path in paths}, {'ntp', 'ntp_dns'})
        resolvers = {destination for path in paths if path['kind'] == 'ntp_dns'
                     for destination in path['destinations']}
        self.assertEqual(resolvers, {'9.9.9.9/32', '2620:fe::fe/128'})
        raw['services']['ntp'] = {'enabled': False}
        self.assertEqual(policy_agent.baseline(config.normalize(raw))['network_model']['core_egress'], [])

    def test_asymmetric_replies_are_distinct_ipv6_return_predicates(self):
        raw = declaration()
        raw['routing'] = {'asymmetric_replies': [
            {'mode': 'tcp_dsr',
             'from': {'network': 'home', 'addresses': 'fd42:1234:5678:10::/64'},
             'to': {'network': 'home', 'addresses': 'fd42:1234:5678:10::50/128'}},
            {'mode': 'icmp_echo_reply',
             'from': {'network': 'devices', 'addresses': 'fd42:1234:5678:16::20/128'},
             'to': {'network': 'home', 'addresses': 'fd42:1234:5678:10::50/128'}},
        ]}
        replies = policy_agent.baseline(config.normalize(raw))['network_model']['asymmetric_replies']
        self.assertEqual(replies, [
            {'mode': 'tcp_dsr', 'source_interface': 'lan',
             'source_addresses': ['fd42:1234:5678:10::/64'], 'destination_interface': 'lan',
             'destination_addresses': ['fd42:1234:5678:10::50/128']},
            {'mode': 'icmp_echo_reply', 'source_interface': 'lan.22',
             'source_addresses': ['fd42:1234:5678:16::20/128'], 'destination_interface': 'lan',
             'destination_addresses': ['fd42:1234:5678:10::50/128']},
        ])

    def test_optional_listener_contract_uses_exact_existing_clients(self):
        from test_authoritative import declaration as authority_declaration
        raw = declaration()
        raw['services'] = authority_declaration()['services']
        raw['networks']['devices']['dns'] = False
        raw['observability'] = {'metrics': {'enabled': True, 'clients': [
            {'network': 'home', 'addresses': '192.168.10.30/32'}]}}
        services = {item['kind']: item for item in
                    policy_agent.baseline(config.normalize(raw))['network_model']['core_services']}
        self.assertEqual(services['metrics']['addresses'], ['10.255.254.50', 'fd42:1234:5678:fe02::50'])
        self.assertEqual(services['metrics']['clients'], [
            {'interface': 'lan', 'addresses': ['192.168.10.30/32']}])
        authority_sources = {prefix for client in services['authoritative']['clients']
                             for prefix in client['addresses']}
        self.assertIn('192.168.10.20/32', authority_sources)
        self.assertIn('192.168.10.21/32', authority_sources)
        self.assertNotIn('192.168.22.0/24', authority_sources)
        raw['services']['dns']['authoritative']['enabled'] = False
        raw['observability']['metrics']['enabled'] = False
        self.assertEqual({item['kind'] for item in policy_agent.baseline(
            config.normalize(raw))['network_model']['core_services']}, {'dns', 'ntp'})

    def test_uplink_source_nat_geometry_tracks_real_masquerade_and_retains_access(self):
        from lanrith import firewall
        raw = declaration()
        raw['uplink']['ipv4'] = {'address': '10.243.0.2/24', 'gateway': '10.243.0.1'}
        raw['hardware']['interfaces']['oob'] = {'name': 'oob', 'match': {'mac': '02:00:00:00:99:01'}}
        raw['networks']['management'] = {'interface': 'oob', 'role': 'management', 'ipv4': '10.99.0.0/24'}
        value = config.normalize(raw)
        model = policy_agent.baseline(value)['network_model']
        self.assertEqual(model['uplink_nat'], [
            {'interface': 'lan', 'sources': ['192.168.10.0/24'], 'addresses': ['10.243.0.2']},
            {'interface': 'lan.22', 'sources': ['192.168.22.0/24'], 'addresses': ['10.243.0.2']}])
        original_rules = model['rules']
        for path in model['uplink_nat']:
            for prefix in path['sources']:
                self.assertIn(f'ip saddr {prefix} oifname "wan" masquerade', firewall.render(value))
        raw['uplink']['masquerade'] = False
        disabled = policy_agent.baseline(config.normalize(raw))['network_model']
        self.assertEqual(disabled['uplink_nat'], [])
        self.assertEqual(disabled['rules'], original_rules)
        raw['uplink']['masquerade'] = True
        raw['uplink']['ipv4'] = 'dhcp'
        self.assertTrue(all(not path['addresses'] for path in policy_agent.baseline(
            config.normalize(raw))['network_model']['uplink_nat']))
        raw['uplink']['ipv4'] = 'disabled'
        self.assertEqual(policy_agent.baseline(config.normalize(raw))['network_model']['uplink_nat'], [])

    def test_metadata_does_not_change_ceiling_but_enforcement_changes_do(self):
        raw = declaration()
        original = policy_agent.baseline(config.normalize(raw))
        raw['access']['rules'][0]['name'] = 'Descriptive metadata'
        raw['access']['rules'][0]['description'] = 'For operators'
        self.assertEqual(original, policy_agent.baseline(config.normalize(raw)))
        raw['access']['rules'][1]['ports'] = [80]
        self.assertNotEqual(original['generation'], policy_agent.baseline(config.normalize(raw))['generation'])

    def test_implicit_router_management_services_and_explicit_delegation_ceilings(self):
        raw = declaration()
        raw['hardware']['interfaces']['oob'] = {'name': 'oob', 'match': {'mac': '02:00:00:00:99:01'}}
        raw['networks']['management'] = {'interface': 'oob', 'role': 'management',
            'ipv4': {'subnet': '10.99.0.0/24', 'address': '10.99.0.11'}}
        raw['access']['delegation_limits'] = {'networks': ['fd42:1234:5678:400::/56'],
            'endpoints': [{'addresses': '192.168.10.40/30', 'protocol': 'tcp', 'ports': [22, 443]}]}
        result = policy_agent.baseline(config.normalize(raw))
        self.assertEqual({n['role'] for n in result['zones']}, {'home', 'devices'})
        networks = [p for block in result['protected_networks'] for p in block['networks']]
        for prefix in ('10.99.0.0/24', '10.99.0.11/32', '192.168.10.1/32',
                       '10.255.254.0/24', 'fd42:1234:5678:fe02::/64', 'fd42:1234:5678:400::/56'):
            self.assertIn(prefix, networks)
        self.assertIn({'protection_id': 'P02', 'networks': ['192.168.10.40/30'],
                       'protocol': 'tcp', 'ports': [22, 443], 'destination_only': True}, result['protected_endpoints'])

    def test_each_translator_has_its_own_ceiling_and_disabled_components_disappear(self):
        import json
        from lanrith import firewall, nat64
        for n64, n46 in ((True, False), (False, True), (True, True), (False, False)):
            raw = declaration()
            raw['translation'] = {'nat64': {'enabled': n64}, 'nat46': {'enabled': n46,
                'mappings': {'application': {'ipv4': '10.255.200.10', 'ipv6': 'fd42:1234:5678:10::20'}}}}
            with self.subTest(nat64=n64, nat46=n46):
                result = policy_agent.baseline(config.normalize(raw))
                self.assertEqual(len(result['nat64']), 2 if n64 else 0)
                self.assertEqual(len(result['nat46']), 1 if n46 else 0)
                self.assertEqual(bool(result['nat46_pools']), n46)
                if n46:
                    self.assertEqual(result['network_model']['nat46_prefix'],
                                     config.intent.translations(config.normalize(raw))['nat46']['prefix'])
                else:
                    self.assertNotIn('nat46_prefix', result['network_model'])
                floor = firewall.render(config.normalize(raw))
                self.assertNotIn('flags dynamic,timeout', floor)
                self.assertNotIn('chain nat46_input', floor)
                self.assertNotIn('chain n64_input', floor)
                self.assertEqual('nat64' in floor, n64)
                self.assertEqual('nat46' in floor, n46)
                if n64:
                    runtime = json.loads(nat64.render(config.normalize(raw))[
                        'etc/router-policy-agent/nat64-runtime/runtime.json'])
                    for index, component in enumerate(runtime['components']):
                        self.assertEqual(component['pending_family'], 'inet')
                        self.assertEqual(component['pending_table'], 'router_policy_agent')
                        self.assertEqual(component['pending_set'], f'native_n64_{index}_pending')

    def test_unsupported_packet_predicates_are_not_silently_discarded(self):
        for field, entry in (('states', ['established']), ('tcp_flags', ['ack']), ('direction', 'reply')):
            raw = declaration()
            raw['access']['rules'][1]['protocol'] = 'tcp'
            raw['access']['rules'][1][field] = entry
            with self.subTest(field=field), self.assertRaisesRegex(ReleaseError, 'packet-state-specific'):
                policy_agent.baseline(config.normalize(raw))
        raw = declaration()
        raw['identity']['policy']['enabled'] = False
        raw['access']['rules'] = []
        with self.assertRaises(ReleaseError):
            policy_agent.baseline(config.normalize(raw))

    def test_retained_nat64_sources_do_not_depend_on_nat46_destination_maps(self):
        raw = declaration()
        raw['translation'] = {'nat64': {'enabled': True}, 'nat46': {'enabled': False}}
        retained = {'fd42:1234:5678:10::84': '10.255.223.200',
                    'fd42:1234:5678:10::85': '10.255.223.201',
                    'fd42:1234:5678:10::86': '10.255.223.202'}
        result = policy_agent.baseline(config.normalize(raw), retained)
        self.assertEqual(result['nat46'], [])
        self.assertEqual(result['nat46_pools'], [])
        component = next(c for c in result['nat64'] if c['id'] == 'nat64-internal')
        self.assertEqual(component['source_pool'], '10.255.208.0/20')
        self.assertEqual({item['source']: item['alias'] for item in component['source_mappings']}, retained)
        self.assertEqual([item['ready'] for item in component['source_mappings']], [True, True, False])
        with self.assertRaises(ReleaseError):
            policy_agent.baseline(config.normalize(raw), {**retained, 'fd42:1234:5678:10::87': '10.255.223.200'})
        raw['translation']['nat64']['enabled'] = False
        with self.assertRaises(ReleaseError):
            policy_agent.baseline(config.normalize(raw), retained)
