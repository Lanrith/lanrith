"""Configuration matrices and adversarial cross-component references."""

import copy
import ipaddress
import json
from pathlib import Path
import unittest

from lanrith import hardware_config, config, hardware, integrations, intent, translation
from lanrith.release import ReleaseError


ROOT = Path(__file__).resolve().parents[1]


def minimal():
    value = config.load(ROOT/'examples/minimal.yaml')
    for key in ('addressing', 'services'):
        value.pop(key, None)
    value['networks'] = {'home': {'interface': 'lan', 'ipv4': '192.168.10.0/24',
                                'dhcp4': {'pools': ['192.168.10.100-192.168.10.150']}}}
    value['addressing'] = {'ula_prefix': 'fd42:1234:5678::/48'}
    return value


class IntentTests(unittest.TestCase):
    def test_minimal_defaults_and_managed_addresses(self):
        value = config.normalize(minimal())
        self.assertEqual(value, config.normalize(value))
        self.assertEqual(value['networks']['home']['addresses'], ['192.168.10.1/24'])
        files = config.render(value)
        scope = json.loads(files['etc/kea/kea-dhcp4.conf'])['Dhcp4']['subnet4'][0]
        options = {item['name']: item['data'] for item in scope['option-data']}
        self.assertEqual(options, {'routers': '192.168.10.1', 'domain-name-servers': '10.255.254.10',
                                  'ntp-servers': '10.255.254.40'})
        self.assertIn('NetworkNamespacePath=/run/netns/lanrith-services',
                      files['etc/systemd/system/unbound.service.d/60-lanrith-services.conf'])
        self.assertEqual(intent.service_addresses(value, 'dns'), ['10.255.254.10', 'fd42:1234:5678:fe02::10'])
        self.assertEqual(files['etc/lanrith/chrony-resolv.conf'], 'nameserver 127.0.0.1\n')

    def test_families_and_all_ra_gua_combinations(self):
        for ipv4 in (False, True):
            for ra in (False, True):
                for gua in (False, True):
                    value = minimal()
                    value['uplink']['ipv6'] = {'address': '2001:db8:10::2/48', 'gateway': '2001:db8:10::1',
                        'downstream_prefix': '2001:db8:10::/48', 'delivery': 'on_link'}
                    lan = value['networks']['home']
                    lan['ipv6'] = {'subnet_id': 16, 'ra': ra, 'gua': gua}
                    if not ipv4:
                        del lan['ipv4'], lan['dhcp4']
                    with self.subTest(ipv4=ipv4, ra=ra, gua=gua):
                        normalized = config.normalize(value)
                        files = config.render(normalized)
                        network = files['etc/systemd/network/40-home.network']
                        self.assertIn('Address=fd42:1234:5678:10::1/64', network)
                        self.assertEqual('Address=2001:db8:10:10::1/64' in network, gua)
                        self.assertIn('IPv6SendRA='+('yes' if ra else 'no'), network)
                        self.assertIn('LinkLocalAddressing=ipv6', network)
                        self.assertEqual('[IPv6Prefix]' in network, ra)

    def test_management_is_not_a_transit_or_service_network(self):
        value = minimal()
        value['networks']['home'] = {'interface': 'lan', 'role': 'management',
            'ipv4': {'subnet': '192.168.10.0/24', 'address': '192.168.10.11'}}
        normalized = config.normalize(value)
        self.assertEqual(normalized['networks']['home']['addresses'], ['192.168.10.11/24'])
        firewall = config.render(normalized)['etc/nftables.conf']
        self.assertIn('iifname "lan" drop', firewall)
        self.assertIn('oifname "lan" drop', firewall)
        self.assertNotIn('iifname "lan" oifname "lr-services"', firewall)

    def test_global_and_network_disabling_remove_connectivity_and_listeners(self):
        for name in ('dns', 'ntp', 'dhcp4'):
            value = minimal()
            value['services'] = {name: {'enabled': False}}
            normalized = config.normalize(value)
            files = config.render(normalized)
            paths = {'dns': 'etc/unbound/unbound.conf.d/lanrith.conf',
                     'ntp': 'etc/chrony/chrony.conf', 'dhcp4': 'etc/kea/kea-dhcp4.conf'}
            self.assertNotIn(paths[name], files)
        value = minimal()
        value['networks']['home'].update(dns=False, ntp=False, dhcp4={'enabled': False})
        files = config.render(value)
        self.assertNotIn('iifname "lan" oifname "lr-services"', files['etc/nftables.conf'])
        self.assertNotIn('allow 192.168.10.0/24', files['etc/chrony/chrony.conf'])

    def test_custom_service_ranges_and_conflicts(self):
        value = minimal()
        value['addressing']['services'] = {'ipv4': '172.30.40.0/24', 'ipv6': 'fd42:1234:5678:700::/64'}
        normalized = config.normalize(value)
        self.assertEqual(intent.service_addresses(normalized, 'ntp'), ['172.30.40.40', 'fd42:1234:5678:700::40'])
        for pool in ('192.168.10.0/24', '172.30.40.0/28', '224.0.0.0/24', '172.30.40.1/24'):
            value['addressing']['services']['ipv4'] = pool
            with self.subTest(pool=pool), self.assertRaises(ReleaseError):
                config.normalize(value)

    def test_split_pools_and_reservations_never_fill_gaps(self):
        value = minimal()
        dhcp = value['networks']['home']['dhcp4']
        dhcp['pools'] = ['192.168.10.100-192.168.10.110', '192.168.10.120-192.168.10.130']
        dhcp['reservations'] = [{'mac': '02:00:00:00:00:01', 'address': '192.168.10.115'}]
        scope = json.loads(config.render(value)['etc/kea/kea-dhcp4.conf'])['Dhcp4']['subnet4'][0]
        self.assertEqual([p['pool'] for p in scope['pools']], dhcp['pools'])
        self.assertEqual(scope['reservations'][0]['ip-address'], '192.168.10.115')
        dhcp['reservations'][0]['address'] = '192.168.10.105'
        with self.assertRaises(ReleaseError):
            config.normalize(value)

    def test_translation_matrix_preserves_independence_and_derived_prefixes(self):
        for nat64 in (False, True):
            for nat46 in (False, True):
                value = minimal()
                value['translation'] = {'nat64': {'enabled': nat64}, 'nat46': {'enabled': nat46,
                    'mappings': {'service': {'ipv4': '10.255.200.2', 'ipv6': 'fd42:1234:5678:10::90'}}}}
                value = config.normalize(value)
                components = intent.translations(value)
                self.assertEqual(set(components), ({'nat64', 'nat64-internal'} if nat64 else set()) |
                                 ({'nat46'} if nat46 else set()))
                if nat46:
                    self.assertEqual(components['nat46']['prefix'], 'fd42:1234:5678:fd46::/96')
                if nat64:
                    self.assertEqual(components['nat64-internal']['prefix'], 'fd42:1234:5678:fd65::/96')
                self.assertEqual(len(translation.manifests(value)), len(components))
                self.assertTrue(all(c['authorization'] == 'none' for c in translation.manifests(value)))

    def test_disabled_translation_references_and_duplicate_maps_fail(self):
        value = minimal()
        value['access']['rules'][0]['to'] = {'translation': 'nat46'}
        with self.assertRaises(ReleaseError):
            config.normalize(value)
        value = minimal()
        value['translation'] = {'nat46': {'enabled': True, 'mappings': {
            'one': {'ipv4': '10.255.200.2', 'ipv6': 'fd42:1234:5678:10::90'},
            'two': {'ipv4': '10.255.200.2', 'ipv6': 'fd42:1234:5678:10::91'}}}}
        with self.assertRaises(ReleaseError):
            config.normalize(value)
        value['translation']['nat46']['mappings']['two']['ipv4'] = '10.255.200.3'
        value['translation']['nat46']['mappings']['two']['ipv6'] = 'fd42:1234:5678:10::90'
        with self.assertRaises(ReleaseError):
            config.normalize(value)

    def test_allocation_overlaps_cover_translators_and_additional_attachments(self):
        for mutate in (
            lambda v: v.update(translation={'nat64': {'enabled': True, 'private_pool': '192.168.0.0/16'}}),
            lambda v: v['networks']['home'].update(additional_subnets=['10.255.254.0/24']),
            lambda v: v.update(translation={'nat64': {'enabled': True, 'internet_pool': '10.255.208.0/20'}})):
            value = minimal()
            mutate(value)
            with self.assertRaises(ReleaseError):
                config.normalize(value)

    def test_groups_ranges_and_conflicting_qualifiers(self):
        value = minimal()
        value['groups'] = {'writers': ['192.168.10.64-192.168.10.70'],
                           'qualified': [{'network': 'home', 'group': 'writers'}]}
        normalized = config.normalize(value)
        expanded = intent.expand(normalized, {'group': 'qualified'})
        addresses = set(a for p in expanded[0]['addresses'] for a in ipaddress.ip_network(p))
        self.assertEqual(addresses, {ipaddress.ip_address('192.168.10.'+str(i)) for i in range(64, 71)})
        self.assertEqual(expanded[0]['network'], 'home')
        with self.assertRaises(ReleaseError):
            intent.expand(normalized, {'network': 'uplink', 'group': 'qualified'})
        value['groups'] = {'loop': [{'group': 'loop'}]}
        with self.assertRaises(ReleaseError):
            config.normalize(value)

    def test_source_maps_keep_retired_slots_reserved_without_granting_them(self):
        value = minimal()
        value['translation'] = {'nat64': {'enabled': True}}
        value['access']['rules'] = [{'action': 'allow', 'from': 'fd42:1234:5678:10::84', 'to': 'home'}]
        value = config.normalize(value)
        old = {'fd42:1234:5678:10::84': '10.255.223.132', 'fd42:1234:5678:10::85': '10.255.223.133'}
        allocation = translation.allocate(value, old)
        self.assertEqual(allocation['reserved'], old)
        self.assertEqual(allocation['active'], {'fd42:1234:5678:10::84': '10.255.223.132'})
        text = next(c['text'] for c in translation.manifests(value, old) if c['interface'] == 'nat64-internal')
        self.assertIn('map 10.255.223.133 fd42:1234:5678:10::85', text)
        self.assertNotIn('fd42:1234:5678:10::85', allocation['active'])

    def test_disabled_optional_components_have_no_runtime_dependencies(self):
        value = minimal()
        value.update(routing={'bgp': {'enabled': False}}, identity={'policy': {'enabled': False},
                     'radius': {'enabled': False}}, translation={'nat64': {'enabled': False},
                     'nat46': {'enabled': False}}, observability={
                     key: {'enabled': False} for key in ('metrics', 'snmp', 'logs', 'ids')})
        value['services'] = {'dns': {'authoritative': {'enabled': False}}, 'discovery': {'enabled': False}}
        files = config.render(value)
        self.assertIn('etc/unbound/unbound.conf.d/lanrith.conf', files)
        self.assertFalse(any('tayga' in path or 'frr' in path or 'radius' in path for path in files))

    def test_service_range_key_order_does_not_change_allocation_validation(self):
        value = minimal()
        value['uplink']['ipv6'] = {'address': '2001:db8:10::2/48', 'gateway': '2001:db8:10::1',
                                  'downstream_prefix': '2001:db8:10::/48', 'delivery': 'on_link'}
        value['addressing']['services'] = {'ipv6': 'fd42:1234:5678:700::/64', 'ipv4': '172.30.40.0/24'}
        forward = config.render(value)
        value['addressing']['services'] = dict(reversed(list(value['addressing']['services'].items())))
        self.assertEqual(forward, config.render(value))
        value['networks']['home']['ipv6'] = {'subnet_id': 0x700, 'gua': True}
        with self.assertRaises(ReleaseError):
            config.normalize(value)

    def test_translation_control_addresses_are_reserved(self):
        for identifier in (0xfd64, 0xfd65, 0xfd46):
            value = minimal()
            value['networks']['home']['ipv6'] = {'subnet_id': identifier, 'gua': False}
            value['translation'] = {'nat64': {'enabled': True}, 'nat46': {'enabled': True, 'mappings': {
                'service': {'ipv4': '10.255.200.2', 'ipv6': 'fd42:1234:5678:11::2'}}}}
            with self.subTest(identifier=identifier), self.assertRaises(ReleaseError):
                config.normalize(value)
        value = minimal()
        value['networks']['home']['ipv6'] = {'subnet_id': 16, 'gua': False}
        value['translation'] = {'nat46': {'enabled': True, 'mappings': {
            'service': {'ipv4': '10.255.200.2', 'ipv6': 'fd42:1234:5678:10::1'}}}}
        with self.assertRaisesRegex(ReleaseError, 'router control address'):
            config.normalize(value)

    def test_hardware_derivation_preserves_one_gib_pages_and_rejects_ambiguous_groups(self):
        value = minimal()
        value['hardware']['interfaces']['core'] = {'name': 'core0', 'match': {'mac': '02:00:00:00:00:09'},
                                                  'owner': 'vpp', 'state': 'down'}
        value = config.normalize(value)
        fact = {'name': 'core0', 'mac': '02:00:00:00:00:09', 'pci': '0000:07:00.0', 'driver': 'i40e',
                'iommu_group': 8, 'iommu_members': ['0000:07:00.0']}
        facts = {'interfaces': [fact], 'hugepages': {'page_size_mib': 1024, 'pages': 2}}
        self.assertEqual(hardware_config.resolve_ownership(value, facts)['hugepages'], facts['hugepages'])
        for bad in ([{**fact, 'iommu_members': ['0000:07:00.0', '0000:07:00.1']}], [fact, fact],
                    [{**fact, 'name': 'wrong0'}]):
            with self.assertRaises(ReleaseError):
                hardware_config.resolve_ownership(value, {**facts, 'interfaces': bad})

    def test_log_runtime_is_a_supported_compiled_integration(self):
        value = minimal()
        value['networks']['home']['ipv6'] = {'subnet_id': 16}
        value['observability'] = {'logs': {'enabled': True, 'endpoint': 'https://[fd42:1234:5678:10::31]/otlp',
                                          'tls_server_name': 'logs.example.test', 'username': 'synthetic-monitor',
                                          'credential': 'log_monitor'}}
        normalized = config.normalize(value)
        files = config.render(normalized)
        self.assertIn('etc/alloy/config.alloy', files)
        self.assertIn('usr/share/lanrith/logs.json', files)

    def test_directory_requirements_need_a_real_integration(self):
        value = minimal()
        value['access']['rules'][0]['authorization'] = 'directory'
        with self.assertRaises(ReleaseError):
            config.normalize(value)


if __name__ == '__main__':
    unittest.main()
