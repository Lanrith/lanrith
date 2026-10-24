"""Controlled discovery is compiled without enabling multicast reflection."""

import copy
import json
import unittest

from lanrith import config, discovery
from lanrith.release import ReleaseError
from test_intent import minimal


def declaration():
    value = minimal()
    value['networks']['home']['ipv6'] = {'subnet_id': 16, 'gua': False}
    value['networks']['home']['additional_subnets'] = ['fd42:1234:5678:ffff::60/124']
    value['groups'] = {
        'publisher_clients': ['fd42:1234:5678:10::/64'],
        'service_vips': ['fd42:1234:5678:ff00::/120'],
    }
    value['services'] = {'dns': {'domain': 'example.test'}, 'discovery': {
        'enabled': True, 'domain': 'devices.example.test', 'alias_prefix': 'lab-',
        'networks': ['home'],
        'additional_sources': [{'network': 'home', 'addresses': 'fd42:1234:5678:ffff::60/124'}],
        'browse': ['_example._tcp'],
        'external_publishers': {'cluster': {
            'network': 'home', 'clients': {'group': 'publisher_clients'},
            'addresses': {'group': 'service_vips'},
        }},
        'exclude': ['fd42:1234:5678:ffff::/64'],
        'views': {'home': 'home'}, 'default_view': 'home',
    }}
    value['translation'] = {
        'nat64': {'enabled': True, 'internet_pool': '10.250.224.0/20',
                  'private_pool': '10.250.208.0/20'},
        'nat46': {'enabled': True, 'pool': '10.250.200.0/24', 'mappings': {
            'service': {'ipv4': '10.250.200.2', 'ipv6': 'fd42:1234:5678:10::20'},
        }},
    }
    return value


class DiscoveryContractTests(unittest.TestCase):
    def test_render_binds_selected_sources_views_and_publication(self):
        value = config.normalize(declaration())
        files = config.render(value)
        router = json.loads(files['etc/discovery-bridge/router.json'])
        self.assertEqual(router['interfaces'], [
            {'interface': 'lan', 'source': 'lan', 'families': [4, 6]}])
        self.assertEqual(router['sources']['lan'], [
            '192.168.10.0/24', 'fd42:1234:5678:10::/64', 'fd42:1234:5678:ffff::60/124'])
        self.assertNotIn('fd42:1234:5678:ffff::70/124', router['sources']['lan'])
        self.assertEqual(router['sources']['cluster'], ['fd42:1234:5678:ff00::/120'])
        self.assertEqual(router['gateway'], {
            'host': 'fd42:1234:5678:10::1', 'port': 9443,
            'clients': ['fd42:1234:5678:10::/64']})
        self.assertEqual(router['publication']['source'], 'cluster')
        self.assertEqual(router['native']['sources'], ['lan'])
        self.assertEqual(router['translators']['nat46']['unit'], 'lanrith-nat46.service')
        self.assertEqual(router['translators']['nat64']['unit'], 'lanrith-nat64-internal.service')

        dns = json.loads(files['etc/discovery-bridge/dns.json'])
        self.assertEqual(dns['default_source'], 'lan')
        self.assertEqual(dns['links'][0]['service_domain'], 'home.devices.example.test.')
        self.assertEqual(dns['mailbox'], 'hostmaster.example.test.')
        self.assertEqual([item['host'] for item in dns['listeners']],
                         ['10.255.254.12', 'fd42:1234:5678:fe02::12'])
        self.assertIn('home.devices.example.test.', files[
            'etc/unbound/unbound.conf.d/61-lanrith-discovery.conf'])

        avahi = files['etc/avahi/avahi-daemon.conf']
        self.assertIn('allow-interfaces=lan', avahi)
        self.assertIn('enable-reflector=no', avahi)
        firewall = files['etc/nftables.conf']
        self.assertIn('ip ttl 255 udp dport 5353 accept', firewall)
        self.assertIn('ip6 hoplimit 255 udp dport 5353 accept', firewall)
        self.assertIn('tcp dport { 9443, 9444 } accept', firewall)
        self.assertNotIn('chain mdns_reflector', firewall)
        namespace = files['etc/lanrith/services.nft']
        self.assertIn('ip daddr { 10.255.254.12 } tcp dport 53 accept', namespace)
        self.assertIn('meta skuid "discovery-bridge-dns"', namespace)
        self.assertIn('discovery-bridge-dns.service', json.loads(
            files['usr/share/lanrith/health.json'])['units'])

    def test_independent_translation_states_do_not_invent_missing_spaces(self):
        for enabled in ('nat64', 'nat46', None):
            value = declaration()
            if enabled != 'nat64':
                value['translation']['nat64']['enabled'] = False
            if enabled != 'nat46':
                value['translation']['nat46']['enabled'] = False
            files = config.render(config.normalize(value))
            router = json.loads(files['etc/discovery-bridge/router.json'])
            self.assertNotIn('translators', router)
            self.assertNotIn('usr/lib/tmpfiles.d/80-lanrith-discovery.conf', files)

    def test_disabled_and_ambiguous_publication_remove_or_reject_runtime(self):
        value = declaration()
        value['services']['discovery']['enabled'] = False
        files = config.render(config.normalize(value))
        self.assertNotIn('etc/discovery-bridge/router.json', files)
        self.assertNotIn('etc/avahi/avahi-daemon.conf', files)

        value = declaration()
        value['services']['discovery']['external_publishers']['second'] = copy.deepcopy(
            value['services']['discovery']['external_publishers']['cluster'])
        with self.assertRaisesRegex(ReleaseError, 'one explicitly named'):
            config.render(config.normalize(value))

        value = declaration()
        value['services']['discovery']['additional_sources'][0]['network'] = 'missing'
        with self.assertRaises(ReleaseError):
            config.normalize(value)


if __name__ == '__main__':
    unittest.main()
