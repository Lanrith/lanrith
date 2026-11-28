"""Controlled discovery is compiled without enabling multicast reflection."""

import copy
import ipaddress as ip
import json
import unittest
import xml.etree.ElementTree as ET

from lanrith import config, discovery, dns64
from lanrith.release import ReleaseError
from test_intent import minimal


def declaration():
    value = minimal()
    value['networks']['home']['ipv6'] = {'subnet_id': 16, 'gua': False}
    value['networks']['home']['additional_subnets'] = ['fd42:1234:5678:ffff::60/124']
    value['groups'] = {
        'publisher_clients': ['fd42:1234:5678:10::40/128'],
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
        'exclude': ['fd42:1234:5678:ffff::70/124'],
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
    def test_exclusions_apply_to_attached_sources_and_reverse_views(self):
        value = declaration()
        settings = value['services']['discovery']
        settings['exclude'] = ['fd42:1234:5678:ffff::/64']
        with self.assertRaisesRegex(ReleaseError, r'additional source .*::60/124 on home is wholly excluded by .*::/64'):
            config.render(value)
        # A covering exclusion can also consist of several smaller declarations.
        settings['exclude'] = ['fd42:1234:5678:ffff::60/125', 'fd42:1234:5678:ffff::68/125']
        with self.assertRaisesRegex(ReleaseError, r'::60/125, .*::68/125'):
            config.render(value)
        settings['exclude'] = ['fd42:1234:5678:ffff::68/125']
        files = config.render(value)
        router = json.loads(files['etc/discovery-bridge/router.json'])
        child = json.loads(files['etc/discovery-bridge/dns.json'])
        source = 'fd42:1234:5678:ffff::60/124'
        self.assertIn(source, router['sources']['lan'])
        self.assertIn(source, child['links'][0]['prefixes'])
        self.assertIn(discovery.reverse_zone(source), files['etc/unbound/unbound.conf.d/61-lanrith-discovery.conf'])
        lines = [line for line in files['etc/nftables.conf'].splitlines()
                 if 'iifname "lan" ip6 saddr' in line and 'hoplimit 255 udp dport 5353 accept' in line]
        self.assertEqual(1, len(lines))
        sources = [ip.ip_network(raw) for raw in lines[0].split('saddr { ')[1].split(' }')[0].split(', ')]
        for raw, expected in [('fd42:1234:5678:ffff::67', True), ('fd42:1234:5678:ffff::68', False),
                              ('fd42:1234:5678:10::40', False), ('fd42:1234:5678:10::41', True)]:
            address = ip.ip_address(raw)
            self.assertEqual(expected, any(address in prefix for prefix in sources))
            self.assertEqual(expected, any(address in ip.ip_network(p) for p in router['sources']['lan'])
                             and not any(address in ip.ip_network(p) for p in router['forbidden']))
        self.assertFalse(any('iifname "wan"' in line and 'udp dport 5353 accept' in line
                             for line in files['etc/nftables.conf'].splitlines()))

    def test_unrepresentable_source_and_permanent_watch_counts_fail_render(self):
        value = declaration()
        settings = value['services']['discovery']
        settings['exclude'] = ['fd42:1234:5678:10:4000::1/128', 'fd42:1234:5678:10:8000::1/128']
        with self.assertRaisesRegex(ReleaseError, '128 effective source prefixes'):
            config.render(value)
        value = declaration()
        settings = value['services']['discovery']
        value['networks']['home']['vlan'] = 20
        for n in range(1, 6):
            key = 'lan'+str(n)
            value['networks'][key] = {'interface': 'lan', 'vlan': n, 'ipv4': f'10.17.{n}.0/24',
                                      'ipv6': {'subnet_id': n, 'gua': False}}
            settings['networks'].append(key)
        settings['browse'] = ['_s'+str(i)+'._tcp' for i in range(41)] + ['_S0._tcp']
        manifest = discovery.router_manifest(config.normalize(value))
        self.assertEqual(41, len(manifest['bootstrap']))
        settings['browse'].append('_late._udp')
        with self.assertRaisesRegex(ReleaseError, '512 permanent browser budget'):
            config.render(value)

    def test_local_avahi_clients_have_only_their_selected_methods(self):
        value = declaration()
        clients = value['services']['discovery']['local_clients'] = {'reader': 'browse', 'writer': 'publish',
                                                                    'operator': 'status'}
        path = 'etc/dbus-1/system.d/lanrith-avahi.conf'
        policy = ET.fromstring(config.render(value)[path])

        def methods(user):
            return {item.get('send_member') for item in policy.findall(f'policy[@user="{user}"]/allow')}

        self.assertEqual(methods('reader'), {'GetState', 'RecordBrowserPrepare', 'Start', 'Free'})
        self.assertEqual(methods('reader'), methods(discovery.COLLECTOR))
        self.assertEqual(methods('writer'), {'GetState', 'EntryGroupNew', 'AddRecord', 'Commit', 'Reset', 'Free'})
        self.assertEqual(methods('writer'), methods(discovery.PUBLISHER))
        self.assertEqual(methods('operator'), {'GetState'})
        self.assertEqual(methods('root'), {'GetState'})
        for name, role in (('*', 'browse'), ('root', 'publish'), (discovery.COLLECTOR, 'publish'),
                           ('reader', 'admin')):
            with self.subTest(name=name, role=role), self.assertRaises(ReleaseError):
                value['services']['discovery']['local_clients'] = {name: role}
                config.render(value)
        value['services']['discovery'].update(local_clients=clients, enabled=False)
        self.assertNotIn(path, config.render(value))

    def test_bus_outlives_avahi_and_its_ordered_consumers(self):
        files = config.render(declaration())
        avahi = files['etc/systemd/system/avahi-daemon.service.d/60-lanrith.conf']
        self.assertIn('Requires=dbus.service\n', avahi)
        self.assertIn('After=dbus.service\n', avahi)
        for consumer in ('collector', 'publisher'):
            unit = files[f'etc/systemd/system/discovery-bridge-{consumer}.service.d/60-lanrith.conf']
            after = next(line.split('=', 1)[1].split() for line in unit.splitlines() if line.startswith('After='))
            self.assertIn('avahi-daemon.service', after)

    def test_native_translator_observation_matches_the_selected_service_binary(self):
        files = config.render(declaration(), access_backend='tun')
        router = json.loads(files['etc/discovery-bridge/router.json'])
        for name, observation in router['translators'].items():
            if name not in ('nat64', 'nat46'):
                continue
            unit = files['usr/lib/systemd/system/'+observation['unit']]
            self.assertIn('ExecStart='+observation['binary']+' --nodetach', unit)

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
            'clients': ['fd42:1234:5678:10::40/128']})
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
        self.assertIn('ratelimit-interval-usec=1000000', avahi.splitlines())
        self.assertIn('ratelimit-burst=1000', avahi.splitlines())
        self.assertIn('allow-interfaces=lan', avahi.splitlines())
        self.assertIn('enable-reflector=no', avahi)
        firewall = files['etc/nftables.conf']
        self.assertIn('ip ttl 255 udp dport 5353 accept', firewall)
        self.assertIn('ip6 hoplimit 255 udp dport 5353 accept', firewall)
        self.assertIn('tcp dport { 9443, 9444 } accept', firewall)
        self.assertNotIn('chain mdns_reflector', firewall)
        publisher = [line for line in firewall.splitlines() if 'meta skuid "discovery-bridge-publisher"' in line]
        self.assertEqual(publisher, [
            '  meta skuid "discovery-bridge-publisher" oifname "lan" fib saddr type local '
            + destination+' udp sport 5353 udp dport 5353 accept'
            for destination in ('ip saddr { 192.168.10.1 } ip daddr 224.0.0.251 ip ttl 255',
                                'ip6 saddr { fd42:1234:5678:10::1, fd42:1234:5678:ffff::61, fe80::/10 } '
                                'ip6 daddr ff02::fb ip6 hoplimit 255')])
        namespace = files['etc/lanrith/services.nft']
        self.assertIn('ip daddr { 10.255.254.12 } tcp dport 53 accept', namespace)
        self.assertIn('meta skuid "discovery-bridge-dns"', namespace)
        self.assertIn('discovery-bridge-dns.service', json.loads(
            files['usr/share/lanrith/health.json'])['units'])

    def test_child_readers_are_independent_of_parent_and_recursive_access(self):
        from test_authoritative import declaration as parent_declaration
        value = declaration()
        parent = parent_declaration()['services']['dns']['authoritative']
        value['services']['dns']['authoritative'] = parent
        parent['direct_readers'] = [{'network': 'home', 'addresses': '192.168.10.44'}]
        service = value['services']['discovery']
        for readers in ([], [{'network': 'home', 'addresses': '192.168.10.23'},
                             {'network': 'home', 'addresses': 'fd42:1234:5678:10::23'}]):
            service['direct_readers'] = readers
            files = config.render(value)
            clients = json.loads(files['etc/discovery-bridge/dns.json'])['clients']
            self.assertCountEqual(clients, ['10.255.254.10/32', 'fd42:1234:5678:fe02::10/128',
                *(reader['addresses']+('/128' if ':' in reader['addresses'] else '/32') for reader in readers)])
            unit = files['etc/systemd/system/discovery-bridge-dns.service.d/60-lanrith.conf']
            self.assertCountEqual(clients, [line.removeprefix('IPAddressAllow=') for line in unit.splitlines()
                                            if line.startswith('IPAddressAllow=')])
            for path in ('etc/nftables.conf', 'etc/lanrith/services.nft'):
                for endpoint in ('10.255.254.12', 'fd42:1234:5678:fe02::12'):
                    for proto in ('udp', 'tcp'):
                        lines = [line for line in files[path].splitlines()
                                 if f'daddr {{ {endpoint} }} {proto} dport 53 accept' in line and 'saddr' in line]
                        if readers:
                            self.assertEqual(len(lines), 1)
                            self.assertIn('::23/128' if ':' in endpoint else '192.168.10.23/32', lines[0])
                            if path == 'etc/nftables.conf':
                                self.assertIn('iifname "lan"', lines[0])
                        else:
                            self.assertEqual(lines, [])
        for reader in ({'addresses': '192.168.10.23'}, {'network': 'home', 'addresses': '192.0.2.23'}):
            service['direct_readers'] = [reader]
            with self.assertRaises(ReleaseError):
                config.render(value)

    def test_deployed_bridge_requires_distinct_view_sources_and_forward_domains(self):
        value = declaration()
        for domain in ('devices.home.arpa', 'ARPA.', 'devices.LOCAL'):
            value['services']['discovery']['domain'] = domain
            with self.subTest(domain=domain), self.assertRaisesRegex(ReleaseError, 'forward domain'):
                config.render(value)
        value = declaration()
        value['services']['discovery']['views']['duplicate'] = 'home'
        with self.assertRaisesRegex(ReleaseError, 'distinct collected link'):
            config.render(value)
        del value['services']['discovery']['views']
        self.assertEqual(discovery.views(config.normalize(value))[0], {'home': 'home'})

    def test_discovery_deadlines_follow_the_dns64_path(self):
        from test_authoritative import declaration as parent_declaration
        for translate, parent, upstream, downstream in (
                (False, False, 8000, 8000), (True, False, 30000, 30000), (True, True, 30000, 30000)):
            value = declaration()
            value['translation']['nat64']['enabled'] = translate
            if parent:
                value['services']['dns'].update(parent_declaration()['services']['dns'])
            files = config.render(value)
            main = files['etc/unbound/unbound.conf.d/61-lanrith-discovery.conf']
            self.assertIn(f'tcp-auth-query-timeout: {upstream}', main)
            self.assertIn(f'discard-timeout: {downstream}', main)
            self.assertNotIn('qname-minimisation: no', main)
            if translate:
                unit = files['usr/lib/systemd/system/lanrith-dns64-private.service']
                self.assertEqual('named.service' in unit, parent)
                self.assertIn('lanrith-dns64-private.service', json.loads(files['usr/share/lanrith/health.json'])['units'])
                self.assertIn('private-domain: "home.devices.example.test."', main)
                private = files['etc/unbound/unbound-private.conf']
                self.assertIn('qname-minimisation: no', private)
                self.assertIn('tcp-auth-query-timeout: 8000', private)
                self.assertIn('discard-timeout: 16000', private)
                for name in ('home.devices.example.test.', '10.168.192.in-addr.arpa.'):
                    self.assertIn(f'name: "{name}"\n  forward-addr: 127.0.0.1@{dns64.PORT}', main)
                    self.assertIn(f'name: "{name}"\n  stub-addr: 10.255.254.12', private)
            else:
                self.assertIn('forward-addr: 10.255.254.12', main)
            value['services']['discovery']['enabled'] = False
            files = config.render(value)
            self.assertNotIn('etc/unbound/unbound.conf.d/61-lanrith-discovery.conf', files)
            self.assertNotIn('tcp-auth-query-timeout', files.get('etc/unbound/unbound-private.conf', ''))

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
