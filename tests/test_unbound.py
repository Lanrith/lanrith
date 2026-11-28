"""Resolver configuration and cross-namespace DNS policy."""

from copy import deepcopy
import unittest

from lanrith import config
from lanrith.release import ReleaseError
from test_authoritative import declaration
from test_discovery import declaration as discovery_declaration
from test_intent import minimal


class UnboundTests(unittest.TestCase):
    def test_host_and_namespace_resolvers_use_specific_paths(self):
        value = minimal()
        value['addressing']['services'] = {'ipv4': '172.30.40.0/24', 'ipv6': 'fd42:1234:5678:700::/64'}
        value['uplink']['ipv4'] = 'disabled'
        files = config.render(value)
        self.assertEqual(files['etc/resolv.conf'], 'nameserver 172.30.40.10\n')
        self.assertEqual(files['etc/unbound/unbound.conf'].splitlines(), [
            'include-toplevel: "/etc/unbound/unbound.conf.d/*.conf"', 'remote-control:', '  control-enable: no'])
        self.assertEqual(files['etc/lanrith/chrony-resolv.conf'], 'nameserver 127.0.0.1\n')
        resolver = files['etc/unbound/unbound.conf.d/lanrith.conf']
        self.assertIn('access-control: 172.30.40.1/32 allow\n', resolver)
        self.assertNotIn('access-control: 172.30.40.0/24 allow', resolver)
        for path, prefix in (('etc/nftables.conf', 'oifname "lr-services"'),
                             ('etc/lanrith/services.nft', 'iifname "lr-host"')):
            rules = [line.strip() for line in files[path].splitlines() if 'ip saddr 172.30.40.1 ' in line]
            self.assertEqual(rules, [f'{prefix} ip saddr 172.30.40.1 ip daddr 172.30.40.10 {proto} dport 53 accept'
                                     for proto in ('udp', 'tcp')])
        value['services']['dns'] = {'enabled': False}
        files = config.render(value)
        self.assertNotIn('etc/resolv.conf', files)
        self.assertNotIn('ip saddr 172.30.40.1 ', files['etc/lanrith/services.nft'])

    def test_private_startup_modes_keep_all_private_zones_pinned(self):
        value = declaration()
        value['services']['discovery'] = discovery_declaration()['services']['discovery']
        for key in ('additional_sources', 'external_publishers', 'exclude'):
            del value['services']['discovery'][key]
        value['translation'] = {'nat64': {'enabled': True}}
        for mode, dependency in ((None, 'Requires'), ('required', 'Requires'), ('independent', 'Wants')):
            if mode:
                value['services']['dns']['private_dns64_startup'] = mode
            files = config.render(value)
            unit = files['etc/systemd/system/unbound.service.d/61-lanrith-dns64.conf']
            self.assertEqual(unit, f'[Unit]\n{dependency}=lanrith-dns64-private.service\n'
                                   'After=lanrith-dns64-private.service\n')
            self.assertEqual('etc/systemd/system/named.service.d/61-lanrith-dns64.conf' in files,
                             mode == 'independent')
            discovery = files['etc/unbound/unbound.conf.d/61-lanrith-discovery.conf']
            for zone in ('home.devices.example.test.', '10.168.192.in-addr.arpa.'):
                forward = next(block for block in discovery.split('forward-zone:\n')[1:] if f'  name: "{zone}"' in block)
                self.assertIn('forward-first: no', forward)
            for zone in ('home.arpa.', 'example.test.'):
                self.assertIn(f'name: "{zone}"\n  forward-addr: 127.0.0.1@5354\n  forward-first: no',
                              files['etc/unbound/unbound.conf.d/lanrith.conf'])
        value['services']['dns']['private_dns64_startup'] = 'typo'
        with self.assertRaises(ReleaseError):
            config.normalize(value)

    def test_direct_recursion_and_plain_forwarding(self):
        value = minimal()
        self.assertNotIn('forward-zone:', config.render(value)['etc/unbound/unbound.conf.d/lanrith.conf'])
        value['services'] = {'dns': {'upstreams': ['198.51.100.53']}}
        resolver = config.render(value)['etc/unbound/unbound.conf.d/lanrith.conf']
        self.assertIn('forward-zone:\n  name: "."\n  forward-addr: 198.51.100.53\n', resolver)
        self.assertNotIn('tls-', resolver)
        value['uplink']['ipv4'] = 'disabled'
        with self.assertRaises(ReleaseError):
            config.normalize(value)

    def test_tls_forwarding_applies_only_to_root(self):
        value = declaration()
        value['translation'] = {'nat64': {'enabled': True}}
        dns = value['services']['dns']
        tls = {'trust': 'system', 'upstreams': [{'address': '192.0.2.4', 'authentication_name': 'dns.example.net.'},
                                               {'address': '2001:db8::4', 'authentication_name': 'dns6.example.net'}]}
        dns['tls_forwarding'] = tls
        files = config.render(value)
        server, root, *private = files['etc/unbound/unbound.conf.d/lanrith.conf'].split('forward-zone:\n')
        self.assertIn('tls-cert-bundle: "/etc/ssl/certs/ca-certificates.crt"', server)
        self.assertIn('  name: "."\n  forward-tls-upstream: yes\n  forward-first: no\n', root)
        self.assertIn('forward-addr: 192.0.2.4@853#dns.example.net\n', root)
        self.assertIn('forward-addr: 2001:db8::4@853#dns6.example.net\n', root)
        self.assertTrue(private)
        self.assertFalse(any('tls' in route for route in private))
        self.assertNotIn('forward-tls-upstream', files['etc/unbound/unbound-private.conf'])
        for change in ({'trust': 'unchecked'}, {'upstreams': []},
                       *({'upstreams': [{'address': address, 'authentication_name': name}]}
                         for address, name in [('dns.example', 'dns.example'), ('192.0.2.1', ''),
                                               ('192.0.2.1', '*.example'), ('192.0.2.1', '192.0.2.4'),
                                               ('192.0.2.1', 'bad.example..')])):
            with self.subTest(change=change), self.assertRaises(ReleaseError):
                selected = deepcopy(value)
                selected['services']['dns']['tls_forwarding'].update(change)
                config.normalize(selected)
        for changes in ({'upstreams': []}, {'enabled': False}):
            with self.subTest(changes=changes), self.assertRaises(ReleaseError):
                selected = deepcopy(value)
                selected['services']['dns'].update(changes)
                config.normalize(selected)
        tls['upstreams'].pop()
        value['uplink']['ipv4'] = 'disabled'
        with self.assertRaises(ReleaseError):
            config.normalize(value)


if __name__ == '__main__':
    unittest.main()
