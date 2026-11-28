"""DNS64 follows translator, authority, transport and RA selections."""

import ipaddress as ip
import json
from pathlib import Path
import tempfile
import unittest

from lanrith import build, config, dns64, service_plane
from test_authoritative import declaration


class DNS64Tests(unittest.TestCase):
    def settings(self):
        value = declaration()
        value['translation'] = {'nat64': {'enabled': True}}
        return value

    def test_public_and_private_synthesis_share_selected_prefixes(self):
        files = config.render(self.settings())
        main = files['etc/unbound/unbound.conf.d/lanrith.conf']
        private = files['etc/unbound/unbound-private.conf']
        self.assertIn('dns64-prefix: 64:ff9b::/96', main)
        self.assertIn('dns64-prefix: fd42:1234:5678:fd65::/96', private)
        self.assertIn('forward-addr: 127.0.0.1@5354', main)
        self.assertNotIn('stub-addr:', main)
        self.assertIn('stub-addr: fd42:1234:5678:fe02::11', private)
        self.assertIn('forward-addr: 10.255.254.10', private)
        for text in (main, private):
            self.assertIn('dns64-synthall: no', text)
            self.assertIn('access-control: 10.255.254.10 allow', text)

    def test_disabling_each_component_removes_its_dns64_dependencies(self):
        for feature in ('nat64', 'authoritative', 'dns'):
            value = self.settings()
            if feature == 'nat64':
                value['translation'][feature]['enabled'] = False
            else:
                value['services']['dns']['authoritative']['enabled'] = False
                if feature == 'dns':
                    value['services']['dns']['enabled'] = False
            files = config.render(value)
            self.assertNotIn('etc/unbound/unbound-private.conf', files)
            self.assertFalse(any('dns64-private' in name for name in files))
            if feature != 'authoritative':
                self.assertNotIn('dns64-prefix:', files.get('etc/unbound/unbound.conf.d/lanrith.conf', ''))
            else:
                self.assertIn('dns64-prefix: 64:ff9b::/96', files['etc/unbound/unbound.conf.d/lanrith.conf'])

    def test_custom_addresses_and_ipv6_only_upstream_use_reachable_local_transport(self):
        value = self.settings()
        value['addressing']['services'] = {'ipv4': '172.30.40.0/24', 'ipv6': 'fd42:1234:5678:700::/64'}
        value['uplink']['ipv4'] = 'disabled'
        files = config.render(value)
        main = files['etc/unbound/unbound.conf.d/lanrith.conf']
        private = files['etc/unbound/unbound-private.conf']
        self.assertIn('forward-addr: ::1@5354', main)
        self.assertIn('forward-addr: fd42:1234:5678:700::10', private)
        self.assertIn('outgoing-interface: 172.30.40.10', private)
        self.assertIn('access-control: fd42:1234:5678:700::10 allow', private)

    def test_private_reverse_paths_follow_scope_family_and_unit_selection(self):
        for v4, v6, loop, authority in (
                ('dhcp', 'ra', '127.0.0.1', 'fd42:1234:5678:fe02::11'),
                ('dhcp', 'disabled', '127.0.0.1', '10.255.254.11'),
                ('disabled', 'ra', '::1', 'fd42:1234:5678:fe02::11'),
                ('disabled', 'disabled', '::1', 'fd42:1234:5678:fe02::11')):
            value = self.settings()
            value['uplink'].update(ipv4=v4, ipv6=v6)
            zones = value['services']['dns']['authoritative']['zones']
            zone = '7.27.172.in-addr.arpa'
            zones[zone] = {}
            normalized = config.normalize(value)
            name = dns64.reverse_zone(normalized)
            self.assertEqual(name, '.'.join(ip.ip_address('fd42:1234:5678:fd65::').reverse_pointer.split('.')[8:])+'.')
            files = config.render(value)
            main = files['etc/unbound/unbound.conf.d/lanrith.conf']
            private = files['etc/unbound/unbound-private.conf']
            reverse = files['etc/unbound/unbound-reverse.conf']
            for entry in (main, private):
                self.assertIn(f'local-zone: "{name}" transparent', entry)
                self.assertIn(f'name: "{name}"\n  forward-addr: {loop}@5356\n  forward-first: no', entry)
                self.assertIn('module-config: "respip dns64 ', entry)
            self.assertIn('module-config: "dns64 iterator"', reverse)
            self.assertIn(f'name: "{zone}."\n  stub-addr: {authority}', reverse)
            self.assertNotIn('forward-zone:', reverse)
            self.assertNotIn('interface: '+authority, reverse)
            self.assertIn('for-upstream: yes\n  fallback-enabled: no', reverse)
            unit = 'lanrith-dns64-reverse.service'
            self.assertIn(unit, json.loads(files['usr/share/lanrith/health.json'])['units'])
            self.assertIn(unit, files['usr/lib/systemd/system/lanrith-dns64-private.service'])
            self.assertIn('RestrictNetworkInterfaces=lo', files['usr/lib/systemd/system/'+unit])
            rules = [line for line in files['etc/lanrith/services.nft'].splitlines() if 'dport 5356 ' in line]
            self.assertEqual(len(rules), 2)
            self.assertTrue(all('tcp dport' in rule for rule in rules))
            self.assertTrue(all('oifname "lo" meta skuid "unbound"' in rule for rule in rules))
            self.assertNotIn('5356', files['etc/nftables.conf'])
            for exact_owner in (False, True):
                if exact_owner:
                    zones[zone] = {}
                    zones[name.rstrip('.')] = {}
                else:
                    del zones[zone]
                unselected = config.render(value)
                self.assertNotIn('usr/lib/systemd/system/'+unit, unselected)
                self.assertNotIn('5356', unselected['etc/lanrith/services.nft'])
                self.assertNotIn(unit, json.loads(unselected['usr/share/lanrith/health.json'])['units'])

    def test_blocked_reverse_tree_keeps_its_local_denial(self):
        value = self.settings()
        value['services']['dns']['authoritative']['zones']['7.27.172.in-addr.arpa'] = {}
        zone = dns64.reverse_zone(config.normalize(value))
        for blocked in [zone, 'ip6.arpa']:
            value['services']['dns']['blocked_domains'] = [blocked]
            files = config.render(value)
            self.assertNotIn('etc/unbound/unbound-reverse.conf', files)
            self.assertIn(f'local-zone: "{blocked.rstrip(".")}." always_nxdomain',
                          files['etc/unbound/unbound.conf.d/lanrith.conf'])

    def test_ra_advertises_public_prefix_only_when_enabled(self):
        for ra in (False, True):
            for gua in (False, True):
                value = self.settings()
                value['uplink']['ipv6'] = {'address': '2001:db8:10::2/48', 'gateway': '2001:db8:10::1',
                    'downstream_prefix': '2001:db8:10::/48', 'delivery': 'on_link'}
                value['networks']['home']['ipv6'].update(ra=ra, gua=gua)
                if ra:
                    value['networks']['home']['pref64'] = 'nat64'
                with self.subTest(ra=ra, gua=gua):
                    files = config.render(value)
                    text = files['etc/systemd/network/40-home.network']
                    self.assertEqual('usr/lib/lanrith/networkd/pref64-nat64.conf' in files, ra)
                    self.assertNotIn('Prefix=fd42:1234:5678:fd65::/96', text)
                    self.assertEqual('Address=2001:db8:10:10::1/64' in text, gua)
        value['translation']['nat64']['enabled'] = False
        value['networks']['home'].pop('pref64')
        self.assertNotIn('[IPv6PREF64Prefix]', config.render(value)['etc/systemd/network/40-home.network'])

    def test_public_rebind_guard_excludes_only_declared_local_zones(self):
        normalized = config.normalize(self.settings())
        text = dns64.rebind_guards(normalized)
        self.assertIn('private-domain: "example.test."', text)
        self.assertIn('private-address: 192.168.0.0/16', text)
        self.assertIn('private-address: 64:ff9b::c0a8:0/112', text)
        self.assertIn('private-address: fc00::/7', text)
        self.assertNotIn('private-domain: "."', text)
        plane = service_plane.render(normalized)['etc/lanrith/services.nft']
        for line in plane.splitlines():
            if 'dport 5354' in line:
                self.assertIn('oifname "lo"', line)
                self.assertIn('meta skuid "unbound"', line)
                self.assertTrue('daddr 127.0.0.1 ' in line or 'daddr ::1 ' in line)


    def test_public_wkp_guard_and_dns_filters_agree_across_both_backends(self):
        wkp = ip.IPv6Network('64:ff9b::/96')
        for backend in ('tun', 'legacy'):
            raw = self.settings()
            files = config.render(raw, access_backend=backend)
            resolver = files['etc/unbound/unbound.conf.d/lanrith.conf']
            filters = {ip.ip_network(line.split()[1]) for line in resolver.splitlines()
                       if line.strip().startswith('private-address: ')}
            dns4 = [net for net in filters if net.version == 4]
            dns6 = {net for net in filters if net.version == 6 and net.subnet_of(wkp)}
            self.assertEqual(list(ip.collapse_addresses([*dns4, ip.IPv4Network('0.0.0.0/32')])),
                             list(ip.collapse_addresses([ip.IPv4Network((int(net.network_address) & 0xffffffff,
                                                                        net.prefixlen-96)) for net in dns6])))
            self.assertIn('response-ip: 0.0.0.0/32 always_nxdomain', resolver)
            self.assertIn('private-domain: "ipv4only.arpa."', resolver)
            nft = files['etc/nftables.conf']
            declaration = next(row for row in nft.splitlines() if row.startswith(' set nat64_non_global '))
            intervals = {ip.IPv6Network(token) for token in
                         declaration.split('elements = { ')[1].split(' }')[0].split(', ')}
            self.assertEqual(dns6, intervals)
            for address in ('0.0.0.0', '10.0.0.1', '100.64.1.2', '127.0.0.1', '169.254.1.2', '172.31.4.5',
                            '192.0.0.8', '192.0.0.11', '192.0.0.170', '192.0.0.171', '192.0.2.4',
                            '192.88.99.2', '192.168.1.2', '198.19.1.1', '198.51.100.1', '203.0.113.1',
                            '224.0.0.0', '239.255.255.255', '240.0.0.0', '250.1.2.3', '255.255.255.255'):
                self.assertTrue(any(wkp.network_address+int(ip.IPv4Address(address)) in net for net in intervals), address)
            for address in ('192.0.0.9', '192.0.0.10', '192.31.196.1', '192.52.193.2', '192.175.48.3', '8.8.8.8'):
                self.assertFalse(any(wkp.network_address+int(ip.IPv4Address(address)) in net for net in intervals), address)
            for chain in ('forward', 'output'):
                first_rule = nft.split(f' chain {chain} {{ type filter hook {chain} ', 1)[1].splitlines()[1]
                self.assertEqual(first_rule.strip(), 'oifname "nat64" ip6 daddr @nat64_non_global '
                                 'counter name nat64_non_global_drops drop')
            self.assertNotIn('oifname "nat64-internal" ip6 daddr @nat64_non_global', nft)
            raw['services']['dns']['enabled'] = False
            self.assertIn(declaration, config.render(raw, access_backend=backend)['etc/nftables.conf'])
            raw['translation']['nat64']['enabled'] = False
            self.assertNotIn('nat64_non_global', config.render(raw, access_backend=backend)['etc/nftables.conf'])

    def test_assembly_installs_translator_runtime_and_requires_readiness(self):
        value = self.settings()
        authority = value['services']['dns']['authoritative']
        authority.pop('writers')
        authority['zones']['7.27.172.in-addr.arpa'] = {}
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            base = root/'base.tar'
            base.write_bytes(b'synthetic assembly input')
            build.assembly(value, base, root/'image', version='0.1.0', sequence=9)
            overlay = root/'image/mkosi.extra'
            health = (overlay/'usr/lib/systemd/system/lanrith-health.service').read_text()
            for name in ('nat64', 'nat64-internal', 'dns64-private', 'dns64-reverse'):
                unit = 'lanrith-'+name+'.service'
                self.assertIn(unit, health)
                self.assertEqual((overlay/'usr/lib/systemd/system/multi-user.target.wants'/unit).readlink(),
                                 Path('/usr/lib/systemd/system')/unit)
            self.assertTrue((overlay/'usr/lib/lanrith/lanrith/translation_runtime.py').is_file())
            for module in ('nat64_runtime.py', 'nat64_packets.py', 'nat64_allocations.py'):
                self.assertFalse((overlay/'usr/lib/lanrith/lanrith'/module).is_file())


if __name__ == '__main__':
    unittest.main()
