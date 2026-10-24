"""DNS64 follows translator, authority, transport and RA selections."""

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

    def test_ra_advertises_public_prefix_only_when_enabled(self):
        for ra in (False, True):
            for gua in (False, True):
                value = self.settings()
                value['uplink']['ipv6'] = {'address': '2001:db8:10::2/48', 'gateway': '2001:db8:10::1',
                    'downstream_prefix': '2001:db8:10::/48', 'delivery': 'on_link'}
                value['networks']['home']['ipv6'].update(ra=ra, gua=gua)
                with self.subTest(ra=ra, gua=gua):
                    text = config.render(value)['etc/systemd/network/40-home.network']
                    self.assertEqual('[IPv6PREF64Prefix]' in text, ra)
                    self.assertNotIn('Prefix=fd42:1234:5678:fd65::/96', text)
                    self.assertEqual('Address=2001:db8:10:10::1/64' in text, gua)
        value['translation']['nat64']['enabled'] = False
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


    def test_assembly_installs_translator_runtime_and_requires_readiness(self):
        value = self.settings()
        value['services']['dns']['authoritative'].pop('writers')
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            base = root/'base.tar'
            base.write_bytes(b'synthetic assembly input')
            build.assembly(value, base, root/'image', version='0.1.0', sequence=9)
            overlay = root/'image/mkosi.extra'
            health = (overlay/'usr/lib/systemd/system/lanrith-health.service').read_text()
            for name in ('nat64', 'nat64-internal', 'dns64-private'):
                self.assertIn('lanrith-'+name+'.service', health)
            for module in ('nat64_runtime.py', 'nat64_packets.py', 'nat64_allocations.py'):
                self.assertTrue((overlay/'usr/lib/lanrith/lanrith'/module).is_file())


if __name__ == '__main__':
    unittest.main()
