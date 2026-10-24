"""DNS alias resolution, writer boundaries and persistent initialization."""

import base64
import json
import os
from pathlib import Path
import tempfile
import unittest

from lanrith import authoritative, config, dns_runtime, service_plane
from lanrith.release import ReleaseError
from test_intent import minimal


def declaration():
    value = minimal()
    value['networks']['home']['ipv6'] = {'subnet_id': 16, 'gua': False}
    value['services'] = {'dns': {'authoritative': {
        'enabled': True, 'primary_zone': 'home.arpa',
        'zones': {'home.arpa': {'records': {'router': {'A': {'network': 'home'}}}},
                  'example.test': {'persistent': True, 'records': {
                      'seeded': {'A': '192.0.2.20'}}}},
        'writers': {
            'first': {'zone': 'example.test', 'sources': {'network': 'home', 'addresses': '192.168.10.20'},
                      'key_name': 'first-key', 'credential': 'first_tsig', 'zone_transfer': True},
            'second': {'zone': 'example.test', 'sources': {'network': 'home', 'addresses': '192.168.10.21'},
                       'key_name': 'second-key', 'credential': 'second_tsig'}}}}}
    return value


class AuthoritativeTests(unittest.TestCase):
    def test_generated_records_and_nested_source_and_key_checks(self):
        value = config.normalize(declaration())
        files = config.render(value)
        text = files['etc/bind/named.conf']
        self.assertIn('acl "writer-0" { !{ !{ 192.168.10.20/32; }; any; }; key "first-key"; };', text)
        self.assertIn('allow-update { "writer-0"; "writer-1"; };', text)
        self.assertIn('allow-transfer { "writer-0"; };', text)
        self.assertIn('recursion no;', text)
        zone = files['usr/share/lanrith/zones/db.home.arpa']
        self.assertIn('router IN A 192.168.10.1', zone)
        self.assertIn('@ IN NS ns1.home.arpa.', zone)
        self.assertIn('ns1 IN A 10.255.254.11', zone)
        self.assertIn('ns1 IN AAAA fd42:1234:5678:fe02::11', zone)
        self.assertIn('ntp IN A 10.255.254.40', zone)
        plane = service_plane.topology(value)
        self.assertIn('authoritative', plane['endpoints'])
        resolver = service_plane.render(value)['etc/unbound/unbound.conf.d/lanrith.conf']
        self.assertIn('stub-addr: fd42:1234:5678:fe02::11', resolver)
        self.assertIn('domain-insecure: "example.test."', resolver)
        # BIND can return local DNS replies, never initiate a new connection.
        for line in files['etc/lanrith/services.nft'].splitlines():
            if 'meta skuid "bind"' in line and line.endswith(' accept'):
                self.assertIn('oifname "lo"', line)
                self.assertIn('ct direction reply ct state { established, related }', line)
                self.assertIn('sport { 53 }', line)
        self.assertIn('BindsTo=lanrith-services.service nftables.service lanrith-dns-state.service',
                      files['etc/systemd/system/named.service.d/60-lanrith-services.conf'])

    def test_all_six_aliases_share_translation_targets(self):
        value = declaration()
        maps = {f'service-{n}': {'ipv4': '10.255.200.'+str(n+2),
                               'ipv6': 'fd42:1234:5678:10::'+str(n+20)}
                for n in range(6)}
        value['translation'] = {'nat46': {'enabled': True, 'mappings': maps}}
        records = value['services']['dns']['authoritative']['zones']['example.test']['records']
        records.update({name: {'A': {'alias': name}, 'AAAA': {'alias': name}} for name in maps})
        files = authoritative.render(config.normalize(value))
        zone = files['usr/share/lanrith/zones/db.example.test']
        for name, mapping in maps.items():
            self.assertIn(f'{name} IN A {mapping["ipv4"]}', zone)
            self.assertIn(f'{name} IN AAAA {mapping["ipv6"]}', zone)

    def test_disabling_authority_removes_dependencies_and_endpoint(self):
        value = declaration()
        value['services']['dns']['authoritative']['enabled'] = False
        value = config.normalize(value)
        files = config.render(value)
        self.assertFalse(any('bind/' in p or 'dns-state' in p for p in files))
        self.assertNotIn('authoritative', service_plane.topology(value)['endpoints'])

    def test_reject_ambiguous_and_unbounded_writers(self):
        for mutate in (
            lambda a: a['writers']['first'].update(sources={'addresses': '192.168.10.20'}),
            lambda a: a['writers']['first'].update(sources={'network': 'home', 'addresses': '192.0.2.20'}),
            lambda a: a['zones']['example.test'].update(persistent=False),
            lambda a: a['writers']['second'].update(key_name='FIRST-KEY'),
            lambda a: a['zones']['home.arpa']['records'].update({'escape.example.': {'A': '192.0.2.1'}}),
            lambda a: a['zones']['home.arpa']['records'].update({'ROUTER': {'A': '192.0.2.1'}}),
            lambda a: a['zones']['home.arpa']['records'].update({'ns1': {'A': '192.0.2.1'}}),
        ):
            value = declaration()
            mutate(value['services']['dns']['authoritative'])
            with self.assertRaises(ReleaseError):
                config.normalize(value)
        value = declaration()
        value['services']['dns']['blocked_domains'] = ['test']
        with self.assertRaisesRegex(ReleaseError, 'blocked domain'):
            config.normalize(value)

    @unittest.skipUnless(os.geteuid() == 0, 'persistent service state requires package ownership')
    def test_restart_retains_zone_and_journal_and_rejects_bad_credentials(self):
        files = authoritative.render(config.normalize(declaration()))
        manifest = json.loads(files['usr/share/lanrith/authoritative.json'])
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for name, text in files.items():
                path = root/name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(text)
            credentials, runtime = root/'credentials', root/'runtime'
            credentials.mkdir(mode=0o700)
            runtime.mkdir(mode=0o700)
            state = root/'var/cache/bind'
            state.mkdir(parents=True)
            for name in ('first_tsig', 'second_tsig'):
                (credentials/name).write_bytes(base64.b64encode(b'synthetic DNS test credential only'))
                (credentials/name).chmod(0o600)
            dns_runtime.prepare(manifest, credentials, runtime, root=root)
            zone = state/'db.example.test'
            zone.write_text('existing dynamic zone contents\n')
            journal = state/'db.example.test.jnl'
            journal.write_bytes(b'existing binary journal')
            dns_runtime.prepare(manifest, credentials, runtime, root=root)
            self.assertEqual(zone.read_text(), 'existing dynamic zone contents\n')
            self.assertEqual(journal.read_bytes(), b'existing binary journal')
            self.assertFalse(list(state.glob('.lanrith-seed-*')))
            key_file = (runtime/'keys.conf').read_bytes()
            (credentials/'first_tsig').write_bytes(b'"; include "/etc/passwd";')
            with self.assertRaises(ValueError):
                dns_runtime.prepare(manifest, credentials, runtime, root=root)
            self.assertEqual((runtime/'keys.conf').read_bytes(), key_file)
            zone.unlink()
            zone.symlink_to(journal)
            with self.assertRaises(ValueError):
                dns_runtime.prepare({**manifest, 'credentials': {}}, credentials, runtime, root=root)
            self.assertEqual(journal.read_bytes(), b'existing binary journal')
