"""DNS alias resolution, writer boundaries and persistent initialization."""

import base64
import errno
import json
import os
from pathlib import Path
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch

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
                      'grants': [{'subtree': '@', 'types': ['A', 'AAAA', 'CNAME', 'SRV', 'TXT']}],
                      'key_name': 'first-key', 'credential': 'first_tsig', 'zone_transfer': True},
            'second': {'zone': 'example.test', 'sources': {'network': 'home', 'addresses': '192.168.10.21'},
                       'grants': [{'name': 'dynamic-second', 'types': ['A']}],
                       'key_name': 'second-key', 'credential': 'second_tsig'}}}}}
    value['services']['ntp'] = {'enabled': True, 'upstreams': ['192.0.2.123']}
    return value


class AuthoritativeTests(unittest.TestCase):
    def test_service_lifecycle_does_not_require_the_disabled_command_channel(self):
        files = authoritative.render(config.normalize(declaration()))
        self.assertIn('controls {};', files['etc/bind/named.conf'])
        unit = files['etc/systemd/system/named.service.d/60-lanrith-services.conf']
        self.assertIn('ExecStop=\n', unit)
        self.assertIn('KillSignal=SIGTERM\n', unit)
        self.assertIn('ExecReload=\nExecReload=/usr/bin/kill -HUP $MAINPID\n', unit)
        self.assertNotIn('rndc', unit)

    def test_generated_records_and_nested_source_and_key_checks(self):
        value = config.normalize(declaration())
        files = config.render(value)
        text = files['etc/bind/named.conf']
        self.assertIn('acl "writer-0" { !{ !{ 192.168.10.20/32; }; any; }; key "first-key"; };', text)
        self.assertIn('grant "first-key" subdomain example.test. A AAAA CNAME SRV TXT;', text)
        self.assertIn('grant "second-key" name dynamic-second.example.test. A;', text)
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

    def test_parent_delegates_only_selected_views(self):
        value = declaration()
        value['hardware']['interfaces']['guest'] = {'name': 'guest', 'match': {'mac': '02:00:00:00:30:01'}}
        value['networks']['guest'] = {'interface': 'guest', 'ipv4': '172.20.30.0/24'}
        value['services']['discovery'] = {
            'enabled': True, 'domain': 'devices.test', 'networks': ['home', 'guest'], 'alias_prefix': 'lab-',
            'views': {'home': 'home', 'other': 'guest'}, 'default_view': 'other'}
        entry = {'discovery_delegation': {'views': ['home'], 'publish_browse': True},
                 'records': {'Discovery-Proxy': {'A': '10.255.254.12'}}}
        zones = value['services']['dns']['authoritative']['zones']
        zones['devices.test'] = entry

        def render():
            return config.render(value)['usr/share/lanrith/zones/db.devices.test']

        output = render()
        for line in ('home IN NS discovery-proxy.devices.test.', 'Discovery-Proxy IN A 10.255.254.12',
                     'Discovery-Proxy IN AAAA fd42:1234:5678:fe02::12',
                     'b._dns-sd._udp IN PTR home.devices.test.', 'lb._dns-sd._udp IN PTR home.devices.test.'):
            self.assertIn(line, output.splitlines())
        self.assertNotIn('db._dns-sd._udp', output)
        self.assertNotIn('other.devices.test', output)
        entry['discovery_delegation']['publish_browse'] = False
        self.assertNotIn(' IN PTR ', render())
        entry['discovery_delegation']['publish_browse'] = True
        for label, record in (('HOME', {'CNAME': 'somewhere.test.'}), ('ns.home', {'A': '192.0.2.8'}),
                              ('B._DNS-SD._UDP', {'A': '192.0.2.9'}), ('Discovery-Proxy', {'A': '192.0.2.1'})):
            original = entry['records']
            entry['records'] = {**original, label: record}
            with self.subTest(label=label), self.assertRaises(ReleaseError):
                render()
            entry['records'] = original
        for child in ('home.devices.test', 'nested.home.devices.test', 'discovery-proxy.devices.test'):
            zones[child] = {}
            with self.subTest(child=child), self.assertRaises(ReleaseError):
                render()
            del zones[child]
        for views in (['unknown'], ['home', 'home'], ['discovery-proxy']):
            entry['discovery_delegation']['views'] = views
            with self.subTest(views=views), self.assertRaises(ReleaseError):
                render()
        entry['discovery_delegation']['views'] = ['home']
        entry['persistent'] = True
        with self.assertRaises(ReleaseError):
            render()
        del entry['discovery_delegation']
        self.assertNotIn('home IN NS ', render())

    def test_direct_readers_and_bounded_grants(self):
        value = declaration()
        authority = value['services']['dns']['authoritative']
        authority['direct_readers'] = [{'network': 'home', 'addresses': '192.168.10.40'}]
        files = config.render(value)
        for name in ('etc/bind/named.conf', 'etc/lanrith/services.nft', 'etc/nftables.conf'):
            contents = files[name].splitlines()
            admission = [line for line in contents if ('allow-query' in line or
                         '10.255.254.11' in line and 'dport 53 accept' in line)]
            self.assertTrue(any('192.168.10.40/32' in line for line in admission), (name, admission))
            self.assertFalse(any('192.168.10.0/24' in line for line in admission), (name, admission))
        for source in ({'network': 'home', 'addresses': '192.0.2.1'}, {'addresses': '192.168.10.40'}):
            authority['direct_readers'] = [source]
            with self.assertRaises(ReleaseError):
                config.render(value)
        del authority['direct_readers']
        writer = authority['writers']['first']
        for grant in ({'subtree': '@', 'types': ['ANY']}, {'name': 'bad.', 'types': ['A']},
                      {'name': 'x', 'subtree': 'y', 'types': ['A']}, {'name': 'x', 'types': []},
                      {'subtree': '@', 'types': ['AAA', 'A']}, {'name': 'x', 'types': ['A', 'A']}):
            writer['grants'] = [grant]
            with self.subTest(grant=grant), self.assertRaises(ReleaseError):
                config.render(value)
        writer['grants'] = []
        transfer_only = config.render(value)['etc/bind/named.conf']
        self.assertIn('allow-transfer { "writer-0"; };', transfer_only)
        self.assertNotIn('grant "first-key"', transfer_only)
        del writer['grants']
        with self.assertRaisesRegex(ReleaseError, 'explicit grants'):
            config.render(value)
        authority['enabled'] = False
        self.assertNotIn('etc/bind/named.conf', config.render(value))

    def test_large_zone_keeps_exact_writer_grants(self):
        value = declaration()
        authority = value['services']['dns']['authoritative']
        records = {f'host-{i}': {'A': '192.0.2.1'} for i in range(4100)}
        authority['zones']['example.test']['records'] = records
        writer = authority['writers']['first']
        writer['grants'] = [{'name': name, 'types': ['TXT']} for name in records]
        files = config.render(value)
        grants = [line.strip() for line in files['etc/bind/named.conf'].splitlines()
                  if line.strip().startswith('grant "first-key"')]
        self.assertEqual(grants, [f'grant "first-key" name {name}.example.test. TXT;' for name in records])
        zone_lines = set(files['usr/share/lanrith/zones/db.example.test'].splitlines())
        self.assertTrue(all(f'{name} IN A 192.0.2.1' in zone_lines for name in records))
        writer['grants'][-1]['name'] = 'outside.example.'
        with self.assertRaises(ReleaseError):
            config.render(value)
        writer['grants'] = {'name': 'single', 'types': ['A']}
        with self.assertRaisesRegex(ReleaseError, 'must be a list'):
            config.render(value)

    def test_routed_resolver_client_needs_a_separate_authority_grant(self):
        from test_routing import declaration as routed_declaration
        value = routed_declaration()
        dns = declaration()['services']['dns']
        value['services'] = {'dns': dns}
        reader = 'fd42:9876:5432::17'
        for declared in (False, True):
            if declared:
                dns['authoritative']['direct_readers'] = [{'network': 'home', 'addresses': reader}]
            files = config.render(value)
            host = files['etc/nftables.conf'].splitlines()
            for transport in ('udp', 'tcp'):
                target = 'ip6 daddr { fd42:1234:5678:fe02::11 } '+transport+' dport 53 accept'
                self.assertEqual([line.strip() for line in host if target in line],
                                 [f'iifname "lan" oifname "lr-services" ip6 saddr {{ {reader}/128 }} '+target]
                                 if declared else [])
            self.assertIn('access-control: fd42:9876:5432::/48 allow', files['etc/unbound/unbound.conf.d/lanrith.conf'])
            self.assertNotIn('fd42:9876:5432::/48;', files['etc/bind/named.conf'])

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

    def test_managed_rrsets_are_opt_in_and_validate_prerequisites(self):
        def with_zone(change):
            value = declaration()
            zone = value['services']['dns']['authoritative']['zones']['example.test']
            zone.update(change)
            return authoritative.render(config.normalize(value))

        self.assertNotIn('etc/bind/lanrith-migration.conf', with_zone({}))
        files = with_zone({'managed_rrsets': {'seeded': {'A': {'previous': ['192.0.2.10']}}}})
        self.assertEqual(json.loads(files['usr/share/lanrith/dns-migration.json']), {
            'example.test': [{'name': 'seeded.example.test.', 'type': 'A',
                              'previous': ['192.0.2.10'], 'desired': ['192.0.2.20']}]})
        policy = files['etc/bind/named.conf']
        self.assertIn('deny "first-key" name seeded.example.test. A CNAME;', policy)
        private = files['etc/bind/lanrith-migration.conf']
        self.assertIn('grant "lanrith-migration" name seeded.example.test. A;', private)
        self.assertNotIn('zonesub', private)
        self.assertNotIn('lanrith-migration', policy)
        for changes in ({'managed_rrsets': {'typo': {'AAAA': {'previous': []}}}},
                        {'managed_rrsets': {'seeded': {'A': {'previous': ['2001:db8::1']}}}},
                        {'managed_rrsets': {'seeded': {'A': {'previous': [], 'remove': True}}}},
                        {'managed_rrsets': {'x': {'A': {'previous': [], 'remove': True}}}},
                        {'managed_rrsets': {'seeded.': {'A': {'previous': []}}}},
                        {'managed_rrsets': {'seeded': {'A': {'previous': ['192.0.2.1']*2}}}},
                        {'persistent': False, 'managed_rrsets': {'seeded': {'A': {'previous': []}}}}):
            with self.subTest(changes=changes), self.assertRaises(ReleaseError):
                with_zone(changes)

    def test_state_checks_before_allocation_and_verifies_publication_winner(self):
        files = authoritative.render(config.normalize(declaration()))
        manifest = json.loads(files['usr/share/lanrith/authoritative.json'])
        manifest['credentials'] = {}
        uid, gid = os.getuid(), os.getgid()
        account = SimpleNamespace(pw_uid=uid, pw_gid=gid, gr_gid=gid)
        with (tempfile.TemporaryDirectory() as temporary,
              patch.object(dns_runtime.pwd, 'getpwnam', return_value=account),
              patch.object(dns_runtime.grp, 'getgrnam', return_value=account),
              patch.object(dns_runtime.os, 'fchown')):
            root = Path(temporary)
            source = root/manifest['seeds'][0]['source'][1:]
            source.parent.mkdir(parents=True)
            source.write_text('seed')
            target = root/manifest['seeds'][0]['target'][1:]
            target.parent.mkdir(parents=True)
            journal = target.with_name(target.name+'.jnl')
            runtime = root/'run'
            runtime.mkdir()

            def prepare():
                dns_runtime.prepare(manifest, root, runtime, root=root)

            allocate = tempfile.mkstemp

            def full_cache(*args, **kwargs):
                if kwargs['dir'] == target.parent:
                    raise OSError(errno.ENOSPC, 'synthetic full cache')
                return allocate(*args, **kwargs)

            with patch.object(tempfile, 'mkstemp', side_effect=full_cache):
                with self.assertRaises(OSError) as failure:
                    prepare()
                self.assertEqual(failure.exception.errno, errno.ENOSPC)
                self.assertFalse(target.exists())
                journal.write_bytes(b'journal marker')
                with self.assertRaisesRegex(dns_runtime.IncompleteRestore, 'example.test'):
                    prepare()
                self.assertFalse(target.exists())
                self.assertEqual(journal.read_bytes(), b'journal marker')
                target.write_bytes(b'retained')
                (runtime/'keys.conf').write_text('expired')
                prepare()
                self.assertEqual(target.read_bytes(), b'retained')
                self.assertEqual(journal.read_bytes(), b'journal marker')
                self.assertEqual((runtime/'keys.conf').read_text(), '')
                with patch.object(dns_runtime.pwd, 'getpwnam', return_value=SimpleNamespace(pw_uid=uid+1)):
                    with self.assertRaisesRegex(ValueError, 'unsafe metadata'):
                        prepare()
                target.chmod(0o664)
                with self.assertRaisesRegex(ValueError, 'unsafe metadata'):
                    prepare()
                target.unlink()
                target.symlink_to(journal)
                with self.assertRaisesRegex(ValueError, 'unsafe metadata'):
                    prepare()
            target.unlink()
            journal.unlink()
            for mode in (0o640, 0o664):
                def winner(*args, **kwargs):
                    target.write_text('another initializer')
                    target.chmod(mode)
                    raise FileExistsError()
                with patch.object(dns_runtime.os, 'link', side_effect=winner):
                    if mode == 0o640:
                        prepare()
                    else:
                        with self.assertRaisesRegex(ValueError, 'unsafe metadata'):
                            prepare()
                    self.assertEqual(target.read_text(), 'another initializer')
                target.unlink()
                self.assertFalse(list(target.parent.glob('.lanrith-seed-*')))

            # A compact declaration can expand into more than one MiB of zone data.
            source.write_text(''.join(f'host-{n} IN AAAA 2001:db8::1\n' for n in range(40000)))
            prepare()
            self.assertEqual(target.read_bytes(), source.read_bytes())

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
