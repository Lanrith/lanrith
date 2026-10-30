"""Directory connectivity and observations stay separate from delegated access."""

import json
import os
from pathlib import Path
import socket
import tempfile
import time
import unittest
from unittest import mock

from lanrith import build, config, directory_config, directory_runtime as runtime, metrics, router_metrics_runtime
from lanrith.release import ReleaseError
from test_policy_agent import declaration


SUCCESS = bytes.fromhex('300c02010178070a010004000400')


def fixture():
    value = declaration()
    value['networks']['home']['vlan'] = 1
    value['observability'] = {'metrics': {'enabled': True, 'clients': [{'network': 'home'}]}}
    return value


class DirectoryTests(unittest.TestCase):
    def test_exact_host_reader_path_and_separate_credential_free_observer(self):
        files = config.render(fixture())
        rule = next(line for line in files['etc/nftables.conf'].splitlines() if 'meta skuid' in line)
        self.assertEqual(rule, '  meta skuid { "router-policy-reader", "lanrith-directory-health" } '
            'oifname "lan.1" ip6 saddr { fd42:1234:5678:10::1 } ip6 daddr fd42:1234:5678:10::30 tcp dport 636 accept')
        unit = files['usr/lib/systemd/system/lanrith-directory-health.service']
        self.assertIn('User=lanrith-directory-health\nGroup=lanrith-directory-health\n', unit)
        self.assertIn('CapabilityBoundingSet=\n', unit)
        self.assertIn('BindsTo=nftables.service\n', unit)
        self.assertIn('RestrictAddressFamilies=AF_INET AF_INET6\n', unit)
        self.assertIn('-/run/router-policy-reader -/run/router-policy-ipc -/var/lib/lanrith', unit)
        self.assertNotIn('LoadCredential=', unit)
        probe = json.loads(files['usr/share/lanrith/directory-health.json'])
        self.assertEqual(probe, {'schema': 1, 'host': 'fd42:1234:5678:10::30', 'port': 636,
            'mode': 'ldaps', 'addresses': ['fd42:1234:5678:10::30'],
            'ca_file': '/usr/share/lanrith/trust/directory.pem'})
        self.assertNotIn('bind_dn', json.dumps(probe))
        self.assertIn('lanrith-directory-health.timer', json.loads(files['usr/share/lanrith/health.json'])['units'])
        collector = files['usr/lib/systemd/system/lanrith-router-metrics.service']
        self.assertIn('SupplementaryGroups=lanrith-directory-health\n', collector)
        self.assertIn('CapabilityBoundingSet=CAP_NET_ADMIN\n', collector)

    def test_metrics_off_removes_probe_but_retains_only_reader_connectivity(self):
        value = fixture()
        value['observability']['metrics']['enabled'] = False
        files = config.render(value)
        self.assertFalse(any('directory-health' in name for name in files))
        self.assertIn('meta skuid "router-policy-reader"', files['etc/nftables.conf'])
        self.assertNotIn('lanrith-directory-health', files['etc/nftables.conf'])
        value['identity']['policy']['enabled'] = False
        value['access']['rules'] = []
        files = config.render(value)
        self.assertNotIn('router-policy-reader', files['etc/nftables.conf'])

    def test_named_endpoints_require_explicit_pins_and_avoid_runtime_dns(self):
        value = fixture()
        directory = value['identity']['directories']['directory']
        directory['url'] = 'ldap+starttls://directory.example.test:1389'
        with self.assertRaises(ReleaseError):
            config.render(value)
        directory['addresses'] = ['fd42:1234:5678:10::30', '192.168.10.30']
        files = config.render(value)
        self.assertIn('192.168.10.30 directory.example.test\n', files['etc/hosts'])
        self.assertIn('fd42:1234:5678:10::30 directory.example.test\n', files['etc/hosts'])
        self.assertEqual(json.loads(files['usr/share/lanrith/directory-health.json'])['mode'], 'starttls')
        self.assertIn('ip saddr { 192.168.10.1 } ip daddr 192.168.10.30 tcp dport 1389 accept',
                      files['etc/nftables.conf'])
        for pins in ([], ['192.168.10.30']*2, ['192.168.10.0/24'], ['127.0.0.1'], ['fe80::1'],
                     ['ff02::1'], ['::ffff:192.168.10.30'], ['fd42:1234:5678:10::30%lan.1'],
                     [True], ['192.168.10.30']*9):
            directory['addresses'] = pins
            with self.subTest(pins=pins), self.assertRaises(ReleaseError):
                config.render(value)
        directory['url'] = 'ldaps://192.168.10.30'
        directory['addresses'] = ['192.168.10.31']
        with self.assertRaises(ReleaseError):
            config.render(value)
        for url in ('ldaps://192.168.10.30:0', 'ldaps://[fd42:1234:5678:10::30%lan.1]',
                    'ldaps://123', 'ldaps://192.168.10.030'):
            directory['url'] = url
            directory['addresses'] = ['192.168.10.30']
            with self.subTest(url=url), self.assertRaises(ReleaseError):
                config.render(value)

    def test_management_router_service_translator_and_unrouted_targets_are_rejected(self):
        for address in ('192.168.10.1', '10.255.254.10', 'fd42:1234:5678:fe02::10',
                        'fd42:1234:5678:99::30', '203.0.113.30'):
            value = fixture()
            value['identity']['directories']['directory']['url'] = 'ldaps://['+address+']:636' if ':' in address else 'ldaps://'+address
            with self.subTest(address=address), self.assertRaises(ReleaseError):
                config.render(value)
        value = fixture()
        value['networks']['devices']['role'] = 'management'
        value['identity']['policy']['networks'] = ['home']
        value['access']['rules'] = []
        value['identity']['directories']['directory']['url'] = 'ldaps://192.168.22.30'
        with self.assertRaises(ReleaseError):
            config.render(value)

    def test_additional_gateway_and_routed_prefix_keep_exact_attachment_and_source_family(self):
        value = fixture()
        value['networks']['home']['additional_subnets'] = ['fd42:1234:5678:700::/64']
        value['identity']['directories']['directory']['url'] = 'ldaps://[fd42:1234:5678:700::30]'
        path = directory_config.paths(config.normalize(value))[0]
        self.assertEqual(path['interface'], 'lan.1')
        self.assertEqual(path['sources'], ['fd42:1234:5678:10::1', 'fd42:1234:5678:700::1'])

    def test_runtime_contract_is_bounded_and_rejects_overrides(self):
        policy = json.loads(config.render(fixture())['usr/share/lanrith/directory-health.json'])
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/'probe.json'
            path.write_text(json.dumps(policy))
            self.assertEqual(runtime.load(path, owner=os.getuid()), policy)
            for change in ({'schema': True}, {'port': True}, {'mode': 'ldap'}, {'password': 'disallowed'},
                           {'addresses': []}, {'addresses': ['::1']}, {'addresses': [True]},
                           {'addresses': policy['addresses']*2}, {'ca_file': '/tmp/authority.pem'},
                           {'host': 'other.example.test\n192.0.2.1'}):
                path.write_text(json.dumps({**policy, **change}))
                with self.subTest(change=change), self.assertRaises(ValueError):
                    runtime.load(path, owner=os.getuid())

    def test_starttls_accepts_only_bounded_correlated_success_before_tls(self):
        responses = [SUCCESS, b'\x30\x24\x02\x01\x01\x78\x1f'+SUCCESS[7:]+
                     b'\x8a\x16'+runtime.STARTTLS_OID]
        for response in responses:
            client, server = socket.socketpair()
            with client, server:
                server.sendall(response)
                runtime.starttls(client, time.monotonic()+1)
                self.assertEqual(server.recv(1024), runtime.STARTTLS_REQUEST)
        for response in (SUCCESS.replace(b'\x02\x01\x01', b'\x02\x01\x02'),
                         SUCCESS.replace(b'\x0a\x01\x00', b'\x0a\x01\x34'),
                         b'\x30\x80', b'\x30\x83\xff\xff\xff',
                         SUCCESS[:-1], b'HTTP/1.1 200 OK\r\n', b'\x30\x82\x20\x00',
                         b'\x30\x0e\x02\x01\x01\x78\x09'+SUCCESS[7:]+b'\x8b\x00'):
            client, server = socket.socketpair()
            with client, server:
                server.sendall(response)
                server.shutdown(socket.SHUT_WR)
                with self.subTest(response=response), self.assertRaises(ValueError):
                    runtime.starttls(client, time.monotonic()+1)

    def test_observations_reject_replay_unsafe_files_and_inconsistent_results(self):
        now = time.monotonic_ns()
        value = {'schema': 1, 'boot_id': Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
                 'observed_monotonic_ns': now, 'observed_timestamp_seconds': int(time.time()),
                 'tls_verified': True, 'endpoints_total': 1, 'endpoints_verified': 1,
                 'certificate_not_after_seconds': int(time.time())+3600}
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/'health.json'
            runtime.publish(value, path)
            self.assertEqual(path.stat().st_mode & 0o777, 0o640)
            self.assertEqual(runtime.read_observation(path, owner=os.getuid()), value)
            for change in ({'boot_id': 'previous'}, {'observed_monotonic_ns': now-100*10**9},
                           {'observed_monotonic_ns': now+100*10**9}, {'tls_verified': 1},
                           {'endpoints_verified': 0}, {'certificate_not_after_seconds': 0},
                           {'schema': True}, {'unexpected': 'owner.yaml'}):
                path.write_text(json.dumps({**value, **change}))
                with self.subTest(change=change), self.assertRaises(ValueError):
                    runtime.read_observation(path, owner=os.getuid())
            path.write_text(json.dumps(value))
            path.chmod(0o660)
            with self.assertRaises(ValueError):
                runtime.read_observation(path, owner=os.getuid())
            path.chmod(0o640)
            alias = Path(directory)/'alias'
            alias.symlink_to(path)
            with self.assertRaises(OSError):
                runtime.read_observation(alias, owner=os.getuid())

    def test_metrics_distinguish_verified_failure_and_unavailable_or_disabled(self):
        policy = metrics.router_manifest(config.normalize(fixture()))
        state = {'tls_verified': False, 'observed_timestamp_seconds': 1234567890, 'endpoints_total': 2,
                 'endpoints_verified': 1, 'certificate_not_after_seconds': 0}
        with mock.patch.object(router_metrics_runtime, 'command', side_effect=ValueError), \
                mock.patch.object(router_metrics_runtime, 'read', side_effect=ValueError), \
                mock.patch.object(runtime, 'read_observation', return_value=state):
            text = router_metrics_runtime.collect(policy)
        self.assertIn('lanrith_router_directory_tls_verified 0\n', text)
        self.assertIn('lanrith_router_directory_tls_endpoints_verified 1\n', text)
        with mock.patch.object(router_metrics_runtime, 'command', side_effect=ValueError), \
                mock.patch.object(router_metrics_runtime, 'read', side_effect=ValueError), \
                mock.patch.object(runtime, 'read_observation', side_effect=ValueError) as query:
            text = router_metrics_runtime.collect(policy)
            self.assertIn('metrics_query_success{collector="directory"} 0\n', text)
            self.assertNotIn('lanrith_router_directory_tls_', text)
            query.reset_mock()
            policy['directory'] = False
            self.assertNotIn('collector="directory"', router_metrics_runtime.collect(policy))
            query.assert_not_called()

    def test_assembled_runtime_has_no_directory_compiler_or_source_configuration(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            base = root/'base.tar'
            base.write_bytes(b'synthetic assembly input')
            build.assembly(fixture(), base, root/'image', version='0.1.0', sequence=9)
            overlay = root/'image/mkosi.extra'
            self.assertTrue((overlay/'usr/lib/lanrith/directory-health').is_file())
            self.assertTrue((overlay/'usr/lib/lanrith/lanrith/directory_runtime.py').is_file())
            self.assertFalse((overlay/'usr/lib/lanrith/lanrith/directory_config.py').exists())
            self.assertFalse(any(p.suffix in ('.yml', '.yaml') for p in overlay.rglob('*')))


if __name__ == '__main__':
    unittest.main()
