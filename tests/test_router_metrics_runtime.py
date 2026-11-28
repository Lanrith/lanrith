"""Router observations distinguish unavailable data and enforce resource bounds."""

import copy
import json
import os
import re
import stat
import struct
from pathlib import Path
import sys
import tempfile
import time
import unittest
from types import SimpleNamespace
from unittest import mock

from lanrith import config, metrics, router_metrics_runtime as runtime
from lanrith.release import ReleaseError
from test_metrics import fixture


class RouterHealthTests(unittest.TestCase):
    def test_manifest_is_compiled_for_arbitrary_owner_names_and_rejects_overrides(self):
        value = fixture()
        name = 'owner-lan'
        value['networks'][name] = value['networks'].pop('home')
        value['observability']['metrics']['clients'] = [{'network': name}]
        value['administration']['networks'] = [name]
        value['access'] = {'default': 'deny', 'rules': []}
        policy = metrics.router_manifest(config.normalize(value))
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary)/'metrics.json'
            path.write_text(json.dumps(policy))
            self.assertEqual(runtime.load(path), policy)
            for change in ({'command': 'anything'}, {'interfaces': ['../interface']},
                           {'units': ['anything.service\nother.service']}, {'ntp': 1}, {'logs': 1}, {'directory': 1},
                           {'clients': [{'network': name, 'interface': 'undeclared'}]}):
                path.write_text(json.dumps({**policy, **change}))
                with self.subTest(change=change), self.assertRaises(ReleaseError):
                    runtime.load(path)

    def test_command_output_and_lifetime_are_bounded_and_diagnostics_are_not_consumed(self):
        self.assertEqual(runtime.command([sys.executable, '-c', 'print("synthetic")'], time.monotonic()+2), 'synthetic\n')
        for script in ('print("x"*4096)', 'import time;time.sleep(10)', 'import sys;print("private",file=sys.stderr);sys.exit(1)'):
            started = time.monotonic()
            with self.subTest(script=script), self.assertRaises(runtime.QueryError):
                runtime.command([sys.executable, '-c', script], started+.15, limit=1024)
            self.assertLess(time.monotonic()-started, 2)

    def test_neighbor_validation_excludes_failed_entries_and_preserves_family(self):
        entries = [{'dst': '192.0.2.10', 'lladdr': '02:00:00:00:00:10', 'state': ['REACHABLE']},
                   {'dst': 'fd42::10', 'lladdr': '02:00:00:00:00:10', 'state': ['STALE']},
                   {'dst': '192.0.2.11', 'state': ['FAILED']}]
        observed = runtime.neighbors(json.dumps(entries+entries))
        self.assertEqual(len(observed), 2)
        self.assertEqual({entry[2] for entry in observed}, {'ipv4', 'ipv6'})
        for change in ({'dst': '224.0.0.1'}, {'lladdr': '01:00:00:00:00:10'}, {'state': 'REACHABLE'},
                       {'dst': 'fe80::1%lan'}, {'lladdr': '00:00:00:00:00:00'}):
            with self.subTest(change=change), self.assertRaises((runtime.QueryError, ValueError)):
                runtime.neighbors(json.dumps([{**entries[0], **change}]))

    def test_clock_checks_reject_unsynchronised_local_and_nonfinite_observations(self):
        fields = ['C0000201', '0', '3', *['1']*10, 'Normal']
        self.assertEqual(runtime.tracking(','.join(fields)), 1)
        for index, value in ((0, '7F7F0101'), (0, '00000000'), (2, '16'), (13, 'Not synchronised')):
            row = fields[:]
            row[index] = value
            self.assertEqual(runtime.tracking(','.join(row)), 0)
        row = fields[:]
        row[4] = 'NaN'
        with self.assertRaises(runtime.QueryError):
            runtime.tracking(','.join(row))

    def test_host_counters_are_scoped_and_duplicate_rows_are_rejected(self):
        text = 'Inter-| synthetic\n face | synthetic\n lan: '+' '.join(str(n) for n in range(16))+'\n'
        self.assertEqual(runtime.netdev(text, ['lan']), {'lan': [0, 1, 2, 3, 8, 9, 10, 11]})
        self.assertEqual(runtime.netdev(text, ['wan']), {})
        with self.assertRaises(runtime.QueryError):
            runtime.netdev(text+text.splitlines()[-1]+'\n', ['lan'])

    def test_failed_queries_are_not_healthy_empty_inventory_and_do_not_advance_timestamp(self):
        policy = metrics.router_manifest(config.normalize(fixture()))
        with mock.patch.object(runtime, 'command', side_effect=runtime.QueryError), \
                mock.patch.object(runtime, 'read', side_effect=runtime.QueryError):
            output = runtime.collect(policy, previous_inventory=1234567890)
        self.assertIn('lanrith_router_metrics_collection_success 0\n', output)
        self.assertIn('lanrith_router_client_inventory_complete 0\n', output)
        self.assertIn('lanrith_router_client_inventory_collection_timestamp_seconds 1234567890\n', output)
        self.assertNotIn('lanrith_router_client_neighbor_count', output)
        self.assertNotIn('chrony_synchronised', output)
        self.assertNotIn('alloy_', output)

    def test_export_loss_observations_are_optional_and_unavailable_is_not_zero(self):
        from lanrith import logs_runtime
        policy = metrics.router_manifest(config.normalize(fixture()))
        policy['logs'] = True
        observed = {'queue_capacity_bytes': 67108864, 'queue_size_bytes': 1234,
                    'enqueue_failed_records': 42, 'send_failed_records': 21}
        with mock.patch.object(runtime, 'command', side_effect=runtime.QueryError), \
                mock.patch.object(runtime, 'read', side_effect=runtime.QueryError), \
                mock.patch.object(logs_runtime, 'read_observation', return_value=observed):
            output = runtime.collect(policy)
        self.assertIn('lanrith_router_alloy_enqueue_failed_records_total 42\n', output)
        self.assertIn('lanrith_router_alloy_send_failed_records_total 21\n', output)
        self.assertIn('lanrith_router_metrics_query_success{collector="alloy"} 1\n', output)
        with mock.patch.object(runtime, 'command', side_effect=runtime.QueryError), \
                mock.patch.object(runtime, 'read', side_effect=runtime.QueryError), \
                mock.patch.object(logs_runtime, 'read_observation', side_effect=ValueError):
            output = runtime.collect(policy)
        self.assertNotIn('lanrith_router_alloy_enqueue_failed_records_total', output)
        self.assertIn('lanrith_router_metrics_query_success{collector="alloy"} 0\n', output)

    def test_mount_flags_require_one_host_mount_and_both_writable_layers(self):
        root = b'28 1 0:8 / / rw - ext4 /dev/test rw,relatime'
        state = b'29 28 0:9 / /var rw shared:2 - ext4 /dev/state rw'
        self.assertTrue(runtime.mount_writable([root, state], b'/var'))
        for read_only in (state.replace(b'rw', b'ro', 1), state[:-2]+b'ro'):
            self.assertFalse(runtime.mount_writable([root, read_only], b'/var'))
        for rows in ([root], [root, state, state], [state.replace(b'rw ', b'ro,rw ')], [b'malformed']):
            with self.subTest(rows=rows), self.assertRaises(runtime.QueryError):
                runtime.mount_writable(rows, b'/var')

    def test_firewall_inventory_checks_device_priority_policy_and_dormant_tables(self):
        from test_directory import fixture as directory
        policy = metrics.router_manifest(config.normalize(directory()))
        expected = policy['hooks']['host']
        tables = {(h['family'], h['table']): True for h in expected}
        index = next(i for i,h in enumerate(expected) if 'dev' in h)
        self.assertTrue(policy['startup_set'])
        for key, bad in (('dev', 'other0'), ('prio', 1), ('policy', 'drop'), ('type', 'nat'), ('hook', 'input')):
            observed = copy.deepcopy(expected)
            observed[index][key] = bad
            with self.subTest(key=key), mock.patch.object(runtime, 'nft_objects', return_value=observed):
                result = runtime.hook_states(expected, tables, 0)
                self.assertFalse(result[index])
                self.assertTrue(all(result[:index]+result[index+1:]))
        tables['netdev', 'lanrith_identity'] = False
        with mock.patch.object(runtime, 'nft_objects', return_value=expected):
            self.assertFalse(runtime.hook_states(expected, tables, 0)[index])

    def test_dhcp_requires_complete_declared_integer_counters_and_uses_no_lease_socket(self):
        value = fixture()
        value['services']['dhcp4'] = {'enabled': True}
        files = config.render(value)
        policy = json.loads(files['usr/share/lanrith/router-metrics.json'])
        subnet, pools = next(iter(policy['dhcp4'].items()))
        pool = {'subnet_id': int(subnet), 'pool': pools[0], 'total': 51, 'assigned': 0}
        counters = {'subnet_id': int(subnet), 'declined': 1, 'allocation_failures': 4}
        response = {'pools': [pool], 'subnets': [counters]}
        self.assertEqual(runtime.dhcp_capacity(policy['dhcp4'], response), response)
        for bad in ({'pools': [], 'subnets': [counters]}, {'pools': [pool, pool], 'subnets': [counters]},
                    {'pools': [dict(pool, assigned=52)], 'subnets': [counters]},
                    {'pools': [dict(pool, assigned=True)], 'subnets': [counters]},
                    {'pools': [dict(pool, pool=pools[0]+1)], 'subnets': [counters]},
                    {'pools': [pool], 'subnets': [dict(counters, declined=-1)]}):
            with self.subTest(bad=bad), self.assertRaises(runtime.QueryError):
                runtime.dhcp_capacity(policy['dhcp4'], bad)
        with mock.patch.object(runtime, 'command', side_effect=ValueError), \
                mock.patch.object(runtime, 'socket_observation', side_effect=ValueError) as query:
            text = runtime.collect(policy)
            self.assertIn('lanrith_router_metrics_query_success{collector="dhcp4"} 0\n', text)
            self.assertNotIn('lanrith_router_dhcp4_pool_', text)
            self.assertIn('lanrith-kea-statistics', [call.args[0] for call in query.call_args_list])
        self.assertNotIn('lanrith-kea-lease-readers', files['usr/lib/systemd/system/lanrith-router-metrics.service'])
        value['services']['dhcp4']['enabled'] = False
        policy = metrics.router_manifest(config.normalize(value))
        with mock.patch.object(runtime, 'command', side_effect=ValueError):
            self.assertNotIn('collector="dhcp4"', runtime.collect(policy))

    def test_root_only_observer_stream_is_bounded_and_never_accepts_partial_json(self):
        info = SimpleNamespace(st_mode=stat.S_IFSOCK|0o600, st_uid=0, st_gid=0)
        with mock.patch.object(Path, 'lstat', return_value=info), mock.patch.object(runtime.socket, 'socket') as create:
            peer = create.return_value.__enter__.return_value
            peer.getsockopt.return_value = struct.pack('3i', 1, 0, 0)
            peer.recv.side_effect = [b'{"pools":', b'[]}', b'']
            self.assertEqual(runtime.socket_observation('lanrith-kea-statistics', time.monotonic()+1, 32), {'pools': []})
            peer.sendall.assert_not_called()
            for chunks in ([b''], [b'{"pools":', b''], [b' '*33], [b'{}{}', b''], [b'{"x":1,"x":2}', b'']):
                peer.recv.side_effect = chunks
                with self.subTest(chunks=chunks), self.assertRaises(ValueError):
                    runtime.socket_observation('lanrith-kea-statistics', time.monotonic()+1, 32)
            peer.getsockopt.return_value = struct.pack('3i', 123, 100, 100)
            with self.assertRaises(runtime.QueryError):
                runtime.socket_observation('lanrith-kea-statistics', time.monotonic()+1, 32)
            info.st_mode |= 0o020
            with self.assertRaises(runtime.QueryError):
                runtime.socket_observation('lanrith-kea-statistics', time.monotonic()+1, 32)

    def test_maximum_pool_response_and_inventory_fit_the_collection_budget(self):
        policy = metrics.router_manifest(config.normalize(fixture()))
        policy['interfaces'] = ['interface%06d' % i for i in range(128)]
        policy['clients'] = [{'network': 'network%05d' % i, 'interface': name}
                             for i, name in enumerate(policy['interfaces'][:64])]
        policy['dhcp4'] = {str(2**32-1-i): list(range(2**32-65,2**32-1)) for i in range(64)}
        policy['units'] = ['unit'+str(i)+'a'*110+'.service' for i in range(256)]
        response = {'subnets': [{'subnet_id': int(s), 'declined': 0, 'allocation_failures': 2**63-1}
                                for s in policy['dhcp4']],
                    'pools': [{'subnet_id': int(s), 'pool': p, 'assigned': 100, 'total': 100}
                              for s, pools in policy['dhcp4'].items() for p in pools]}
        self.assertLess(len(json.dumps(response, separators=(',', ':'))), 512*1024)
        entries = [{'dst': '2001:db8:1111:2222:3333:4444:5555:'+format(i,'04x'),
                    'lladdr': '02:00:00:00:00:01', 'state': ['REACHABLE']} for i in range(256)]
        cache = json.dumps(entries)
        def command(argv, *args):
            if argv[:4] == ['ip', '-j', 'neigh', 'show']:
                return cache
            if argv == ['cat', '/proc/net/dev']:
                return ('Inter-| net\n face | test\n'+'\n'.join(
                    f'{name}: '+' '.join(['18446744073709551615']*16) for name in policy['interfaces']))
            raise ValueError
        def observe(name, end, limit):
            if name != 'lanrith-kea-statistics':
                raise ValueError
            return response
        with mock.patch.object(runtime, 'command', command), mock.patch.object(runtime, 'socket_observation', observe):
            text = runtime.collect(policy)
        self.assertGreater(len(text.encode()), 1024*1024)
        self.assertLess(len(text.encode()), 2*1024*1024)
        self.assertEqual(text.count('lanrith_router_dhcp4_pool_assigned_addresses{'), 4096)
        self.assertEqual(text.count('lanrith_router_client_neighbor_info{'), 1024)
        self.assertIn('lanrith_router_client_inventory_complete 0\n', text)

    def test_monitoring_rules_select_families_and_neighbor_labels_from_the_producer(self):
        from lanrith import directory_runtime, ids_observer, logs_runtime, ntp_health_runtime
        from test_directory import fixture as directory
        value = directory()
        value.setdefault('observability', {})['ids'] = {'enabled': True}
        value['observability']['logs'] = {'enabled': True, 'endpoint': 'https://192.168.10.31/otlp',
                                          'tls_server_name': 'logs.example.test'}
        policy = metrics.router_manifest(config.normalize(value))
        def command(argv, *args):
            if argv[:4] == ['ip', '-j', 'neigh', 'show']:
                return '[{"dst":"192.0.2.1","lladdr":"02:00:00:00:00:01","state":["STALE"]}]'
            raise ValueError
        def observe(name, end, limit):
            if name == 'lanrith-router-policy-status':
                return {'ready': True, 'applied': True, 'directory_age_ms': 500, 'apply_age_ms': 300}
            raise ValueError
        with mock.patch.object(runtime, 'command', command), mock.patch.object(runtime, 'socket_observation', observe), \
                mock.patch.object(runtime, 'reader_attempt', return_value=('applied', 50)), \
                mock.patch.object(directory_runtime, 'trust_expiries', return_value={'a'*64: 1200}), \
                mock.patch.object(logs_runtime, 'read_observation', return_value={
                    'queue_capacity_bytes': 67108864, 'queue_size_bytes': 0,
                    'enqueue_failed_records': 0, 'send_failed_records': 0}), \
                mock.patch.object(ids_observer, 'read_observation', return_value={
                    'timestamp': 100, 'totals': {name: 2 for name in ids_observer.FIELDS}, 'delta': None}), \
                mock.patch.object(ntp_health_runtime, 'read_observation', return_value={
                    'query_success': True, 'synchronised': True, 'observed_timestamp_seconds': 50,
                    'reference_timestamp_seconds': 48, 'clock_error_bound_seconds': 0.002}), \
                mock.patch.object(directory_runtime, 'read_observation', return_value={
                    'tls_verified': True, 'observed_timestamp_seconds': 50, 'endpoints_total': 1,
                    'endpoints_verified': 1, 'certificate_not_after_seconds': 100}):
            text = runtime.collect(policy)
        rules = (Path(__file__).resolve().parents[1]/'examples/monitoring/router.rules.yml').read_text()
        selectors = set(re.findall(r'\blanrith_router_\w+', rules))
        families = set(re.findall(r'^(lanrith_router_\w+)[ {]', text, re.MULTILINE))
        self.assertEqual(selectors-families, set())
        sample = next(line for line in text.splitlines() if line.startswith('lanrith_router_client_neighbor_info{'))
        self.assertEqual(set(re.findall(r'(\w+)="', sample)), {'address', 'family', 'interface', 'mac', 'network'})

    def test_global_neighbor_budget_empty_and_failed_collection(self):
        policy = metrics.router_manifest(config.normalize(fixture()))
        policy['clients'] = [{'network': f'home{i}', 'interface': f'lan{i}'} for i in range(5)]
        rows = [{'dst': '2001:db8::'+format(i+1, 'x'), 'lladdr': '02:00:00:00:00:01', 'state': ['STALE']}
                for i in range(256)]
        cache = {c['interface']: json.dumps(rows) for c in policy['clients']}
        def command(args, end, limit=None):
            if args[:4] == ['ip', '-j', 'neigh', 'show']:
                return cache[args[-1]]
            raise ValueError
        with mock.patch.object(runtime, 'command', side_effect=command):
            text = runtime.collect(policy, previous_inventory=100)
            self.assertEqual(text.count('lanrith_router_client_neighbor_info{'), 1024)
            self.assertIn('lanrith_router_client_inventory_complete 0\n', text)
            self.assertIn('lanrith_router_client_inventory_collection_timestamp_seconds 100\n', text)
            self.assertIn('interface="lan4",network="home4"} 256\n', text)
            cache = {c['interface']: '[]' for c in policy['clients']}
            del cache['lan4']
            text = runtime.collect(policy, previous_inventory=100)
            self.assertIn('lanrith_router_client_inventory_collection_timestamp_seconds 100\n', text)
            cache['lan4'] = '[]'
            with mock.patch.object(runtime.time, 'time', return_value=200):
                text = runtime.collect(policy, previous_inventory=100)
            self.assertIn('lanrith_router_client_inventory_complete 1\n', text)
            self.assertIn('lanrith_router_client_inventory_collection_timestamp_seconds 200\n', text)

    def test_stop_after_success_preserves_observations_but_failure_invalidates_them(self):
        with mock.patch.object(runtime.os, 'geteuid', return_value=0), \
                mock.patch.object(runtime, 'publish') as publish, \
                mock.patch.object(runtime, 'last_inventory', return_value=1234567890):
            with mock.patch.dict(os.environ, SERVICE_RESULT='success'):
                self.assertEqual(runtime.main(['--on-stop']), 0)
                publish.assert_not_called()
            with mock.patch.dict(os.environ, SERVICE_RESULT='timeout'):
                self.assertEqual(runtime.main(['--on-stop']), 0)
                self.assertIn('lanrith_router_metrics_collection_success 0\n', publish.call_args.args[0])
                self.assertIn('1234567890', publish.call_args.args[0])

    @unittest.skipUnless(os.geteuid() == 0, 'Exercises actual root-owned publication metadata.')
    def test_atomic_publication_rejects_exporter_writable_directory_and_retains_last_complete_inventory(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            path = root/'router.prom'
            runtime.publish('lanrith_router_client_inventory_collection_timestamp_seconds 1234567890\n', path)
            self.assertEqual(path.stat().st_mode & 0o777, 0o644)
            self.assertEqual(runtime.last_inventory(path), 1234567890)
            before = path.read_bytes()
            root.chmod(0o777)
            with self.assertRaises(ReleaseError):
                runtime.publish('replaced', path)
            self.assertEqual(path.read_bytes(), before)
            root.chmod(0o700)
            link = root/'linked'
            link.symlink_to(root, target_is_directory=True)
            with self.assertRaises(ReleaseError):
                runtime.publish('replaced', link/'router.prom')


if __name__ == '__main__':
    unittest.main()
