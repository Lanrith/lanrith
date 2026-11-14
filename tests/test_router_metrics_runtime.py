"""Router observations distinguish unavailable data and enforce resource bounds."""

import json
import os
from pathlib import Path
import sys
import tempfile
import time
import unittest
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
