"""NTP health retains its service identity, original age and unavailable state."""

import json
import os
from pathlib import Path
import runpy
from types import SimpleNamespace
import tempfile
import time
import unittest
from unittest import mock

from lanrith import build, config, ntp_health_runtime as runtime, router_metrics_runtime
from test_metrics import fixture


class NtpHealthTests(unittest.TestCase):
    def observation(self):
        return {'schema': 1, 'boot_id': 'synthetic-boot', 'network_namespace_inode': 1234,
                'observed_monotonic_ns': time.monotonic_ns(), 'observed_timestamp_seconds': int(time.time())-10,
                'query_success': True, 'synchronised': True}

    def test_observer_is_selected_only_with_metrics_and_ntp_and_host_gains_no_capabilities(self):
        value = fixture()
        self.assertFalse(any('ntp-health' in path for path in config.render(value)))
        value['services']['ntp']['enabled'] = True
        files = config.render(value)
        unit = files['usr/lib/systemd/system/lanrith-ntp-health.service']
        self.assertIn('User=_chrony\nGroup=_chrony\n', unit)
        self.assertIn('CapabilityBoundingSet=\n', unit)
        self.assertIn('NetworkNamespacePath=/run/netns/lanrith-services\n', unit)
        self.assertIn('RestrictAddressFamilies=AF_UNIX\n', unit)
        self.assertIn('RuntimeDirectoryMode=0750\n', unit)
        self.assertNotIn('LoadCredential=', unit)
        collector = files['usr/lib/systemd/system/lanrith-router-metrics.service']
        self.assertIn('SupplementaryGroups=_chrony\n', collector)
        self.assertIn('CapabilityBoundingSet=CAP_NET_ADMIN\n', collector)
        self.assertNotIn('lanrith-ntp-health.timer', json.loads(files['usr/share/lanrith/health.json'])['units'])
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root/'base.tar').write_bytes(b'synthetic')
            build.assembly(value, root/'base.tar', root/'image', version='0.1.0', sequence=9)
            overlay = root/'image/mkosi.extra'
            self.assertTrue((overlay/'usr/lib/lanrith/ntp-health').is_file())
            self.assertTrue((overlay/'usr/lib/lanrith/lanrith/ntp_health_runtime.py').is_file())
            self.assertTrue((overlay/'usr/lib/systemd/system/multi-user.target.wants/lanrith-ntp-health.timer').is_symlink())
        value['observability']['metrics']['enabled'] = False
        self.assertFalse(any('ntp-health' in path for path in config.render(value)))

    def test_snapshot_rejects_stale_cross_boot_namespace_and_malformed_success(self):
        account = SimpleNamespace(pw_uid=os.getuid(), pw_gid=os.getgid())
        with tempfile.TemporaryDirectory() as temporary, mock.patch.object(runtime.pwd, 'getpwnam', return_value=account):
            root = Path(temporary)
            root.chmod(0o750)
            path = root/'health.json'
            original = self.observation()
            runtime.publish(original, path)
            self.assertEqual(runtime.read_observation(path, boot='synthetic-boot', namespace=1234), original)
            for change in ({'observed_monotonic_ns': time.monotonic_ns()-91*10**9},
                           {'observed_monotonic_ns': time.monotonic_ns()+10**9}, {'boot_id': 'old'},
                           {'network_namespace_inode': 4321}, {'query_success': False},
                           {'synchronised': 1}, {'query_success': 1}, {'schema': True},
                           {'observed_timestamp_seconds': int(time.time())+10}, {'extra': 1}):
                with self.subTest(change=change):
                    runtime.publish({**original, **change}, path)
                    with self.assertRaises(ValueError):
                        runtime.read_observation(path, boot='synthetic-boot', namespace=1234)
            for value in ({**original, 'synchronised': False},
                          {**original, 'query_success': False, 'synchronised': False}):
                runtime.publish(value, path)
                self.assertEqual(runtime.read_observation(path, boot='synthetic-boot', namespace=1234), value)

    def test_accuracy_uses_reference_time_and_remaining_correction_from_same_tracking_row(self):
        fields = ['C0000201', '', '3', '12345.5', '-0.01', '30', '0', '0', '0', '0',
                  '0.04', '0.02', '64', 'Normal']
        for index, value, reference, error in ((3, '12345.5', 12345.5, 0.05),
                                                (3, '1', 1, 0.05), (4, '-120', 12345.5, 120.04),
                                                (11, '25', 12345.5, 25.03)):
            row = fields.copy()
            row[index] = value
            measured = router_metrics_runtime.tracking_measurements(','.join(row))
            self.assertTrue(measured['synchronised'])
            self.assertEqual(measured['reference_timestamp_seconds'], reference)
            self.assertAlmostEqual(measured['clock_error_bound_seconds'], error)
        for index, value in ((3, '0'), (11, '-0.1'), (0, '7F7F0101'), (13, 'Not synchronised')):
            row = fields.copy()
            row[index] = value
            measured = router_metrics_runtime.tracking_measurements(','.join(row))
            self.assertIsNone(measured['clock_error_bound_seconds'])
            self.assertIsNone(measured['reference_timestamp_seconds'])
        for invalid in ('NaN', 'inf', '-inf'):
            row = fields.copy()
            row[10] = invalid
            with self.assertRaises(ValueError):
                router_metrics_runtime.tracking_measurements(','.join(row))

    def test_v2_snapshot_rejects_partial_inconsistent_and_unrepresentable_measurements(self):
        account = SimpleNamespace(pw_uid=os.getuid(), pw_gid=os.getgid())
        with tempfile.TemporaryDirectory() as temporary, mock.patch.object(runtime.pwd, 'getpwnam', return_value=account):
            root = Path(temporary)
            root.chmod(0o750)
            path = root/'health.json'
            pair = {'reference_timestamp_seconds': 123.5, 'clock_error_bound_seconds': 0.01}
            original = {**self.observation(), 'schema': 2, **pair}
            runtime.publish(original, path)
            self.assertEqual(runtime.read_observation(path, boot='synthetic-boot', namespace=1234), original)
            for change in ({'schema': 1}, {'synchronised': False}, {'query_success': False},
                           {'reference_timestamp_seconds': 0}, {'clock_error_bound_seconds': -0.1},
                           {'clock_error_bound_seconds': True}, {'reference_timestamp_seconds': None},
                           {'clock_error_bound_seconds': None}, {'clock_error_bound_seconds': 10**400},
                           {'reference_timestamp_seconds': '42'}):
                with self.subTest(change=change):
                    runtime.publish({**original, **change}, path)
                    with self.assertRaises(ValueError):
                        runtime.read_observation(path, boot='synthetic-boot', namespace=1234)
            nulls = dict.fromkeys(pair)
            for query, sync in ((False, False), (True, False), (True, True)):
                value = {**original, **nulls, 'query_success': query, 'synchronised': sync}
                runtime.publish(value, path)
                self.assertEqual(runtime.read_observation(path, boot='synthetic-boot', namespace=1234), value)
            for name in pair:
                value = original.copy()
                del value[name]
                runtime.publish(value, path)
                with self.assertRaises(ValueError):
                    runtime.read_observation(path, boot='synthetic-boot', namespace=1234)

    def test_client_qualification_uses_selected_families_and_omissions(self):
        qualify = runpy.run_path(str(Path(__file__).resolve().parents[1]/'scripts/qualify-ntp-client.py'))['qualify']
        measure = mock.Mock(side_effect=lambda target, scopes: {'family': target.version, 'accepted': True})
        with mock.patch.dict(qualify.__globals__, measure=measure):
            value = config.normalize(fixture())
            self.assertEqual(qualify(value, 'home')['result'], 'not-selected')
            measure.assert_not_called()
            raw = fixture()
            raw['services']['ntp']['enabled'] = True
            raw['networks']['home']['ipv6'] = {'subnet_id': 1}
            raw['addressing']['services'] = {'ipv4': '172.30.40.0/24', 'ipv6': 'fd42:1234:5678:700::/64'}
            self.assertEqual([r['family'] for r in qualify(config.normalize(raw), 'home')['measurements']], [4, 6])
            self.assertEqual(str(measure.call_args.args[0]), 'fd42:1234:5678:700::40')
            raw['networks']['home'].pop('ipv6')
            raw['networks']['home']['ra'] = False
            self.assertEqual([r['family'] for r in qualify(config.normalize(raw), 'home')['measurements']], [4])
            del raw['networks']['home']['ipv4'], raw['networks']['home']['dhcp4'], raw['networks']['home']['ra']
            raw['networks']['home']['ipv6'] = {'subnet_id': 1}
            self.assertEqual([r['family'] for r in qualify(config.normalize(raw), 'home')['measurements']], [6])
            raw['networks']['home']['ntp'] = False
            self.assertEqual(qualify(config.normalize(raw), 'home')['result'], 'not-selected')
            with self.assertRaises(ValueError):
                qualify(value, 'misspelling')

    def test_publication_is_bounded_across_interrupted_writes_and_rejects_unsafe_paths(self):
        account = SimpleNamespace(pw_uid=os.getuid(), pw_gid=os.getgid())
        with tempfile.TemporaryDirectory() as temporary, mock.patch.object(runtime.pwd, 'getpwnam', return_value=account):
            root = Path(temporary)
            root.chmod(0o750)
            path, orphan = root/'health.json', root/'.health.json.tmp'
            original = self.observation()
            for _ in range(3):
                orphan.write_bytes(b'interrupted')
                orphan.chmod(0o600)
                runtime.publish(original, path)
                self.assertEqual(list(root.iterdir()), [path])
            for mode in (0o777, 0o755):
                root.chmod(mode)
                with self.assertRaises(ValueError):
                    runtime.publish(original, path)
            root.chmod(0o750)
            before = path.read_bytes()
            orphan.symlink_to(path)
            with self.assertRaises(ValueError):
                runtime.publish(original, path)
            self.assertEqual(path.read_bytes(), before)
            orphan.unlink()
            os.link(path, orphan)
            with self.assertRaises(ValueError):
                runtime.publish(original, path)
            orphan.unlink()
            path.chmod(0o644)
            with self.assertRaises(ValueError):
                runtime.read_observation(path, boot='synthetic-boot', namespace=1234)

    def test_host_metrics_preserve_observed_age_and_distinguish_failed_query_from_unsynchronised(self):
        policy = json.loads(config.render(fixture())['usr/share/lanrith/router-metrics.json'])
        policy['ntp'] = True
        original = self.observation()
        for succeeded, synchronised in ((True, True), (True, False), (False, False)):
            with self.subTest(succeeded=succeeded, synchronised=synchronised), \
                    mock.patch.object(router_metrics_runtime, 'command', side_effect=ValueError), \
                    mock.patch.object(router_metrics_runtime, 'read', side_effect=ValueError), \
                    mock.patch.object(runtime, 'read_observation', return_value={**original,
                        'query_success': succeeded, 'synchronised': synchronised}):
                text = router_metrics_runtime.collect(policy)
                self.assertIn('lanrith_router_metrics_query_success{collector="chrony"} '+str(int(succeeded))+'\n', text)
                self.assertIn('lanrith_router_chrony_synchronised '+str(int(synchronised))+'\n', text)
                self.assertIn('lanrith_router_chrony_observation_timestamp_seconds '+
                              str(original['observed_timestamp_seconds'])+'\n', text)
        with mock.patch.object(router_metrics_runtime, 'command', side_effect=ValueError), \
                mock.patch.object(router_metrics_runtime, 'read', side_effect=ValueError), \
                mock.patch.object(runtime, 'read_observation', side_effect=ValueError):
            text = router_metrics_runtime.collect(policy)
            self.assertIn('lanrith_router_metrics_query_success{collector="chrony"} 0\n', text)
            self.assertNotIn('lanrith_router_chrony_synchronised', text)
            self.assertNotIn('lanrith_router_chrony_observation_timestamp_seconds', text)


if __name__ == '__main__':
    unittest.main()
