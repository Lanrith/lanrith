"""NTP health retains its service identity, original age and unavailable state."""

import json
import os
from pathlib import Path
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
        self.assertIn('lanrith-ntp-health.timer', json.loads(files['usr/share/lanrith/health.json'])['units'])
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root/'base.tar').write_bytes(b'synthetic')
            build.assembly(value, root/'base.tar', root/'image', version='0.1.0', sequence=9)
            overlay = root/'image/mkosi.extra'
            self.assertTrue((overlay/'usr/lib/lanrith/ntp-health').is_file())
            self.assertTrue((overlay/'usr/lib/lanrith/lanrith/ntp_health_runtime.py').is_file())
            self.assertTrue((overlay/'etc/systemd/system/lanrith-ntp-health.timer').is_symlink())
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
