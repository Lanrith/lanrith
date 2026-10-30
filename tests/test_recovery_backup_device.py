"""Verify fail-closed gates and recovery-key binding for offline backup."""

import json
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from lanrith import recovery_backup_device as device
from lanrith.release import ReleaseError


class BackupDeviceGateTests(unittest.TestCase):
    def setUp(self):
        self.secret = bytearray(b'aaaaaaaa-bbbbbbbb-cccccccc-dddddddd-eeeeeeee-ffffffff-gggggggg-hhhhhhhh')
        self.metadata = {'tokens': {'0': {'type': 'systemd-recovery', 'keyslots': ['1']}},
                         'keyslots': {'1': {}}}

    def test_unqualified_controller_rejects_before_any_disk_observation(self):
        with patch.object(device.recovery_backup_preflight, 'inspect') as inspect, \
                patch.object(device, 'mounted_backup') as mount, self.assertRaisesRegex(ReleaseError, 'not qualified'):
            device.create({}, self.secret, image_id='lanrith')
        inspect.assert_not_called()
        mount.assert_not_called()

    def test_invalid_image_identity_is_rejected_before_disk_observation(self):
        with patch.object(device, 'BACKUP_WRITE_QUALIFIED', True), \
                patch.object(device.recovery_backup_preflight, 'inspect') as inspect, self.assertRaises(ReleaseError):
            device.create({}, self.secret, image_id='../unsafe')
        inspect.assert_not_called()

    def test_unverified_image_identity_cannot_mount_backup_media(self):
        observation = {'authorized_to_write': False, 'authorized_to_restore': False}
        with patch.object(device, 'BACKUP_WRITE_QUALIFIED', True), \
                patch.object(device.recovery_backup_preflight, 'policy', return_value={}), \
                patch.object(device.recovery_backup_preflight, 'inspect', return_value=observation), \
                patch.object(device.release, 'read', return_value='{"image_id":"different"}'), \
                patch.object(device, 'mounted_backup') as mount, self.assertRaises(ReleaseError):
            device.create({}, self.secret, image_id='lanrith')
        mount.assert_not_called()

    def test_backup_mount_requires_expected_device_and_restrictive_options(self):
        point = Path('/run/synthetic-backup')
        row = {'target': str(point), 'fstype': 'ext4', 'source': '/dev/synthetic',
               'options': 'rw,nodev,nosuid,noexec'}
        for overrides in ({'options': 'rw,nodev,nosuid'}, {'options': 'ro,nodev,nosuid,noexec'},
                          {'source': '/dev/other'}, {'fstype': 'xfs'}, {'target': '/run/other'}):
            with self.subTest(overrides=overrides), \
                    patch.object(device.update, 'command', return_value=json.dumps({'filesystems': [row | overrides]})), \
                    self.assertRaises(ReleaseError):
                device.verify_mount(point, '/dev/synthetic')

    def test_unmount_failure_does_not_remove_mountpoint(self):
        def command(args):
            if args[0] == 'umount':
                raise ReleaseError('Unmount failed.')
        with patch.object(device.tempfile, 'mkdtemp', return_value='/run/synthetic-backup'), \
                patch.object(device.update, 'command', side_effect=command), \
                patch.object(device, 'verify_mount'), patch.object(Path, 'is_mount', return_value=True), \
                patch.object(Path, 'rmdir') as remove, self.assertRaises(ReleaseError):
            with device.mounted_backup('/dev/synthetic'):
                pass
        remove.assert_not_called()

    def test_only_a_systemd_recovery_slot_can_validate_the_key(self):
        with patch.object(device.update, 'command', return_value=json.dumps(self.metadata)), \
                patch.object(device.subprocess, 'run', return_value=SimpleNamespace(returncode=0)) as run:
            device.check_key('/dev/synthetic', self.secret)
        self.assertIn('--key-slot', run.call_args.args[0])
        self.assertIn('1', run.call_args.args[0])
        self.assertFalse(any(self.secret.decode() in str(arg) for arg in run.call_args.args[0]))
        self.assertEqual(run.call_args.kwargs['input'], self.secret)

    def test_missing_bad_or_mismatched_recovery_slots_fail_closed(self):
        invalid = [ {'tokens': {}, 'keyslots': {}},
                    {'tokens': {'0': {'type': 'systemd-recovery', 'keyslots': ['2']}}, 'keyslots': {'1': {}}},
                    {'tokens': {'0': {'type': 'systemd-recovery', 'keyslots': ['99']}}, 'keyslots': {'99': {}}},
                    {'tokens': {'0': {'type': 'systemd-recovery', 'keyslots': ['1', '2']}}, 'keyslots': {'1': {}}} ]
        for metadata in invalid:
            with self.subTest(metadata=metadata), patch.object(device.update, 'command', return_value=json.dumps(metadata)), \
                    patch.object(device.subprocess, 'run') as run, self.assertRaises(ReleaseError):
                device.check_key('/dev/synthetic', self.secret)
            run.assert_not_called()
        with patch.object(device.update, 'command', return_value=json.dumps(self.metadata)), \
                patch.object(device.subprocess, 'run', return_value=SimpleNamespace(returncode=1)), \
                self.assertRaises(ReleaseError):
            device.check_key('/dev/synthetic', self.secret)
        with patch.object(device.update, 'command') as command, self.assertRaises(ReleaseError):
            device.check_key('/dev/synthetic', bytearray(b'weak'))
        command.assert_not_called()


if __name__ == '__main__':
    unittest.main()
