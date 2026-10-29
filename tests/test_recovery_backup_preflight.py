"""Check offline backup disk observations never authorize writes."""

from copy import deepcopy
from pathlib import Path
import unittest
from unittest.mock import patch

from lanrith import recovery_backup_preflight as preflight
from lanrith.release import ReleaseError


class OfflineBackupPreflightTests(unittest.TestCase):
    def setUp(self):
        self.binding = {'schema': 1, 'target_disk_by_id': '/dev/disk/by-id/synthetic-target',
                        'state_partuuid': '12345678-1234-1234-1234-123456789abc',
                        'state_uuid': '12345678-1234-1234-1234-123456789abd',
                        'backup_disk_by_id': '/dev/disk/by-id/synthetic-backup',
                        'backup_partuuid': '12345678-1234-1234-1234-123456789abe'}
        self.target_rows = [{'device': '/dev/vda1', 'size': 1024*1024*1024, 'mounted': False}]
        self.backup_rows = [{'device': '/dev/vdb1', 'size': 2*1024*1024*1024, 'mounted': False}]
        self.snapshots = {'/dev/vda': ({'disk': 'target'}, self.target_rows),
                          '/dev/vdb': ({'disk': 'backup'}, self.backup_rows)}
        self.mapping = {self.binding['target_disk_by_id']: '/dev/vda',
                        self.binding['backup_disk_by_id']: '/dev/vdb'}
        patches = [patch.object(preflight.os, 'geteuid', return_value=0),
                   patch.object(Path, 'is_file', return_value=True),
                   patch.object(preflight.factory, 'secure_boot'),
                   patch.object(preflight.factory, 'verified_root', return_value=('/dev/vdc', [])),
                   patch.object(preflight.recovery_inputs, 'canonical_disk', side_effect=lambda x: self.mapping[x]),
                   patch.object(preflight.recovery_inputs, 'disk_snapshot', side_effect=lambda x: deepcopy(self.snapshots[x])),
                   patch.object(preflight.recovery_inputs, 'partition', side_effect=lambda rows, disk, *a, **kw:
                                '/dev/vda1' if disk == '/dev/vda' else '/dev/vdb1'),
                   patch.object(preflight.update, 'command', side_effect=self.command)]
        for item in patches:
            item.start()
            self.addCleanup(item.stop)

    def command(self, arguments):
        if arguments[0] == 'cryptsetup':
            return self.binding['state_uuid']+'\n'
        if arguments[0] == 'blkid':
            return 'ext4\n'
        self.fail('Unexpected command in read-only preflight.')

    def test_independent_bound_disks_are_observed_without_write_authority(self):
        result = preflight.inspect(self.binding)
        self.assertEqual(result['scope'], 'offline-backup-preflight')
        self.assertFalse(result['authorized_to_write'])
        self.assertFalse(result['authorized_to_restore'])
        self.assertEqual(preflight.update.command.call_count, 2)

    def test_disk_aliases_and_busy_disks_are_rejected_before_commands(self):
        self.mapping[self.binding['backup_disk_by_id']] = '/dev/vda'
        with self.assertRaises(ReleaseError):
            preflight.inspect(self.binding)
        self.assertEqual(preflight.update.command.call_count, 0)
        self.mapping[self.binding['backup_disk_by_id']] = '/dev/vdb'
        self.target_rows[0]['mounted'] = True
        with self.assertRaises(ReleaseError):
            preflight.inspect(self.binding)
        self.assertEqual(preflight.update.command.call_count, 0)
        self.target_rows[0]['mounted'] = False
        self.backup_rows[0]['mounted'] = True
        with self.assertRaises(ReleaseError):
            preflight.inspect(self.binding)
        self.assertEqual(preflight.update.command.call_count, 0)
        self.backup_rows[0]['mounted'] = False
        self.mapping[self.binding['target_disk_by_id']] = '/dev/vdc'
        with self.assertRaises(ReleaseError):
            preflight.inspect(self.binding)
        self.assertEqual(preflight.update.command.call_count, 0)

    def test_capacity_wrong_volume_and_filesystem_fail_closed(self):
        self.backup_rows[0]['size'] = self.target_rows[0]['size']
        with self.assertRaises(ReleaseError):
            preflight.inspect(self.binding)
        self.backup_rows[0]['size'] = 2*1024*1024*1024
        with patch.object(preflight.update, 'command', side_effect=['different\n', 'ext4\n']):
            with self.assertRaises(ReleaseError):
                preflight.inspect(self.binding)
        with patch.object(preflight.update, 'command', side_effect=[self.binding['state_uuid']+'\n', 'vfat\n']):
            with self.assertRaises(ReleaseError):
                preflight.inspect(self.binding)

    def test_changed_disk_snapshot_is_rejected(self):
        first = deepcopy(self.snapshots['/dev/vda'])
        second = deepcopy(self.snapshots['/dev/vdb'])
        changed = deepcopy(first)
        changed[1][0]['size'] += 512
        with patch.object(preflight.recovery_inputs, 'disk_snapshot', side_effect=[first, second, changed]):
            with self.assertRaises(ReleaseError):
                preflight.inspect(self.binding)

    def test_malformed_bindings_are_rejected(self):
        for changed in ({'target_disk_by_id': '/dev/sda'}, {'backup_disk_by_id': '/dev/disk/by-id/x-part1'},
                        {'state_uuid': 'bad'}, {'backup_partuuid': self.binding['state_partuuid']},
                        {'schema': True}, {'extra': 'unknown'}):
            with self.subTest(changed=changed), self.assertRaises(ReleaseError):
                preflight.policy({**self.binding, **changed})

    def test_readonly_preparation_is_gated_and_rejects_busy_or_aliased_disks(self):
        with self.assertRaises(ReleaseError):
            preflight.prepare_readonly(self.binding, include_backup=True)
        preflight.update.command.assert_not_called()
        with patch.object(preflight, 'READONLY_PREPARATION_QUALIFIED', True):
            self.target_rows[0]['mounted'] = True
            with self.assertRaises(ReleaseError):
                preflight.prepare_readonly(self.binding, include_backup=True)
            preflight.update.command.assert_not_called()
            self.target_rows[0]['mounted'] = False
            self.mapping[self.binding['backup_disk_by_id']] = '/dev/vda'
            with self.assertRaises(ReleaseError):
                preflight.prepare_readonly(self.binding, include_backup=True)
            preflight.update.command.assert_not_called()

    def test_readonly_preparation_protects_only_bound_disks_and_never_enables_writes(self):
        for include_backup, expected in ((False, ['/dev/vda', '/dev/vda1']),
                                         (True, ['/dev/vda', '/dev/vda1', '/dev/vdb', '/dev/vdb1'])):
            with self.subTest(include_backup=include_backup), \
                    patch.object(preflight, 'READONLY_PREPARATION_QUALIFIED', True), \
                    patch.object(preflight.update, 'command', return_value='1\n') as command:
                result = preflight.prepare_readonly(self.binding, include_backup=include_backup)
                self.assertFalse(result['authorized_to_write'])
                self.assertFalse(result['authorized_to_restore'])
                self.assertEqual([call.args[0] for call in command.call_args_list],
                                 [['blockdev', '--setro', disk] for disk in expected] +
                                 [['blockdev', '--getro', disk] for disk in expected])
        with patch.object(preflight, 'READONLY_PREPARATION_QUALIFIED', True), \
                patch.object(preflight.update, 'command', return_value='0\n'), self.assertRaises(ReleaseError):
            preflight.prepare_readonly(self.binding, include_backup=True)

    def test_readonly_preparation_fails_if_target_changes_during_protection(self):
        target = deepcopy(self.snapshots['/dev/vda'])
        backup = deepcopy(self.snapshots['/dev/vdb'])
        changed = deepcopy(target)
        changed[1][0]['size'] += 512
        with patch.object(preflight, 'READONLY_PREPARATION_QUALIFIED', True), \
                patch.object(preflight.recovery_inputs, 'disk_snapshot', side_effect=[target, backup, changed]), \
                patch.object(preflight.update, 'command', return_value='1\n') as command, \
                self.assertRaises(ReleaseError):
            preflight.prepare_readonly(self.binding, include_backup=True)
        self.assertTrue(command.call_args_list)
        self.assertTrue(all(call.args[0][1] == '--setro' for call in command.call_args_list))


class OfflineRestorePreflightTests(unittest.TestCase):
    setUp = OfflineBackupPreflightTests.setUp

    def command(self, arguments):
        if arguments[0] == 'blockdev':
            return '1\n'
        if arguments[0] == 'blkid':
            return 'ext4\n'
        self.fail('Restore preflight must not inspect or write the damaged header.')

    def test_header_damage_does_not_prevent_safe_observation(self):
        result = preflight.inspect_restore(self.binding)
        self.assertEqual(result['scope'], 'offline-restore-preflight')
        for field in ('header_authenticated', 'backup_authenticated', 'authorized_to_write', 'authorized_to_restore'):
            self.assertIs(result[field], False)
        self.assertFalse(any(call.args[0][0] == 'cryptsetup' for call in preflight.update.command.call_args_list))

    def test_writable_busy_aliased_and_undersized_disks_are_rejected(self):
        with patch.object(preflight.update, 'command', return_value='0\n'), self.assertRaises(ReleaseError):
            preflight.inspect_restore(self.binding)
        self.target_rows[0]['mounted'] = True
        with self.assertRaises(ReleaseError):
            preflight.inspect_restore(self.binding)
        self.target_rows[0]['mounted'] = False
        self.mapping[self.binding['backup_disk_by_id']] = '/dev/vda'
        with self.assertRaises(ReleaseError):
            preflight.inspect_restore(self.binding)
        self.mapping[self.binding['backup_disk_by_id']] = '/dev/vdb'
        self.backup_rows[0]['size'] = self.target_rows[0]['size']
        with self.assertRaises(ReleaseError):
            preflight.inspect_restore(self.binding)

    def test_wrong_filesystem_and_changed_target_are_rejected(self):
        def wrong_fs(arguments):
            return '1\n' if arguments[0] == 'blockdev' else 'vfat\n'
        with patch.object(preflight.update, 'command', side_effect=wrong_fs), self.assertRaises(ReleaseError):
            preflight.inspect_restore(self.binding)
        first = deepcopy(self.snapshots['/dev/vda'])
        second = deepcopy(self.snapshots['/dev/vdb'])
        changed = deepcopy(first)
        changed[1][0]['size'] += 512
        with patch.object(preflight.recovery_inputs, 'disk_snapshot', side_effect=[first, second, changed]), \
                self.assertRaises(ReleaseError):
            preflight.inspect_restore(self.binding)


if __name__ == '__main__':
    unittest.main()
