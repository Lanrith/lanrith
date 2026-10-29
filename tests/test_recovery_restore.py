"""Ordering and fail-closed tests for the gated offline restore workflow."""
from contextlib import ExitStack, contextmanager
from types import SimpleNamespace
import json
import unittest
from unittest.mock import patch

from lanrith import recovery_restore as restore
from lanrith.release import ReleaseError


class RestoreWorkflowTests(unittest.TestCase):
    def setUp(self):
        self.binding = {'target_disk_by_id': 'target', 'backup_disk_by_id': 'backup',
                        'state_partuuid': 'state-part', 'state_uuid': 'state-uuid', 'backup_partuuid': 'backup-part'}
        self.name = 'backup-'+'a'*32
        self.measurement = bytes.fromhex('ab'*32)
        self.events = []
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        def mock(obj, name, **kwargs):
            return self.stack.enter_context(patch.object(obj, name, **kwargs))
        mock(restore.recovery_backup_preflight, 'policy', side_effect=lambda v: v)
        mock(restore.recovery_backup_preflight, 'inspect_restore', return_value={
            'state_size': 4096, 'authorized_to_restore': False, 'authorized_to_write': False})
        mock(restore.release, 'read', return_value=json.dumps({'image_id': 'lanrith'}).encode())
        mock(restore.factory, 'verified_root', return_value=('/dev/recovery', None))
        mock(restore.factory, 'secure_boot')
        mock(restore.recovery_inputs, 'canonical_disk', side_effect=lambda v: '/dev/'+v)
        mock(restore.recovery_inputs, 'disk_snapshot', side_effect=lambda d: ({}, []))
        mock(restore.recovery_inputs, 'partition', side_effect=lambda rows, disk, uid, *a, **k:
             '/dev/state' if uid == 'state-part' else '/dev/media')
        mock(restore.recovery_inputs, 'stable_snapshot')
        mock(restore.recovery_inputs, 'verify_mount')
        @contextmanager
        def mounted(*a):
            yield restore.Path('/synthetic')
        mock(restore.recovery_inputs, 'mounted', side_effect=mounted)
        @contextmanager
        def authenticated(*a, **k):
            yield 99, {'authorized_to_restore': False, 'measurement_sha256': self.measurement.hex()}
        self.auth = mock(restore.recovery_backup_files, 'open_authenticated', side_effect=authenticated)
        mock(restore.os, 'fstat', return_value=SimpleNamespace(st_size=4096))
        mock(restore.recovery_backup_verity, 'measure', return_value=self.measurement)
        mock(restore.recovery_restore_layout, 'inspect_pinned', return_value={'metadata_size': 16384, 'data_offset': 32768})
        self.key = mock(restore.recovery_restore_layout, 'verify_recovery_key_pinned',
                        return_value={'key_verified': True, 'authorized_to_restore': False})
        @contextmanager
        def claim(*a, **k):
            self.events.append('claim')
            yield 42, lambda: self.events.append('check')
        mock(restore.recovery_restore_target, 'claim', side_effect=claim)
        def copy(*a, **k):
            self.events.append('copy')
            k['revalidate']()
            return {'authorized_to_boot': False}
        self.copy = mock(restore.recovery_restore_transaction, 'restore_pinned', side_effect=copy)
        def command(args):
            self.events.append(tuple(args))
            return '1'
        self.command = mock(restore.update, 'command', side_effect=command)

    def call(self, confirm=None):
        return restore.restore(self.binding, self.name, bytearray(b'synthetic'), image_id='lanrith',
                               confirm=confirm or (lambda name, measurement: name))

    def test_closed_gates_prevent_all_operations(self):
        with self.assertRaises(ReleaseError):
            self.call()
        self.auth.assert_not_called()
        self.command.assert_not_called()

    def test_confirmation_failure_prevents_writable_target(self):
        with patch.object(restore, 'RESTORE_WORKFLOW_QUALIFIED', True), \
                patch.object(restore, 'BACKUP_FRESHNESS_QUALIFIED', True), self.assertRaises(ReleaseError):
            self.call(lambda name, measurement: 'no')
        self.assertFalse(any('--setrw' in event for event in self.events if isinstance(event, tuple)))
        self.copy.assert_not_called()

    def test_key_failure_prevents_writable_target(self):
        self.key.side_effect = ReleaseError('synthetic wrong key')
        with patch.object(restore, 'RESTORE_WORKFLOW_QUALIFIED', True), \
                patch.object(restore, 'BACKUP_FRESHNESS_QUALIFIED', True), self.assertRaises(ReleaseError):
            self.call()
        self.assertFalse(any('--setrw' in event for event in self.events if isinstance(event, tuple)))
        self.copy.assert_not_called()

    def test_copy_failure_restores_readonly_state(self):
        self.copy.side_effect = ReleaseError('synthetic interruption')
        with patch.object(restore, 'RESTORE_WORKFLOW_QUALIFIED', True), \
                patch.object(restore, 'BACKUP_FRESHNESS_QUALIFIED', True), self.assertRaises(ReleaseError):
            self.call()
        self.assertIn(('blockdev', '--setrw', '/dev/state'), self.events)
        self.assertIn(('blockdev', '--setro', '/dev/state'), self.events)
        self.assertLess(self.events.index(('blockdev', '--setrw', '/dev/state')),
                        self.events.index(('blockdev', '--setro', '/dev/state')))
        self.assertIn(('blockdev', '--setrw', '/dev/target'), self.events)
        self.assertIn(('blockdev', '--setro', '/dev/target'), self.events)

    def test_failed_setrw_still_attempts_readonly_cleanup(self):
        def command(args):
            self.events.append(tuple(args))
            if '--setrw' in args:
                raise ReleaseError('synthetic setrw failure')
            return '1'
        self.command.side_effect = command
        with patch.object(restore, 'RESTORE_WORKFLOW_QUALIFIED', True), \
                patch.object(restore, 'BACKUP_FRESHNESS_QUALIFIED', True), self.assertRaises(ReleaseError):
            self.call()
        self.assertIn(('blockdev', '--setro', '/dev/state'), self.events)
        self.copy.assert_not_called()

    def test_state_readonly_failure_still_protects_parent_disk(self):
        def command(args):
            self.events.append(tuple(args))
            if args == ['blockdev', '--setro', '/dev/state']:
                raise ReleaseError('synthetic state cleanup failure')
            return '1'
        self.command.side_effect = command
        self.copy.side_effect = ReleaseError('synthetic interruption')
        with patch.object(restore, 'RESTORE_WORKFLOW_QUALIFIED', True), \
                patch.object(restore, 'BACKUP_FRESHNESS_QUALIFIED', True), self.assertRaises(ReleaseError):
            self.call()
        self.assertIn(('blockdev', '--setro', '/dev/target'), self.events)

    def test_other_partitions_are_protected_before_parent_is_writable(self):
        rows = [{'device': '/dev/state', 'mounted': False}, {'device': '/dev/other', 'mounted': False}]
        with patch.object(restore, 'RESTORE_WORKFLOW_QUALIFIED', True), \
                patch.object(restore, 'BACKUP_FRESHNESS_QUALIFIED', True), \
                patch.object(restore.recovery_inputs, 'disk_snapshot',
                             side_effect=lambda disk: ({}, rows if disk == '/dev/target' else [])):
            self.call()
        self.assertLess(self.events.index(('blockdev', '--setro', '/dev/other')),
                        self.events.index(('blockdev', '--setrw', '/dev/target')))
        self.assertIn(('blockdev', '--getro', '/dev/other'), self.events)
        self.assertIn(('blockdev', '--setro', '/dev/target'), self.events)

    def test_success_does_not_authorize_boot_and_restores_readonly(self):
        with patch.object(restore, 'RESTORE_WORKFLOW_QUALIFIED', True), \
                patch.object(restore, 'BACKUP_FRESHNESS_QUALIFIED', True):
            result = self.call()
        self.assertFalse(result['authorized_to_boot'])
        self.assertIn('copy', self.events)
        self.assertIn(('blockdev', '--setro', '/dev/state'), self.events)


if __name__ == '__main__':
    unittest.main()
