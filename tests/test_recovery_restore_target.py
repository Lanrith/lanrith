"""Unit tests for the gated offline target claim boundary."""
from contextlib import ExitStack
from types import SimpleNamespace
import os
import unittest
from unittest.mock import patch

from lanrith import recovery_restore_target as target
from lanrith.release import ReleaseError


class TargetClaimTests(unittest.TestCase):
    def setUp(self):
        self.binding = {'schema': 1, 'target_disk_by_id': '/dev/disk/by-id/target',
                        'backup_disk_by_id': '/dev/disk/by-id/backup',
                        'state_partuuid': '12345678-1234-1234-1234-123456789abc',
                        'state_uuid': '22345678-1234-1234-1234-123456789abc',
                        'backup_partuuid': '32345678-1234-1234-1234-123456789abc'}
        self.rows = [{'device': '/dev/vdb1', 'disk': '/dev/vdb', 'mounted': False, 'size': 4096}]
        self.snapshot = ({'sector': 512}, self.rows)
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        def mock(obj, name, **kwargs):
            return self.stack.enter_context(patch.object(obj, name, **kwargs))
        mock(target.recovery_authority, 'permits', return_value=False)
        mock(target.os, 'geteuid', return_value=0)
        mock(target.Path, 'is_file', return_value=True)
        mock(target.factory, 'secure_boot')
        mock(target.factory, 'verified_root', return_value=('/dev/vda', None))
        mock(target.recovery_inputs, 'canonical_disk', side_effect=lambda p: '/dev/vdb' if p.endswith('target') else '/dev/vdc')
        self.snapshot_mock = mock(target.recovery_inputs, 'disk_snapshot', return_value=self.snapshot)
        mock(target.recovery_inputs, 'partition', return_value='/dev/vdb1')
        mock(target.update, 'command', side_effect=lambda c: '0' if c[-1] == '/dev/vdb1' else '1')
        self.open = mock(target.os, 'open', return_value=42)
        self.close = mock(target.os, 'close')
        mock(target.os, 'fstat', return_value=SimpleNamespace(st_mode=0o060000, st_rdev=17))
        mock(target.os, 'stat', return_value=SimpleNamespace(st_rdev=17))
        mock(target.recovery_restore_transaction, '_target_size', return_value=4096)

    def test_gate_is_closed_without_opening_target(self):
        with self.assertRaises(ReleaseError):
            with target.claim(self.binding, expected_size=4096):
                pass
        self.open.assert_not_called()

    def test_claim_requires_exclusive_open_and_revalidates(self):
        with patch.object(target, 'TARGET_CLAIM_QUALIFIED', True):
            with target.claim(self.binding, expected_size=4096) as (fd, check):
                self.assertEqual(fd, 42)
                check()
        flags = self.open.call_args.args[1]
        self.assertEqual(flags & (os.O_RDWR | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC),
                         os.O_RDWR | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC)
        self.close.assert_called_once_with(42)
        self.assertGreaterEqual(self.snapshot_mock.call_count, 3)

    def test_target_topology_change_rejects_and_closes(self):
        with patch.object(target, 'TARGET_CLAIM_QUALIFIED', True):
            with self.assertRaises(ReleaseError):
                with target.claim(self.binding, expected_size=4096) as (_, check):
                    self.snapshot_mock.return_value = ({'sector': 4096}, self.rows)
                    check()
        self.close.assert_called_once_with(42)

    def test_busy_target_is_rejected_before_open(self):
        self.rows[0]['mounted'] = True
        with patch.object(target, 'TARGET_CLAIM_QUALIFIED', True), self.assertRaises(ReleaseError):
            with target.claim(self.binding, expected_size=4096):
                pass
        self.open.assert_not_called()

    def test_backup_disk_alias_is_rejected_before_open(self):
        with patch.object(target, 'TARGET_CLAIM_QUALIFIED', True), \
                patch.object(target.recovery_inputs, 'canonical_disk', return_value='/dev/vdb'), \
                self.assertRaises(ReleaseError):
            with target.claim(self.binding, expected_size=4096):
                pass
        self.open.assert_not_called()

    def test_changed_block_device_identity_is_rejected_and_closed(self):
        with patch.object(target, 'TARGET_CLAIM_QUALIFIED', True), \
                patch.object(target.os, 'stat', return_value=SimpleNamespace(st_rdev=18)), \
                self.assertRaises(ReleaseError):
            with target.claim(self.binding, expected_size=4096):
                pass
        self.close.assert_called_once_with(42)


if __name__ == '__main__':
    unittest.main()
