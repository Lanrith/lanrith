import copy
import json
from pathlib import Path
import unittest
from unittest.mock import patch

from lanrith import recovery_authority as authority, recovery_console, release


class RecoveryAuthorityTests(unittest.TestCase):
    def policy(self):
        return {'schema': 1, 'tty': 'ttyS0', 'image_id': 'lanrith',
            'disk_by_id': '/dev/disk/by-id/synthetic-target', 'state_uuid': 'a'*8+'-1234-1234-1234-'+'b'*12,
            'operations': ['backup', 'restore'], 'offline_backup': {
                'schema': 1, 'target_disk_by_id': '/dev/disk/by-id/synthetic-target',
                'backup_disk_by_id': '/dev/disk/by-id/synthetic-backup',
                'state_uuid': 'a'*8+'-1234-1234-1234-'+'b'*12,
                'state_partuuid': 'b'*8+'-1234-1234-1234-'+'c'*12,
                'backup_partuuid': 'c'*8+'-1234-1234-1234-'+'d'*12}}

    def test_unprivileged_caller_cannot_reach_recovery_policy_or_boot_checks(self):
        with patch.object(authority.os, 'geteuid', return_value=1000), \
                patch.object(recovery_console, 'protected_file') as read:
            self.assertFalse(authority.permits('restore', self.policy()['offline_backup']))
            read.assert_not_called()

    def test_signed_operations_require_exact_binding_and_secure_boot(self):
        value = self.policy()
        with patch.object(authority.os, 'geteuid', return_value=0), \
                patch.object(Path, 'is_file', return_value=True), \
                patch.object(recovery_console, 'protected_file', return_value=json.dumps(value).encode()), \
                patch.object(authority.factory, 'secure_boot') as secure, \
                patch.object(authority.factory, 'verified_root') as verified:
            self.assertTrue(authority.permits('restore', value['offline_backup']))
            secure.assert_called_once()
            verified.assert_called_once_with('/sysroot')
            other = copy.deepcopy(value['offline_backup'])
            other['backup_disk_by_id'] = '/dev/disk/by-id/another-disk'
            with self.assertRaisesRegex(release.ReleaseError, 'binding differs'):
                authority.permits('restore', other)
            secure.side_effect = release.ReleaseError('Secure Boot disabled')
            with self.assertRaises(release.ReleaseError):
                authority.permits('backup', value['offline_backup'])

    def test_readonly_recovery_policy_grants_no_write_operation(self):
        value = self.policy()
        del value['operations']
        with patch.object(authority.os, 'geteuid', return_value=0), \
                patch.object(Path, 'is_file', return_value=True), \
                patch.object(recovery_console, 'protected_file', return_value=json.dumps(value).encode()), \
                patch.object(authority.factory, 'secure_boot') as secure:
            self.assertFalse(authority.permits('restore', value['offline_backup']))
            secure.assert_not_called()

    def test_os_repair_needs_its_full_signed_policy_and_does_not_enable_state_restore(self):
        value = self.policy()
        del value['offline_backup']
        value['operations'] = ['repair']
        value['offline_inputs'] = {'release_disk_by_id': '/dev/disk/by-id/synthetic-source',
            'release_partition_uuid': 'e'*8+'-1234-1234-1234-'+'f'*12,
            'target_esp_uuid': 'f'*8+'-1234-1234-1234-'+'e'*12}
        with patch.object(authority.os, 'geteuid', return_value=0), \
                patch.object(Path, 'is_file', return_value=True), \
                patch.object(recovery_console, 'protected_file', return_value=json.dumps(value).encode()), \
                patch.object(authority.factory, 'secure_boot'), patch.object(authority.factory, 'verified_root'):
            self.assertTrue(authority.permits('repair', value))
            self.assertFalse(authority.permits('restore'))
            with self.assertRaises(release.ReleaseError):
                authority.permits('repair', {**value, 'disk_by_id': '/dev/disk/by-id/other-target'})

    def test_os_repair_menu_requires_confirmation_and_clears_the_key(self):
        value = {**self.policy(), 'operations': ['repair']}
        key = bytearray(b'synthetic-offline-key')
        commands = iter(['repair', '9', 'exit'])
        confirmed = []
        def repair(policy, secret, *, confirm):
            confirmed.append(confirm(9, 'ab'*32))
            return {'deployment_sequence': 9, 'state_preserved': True, 'authorized_to_boot': False}
        recovery_console.fixed_menu(value, read_command=lambda: next(commands), write=lambda _: None,
            inspect=lambda _: None, read_repair_key=lambda: key, repair_slot=repair)
        self.assertEqual(confirmed, ['9'])
        self.assertEqual(key, bytearray(len(key)))

    def test_restore_confirmation_requires_the_independently_retained_receipt(self):
        name = 'backup-'+'a'*32
        for expected, succeeds in (('ab'*32, True), ('cd'*32, False)):
            key = bytearray(b'synthetic-offline-key')
            commands = iter(['restore', name, expected, *([name] if succeeds else []), 'exit'])
            committed = []
            def restore(value, selected, secret, confirm):
                receipt = confirm(selected, 'ab'*32)
                committed.append(receipt)
                return {'authorized_to_boot': False}
            recovery_console.fixed_menu(self.policy(), read_command=lambda: next(commands), write=lambda _: None,
                inspect=lambda _: None, read_restore_key=lambda: key, restore=restore)
            self.assertEqual(bool(committed), succeeds)
            if succeeds:
                self.assertEqual(committed, [{'backup_id': name, 'measurement_sha256': 'ab'*32}])
            self.assertEqual(key, bytearray(len(key)))
