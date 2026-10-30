"""Read-only state inspection never writes a LUKS header or exports its key."""

import json
import os
from pathlib import Path
import stat
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from lanrith import factory, recovery_state as state, release, repair, update


class ReadOnlyRecoveryTests(unittest.TestCase):
    uuid = '12345678-1234-1234-1234-123456789abc'
    disk = '/dev/synthetic'
    device = '/dev/synthetic1'

    def row(self):
        return {'device': self.device, 'disk': self.disk, 'type': factory.VAR_GUID,
                'label': 'var', 'size': 4096, 'mounted': False}

    def test_credential_is_only_stdin_and_diagnostics_never_expose_it(self):
        secret = bytearray(b'synthetic-offline-key')
        result = subprocess.CompletedProcess([], 0, b'', b'')
        with patch.object(state.subprocess, 'run', return_value=result) as run:
            state.cryptsetup_open('/dev/mapper/test-backing', 'test-state', secret)
        args = run.call_args.args[0]
        self.assertIn('--readonly', args)
        self.assertIn('--disable-external-tokens', args)
        self.assertIn('--key-file=-', args)
        self.assertTrue(all('synthetic-offline-key' not in value for value in args))
        self.assertIs(run.call_args.kwargs['input'], secret)
        result.returncode = 1
        result.stderr = b'synthetic-offline-key'
        with patch.object(state.subprocess, 'run', return_value=result), self.assertRaises(release.ReleaseError) as error:
            state.cryptsetup_open('/dev/mapper/test-backing', 'test-state', secret)
        self.assertNotIn('synthetic-offline-key', str(error.exception))

    def test_readonly_check_does_not_disclose_command_output(self):
        for status, stdout, stderr, expected in (
                (0, b'1\n', b'', None),
                (0, b'0\n', b'', 'not read-only'),
                (1, b'', b'No such file: sensitive-data', 'device missing'),
                (1, b'', b'Permission denied: sensitive-data', 'device denied'),
                (1, b'', b'other sensitive-data', 'check failed')):
            result = subprocess.CompletedProcess([], status, stdout, stderr)
            with self.subTest(status=status, expected=expected), patch.object(state.subprocess, 'run', return_value=result):
                if expected is None:
                    state.require_readonly('/dev/mapper/synthetic')
                else:
                    with self.assertRaises(release.ReleaseError) as error:
                        state.require_readonly('/dev/mapper/synthetic')
                    self.assertIn(expected, str(error.exception))
                    self.assertNotIn('sensitive-data', str(error.exception))

    def test_state_mount_requires_the_bound_device_and_all_restrictions(self):
        point = Path('/run/synthetic-state')
        mapping = '/dev/mapper/synthetic-state'
        row = {'target': str(point), 'source': mapping, 'fstype': 'ext4', 'options': 'ro,nodev,nosuid,noexec'}
        with patch.object(update, 'command', return_value=json.dumps({'filesystems': [row]})):
            state.verify_mount(point, mapping)
        for change in ({'source': '/dev/mapper/other'}, {'target': '/run/other'}, {'fstype': 'xfs'},
                       {'options': 'rw,nodev,nosuid,noexec'}, {'options': 'ro,nodev,nosuid'}):
            with self.subTest(change=change), \
                    patch.object(update, 'command', return_value=json.dumps({'filesystems': [{**row, **change}]})), \
                    self.assertRaises(release.ReleaseError):
                state.verify_mount(point, mapping)

    def exercise(self, *, wrong_uuid=False, fail_mount=False, fail_unmount=False):
        with tempfile.TemporaryDirectory(prefix='lanrith-recovery-state-test-') as temporary:
            scratch = Path(temporary)
            source = scratch/'block'
            source.write_bytes(b'synthetic block')
            point = scratch/'mount'
            point.mkdir(mode=0o700)
            layout = {'sector': 512, 'extents': [(8, 16, self.device)]}
            events = []
            def command(args, **_):
                events.append(args)
                if args[:2] == ['blockdev', '--getro']:
                    return '1\n'
                if args[:2] == ['cryptsetup', 'luksUUID']:
                    return ('abcdefab-1234-1234-1234-123456789abc' if wrong_uuid else self.uuid)+'\n'
                if args[0] == 'mount' and fail_mount:
                    raise release.ReleaseError('synthetic mount failure')
                if args[0] == 'umount' and fail_unmount:
                    raise release.ReleaseError('synthetic unmount failure')
                return ''
            native_open = os.open
            def open_device(path, flags):
                self.assertEqual(path, self.device)
                self.assertFalse(flags & os.O_WRONLY)
                self.assertTrue(flags & os.O_NOFOLLOW)
                return native_open(source, os.O_RDONLY)
            is_mount = [True, False] if not fail_mount and not wrong_uuid and not fail_unmount else [True] if fail_unmount else [False]
            secret = bytearray(b'synthetic-offline-key')
            with patch.object(state.os, 'geteuid', return_value=0), patch.object(Path, 'is_file', return_value=True), \
                    patch.object(factory, 'verified_root', return_value=('/dev/recovery', {1, 2})), \
                    patch.object(repair, 'disk_layout', return_value=layout), patch.object(update, 'geometry', return_value=[self.row()]), \
                    patch.object(state.os, 'open', side_effect=open_device), \
                    patch.object(state.os, 'fstat', return_value=SimpleNamespace(st_mode=stat.S_IFBLK, st_rdev=os.makedev(7, 5))), \
                    patch.object(state.secrets, 'token_hex', return_value='a'*16), \
                    patch.object(state.tempfile, 'mkdtemp', return_value=str(point)), \
                    patch.object(Path, 'is_mount', side_effect=is_mount), patch.object(update, 'command', side_effect=command), \
                    patch.object(state, 'verify_mount') as verify, patch.object(state, 'require_readonly'), \
                    patch.object(state, 'cryptsetup_open') as crypt:
                if wrong_uuid or fail_mount or fail_unmount:
                    with self.assertRaises(release.ReleaseError):
                        with state.open_readonly(self.disk, self.uuid, secret):
                            if not fail_unmount:
                                self.fail('Unexpectedly mounted recovery state')
                else:
                    with state.open_readonly(self.disk, self.uuid, secret) as mounted:
                        self.assertEqual(mounted, point)
                    verify.assert_called_once()
                if wrong_uuid:
                    crypt.assert_not_called()
                else:
                    crypt.assert_called_once()
            self.assertTrue(any(args[0:3] == ['dmsetup', '--readonly', 'create'] and
                                args[-1].endswith('linear 7:5 0') for args in events))
            self.assertTrue(any(args[0:2] == ['dmsetup', 'mknodes'] for args in events))
            self.assertEqual(any(args[0:2] == ['dmsetup', 'remove'] for args in events), not fail_unmount)
            if not wrong_uuid and not fail_unmount:
                self.assertTrue(any(args[0:2] == ['cryptsetup', 'close'] for args in events))
            if fail_unmount:
                self.assertFalse(any(args[0:2] == ['cryptsetup', 'close'] for args in events))
            self.assertTrue(all('synthetic-offline-key' not in ' '.join(args) for args in events))
            self.assertEqual(point.exists(), fail_unmount)

    def test_readonly_layer_wraps_unlock_mount_and_ordered_teardown(self):
        self.exercise()
        self.exercise(wrong_uuid=True)
        self.exercise(fail_mount=True)
        self.exercise(fail_unmount=True)

    def test_target_disk_cannot_be_the_verified_recovery_boot_disk(self):
        with patch.object(state.os, 'geteuid', return_value=0), patch.object(Path, 'is_file', return_value=True), \
                patch.object(factory, 'verified_root', return_value=(self.disk, {1, 2})), \
                patch.object(update, 'command') as command:
            with self.assertRaisesRegex(release.ReleaseError, 'boot disk'):
                with state.open_readonly(self.disk, self.uuid, bytearray(b'synthetic')):
                    pass
            command.assert_not_called()


@unittest.skipUnless(os.geteuid() == 0, 'root-owned synthetic inventory fixture')
class RetainedContractTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='lanrith-state-inventory-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.directory = self.root/'lib/lanrith'
        self.directory.mkdir(parents=True, mode=0o700)
        self.path = self.directory/'state-contract.json'
        self.value = {'schema': 1, 'machine_id': '1'*32,
                      'state': {'dns': {'writes': 'dns-v1', 'reads': ['dns-v1']}},
                      'trust': {'generation': 1, 'transition': 'steady', 'authorities':
                                {'manifest': '2'*64, 'secure_boot': '3'*64,
                                 'verity': '4'*64, 'pcr_policy': '5'*64}}}
        self.path.write_text(json.dumps(self.value))
        self.path.chmod(0o600)

    def read(self, *, readonly=True):
        with patch.object(Path, 'is_mount', return_value=True), \
                patch.object(state.os, 'statvfs', return_value=SimpleNamespace(f_flag=os.ST_RDONLY if readonly else 0)):
            return state.retained_contract(self.root)

    def test_valid_inventory_requires_readonly_mount(self):
        self.assertEqual(self.read(), self.value)
        with self.assertRaises(release.ReleaseError): self.read(readonly=False)

    def test_unsafe_file_mode_hardlink_and_symlink_are_rejected(self):
        self.path.chmod(0o644)
        with self.assertRaises(release.ReleaseError): self.read()
        self.path.chmod(0o600)
        linked = self.directory/'linked'
        os.link(self.path, linked)
        with self.assertRaises(release.ReleaseError): self.read()
        linked.unlink()
        self.path.unlink()
        self.path.symlink_to('/etc/passwd')
        with self.assertRaises(OSError): self.read()

    def test_symlinked_directory_and_duplicate_json_are_rejected(self):
        self.path.write_text('{"schema":1,"schema":1}')
        with self.assertRaises(release.ReleaseError): self.read()
        self.path.unlink()
        self.directory.rmdir()
        self.directory.symlink_to('/etc')
        with self.assertRaises(OSError): self.read()


if __name__ == '__main__':
    unittest.main()
