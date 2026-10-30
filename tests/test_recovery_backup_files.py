"""Qualify the non-writing-to-devices synthetic backup-file fixture."""

import json
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from lanrith import recovery_backup_files as backup
from lanrith.release import ReleaseError


class BackupFileFixtureTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='lanrith-backup-files-')
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.directory = self.root/'backups'
        self.directory.mkdir(mode=0o700)
        self.source = self.root/'synthetic-encrypted-volume'
        self.source.write_bytes(b'synthetic encrypted header and payload')
        self.secret = bytearray(b'synthetic-offline-key')
        self.binding = {'image_id': 'lanrith', 'volume_uuid': '12345678-1234-1234-1234-123456789abc'}

    def create(self):
        return backup.create(self.directory, self.source, self.secret, **self.binding)

    def inspect(self, name, secret=None, **binding):
        return backup.inspect(self.directory, name, self.secret if secret is None else secret,
                              **(binding or self.binding))

    def test_complete_copy_is_authenticated_without_authorizing_restore(self):
        name = self.create()
        result = self.inspect(name)
        self.assertFalse(result['authorized_to_restore'])
        self.assertEqual((self.directory/name/'payload').read_bytes(), self.source.read_bytes())
        other = self.create()
        self.assertNotEqual(name, other)
        first = json.loads((self.directory/name/'seal').read_text())
        second = json.loads((self.directory/other/'seal').read_text())
        self.assertNotIn(bytes(self.secret), (self.directory/name/'seal').read_bytes())
        self.assertNotEqual(first['descriptor']['salt'], second['descriptor']['salt'])

    def test_tampering_wrong_key_and_wrong_binding_are_rejected(self):
        name = self.create()
        with self.assertRaises(ReleaseError):
            self.inspect(name, bytearray(b'wrong-key'))
        with self.assertRaises(ReleaseError):
            self.inspect(name, volume_uuid='12345678-1234-1234-1234-123456789abd', image_id='lanrith')
        payload = self.directory/name/'payload'
        payload.write_bytes(b'X'+payload.read_bytes()[1:])
        with self.assertRaises(ReleaseError):
            self.inspect(name)

    def test_changed_or_malformed_seal_is_rejected(self):
        name = self.create()
        seal = self.directory/name/'seal'
        record = json.loads(seal.read_text())
        record['descriptor']['salt'] = 'b2'*32
        from lanrith.release import canonical
        seal.write_bytes(canonical(record))
        with self.assertRaises(ReleaseError):
            self.inspect(name)
        seal.write_bytes(b'{"schema":1,"schema":1}\n')
        with self.assertRaises(ReleaseError):
            self.inspect(name)

    def test_incomplete_copy_never_publishes_a_valid_seal(self):
        with patch.object(backup.auth, 'copy_and_authenticate', side_effect=ReleaseError('synthetic failure')):
            with self.assertRaises(ReleaseError):
                self.create()
        names = [item.name for item in self.directory.iterdir()]
        self.assertEqual(len(names), 1)
        self.assertFalse((self.directory/names[0]/'seal').exists())
        with self.assertRaises(ReleaseError):
            self.inspect(names[0])

    def test_prepublication_sync_failures_leave_no_inspectable_backup(self):
        for failed_sync in (1, 2):
            with self.subTest(failed_sync=failed_sync):
                calls = 0
                def fail_sync(fd):
                    nonlocal calls
                    calls += 1
                    if calls == failed_sync:
                        raise OSError('Synthetic sync failure')
                with patch.object(backup.os, 'fsync', side_effect=fail_sync), self.assertRaises(OSError):
                    self.create()
                entries = list(self.directory.iterdir())
                self.assertEqual(len(entries), 1)
                self.assertFalse((entries[0]/'seal').exists())
                with self.assertRaises(ReleaseError):
                    self.inspect(entries[0].name)
                for path in entries[0].iterdir():
                    path.unlink()
                entries[0].rmdir()

    def test_immutable_protection_precedes_seal_publication(self):
        fd = os.open(self.source, os.O_RDONLY | os.O_NOFOLLOW)
        value = {'schema': 1, **self.binding, 'size': self.source.stat().st_size, 'salt': '12'*32}
        def protect(payload):
            entries = list(self.directory.iterdir())
            self.assertEqual(len(entries), 1)
            self.assertFalse((entries[0]/'seal').exists())
            self.assertEqual(os.read(payload, 4096), self.source.read_bytes())
        try:
            name = backup._publish(self.directory, fd, self.secret, value, lambda: None, protect=protect)
        finally:
            os.close(fd)
        self.assertTrue((self.directory/name/'seal').is_file())
        self.assertFalse(self.inspect(name)['authorized_to_restore'])

    def test_failed_immutable_protection_never_publishes_a_seal(self):
        fd = os.open(self.source, os.O_RDONLY | os.O_NOFOLLOW)
        value = {'schema': 1, **self.binding, 'size': self.source.stat().st_size, 'salt': '12'*32}
        try:
            with self.assertRaises(ReleaseError):
                backup._publish(self.directory, fd, self.secret, value, lambda: None,
                                protect=lambda _: (_ for _ in ()).throw(ReleaseError('unavailable')))
        finally:
            os.close(fd)
        entries = list(self.directory.iterdir())
        self.assertEqual(len(entries), 1)
        self.assertFalse((entries[0]/'seal').exists())
        with self.assertRaises(ReleaseError):
            self.inspect(entries[0].name)

    def test_verity_required_inspection_rejects_unprotected_backup(self):
        name = self.create()
        from lanrith import recovery_backup_verity
        with patch.object(recovery_backup_verity, 'measure', side_effect=ReleaseError('unavailable')):
            with self.assertRaises(ReleaseError):
                backup.inspect(self.directory, name, self.secret, require_verity=True, **self.binding)

    def test_source_change_during_copy_does_not_publish_a_seal(self):
        original = backup.auth.copy_and_authenticate
        def mutate(source, destination, secret, value):
            mac = original(source, destination, secret, value)
            self.source.write_bytes(b'X'+self.source.read_bytes()[1:])
            return mac
        with patch.object(backup.auth, 'copy_and_authenticate', side_effect=mutate):
            with self.assertRaises(ReleaseError):
                self.create()
        names = [item.name for item in self.directory.iterdir()]
        self.assertEqual(len(names), 1)
        self.assertFalse((self.directory/names[0]/'seal').exists())
        with self.assertRaises(ReleaseError):
            self.inspect(names[0])

    def test_authenticated_handle_is_pinned_and_closed_after_use(self):
        from lanrith import recovery_backup_verity
        name = self.create()
        with patch.object(recovery_backup_verity, 'measure', return_value=bytes.fromhex('ab'*32)):
            with backup.open_authenticated(self.directory, name, self.secret, **self.binding) as (fd, result):
                self.assertFalse(result['authorized_to_restore'])
                self.assertEqual(os.read(fd, 4096), self.source.read_bytes())
            with self.assertRaises(OSError):
                os.read(fd, 1)

    def test_changed_verity_measurement_during_use_is_rejected(self):
        from lanrith import recovery_backup_verity
        name = self.create()
        first, changed = bytes.fromhex('ab'*32), bytes.fromhex('ac'*32)
        with patch.object(recovery_backup_verity, 'measure', side_effect=[first, first, first, changed]):
            with self.assertRaisesRegex(ReleaseError, 'measurement changed'):
                with backup.open_authenticated(self.directory, name, self.secret, **self.binding) as (fd, _):
                    self.assertEqual(os.read(fd, 9), b'synthetic')

    def test_replaced_backup_directory_is_detected_before_context_completes(self):
        from lanrith import recovery_backup_verity
        name = self.create()
        with patch.object(recovery_backup_verity, 'measure', return_value=bytes.fromhex('ab'*32)):
            with self.assertRaises((OSError, ReleaseError)):
                with backup.open_authenticated(self.directory, name, self.secret, **self.binding) as (fd, _):
                    self.assertEqual(os.read(fd, 9), b'synthetic')
                    (self.directory/name).rename(self.directory/'removed')

    def test_unsafe_links_permissions_and_extra_files_are_rejected(self):
        link = self.root/'source-link'
        link.symlink_to(self.source)
        with self.assertRaises(ReleaseError):
            backup.create(self.directory, link, self.secret, **self.binding)
        name = self.create()
        (self.directory/name/'extra').write_bytes(b'extra')
        with self.assertRaises(ReleaseError):
            self.inspect(name)
        (self.directory/name/'extra').unlink()
        payload = self.directory/name/'payload'
        payload.chmod(0o644)
        with self.assertRaises(ReleaseError):
            self.inspect(name)
        payload.chmod(0o600)
        hardlink = self.root/'payload-hardlink'
        os.link(payload, hardlink)
        with self.assertRaises(ReleaseError):
            self.inspect(name)
        hardlink.unlink()
        payload.unlink()
        payload.symlink_to(self.source)
        with self.assertRaises((OSError, ReleaseError)):
            self.inspect(name)

    def test_symlinked_and_nonprivate_backup_directories_are_rejected(self):
        link = self.root/'backup-link'
        link.symlink_to(self.directory, target_is_directory=True)
        with self.assertRaises(ReleaseError):
            backup.create(link, self.source, self.secret, **self.binding)
        self.directory.chmod(0o755)
        with self.assertRaises(ReleaseError):
            self.create()

    def test_nonregular_source_and_invalid_backup_name_are_rejected(self):
        fifo = self.root/'synthetic-fifo'
        os.mkfifo(fifo)
        with self.assertRaises(ReleaseError):
            backup.create(self.directory, fifo, self.secret, **self.binding)
        self.assertEqual(list(self.directory.iterdir()), [])
        for name in ('../escape', '/tmp/other', 'backup-'+('a'*31), 'backup-'+('A'*32)):
            with self.subTest(name=name), self.assertRaises(ReleaseError):
                self.inspect(name)

    def test_insufficient_space_is_rejected_before_creating_a_backup(self):
        with patch.object(backup.os, 'fstatvfs', return_value=SimpleNamespace(f_bavail=1, f_frsize=4096)):
            with self.assertRaisesRegex(ReleaseError, 'space and reserve'):
                self.create()
        self.assertEqual(list(self.directory.iterdir()), [])


if __name__ == '__main__':
    unittest.main()
