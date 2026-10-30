"""Test fs-verity boundaries without requiring a particular test filesystem."""

import io
import os
from pathlib import Path
import struct
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from lanrith import recovery_backup_auth as auth, recovery_backup_verity as verity
from lanrith.release import ReleaseError


class ImmutableBackupTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='lanrith-verity-test-')
        self.addCleanup(self.temporary.cleanup)
        self.file = Path(self.temporary.name)/'payload'
        self.file.write_bytes(b'synthetic encrypted volume')
        self.file.chmod(0o600)
        self.fd = os.open(self.file, os.O_RDONLY | os.O_NOFOLLOW)
        self.addCleanup(os.close, self.fd)
        self.secret = bytearray(b'synthetic recovery key')
        self.descriptor = {'schema': 1, 'image_id': 'lanrith',
                           'volume_uuid': '12345678-1234-1234-1234-123456789abc',
                           'size': self.file.stat().st_size, 'salt': '12'*32}
        self.authenticator = auth.authentication(io.BytesIO(self.file.read_bytes()), self.secret, self.descriptor)

    def ioctl(self, fd, request, data, *args):
        self.assertEqual(fd, self.fd)
        if request == verity.ENABLE_VERITY:
            self.assertEqual(len(data), 128)
            self.assertEqual(struct.unpack_from('=III', data),
                             (1, 1, min(os.sysconf('SC_PAGESIZE'), os.fstatvfs(fd).f_bsize)))
        elif request == verity.MEASURE_VERITY:
            struct.pack_into('=HH', data, 0, 1, 32)
            data[4:] = bytes.fromhex('ab'*32)
        else:
            self.fail('Unexpected ioctl.')
        return 0

    def test_pinned_authenticated_file_does_not_authorize_restoration(self):
        with patch.object(verity.fcntl, 'ioctl', side_effect=self.ioctl):
            result = verity.verify_pinned(self.fd, self.secret, self.descriptor, self.authenticator)
        self.assertFalse(result['authorized_to_restore'])
        self.assertEqual(result['measurement_sha256'], 'ab'*32)
        self.assertEqual(os.read(self.fd, 9), b'synthetic')

    def test_wrong_key_tampered_payload_and_missing_verity_are_rejected(self):
        with patch.object(verity.fcntl, 'ioctl', side_effect=self.ioctl):
            with self.assertRaises(ReleaseError):
                verity.verify_pinned(self.fd, bytearray(b'wrong'), self.descriptor, self.authenticator)
            self.file.write_bytes(b'X'+self.file.read_bytes()[1:])
            with self.assertRaises(ReleaseError):
                verity.verify_pinned(self.fd, self.secret, self.descriptor, self.authenticator)
        with patch.object(verity.fcntl, 'ioctl', side_effect=OSError('not supported')):
            with self.assertRaisesRegex(ReleaseError, 'unavailable'):
                verity.verify_pinned(self.fd, self.secret, self.descriptor, self.authenticator)

    def test_changed_measurement_invalid_digest_and_writable_descriptor_are_rejected(self):
        def changed(fd, request, data, *args):
            self.ioctl(fd, request, data, *args)
            changed.count += 1
            if changed.count == 2:
                data[4] ^= 1
        changed.count = 0
        with patch.object(verity.fcntl, 'ioctl', side_effect=changed), self.assertRaises(ReleaseError):
            verity.verify_pinned(self.fd, self.secret, self.descriptor, self.authenticator)
        def bad_digest(fd, request, data, *args):
            struct.pack_into('=HH', data, 0, 2, 32)
        with patch.object(verity.fcntl, 'ioctl', side_effect=bad_digest), self.assertRaises(ReleaseError):
            verity.measure(self.fd)
        writable = os.open(self.file, os.O_RDWR | os.O_NOFOLLOW)
        try:
            with self.assertRaises(ReleaseError):
                verity.measure(writable)
        finally:
            os.close(writable)

    def test_invalid_merkle_block_size_is_rejected_before_ioctl(self):
        for size in (0, 3000):
            with self.subTest(size=size), patch.object(verity.os, 'fstatvfs', return_value=SimpleNamespace(f_bsize=size)), \
                    patch.object(verity.fcntl, 'ioctl') as ioctl, self.assertRaises(ReleaseError):
                verity.enable(self.fd)
            ioctl.assert_not_called()

    def test_enable_fails_closed_without_filesystem_support(self):
        with patch.object(verity.fcntl, 'ioctl', side_effect=self.ioctl):
            self.assertEqual(verity.enable(self.fd), bytes.fromhex('ab'*32))
        with patch.object(verity.fcntl, 'ioctl', side_effect=OSError('unsupported')):
            with self.assertRaises(ReleaseError):
                verity.enable(self.fd)


if __name__ == '__main__':
    unittest.main()
