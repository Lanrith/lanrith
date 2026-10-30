"""Bound and authenticate synthetic encrypted-backup streams."""

import io
import unittest

from lanrith import recovery_backup_auth as auth
from lanrith.release import ReleaseError


class EncryptedBackupAuthenticationTests(unittest.TestCase):
    def setUp(self):
        self.data = b'synthetic encrypted LUKS header and payload'
        self.secret = bytearray(b'synthetic-offline-recovery-key')
        self.value = {'schema': 1, 'image_id': 'lanrith',
                      'volume_uuid': '12345678-1234-1234-1234-123456789abc',
                      'size': len(self.data), 'salt': 'a1'*32}
        self.mac = auth.authentication(io.BytesIO(self.data), self.secret, self.value)

    def test_valid_stream_is_observation_not_restore_authority(self):
        result = auth.verify(io.BytesIO(self.data), self.secret, self.value, self.mac)
        self.assertEqual(result['scope'], 'encrypted-backup-authentication')
        self.assertIs(result['authorized_to_restore'], False)

    def test_copy_authenticates_exact_written_bytes_and_handles_short_writes(self):
        class ShortWriter(io.BytesIO):
            def write(self, value):
                return super().write(value[:3])
        output = ShortWriter()
        mac = auth.copy_and_authenticate(io.BytesIO(self.data), output, self.secret, self.value)
        self.assertEqual(output.getvalue(), self.data)
        self.assertEqual(mac, self.mac)
        self.assertFalse(auth.verify(io.BytesIO(output.getvalue()), self.secret,
                                     self.value, mac)['authorized_to_restore'])
        stream = io.BytesIO(self.data)
        with self.assertRaises(ReleaseError):
            auth.copy_and_authenticate(stream, stream, self.secret, self.value)

    def test_failed_copy_does_not_return_an_authenticator(self):
        class FailedWriter:
            def write(self, value):
                return 0
        with self.assertRaises(ReleaseError):
            auth.copy_and_authenticate(io.BytesIO(self.data), FailedWriter(), self.secret, self.value)

    def test_stream_crosses_chunk_boundaries_without_losing_bytes(self):
        data = bytes(range(256))*8193
        value = {**self.value, 'size': len(data)}
        output = io.BytesIO()
        mac = auth.copy_and_authenticate(io.BytesIO(data), output, self.secret, value)
        self.assertEqual(output.getvalue(), data)
        self.assertFalse(auth.verify(io.BytesIO(output.getvalue()), self.secret,
                                     value, mac)['authorized_to_restore'])

    def test_wrong_key_tampered_bytes_and_metadata_are_rejected(self):
        mutated = b'X'+self.data[1:]
        variants = [(mutated, self.secret, self.value),
                    (self.data, bytearray(b'wrong-offline-key'), self.value),
                    (self.data, self.secret, {**self.value, 'volume_uuid':
                                              '12345678-1234-1234-1234-123456789abd'}),
                    (self.data, self.secret, {**self.value, 'image_id': 'different'}),
                    (self.data, self.secret, {**self.value, 'salt': 'b2'*32})]
        for data, secret, value in variants:
            with self.subTest(value=value), self.assertRaises(ReleaseError):
                auth.verify(io.BytesIO(data), secret, value, self.mac)

    def test_truncated_extended_and_malformed_inputs_are_rejected(self):
        for data in (self.data[:-1], self.data+b'x'):
            with self.subTest(size=len(data)), self.assertRaises(ReleaseError):
                auth.verify(io.BytesIO(data), self.secret, self.value, self.mac)
        for value in ({**self.value, 'size': True}, {**self.value, 'size': 0},
                      {**self.value, 'salt': 'A1'*32}, {**self.value, 'extra': 'unknown'}):
            with self.subTest(value=value), self.assertRaises(ReleaseError):
                auth.authentication(io.BytesIO(self.data), self.secret, value)
        for secret in (b'immutable', bytearray(), bytearray(b'bad\0key')):
            with self.subTest(secret_type=type(secret)), self.assertRaises(ReleaseError):
                auth.authentication(io.BytesIO(self.data), secret, self.value)
        with self.assertRaises(ReleaseError):
            auth.verify(io.BytesIO(self.data), self.secret, self.value, 'f'*63)


if __name__ == '__main__':
    unittest.main()
