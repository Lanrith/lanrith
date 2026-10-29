"""Fault tests for the unqualified header-last copy primitive."""
import os
import json
import subprocess
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from lanrith import recovery_backup_verity as verity, recovery_restore_transaction as transaction
from lanrith.release import ReleaseError


class RestoreTransactionTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='lanrith-restore-transaction-')
        self.addCleanup(self.tmp.cleanup)
        root = Path(self.tmp.name)
        self.source = root/'source'
        self.target = root/'target'
        self.size = 2*1024*1024
        self.metadata = 16*1024
        contents = bytearray(os.urandom(self.size))
        contents[:16] = b'LUKS\xba\xbe\x00\x02'+self.metadata.to_bytes(8, 'big')
        contents[self.metadata:self.metadata+16] = b'SKUL\xba\xbe\x00\x02'+self.metadata.to_bytes(8, 'big')
        self.contents = bytes(contents)
        self.source.write_bytes(self.contents)
        self.source.chmod(0o600)
        self.target.write_bytes(b'Z'*self.size)
        self.src = os.open(self.source, os.O_RDONLY)
        self.dst = os.open(self.target, os.O_RDWR)
        self.addCleanup(os.close, self.src)
        self.addCleanup(os.close, self.dst)
        self.measure = bytes.fromhex('aa'*32)
        self.patches = [patch.object(transaction, '_target_size', return_value=self.size),
                        patch.object(verity, 'measure', return_value=self.measure)]
        for p in self.patches:
            p.start()
            self.addCleanup(p.stop)

    def run_copy(self, check=lambda: None):
        return transaction.restore_pinned(self.src, self.dst, expected_measurement=self.measure,
                                          metadata_size=self.metadata, data_offset=1024*1024,
                                          revalidate=check)

    def test_gate_is_closed_without_any_write(self):
        with self.assertRaises(ReleaseError):
            self.run_copy()
        self.assertEqual(self.target.read_bytes(), b'Z'*self.size)

    def test_success_copies_all_bytes_and_preserves_source(self):
        calls = []
        with patch.object(transaction, 'RESTORE_WRITE_QUALIFIED', True):
            result = self.run_copy(lambda: calls.append('checked'))
        self.assertFalse(result['authorized_to_boot'])
        self.assertGreaterEqual(len(calls), 4)
        self.assertEqual(self.target.read_bytes(), self.contents)
        self.assertEqual(self.source.read_bytes(), self.contents)

    def test_interrupted_body_copy_keeps_both_headers_invalid_and_backup_unchanged(self):
        original = transaction._copy_and_verify
        def fail_body(source, target, start, end):
            if start == 2*self.metadata:
                os.pwrite(target, b'partial', start)
                os.fsync(target)
                raise OSError('synthetic interruption')
            return original(source, target, start, end)
        with patch.object(transaction, 'RESTORE_WRITE_QUALIFIED', True), \
                patch.object(transaction, '_copy_and_verify', side_effect=fail_body):
            with self.assertRaises(OSError):
                self.run_copy()
        data = self.target.read_bytes()
        self.assertEqual(data[:4096], bytes(4096))
        self.assertEqual(data[self.metadata:self.metadata+4096], bytes(4096))
        self.assertEqual(self.source.read_bytes(), self.contents)

    def test_readback_corruption_does_not_publish_either_header(self):
        original = os.pread
        def corrupt(fd, length, offset):
            data = original(fd, length, offset)
            if fd == self.dst and offset >= 2*self.metadata and len(data) > 32:
                return bytes([data[0] ^ 1])+data[1:]
            return data
        with patch.object(transaction, 'RESTORE_WRITE_QUALIFIED', True), \
                patch.object(transaction.os, 'pread', side_effect=corrupt), self.assertRaises(ReleaseError):
            self.run_copy()
        data = self.target.read_bytes()
        self.assertEqual(data[:4096], bytes(4096))
        self.assertEqual(data[self.metadata:self.metadata+4096], bytes(4096))
        self.assertEqual(self.source.read_bytes(), self.contents)

    def test_zero_length_write_does_not_publish_either_header(self):
        original = os.pwrite
        def short_write(fd, data, offset):
            if fd == self.dst and offset >= 2*self.metadata:
                return 0
            return original(fd, data, offset)
        with patch.object(transaction, 'RESTORE_WRITE_QUALIFIED', True), \
                patch.object(transaction.os, 'pwrite', side_effect=short_write), self.assertRaises(ReleaseError):
            self.run_copy()
        data = self.target.read_bytes()
        self.assertEqual(data[:4096], bytes(4096))
        self.assertEqual(data[self.metadata:self.metadata+4096], bytes(4096))
        self.assertEqual(self.source.read_bytes(), self.contents)

    def test_revalidation_failure_before_writes_leaves_target_unchanged(self):
        def deny():
            raise ReleaseError('synthetic binding change')
        with patch.object(transaction, 'RESTORE_WRITE_QUALIFIED', True), self.assertRaises(ReleaseError):
            self.run_copy(deny)
        self.assertEqual(self.target.read_bytes(), b'Z'*self.size)

    def test_binding_change_at_each_revalidation_boundary(self):
        # These checkpoints model detected binding changes, not power loss or
        # a block device that lies about durability. The independent source
        # must stay intact in every case.
        for stop in range(1, 6):
            with self.subTest(checkpoint=stop):
                os.pwrite(self.dst, b'Z'*self.size, 0)
                os.fsync(self.dst)
                calls = 0
                def revalidate():
                    nonlocal calls
                    calls += 1
                    if calls == stop:
                        raise ReleaseError('synthetic binding change')
                with patch.object(transaction, 'RESTORE_WRITE_QUALIFIED', True), self.assertRaises(ReleaseError):
                    self.run_copy(revalidate)
                self.assertEqual(calls, stop)
                data = self.target.read_bytes()
                if stop <= 2:
                    self.assertEqual(data, b'Z'*self.size)
                elif stop <= 4:
                    self.assertEqual(data[:4096], bytes(4096))
                    self.assertEqual(data[self.metadata:self.metadata+4096], bytes(4096))
                else:
                    self.assertEqual(data, self.contents)
                self.assertEqual(self.source.read_bytes(), self.contents)

    def test_conflicting_target_header_rejected_before_any_write(self):
        os.pwrite(self.dst, b'SKUL\xba\xbe', 32768)
        before = self.target.read_bytes()
        with patch.object(transaction, 'RESTORE_WRITE_QUALIFIED', True), self.assertRaises(ReleaseError):
            self.run_copy()
        self.assertEqual(self.target.read_bytes(), before)

    def test_conflicting_backup_header_rejected_before_any_write(self):
        self.source.chmod(0o600)
        with self.source.open('r+b') as stream:
            stream.seek(32768)
            stream.write(b'SKUL\xba\xbe')
        before = self.target.read_bytes()
        with patch.object(transaction, 'RESTORE_WRITE_QUALIFIED', True), self.assertRaises(ReleaseError):
            self.run_copy()
        self.assertEqual(self.target.read_bytes(), before)

    @unittest.skipUnless(subprocess.run(['sh', '-c', 'command -v cryptsetup >/dev/null'],
                                        capture_output=True).returncode == 0, 'cryptsetup is unavailable')
    def test_real_luks_after_interruption_before_primary_publish(self):
        root = Path(self.tmp.name)
        source, target = root/'luks-source', root/'luks-target'
        size = 64*1024*1024
        with source.open('xb') as stream:
            stream.truncate(size)
        subprocess.run(['cryptsetup', 'luksFormat', '--batch-mode', '--type=luks2', '--pbkdf=pbkdf2',
                        '--pbkdf-force-iterations=1000', '--key-file=-', str(source)],
                       input=b'synthetic-only-key', capture_output=True, check=True, timeout=120)
        metadata = json.loads(subprocess.run(['cryptsetup', 'luksDump', '--dump-json-metadata', str(source)],
                                             capture_output=True, check=True, timeout=30).stdout)
        observed = transaction.recovery_restore_layout.observe(metadata, size)
        source.chmod(0o600)
        with target.open('xb') as stream:
            stream.truncate(size)
        src, dst = os.open(source, os.O_RDONLY), os.open(target, os.O_RDWR)
        original = transaction._copy_and_verify
        def stop_before_primary(a, b, start, end):
            if start == 0:
                raise OSError('synthetic interruption')
            return original(a, b, start, end)
        try:
            with patch.object(transaction, 'RESTORE_WRITE_QUALIFIED', True), \
                    patch.object(transaction, '_target_size', return_value=size), \
                    patch.object(transaction, '_copy_and_verify', side_effect=stop_before_primary):
                with self.assertRaises(OSError):
                    transaction.restore_pinned(src, dst, expected_measurement=self.measure,
                        metadata_size=observed['metadata_size'], data_offset=observed['data_offset'],
                        revalidate=lambda: None)
            self.assertEqual(os.pread(dst, 4096, 0), bytes(4096))
            result = subprocess.run(['cryptsetup', 'open', '--test-passphrase', '--type', 'luks2',
                                     '--key-file=-', str(target)], input=b'synthetic-only-key',
                                    capture_output=True, timeout=120)
            self.assertEqual(result.returncode, 0)
        finally:
            os.close(src)
            os.close(dst)


if __name__ == '__main__':
    unittest.main()
