"""Qualify LUKS header restoration on disposable files, not recovery media."""

import hashlib
import shutil
import subprocess
import tempfile
from pathlib import Path
import unittest

from lanrith import recovery_backup_files as backup_files
from lanrith.release import ReleaseError


@unittest.skipUnless(shutil.which('cryptsetup'), 'cryptsetup is unavailable')
class LuksHeaderRecoveryTests(unittest.TestCase):
    def cryptsetup(self, *arguments, data=None, success=True):
        result = subprocess.run(['cryptsetup', *map(str, arguments)], input=data,
                                capture_output=True, timeout=120)
        if success:
            self.assertEqual(result.returncode, 0, 'Synthetic cryptsetup operation failed.')
        return result

    def test_synthetic_header_backup_restores_unlock_without_changing_payload(self):
        with tempfile.TemporaryDirectory(prefix='lanrith-luks-header-test-') as temporary:
            root = Path(temporary)
            volume, backup = root/'synthetic-volume', root/'synthetic-header'
            with volume.open('xb') as stream:
                stream.truncate(64*1024*1024)
            key = b'disposable-synthetic-luks-passphrase'
            self.cryptsetup('luksFormat', '--batch-mode', '--type', 'luks2', '--pbkdf', 'pbkdf2',
                            '--pbkdf-force-iterations', '1000', '--key-file', '-', volume, data=key)
            identity = self.cryptsetup('luksUUID', volume).stdout.strip()
            with volume.open('r+b') as stream:
                stream.seek(32*1024*1024)
                stream.write(b'synthetic-encrypted-payload-marker')
                stream.flush()
            with volume.open('rb') as stream:
                stream.seek(32*1024*1024)
                payload = hashlib.sha256(stream.read(4096)).digest()
            secret = bytearray(key)
            backups = root/'backups'
            backups.mkdir(mode=0o700)
            binding = {'image_id': 'lanrith', 'volume_uuid': identity.decode('ascii')}
            name = backup_files.create(backups, volume, secret, **binding)
            self.assertFalse(backup_files.inspect(backups, name, secret, **binding)['authorized_to_restore'])
            encrypted_backup = backups/name/'payload'
            with encrypted_backup.open('r+b') as stream:
                stream.seek(32*1024*1024)
                original = stream.read(1)
                stream.seek(32*1024*1024)
                stream.write(bytes([original[0] ^ 1]))
            with self.assertRaises(ReleaseError):
                backup_files.inspect(backups, name, secret, **binding)
            self.cryptsetup('luksHeaderBackup', volume, '--header-backup-file', backup)
            self.assertGreater(backup.stat().st_size, 0)
            self.assertLessEqual(backup.stat().st_size, 32*1024*1024)
            with volume.open('r+b') as stream:
                stream.write(b'\0'*backup.stat().st_size)
                stream.flush()
            self.assertNotEqual(self.cryptsetup('isLuks', volume, success=False).returncode, 0)
            missing = self.cryptsetup('luksHeaderRestore', '--batch-mode', volume,
                                      '--header-backup-file', root/'missing-header', success=False)
            self.assertNotEqual(missing.returncode, 0)
            self.assertNotEqual(self.cryptsetup('isLuks', volume, success=False).returncode, 0)
            self.cryptsetup('luksHeaderRestore', '--batch-mode', volume, '--header-backup-file', backup)
            self.assertEqual(self.cryptsetup('luksUUID', volume).stdout.strip(), identity)
            self.cryptsetup('open', '--test-passphrase', '--key-file', '-', volume, data=key)
            self.assertNotEqual(self.cryptsetup('open', '--test-passphrase', '--key-file', '-', volume,
                                                data=b'wrong-synthetic-passphrase', success=False).returncode, 0)
            with volume.open('rb') as stream:
                stream.seek(32*1024*1024)
                self.assertEqual(hashlib.sha256(stream.read(4096)).digest(), payload)
            for index in range(len(secret)):
                secret[index] = 0


if __name__ == '__main__':
    unittest.main()
