"""Conservative LUKS2 restore-boundary observation, with no write authority."""

from copy import deepcopy
import json
import fcntl
import hashlib
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from lanrith import recovery_backup_verity as verity, recovery_restore_layout as layout
from lanrith.release import ReleaseError


class RestoreLayoutTests(unittest.TestCase):
    def setUp(self):
        self.value = {'keyslots': {'0': {}}, 'tokens': {}, 'digests': {'0': {}},
                      'config': {'json_size': '12288', 'keyslots_size': '16744448'},
                      'segments': {'0': {'type': 'crypt', 'offset': '16777216', 'size': 'dynamic',
                                         'iv_tweak': '0', 'encryption': 'aes-xts-plain64', 'sector_size': 4096}}}

    def test_common_attached_layout_only_reports_observation(self):
        result = layout.observe(self.value, 64*1024*1024)
        self.assertEqual(result['data_offset'], 16*1024*1024)
        self.assertFalse(result['header_authenticated'])
        self.assertFalse(result['authorized_to_restore'])

    def test_reencryption_integrity_multiple_segments_and_detached_headers_are_denied(self):
        cases = []
        value = deepcopy(self.value); value['config']['requirements'] = ['offline-reencrypt']; cases.append(value)
        value = deepcopy(self.value); value['segments']['1'] = deepcopy(value['segments']['0']); cases.append(value)
        value = deepcopy(self.value); value['segments']['0']['integrity'] = {'type': 'journal'}; cases.append(value)
        value = deepcopy(self.value); value['segments']['0']['offset'] = '0'; cases.append(value)
        value = deepcopy(self.value); value['segments']['0']['size'] = '1048576'; cases.append(value)
        for value in cases:
            with self.subTest(value=value), self.assertRaises(ReleaseError):
                layout.observe(value, 64*1024*1024)

    def test_noncanonical_and_unsafe_geometry_is_denied(self):
        cases = [('offset', '016777216'), ('offset', '16777217'), ('offset', '268435968'),
                 ('iv_tweak', '-1'), ('sector_size', True), ('encryption', 'bad/command')]
        for key, value in cases:
            altered = deepcopy(self.value); altered['segments']['0'][key] = value
            with self.subTest(key=key, value=value), self.assertRaises(ReleaseError):
                layout.observe(altered, 512*1024*1024)
        for config in ({'json_size': '1'}, {'keyslots_size': '0'}, {'keyslots_size': '16744449'}):
            altered = deepcopy(self.value); altered['config'].update(config)
            with self.subTest(config=config), self.assertRaises(ReleaseError):
                layout.observe(altered, 64*1024*1024)
        with self.assertRaises(ReleaseError):
            layout.observe(self.value, 16*1024*1024)

    @unittest.skipUnless(subprocess.run(['sh', '-c', 'command -v cryptsetup >/dev/null'],
                                        capture_output=True).returncode == 0, 'cryptsetup is unavailable')
    def test_cryptsetup_synthetic_regular_file_metadata(self):
        with tempfile.TemporaryDirectory(prefix='lanrith-layout-test-') as temporary:
            target = Path(temporary)/'synthetic-luks'
            with target.open('xb') as stream:
                stream.truncate(64*1024*1024)
            subprocess.run(['cryptsetup', 'luksFormat', '--batch-mode', '--type=luks2', '--pbkdf=pbkdf2',
                            '--pbkdf-force-iterations=1000', '--key-file=-', str(target)],
                           input=b'synthetic-fixture-key', capture_output=True, check=True, timeout=120)
            result = subprocess.run(['cryptsetup', 'luksDump', '--dump-json-metadata', str(target)],
                                    capture_output=True, check=True, timeout=30)
            observed = layout.observe(json.loads(result.stdout), target.stat().st_size)
            self.assertGreater(observed['data_offset'], 0)
            self.assertFalse(observed['authorized_to_restore'])
            target.chmod(0o600)
            volume_uuid = subprocess.run(['cryptsetup', 'luksUUID', str(target)], capture_output=True,
                                         check=True, timeout=30).stdout.decode().strip()
            digest = hashlib.sha256(target.read_bytes()).digest()
            fd = os.open(target, os.O_RDONLY | os.O_NOFOLLOW)
            real_run = subprocess.run
            def checked_run(*args, **kwargs):
                sealed = kwargs['pass_fds'][0]
                required = fcntl.F_SEAL_WRITE | fcntl.F_SEAL_GROW | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_SEAL
                self.assertEqual(fcntl.fcntl(sealed, fcntl.F_GET_SEALS) & required, required)
                return real_run(*args, **kwargs)
            try:
                with patch.object(verity, 'measure', return_value=bytes.fromhex('ab'*32)), \
                        patch.object(subprocess, 'run', side_effect=checked_run):
                    snapshot = layout.inspect_pinned(fd, expected_uuid=volume_uuid,
                                                     expected_measurement=bytes.fromhex('ab'*32))
                    self.assertEqual(snapshot['data_offset'], observed['data_offset'])
                    self.assertFalse(snapshot['authorized_to_restore'])
                    with self.assertRaises(ReleaseError):
                        layout.inspect_pinned(fd, expected_uuid='12345678-1234-1234-1234-123456789abc',
                                              expected_measurement=bytes.fromhex('ab'*32))
                with patch.object(verity, 'measure', side_effect=[bytes.fromhex('ab'*32), bytes.fromhex('ac'*32)]):
                    with self.assertRaisesRegex(ReleaseError, 'changed during LUKS2 inspection'):
                        layout.inspect_pinned(fd, expected_uuid=volume_uuid, expected_measurement=bytes.fromhex('ab'*32))
                with patch.object(verity, 'measure', return_value=bytes.fromhex('ac'*32)), \
                        patch.object(subprocess, 'run') as command, self.assertRaises(ReleaseError):
                    layout.inspect_pinned(fd, expected_uuid=volume_uuid, expected_measurement=bytes.fromhex('ab'*32))
                command.assert_not_called()
            finally:
                os.close(fd)
            self.assertEqual(hashlib.sha256(target.read_bytes()).digest(), digest)

    @unittest.skipUnless(subprocess.run(['sh', '-c', 'command -v cryptsetup >/dev/null'],
                                        capture_output=True).returncode == 0, 'cryptsetup is unavailable')
    def test_recovery_key_is_checked_only_against_sealed_enrolled_slot(self):
        secret = bytearray(b'aaaaaaaa-bbbbbbbb-cccccccc-dddddddd-eeeeeeee-ffffffff-gggggggg-hhhhhhhh')
        wrong = bytearray(b'aaaaaaaa-bbbbbbbb-cccccccc-dddddddd-eeeeeeee-ffffffff-gggggggg-iiiiiiii')
        with tempfile.TemporaryDirectory(prefix='lanrith-key-test-') as temporary:
            target = Path(temporary)/'synthetic-luks'
            with target.open('xb') as stream:
                stream.truncate(64*1024*1024)
            subprocess.run(['cryptsetup', 'luksFormat', '--batch-mode', '--type=luks2', '--pbkdf=pbkdf2',
                            '--pbkdf-force-iterations=1000', '--key-file=-', str(target)],
                           input=secret, capture_output=True, check=True, timeout=120)
            uuid = subprocess.run(['cryptsetup', 'luksUUID', str(target)], capture_output=True,
                                  check=True, timeout=30).stdout.decode().strip()
            token = json.dumps({'type': 'systemd-recovery', 'keyslots': ['0']}).encode()
            subprocess.run(['cryptsetup', 'token', 'import', '--token-id', '0', '--json-file=-', str(target)],
                           input=token, capture_output=True, check=True, timeout=30)
            target.chmod(0o600)
            digest = hashlib.sha256(target.read_bytes()).digest()
            fd = os.open(target, os.O_RDONLY | os.O_NOFOLLOW)
            real_run = subprocess.run
            def checked_run(*args, **kwargs):
                sealed = kwargs['pass_fds'][0]
                required = fcntl.F_SEAL_WRITE | fcntl.F_SEAL_GROW | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_SEAL
                self.assertEqual(fcntl.fcntl(sealed, fcntl.F_GET_SEALS) & required, required)
                return real_run(*args, **kwargs)
            try:
                with patch.object(verity, 'measure', return_value=bytes.fromhex('ab'*32)), \
                        patch.object(subprocess, 'run', side_effect=checked_run):
                    result = layout.verify_recovery_key_pinned(fd, secret, expected_uuid=uuid,
                                                               expected_measurement=bytes.fromhex('ab'*32))
                    self.assertTrue(result['key_verified'])
                    self.assertFalse(result['authorized_to_restore'])
                    with self.assertRaises(ReleaseError):
                        layout.verify_recovery_key_pinned(fd, wrong, expected_uuid=uuid,
                                                          expected_measurement=bytes.fromhex('ab'*32))
                    with self.assertRaises(ReleaseError):
                        layout.verify_recovery_key_pinned(fd, bytearray(b'invalid'), expected_uuid=uuid,
                                                          expected_measurement=bytes.fromhex('ab'*32))
            finally:
                os.close(fd)
            self.assertEqual(hashlib.sha256(target.read_bytes()).digest(), digest)
            subprocess.run(['cryptsetup', 'token', 'remove', '--token-id', '0', str(target)],
                           capture_output=True, check=True, timeout=30)
            digest = hashlib.sha256(target.read_bytes()).digest()
            fd = os.open(target, os.O_RDONLY | os.O_NOFOLLOW)
            try:
                with patch.object(verity, 'measure', return_value=bytes.fromhex('ab'*32)):
                    with self.assertRaisesRegex(ReleaseError, 'systemd recovery keyslot'):
                        layout.verify_recovery_key_pinned(fd, secret, expected_uuid=uuid,
                                                          expected_measurement=bytes.fromhex('ab'*32))
            finally:
                os.close(fd)
            self.assertEqual(hashlib.sha256(target.read_bytes()).digest(), digest)


if __name__ == '__main__':
    unittest.main()
