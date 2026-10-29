"""A signed PCR policy is not proof that a UKI has matching measurements."""

from pathlib import Path
import hashlib
import struct
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import json

from lanrith import measured_boot, release


class MeasuredContentTests(unittest.TestCase):
    def test_signature_alone_cannot_authorize_mismatched_contents(self):
        policy = {'public_key_sha256': 'a'*64, 'signed_pcrs': [11]}
        observation = {'authorized_to_unlock': False, 'content_matches': False}
        signed = {b'.pcrsig': json.dumps({'sha256': [{'pol': 'b'*64}]}).encode()}
        with patch.object(measured_boot, 'inspect_signature', return_value=observation) as inspect, \
                patch.object(measured_boot, 'file_record', return_value={'sha256': 'a'*64}), \
                patch.object(measured_boot, 'initrd_policy_digest', return_value='c'*64), \
                patch.object(measured_boot, 'sections', return_value=signed):
            with self.assertRaisesRegex(release.ReleaseError, 'not covered'):
                measured_boot.verify(Path('/test/fixture.efi'), policy)
            inspect.assert_called_once_with(Path('/test/fixture.efi'), policy)

    def test_initrd_policy_digest_rejects_overlapping_virtual_sections(self):
        data = bytearray(4096)
        data[:2] = b'MZ'
        struct.pack_into('<I', data, 60, 128)
        data[128:132] = b'PE\0\0'
        struct.pack_into('<HH', data, 132, 0x8664, 4)
        struct.pack_into('<H', data, 148, 240)
        struct.pack_into('<H', data, 152, 0x20b)
        struct.pack_into('<I', data, 152+32, 4096)
        struct.pack_into('<I', data, 152+56, 0x5000)
        table = 128+24+240
        for index, name in enumerate((b'.linux', b'.initrd', b'.pcrpkey', b'.pcrsig')):
            offset = table+40*index
            data[offset:offset+8] = name.ljust(8, b'\0')
            struct.pack_into('<IIII', data, offset+8, 4, (index+1)*4096, 512, 1024+index*512)
        result = {'sha256': [{'phase': 'enter-initrd', 'pcr': 11, 'hash': '00'*32}]}
        with tempfile.TemporaryDirectory() as directory:
            image = Path(directory)/'fixture.efi'
            image.write_bytes(data)
            with patch.object(measured_boot.subprocess, 'run', return_value=SimpleNamespace(
                    returncode=0, stdout=json.dumps(result).encode())):
                observed = measured_boot.initrd_policy_digest(image)
            expected = hashlib.sha256(bytes(32)+bytes.fromhex('0000017f00000001000b03000800')+
                                      hashlib.sha256(bytes(32)).digest()).hexdigest()
            self.assertEqual(observed, expected)
            struct.pack_into('<I', data, table+40+12, 4096)
            image.write_bytes(data)
            with patch.object(measured_boot.subprocess, 'run') as run, \
                    self.assertRaisesRegex(release.ReleaseError, 'overlapping'):
                measured_boot.initrd_policy_digest(image)
            run.assert_not_called()


if __name__ == '__main__':
    unittest.main()
