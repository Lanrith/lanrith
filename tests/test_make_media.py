"""Exercise the writer's partition definition with real repart on regular files."""

import importlib.util
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch


SCRIPT = Path(__file__).resolve().parents[1]/'scripts/make-media.py'
spec = importlib.util.spec_from_file_location('make_media', SCRIPT)
writer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(writer)


class MediaWriterTests(unittest.TestCase):
    @unittest.skipUnless(shutil.which('systemd-repart') and shutil.which('mkfs.ext4'),
                         'native repart and ext4 tools are required')
    def test_native_payload_definition_accepts_aligned_and_unaligned_artifacts(self):
        for size in (4096, 17):
            with self.subTest(artifact_bytes=size), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                factory = root/'factory'
                factory.mkdir()
                (factory/'factory.raw').write_bytes(b'x'*size)
                target = Path('/dev/disk/by-id/usb-synthetic-media')
                manifest = {'artifacts': [{'role': 'disk', 'name': 'factory.raw', 'size': size}]}
                executed = []

                def run(*args):
                    executed.append(args)
                    if args[0] == 'lsblk':
                        return subprocess.CompletedProcess(args, 0, json.dumps({'blockdevices': [{
                            'name': str(target), 'type': 'disk', 'tran': 'usb', 'ro': False,
                            'log-sec': 512, 'size': 512*1024**2, 'mountpoints': []}]}), '')
                    if args[0] == 'findmnt':
                        return subprocess.CompletedProcess(args, 0, '{"filesystems": []}', '')
                    if args[0] == 'systemd-repart':
                        definitions = next(arg for arg in args if arg.startswith('--definitions='))
                        # Only this regular disposable file reaches native repart.
                        # All block-device writes, mounts and discovery are mocked.
                        actual = subprocess.run(['systemd-repart', definitions, '--empty=create',
                            '--dry-run=yes', '--offline=yes', '--size=512M', str(root/'disposable.raw')],
                            check=False, capture_output=True, text=True, timeout=60)
                        self.assertEqual(actual.returncode, 0, actual.stderr)
                    return subprocess.CompletedProcess(args, 0, '', '')

                with patch.object(sys, 'argv', [str(SCRIPT), str(factory), '--certificate',
                        str(root/'controller.crt'), '--target', str(target)]), \
                        patch.object(writer.os, 'geteuid', return_value=0), \
                        patch.object(writer.release, 'verify', return_value=manifest), \
                        patch.object(writer, 'run', side_effect=run), \
                        patch('builtins.input', return_value='ERASE-AND-WRITE '+str(target)), \
                        patch('builtins.print'), \
                        patch.object(writer.media, 'verify') as verify:
                    writer.main()
                    verify.assert_called_once_with(str(target), factory, root/'controller.crt', manifest)
                self.assertEqual(sum(args[0] == 'systemd-repart' for args in executed), 1)
