"""EFI discovery must follow the running root's disk, not a fixed mount path."""

import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from lanrith import update
from lanrith.release import ReleaseError


class BootESPTests(unittest.TestCase):
    def observe(self, esp, *, parent='/dev/vda', kind='vfat', mounted=True, multiple=False, nested=False):
        actual_stat = Path.stat

        def root_owned(path, **options):
            info = list(actual_stat(path, **options))
            info[4] = 0
            return os.stat_result(info)

        def command(arguments, **_):
            if arguments[0] == 'bootctl':
                return str(esp)+'\n'
            if arguments[0] == 'findmnt':
                self.assertIn('--target', arguments)
                self.assertIn(str(esp/'EFI'), arguments)
                rows = [{'source': '/dev/vda1', 'fstype': kind, 'target': str(esp/'EFI' if nested else esp)}]
                return json.dumps({'filesystems': rows*2 if multiple else rows})
            if arguments[0] == 'lsblk':
                return json.dumps({'blockdevices': [{'name': '/dev/vda1', 'type': 'part',
                    'pkname': parent, 'parttype': 'C12A7328-F81F-11D2-BA4B-00A0C93EC93B'}]})
            raise AssertionError('Unexpected diagnostic command.')

        with patch.object(Path, 'stat', autospec=True, side_effect=root_owned), \
                patch.object(Path, 'is_mount', return_value=mounted), \
                patch.object(update, 'command', side_effect=command):
            return update.boot_esp({'esp': 'auto'}, disk='/dev/vda')

    def test_automatic_esp_detection_supports_both_standard_mount_names(self):
        with tempfile.TemporaryDirectory() as temporary:
            for name in ('boot', 'efi'):
                esp = Path(temporary)/name
                (esp/'EFI').mkdir(parents=True)
                self.assertEqual(self.observe(esp), esp)

    def test_foreign_unmounted_nonfat_and_ambiguous_filesystems_are_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            esp = Path(temporary)/'boot'
            (esp/'EFI').mkdir(parents=True)
            for change in ({'parent': '/dev/vdb'}, {'kind': 'ext4'}, {'mounted': False},
                           {'multiple': True}, {'nested': True}):
                with self.subTest(change=change), self.assertRaises(ReleaseError):
                    self.observe(esp, **change)
