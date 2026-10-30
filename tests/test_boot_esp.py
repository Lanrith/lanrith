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
    def observe(self, esp, *, parent='/dev/vda', kind='vfat', mounted=True, multiple=False, nested=False,
                options='ro,nodev,nosuid,noexec',
                parttype='c12a7328-f81f-11d2-ba4b-00a0c93ec93b', duplicate_partition=False):
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
                self.assertIn('--uniq', arguments)
                self.assertIn(str(esp/'EFI'), arguments)
                rows = [{'source': '/dev/vda1', 'fstype': kind, 'target': str(esp/'EFI' if nested else esp),
                         'options': options}]
                return json.dumps({'filesystems': rows*2 if multiple else rows})
            raise AssertionError('Unexpected diagnostic command.')

        with patch.object(Path, 'stat', autospec=True, side_effect=root_owned), \
                patch.object(Path, 'is_mount', return_value=mounted), \
                patch.object(update, 'command', side_effect=command), \
                patch.object(update, 'geometry', return_value=[{'device': '/dev/vda1', 'disk': parent,
                    'type': parttype}] * (2 if duplicate_partition else 1)):
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
                           {'multiple': True}, {'nested': True}, {'options': 'rw,nodev,nosuid,noexec'},
                           {'options': 'ro,nodev,nosuid'}, {'parttype': 'other'},
                           {'duplicate_partition': True}):
                with self.subTest(change=change), self.assertRaises(ReleaseError):
                    self.observe(esp, **change)

    def test_writable_window_is_bounded_and_always_restores_read_only_mount(self):
        with tempfile.TemporaryDirectory() as temporary:
            esp = Path(temporary)
            commands = []
            fail_close = False
            def command(arguments, **_):
                commands.append(arguments)
                if fail_close and arguments[2].startswith('remount,ro'):
                    raise ReleaseError('synthetic close failure')
                return ''
            with patch.object(Path, 'is_mount', return_value=True), patch.object(update, 'command', side_effect=command), \
                    patch.object(update.os, 'fsync') as fsync:
                with self.assertRaisesRegex(RuntimeError, 'body failure'):
                    with update.writable_esp({}, esp=esp):
                        raise RuntimeError('body failure')
                self.assertEqual(commands[0][0:3], ['mount', '--options', 'remount,rw,nodev,nosuid,noexec'])
                self.assertEqual(commands[1][0:3], ['mount', '--options', 'remount,ro,nodev,nosuid,noexec'])
                fsync.assert_not_called()
            commands.clear()
            fail_close = True
            with patch.object(Path, 'is_mount', return_value=True), patch.object(update, 'command', side_effect=command), \
                    patch.object(update.os, 'fsync'):
                with self.assertRaisesRegex(ReleaseError, 'synthetic close failure'):
                    with update.writable_esp({}, esp=esp):
                        pass
            commands.clear()
            fail_close = False
            with patch.object(Path, 'is_mount', return_value=True), patch.object(update, 'command', side_effect=command), \
                    patch.object(update.os, 'fsync') as fsync:
                with update.writable_esp({}, esp=esp):
                    pass
                self.assertEqual(len(commands), 2)
                fsync.assert_called_once()
