"""Offline recovery inputs are bound, read-only and never authorize boot."""

from contextlib import nullcontext
import copy
import json
from pathlib import Path
import stat
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from lanrith import recovery_inputs as inputs, release, repair, update


class OfflineInputsTests(unittest.TestCase):
    uuid = '12345678-1234-1234-1234-123456789abc'

    def row(self):
        return {'disk': '/dev/synthetic', 'device': '/dev/synthetic1', 'number': 1,
                'uuid': self.uuid, 'type': inputs.LINUX_GUID, 'label': 'lanrith-recovery-input',
                'size': 512, 'mounted': False}

    def test_disk_binding_requires_a_whole_canonical_block_device(self):
        with patch.object(Path, 'resolve', return_value=Path('/dev/synthetic')), \
                patch.object(Path, 'stat', return_value=SimpleNamespace(st_mode=stat.S_IFBLK)):
            self.assertEqual(inputs.canonical_disk('/dev/disk/by-id/synthetic-disk'), '/dev/synthetic')
            for path in ('/dev/synthetic', '/dev/disk/by-id/..', '/dev/disk/by-id/synthetic-part1'):
                with self.subTest(path=path), self.assertRaises(release.ReleaseError):
                    inputs.canonical_disk(path)
        with patch.object(Path, 'resolve', return_value=Path('/dev/synthetic')), \
                patch.object(Path, 'stat', return_value=SimpleNamespace(st_mode=stat.S_IFREG)), \
                self.assertRaises(release.ReleaseError):
            inputs.canonical_disk('/dev/disk/by-id/synthetic-disk')

    def test_partition_rejects_ambiguous_busy_or_substituted_devices(self):
        row = self.row()
        with patch.object(Path, 'stat', return_value=SimpleNamespace(st_mode=stat.S_IFBLK)):
            self.assertEqual(inputs.partition([row], '/dev/synthetic', self.uuid, inputs.LINUX_GUID,
                                              label='lanrith-recovery-input'), '/dev/synthetic1')
            cases = ([row, copy.deepcopy(row)], [{**row, 'mounted': True}],
                     [{**row, 'label': 'other'}], [{**row, 'disk': '/dev/other'}],
                     [{**row, 'device': '/tmp/not-a-device'}])
            for index, rows in enumerate(cases):
                with self.subTest(index=index), self.assertRaises(release.ReleaseError):
                    inputs.partition(rows, '/dev/synthetic', self.uuid, inputs.LINUX_GUID,
                                     label='lanrith-recovery-input')

    def test_mount_observation_requires_no_journal_replay_and_restricted_options(self):
        point, device = Path('/run/synthetic-input'), '/dev/synthetic1'
        row = {'target': str(point), 'source': device, 'fstype': 'ext4',
               'options': 'ro,nodev,nosuid,noexec,norecovery'}
        with patch.object(update, 'command') as command:
            command.return_value = json.dumps({'filesystems': [row]})
            inputs.verify_mount(point, device, 'ext4')
            command.return_value = json.dumps({'filesystems': [{**row, 'options': 'ro,nodev,nosuid,noexec,noload'}]})
            inputs.verify_mount(point, device, 'ext4')
            for change in ({'options': 'ro,nodev,nosuid,noexec'},
                           {'options': 'rw,nodev,nosuid,noexec,norecovery'},
                           {'source': '/dev/other'}, {'fstype': 'vfat'}, {'target': '/run/other'}):
                command.return_value = json.dumps({'filesystems': [{**row, **change}]})
                with self.subTest(change=change), self.assertRaises(release.ReleaseError):
                    inputs.verify_mount(point, device, 'ext4')

    def test_failed_unmount_leaves_mountpoint_contents_untouched(self):
        with tempfile.TemporaryDirectory(prefix='lanrith-offline-test-') as temporary:
            point = Path(temporary)/'mount'; point.mkdir()
            sentinel = point/'sentinel'; sentinel.write_text('must remain')
            with patch.object(inputs.tempfile, 'mkdtemp', return_value=str(point)), \
                    patch.object(Path, 'is_mount', side_effect=[True, True]), \
                    patch.object(inputs, 'verify_mount'), \
                    patch.object(update, 'command', side_effect=[None, release.ReleaseError('unmount failed')]), \
                    self.assertRaisesRegex(release.ReleaseError, 'unmount failed'):
                with inputs.mounted('/dev/synthetic1', 'ext4'):
                    pass
            self.assertEqual(sentinel.read_text(), 'must remain')

    def test_topology_recheck_allows_only_our_expected_mount(self):
        row = self.row()
        layout = {'sector': 512, 'extents': [(1, 2, row['device'])]}
        with patch.object(inputs, 'disk_snapshot', return_value=(layout, [{**row, 'mounted': True}])):
            inputs.stable_snapshot('/dev/synthetic', (layout, [row]), row['device'])
        for changed in ({**row, 'mounted': False}, {**row, 'mounted': True, 'uuid': 'different'}):
            with patch.object(inputs, 'disk_snapshot', return_value=(layout, [changed])), \
                    self.assertRaises(release.ReleaseError):
                inputs.stable_snapshot('/dev/synthetic', (layout, [row]), row['device'])

    def test_inspection_rejects_same_disk_and_never_authorizes_boot(self):
        value = {'image_id': 'lanrith', 'disk_by_id': '/dev/disk/by-id/target',
                 'offline_inputs': {'release_disk_by_id': '/dev/disk/by-id/source',
                                    'release_partition_uuid': self.uuid,
                                    'target_esp_uuid': 'abcdefab-1234-1234-1234-123456789abc'}}
        def resolve(path):
            return '/dev/source' if path.endswith('/source') else '/dev/target'
        snapshots = [({'sector': 512, 'extents': []}, []), ({'sector': 512, 'extents': []}, [])]
        with patch.object(inputs.os, 'geteuid', return_value=0), \
                patch.object(Path, 'is_file', return_value=True), \
                patch.object(inputs, 'canonical_disk', side_effect=resolve), \
                patch.object(inputs, 'disk_snapshot', side_effect=snapshots), \
                patch.object(inputs, 'partition', side_effect=['/dev/source1', '/dev/target1']), \
                patch.object(inputs, 'mounted', side_effect=[nullcontext(Path('/run/source')),
                                                             nullcontext(Path('/run/target'))]), \
                patch.object(inputs, 'stable_snapshot') as stable, \
                patch.object(repair, 'inspect_slot', return_value={'authorized_to_boot': False}) as inspect:
            result = inputs.inspect(value, target_disk='/dev/target', recovery_disk='/dev/recovery',
                                    certificate=Path('/trusted/cert'))
            self.assertFalse(result['authorized_to_boot'])
            inspect.assert_called_once_with(Path('/run/source/release'), Path('/trusted/cert'),
                                            image_id='lanrith', disk='/dev/target', esp=Path('/run/target'))
            self.assertEqual(stable.call_count, 2)
        with patch.object(inputs.os, 'geteuid', return_value=0), \
                patch.object(Path, 'is_file', return_value=True), \
                patch.object(inputs, 'canonical_disk', return_value='/dev/target'), \
                patch.object(repair, 'inspect_slot') as inspect, self.assertRaises(release.ReleaseError):
            inputs.inspect(value, target_disk='/dev/target', recovery_disk='/dev/recovery',
                           certificate=Path('/trusted/cert'))
        inspect.assert_not_called()
        with patch.object(inputs.os, 'geteuid', return_value=0), \
                patch.object(Path, 'is_file', return_value=True), \
                patch.object(inputs, 'canonical_disk', side_effect=resolve), \
                patch.object(inputs, 'disk_snapshot', side_effect=[snapshots[0],
                    ({'sector': 512, 'extents': []}, [{'mounted': True}])]), \
                patch.object(repair, 'inspect_slot') as inspect, \
                self.assertRaisesRegex(release.ReleaseError, 'mounted or held'):
            inputs.inspect(value, target_disk='/dev/target', recovery_disk='/dev/recovery',
                           certificate=Path('/trusted/cert'))
        inspect.assert_not_called()


if __name__ == '__main__':
    unittest.main()
