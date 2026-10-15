"""Protect active slots while allowing image/version naming to change."""

import copy
from pathlib import Path
import unittest

from lanrith import update
from lanrith.release import ReleaseError


class UpdatePlanTests(unittest.TestCase):
    def setUp(self):
        self.installed = {'deployment_sequence': 8, 'layout': 'ab-verity-v1',
                          'active_labels': {role: 'current-' + role for role in update.PARTITION_ROLES}}
        self.manifest = {'purpose': 'update', 'architecture': 'x86-64', 'image_id': 'lanrith',
                         'deployment_sequence': 9, 'artifacts': [
                             {'role': 'uki', 'name': 'lanrith_9.efi', 'size': 1024}]}
        self.partitions = []
        for index, role in enumerate(update.PARTITION_ROLES):
            uuid = f'00000000-0000-0000-0000-{index:012d}'
            self.manifest['artifacts'].append({'role': role, 'name': f'lanrith_9_{uuid}.{role}.raw', 'size': 2048})
            for active in (True, False):
                self.partitions.append({'disk': '/dev/vda', 'number': index * 2 + (1 if active else 2),
                                        'type': update.GUIDS[role], 'label': 'current-' + role if active else 'previous-' + role,
                                        'size': 4096, 'mounted': False})

    def plan(self):
        return update.plan(self.manifest, self.installed, self.partitions,
                           disk='/dev/vda', active_partitions={3, 5}, esp_available=64 * 1024 * 1024)

    def test_foreign_previous_labels_do_not_force_old_public_image_names(self):
        value = self.plan()
        self.assertEqual({item['number'] for item in value['partitions'].values()}, {2, 4, 6})
        self.assertEqual(value['uki'], 'lanrith_9.efi')
        transfers = update.transfers(value, Path('/var/lib/lanrith/update-inbox/9'), Path('/efi'))
        self.assertEqual(sorted(transfers)[-1], '59-uki.transfer')
        self.assertIn('TriesLeft=3', transfers['59-uki.transfer'])
        self.assertNotIn('current-', ''.join(transfers.values()))

    def test_ambiguous_mounted_small_or_foreign_disk_targets_are_rejected(self):
        cases = (
            lambda: self.partitions.pop(),
            lambda: self.partitions[1].update(mounted=True),
            lambda: self.partitions[1].update(size=1),
            lambda: self.partitions[1].update(disk='/dev/vdb'),
            lambda: self.partitions[1].update(label='current-verity-sig'),
            lambda: self.installed['active_labels'].update(root='previous-root'),
            lambda: self.manifest.update(deployment_sequence=8),
            lambda: self.manifest['artifacts'][0].update(name='other.efi'),
        )
        for mutate in cases:
            partitions, manifest, installed = (copy.deepcopy(self.partitions), copy.deepcopy(self.manifest),
                                               copy.deepcopy(self.installed))
            mutate()
            with self.subTest(mutation=mutate), self.assertRaises(ReleaseError):
                self.plan()
            self.partitions, self.manifest, self.installed = partitions, manifest, installed


if __name__ == '__main__':
    unittest.main()
