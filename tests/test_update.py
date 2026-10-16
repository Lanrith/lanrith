"""Protect active slots while allowing image/version naming to change."""

import copy
from pathlib import Path
import unittest
import tempfile

from lanrith import update
from lanrith.release import ReleaseError


class UpdatePlanTests(unittest.TestCase):
    def test_running_slot_must_be_the_explicitly_accepted_default(self):
        with tempfile.TemporaryDirectory() as temporary:
            variable = Path(temporary)/'LoaderEntryDefault'
            accepted = Path('/efi/EFI/Linux/lanrith_41.efi')
            variable.write_bytes(bytes(4)+(accepted.name+'\0').encode('utf-16-le'))
            update.require_default(accepted, variable)
            for value in ('lanrith_40.efi', 'lanrith_41.efi\0extra', '', 'lanrith_41.efi\n'):
                variable.write_bytes(bytes(4)+(value+'\0').encode('utf-16-le'))
                with self.subTest(value=value), self.assertRaises(ReleaseError):
                    update.require_default(accepted, variable)
    def setUp(self):
        self.installed = {'deployment_sequence': 8, 'layout': 'ab-verity-v1',
                          'active_labels': {role: 'current-' + role for role in update.PARTITION_ROLES}}
        self.manifest = {'purpose': 'update', 'architecture': 'x86-64', 'image_id': 'lanrith',
                         'deployment_sequence': 9, 'artifacts': [
                             {'role': 'uki', 'name': 'lanrith_9.efi', 'size': 1024}]}
        self.partitions = []
        for index, role in enumerate(update.PARTITION_ROLES):
            uuid = f'20000000-0000-0000-0000-{index:012d}'
            self.manifest['artifacts'].append({'role': role, 'name': f'lanrith_9_{uuid}.{role}.raw', 'size': 2048})
            for active in (True, False):
                self.partitions.append({'disk': '/dev/vda', 'number': index * 2 + (1 if active else 2),
                                        'uuid': f'10000000-0000-0000-0000-{index*2+(1 if active else 2):012d}',
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

    def test_upload_capacity_comes_from_real_slots_and_owner_policy(self):
        root = next(artifact for artifact in self.manifest['artifacts'] if artifact['role'] == 'root')
        root['size'] = 3*1024**3
        for part in self.partitions:
            if part['type'] == update.GUIDS['root']:
                part['size'] = 4*1024**3
        arguments = {'disk': '/dev/vda', 'active_partitions': {3, 5}, 'esp_available': 64*1024**2}
        limits = update.upload_limits(self.manifest, self.installed, self.partitions, **arguments)
        self.assertEqual(limits['root'], 4*1024**3)
        self.installed['payload_limits'] = {**limits, 'root': 2*1024**3}
        with self.assertRaises(ReleaseError):
            update.upload_limits(self.manifest, self.installed, self.partitions, **arguments)

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
            lambda: self.manifest['artifacts'][1].update(
                name=f'lanrith_9_{self.partitions[0]["uuid"]}.verity-sig.raw'),
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
