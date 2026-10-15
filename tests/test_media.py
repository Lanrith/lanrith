"""Media read-back preserves partition identity after GPT backup relocation."""

import copy
import unittest

from lanrith import media
from lanrith.release import ReleaseError


class MediaTests(unittest.TestCase):
    def test_partition_mutation_overlap_and_extra_partition_rejected(self):
        original = {'label': 'gpt', 'id': 'synthetic-disk', 'sectorsize': 512,
                    'partitions': [{'start': 2048, 'size': 4096, 'type': 'synthetic-root', 'uuid': 'synthetic-root-id'}]}
        written = copy.deepcopy(original)
        written['lastlba'] = 100000
        written['partitions'].append({'start': 8192, 'size': 4096, 'name': 'lanrith-factory-media',
            'type': '0fc63daf-8483-4772-8e79-3d69d8477de4', 'uuid': 'synthetic-media-id'})
        self.assertEqual(media.partitions(original, written)[0], original['partitions'])
        for change in ('uuid', 'start', 'size', 'type'):
            value = copy.deepcopy(written)
            value['partitions'][0][change] = 1 if change in ('start', 'size') else 'changed'
            with self.subTest(change=change), self.assertRaises(ReleaseError):
                media.partitions(original, value)
        value = copy.deepcopy(written)
        value['partitions'][-1]['start'] = 4096
        with self.assertRaises(ReleaseError):
            media.partitions(original, value)
        with self.assertRaises(ReleaseError):
            media.partitions(original, {**written, 'partitions': written['partitions']*2})
