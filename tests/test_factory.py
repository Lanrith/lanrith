"""Destructive target eligibility fails closed for unsafe disk conditions."""

import copy
import unittest
from lanrith.factory import eligible


class FactorySelectionTests(unittest.TestCase):
    def test_boot_disk_readonly_mount_holders_and_sector_constraints(self):
        disk = {'name': '/dev/synthetic-disk', 'type': 'disk', 'ro': False,
                'log-sec': 512, 'size': 128*1024**3, 'mountpoints': [None],
                'children': [{'name': '/dev/synthetic-part', 'type': 'part', 'mountpoints': [None]}]}
        self.assertTrue(eligible(disk, '/dev/boot-disk', 80*1024**3))
        self.assertFalse(eligible(disk, '/dev/synthetic-disk', 80*1024**3))
        for change in ({'ro': True}, {'ro': 0}, {'log-sec': 4096}, {'size': 8*1024**3}, {'type': 'loop'},
                       {'mountpoints': ['/mnt/in-use']},
                       {'children': [{'name': '/dev/synthetic-part', 'type': 'crypt', 'mountpoints': [None]}]},
                       {'children': [{'name': '/dev/synthetic-part', 'type': 'part', 'mountpoints': ['/var']}]}):
            value = copy.deepcopy(disk)
            value.update(change)
            with self.subTest(change=change):
                self.assertFalse(eligible(value, '/dev/boot-disk', 80*1024**3))
