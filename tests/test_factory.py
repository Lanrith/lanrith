"""Destructive target eligibility fails closed for unsafe disk conditions."""

import copy
import json
import unittest
from unittest.mock import patch
from lanrith import factory
from lanrith.factory import eligible
from lanrith.release import ReleaseError
from lanrith.update import GUIDS


class FactorySelectionTests(unittest.TestCase):
    def test_unbound_or_different_tpm_policy_is_rejected_even_with_a_valid_token(self):
        valid = {'type': 'systemd-tpm2', 'tpm2-pcrs': [7]}
        self.assertEqual(factory.enrollment_tokens({'tokens': {'0': valid}}, tpm_required=True), ['systemd-tpm2'])
        self.assertEqual(factory.enrollment_tokens({'tokens': {}}, tpm_required=False), [])
        for tokens in ({}, [], {'0': None}, {'0': {'type': 'systemd-recovery'}},
                       *({'0': valid, '1': {**valid, 'tpm2-pcrs': pcrs}}
                         for pcrs in (None, [], [0], [7, 11], ['7']))):
            with self.subTest(tokens=tokens), self.assertRaises(ReleaseError):
                factory.enrollment_tokens({'tokens': tokens}, tpm_required=True)

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

    def fixture(self):
        installed = {'storage': {'esp_mib': 1024, 'root_mib': 4096, 'state_mib': 65536},
                     'active_labels': {role: 'l_9_'+role.replace('-', '_') for role in GUIDS}}
        rows = [{'type': 'c12a7328-f81f-11d2-ba4b-00a0c93ec93b', 'number': 1}]+[
            {'type': guid, 'number': index, 'label': installed['active_labels'][role]}
            for index, (role, guid) in enumerate(GUIDS.items(), 2)]
        return installed, rows

    def test_first_boot_refuses_foreign_layout_or_unverified_active_slot(self):
        installed, rows = self.fixture()
        for observed, active in ((rows+[{'type': 'foreign'}], {2, 3}), (rows, {4, 5})):
            with self.subTest(active=active), patch.object(factory, 'geometry', return_value=observed), \
                    patch.object(factory, 'command') as command, patch.object(factory, 'repartition') as repartition:
                with self.assertRaises(ReleaseError):
                    factory.prepare_state(installed, '/dev/synthetic', active)
                command.assert_not_called()
                repartition.assert_not_called()

    def test_state_creation_uses_only_the_verified_disk_and_preserves_existing_state(self):
        installed, rows = self.fixture()
        state = {'type': factory.VAR_GUID, 'number': 8, 'label': 'var', 'size': 64*1024**3}
        capacity = json.dumps({'blockdevices': [{'ro': False, 'log-sec': 512, 'size': 128*1024**3}]})
        listing = json.dumps({'blockdevices': [{'children': [{'type': 'part', 'partn': 8, 'name': '/dev/synthetic8'}]}]})
        with patch.object(factory, 'geometry', side_effect=[rows, rows+[state]]), \
                patch.object(factory, 'command', side_effect=[capacity, listing, '']) as command, \
                patch.object(factory, 'repartition') as repartition:
            factory.prepare_state(installed, '/dev/synthetic', {2, 3})
            repartition.assert_called_once_with(installed, '/dev/synthetic', installed_root=True)
            self.assertEqual(command.call_args.args[0], ['cryptsetup', 'isLuks', '/dev/synthetic8'])
        with patch.object(factory, 'geometry', return_value=rows+[state]), \
                patch.object(factory, 'command', side_effect=[listing, '']), \
                patch.object(factory, 'repartition') as repartition:
            factory.prepare_state(installed, '/dev/synthetic', {2, 3})
            repartition.assert_not_called()
