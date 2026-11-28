"""Destructive target eligibility fails closed for unsafe disk conditions."""

import copy
from contextlib import contextmanager
from pathlib import Path
import json
import unittest
from unittest.mock import MagicMock, Mock, patch
from lanrith import factory
from lanrith.factory import eligible
from lanrith.release import ReleaseError
from lanrith.update import GUIDS


@contextmanager
def target_fixture(answers=None):
    identity = '/dev/disk/by-id/virtio-synthetic-disk'
    disk = {'name': '/dev/synthetic-disk', 'type': 'disk', 'ro': False,
            'log-sec': 512, 'size': 128*1024**3, 'mountpoints': [None], 'tran': None}
    link = MagicMock(spec=Path)
    link.__str__.return_value = identity
    link.name = 'virtio-synthetic-disk'
    link.is_symlink.return_value = True
    link.resolve.return_value = Path(disk['name'])
    directory = Mock()
    directory.glob.return_value = [link]
    def path(value):
        if value == identity:
            return link
        return directory if value == '/dev/disk/by-id' else Path(value)
    installed = {'storage': {'esp_mib': 1024, 'root_mib': 4096, 'state_mib': 65536}}
    console = Mock()
    console.input.side_effect = answers
    with patch.object(factory, 'Path', side_effect=path), \
            patch.object(factory, 'command', return_value=json.dumps({'blockdevices': [disk]})) as command:
        yield installed, identity, console, command, link, disk


class FactorySelectionTests(unittest.TestCase):
    def test_confirmation_retries_require_the_exact_phrase_and_selected_identity(self):
        for wrong in ('', 'ERASE-AND-INSTALL', 'erase-and-install /dev/disk/by-id/virtio-synthetic-disk',
                      'ERASE-AND-INSTALL /dev/disk/by-id/a-different-disk'):
            with self.subTest(wrong=wrong), target_fixture() as (installed, identity, console, command, _, _):
                console.input.side_effect = [identity, wrong, 'ERASE-AND-INSTALL '+identity]
                self.assertEqual(factory.target(installed, '/dev/boot-disk', console), '/dev/synthetic-disk')
                self.assertEqual(console.input.call_count, 3)
                self.assertEqual(command.call_count, 2)
                self.assertTrue(all(call.args[0][0] == 'lsblk' for call in command.call_args_list))
                self.assertTrue(any('Confirmation did not match' in call.args[0]
                                    for call in console.write.call_args_list))

    def test_confirmation_attempts_are_bounded_and_cancel_never_returns_a_disk(self):
        for answers in (['', 'wrong', 'ERASE-AND-INSTALL'], ['CANCEL']):
            with self.subTest(answers=answers), target_fixture() as (installed, identity, console, command, _, _):
                console.input.side_effect = [identity, *answers]
                with self.assertRaises(ReleaseError):
                    factory.target(installed, '/dev/boot-disk', console)
                self.assertEqual(command.call_count, 1)
                self.assertEqual(console.input.call_count, len(answers)+1)

    def test_correct_confirmation_still_rechecks_identity_and_disk_eligibility(self):
        for change in ('identity', 'mounted'):
            with self.subTest(change=change), target_fixture() as (installed, identity, console, command, link, disk):
                console.input.side_effect = [identity, 'wrong', 'ERASE-AND-INSTALL '+identity]
                if change == 'identity':
                    link.resolve.side_effect = [Path(disk['name']), Path('/dev/changed-disk')]
                else:
                    command.side_effect = [json.dumps({'blockdevices': [disk]}),
                        json.dumps({'blockdevices': [{**disk, 'mountpoints': ['/in-use']}]})]
                message = 'identity changed' if change == 'identity' else 'became ineligible'
                with self.assertRaisesRegex(ReleaseError, message):
                    factory.target(installed, '/dev/boot-disk', console)
                self.assertEqual(console.input.call_count, 3)
                self.assertTrue(all(call.args[0][0] == 'lsblk' for call in command.call_args_list))

    def test_candidates_and_recheck_obey_installed_pin_and_transport(self):
        for transport, pin, changed, admitted in (
                ('sata', None, None, True), ('usb', None, None, False),
                ('usb', 'match', None, True), ('sata', 'wrong', None, False),
                ('sata', None, 'usb', False)):
            with self.subTest(transport=transport, pin=pin, changed=changed), target_fixture() as fixture:
                installed, identity, console, command, _, disk = fixture
                if pin:
                    installed['storage']['target'] = identity if pin == 'match' else '/dev/disk/by-id/other'
                initial = {**disk, 'tran': transport}
                recheck = {**initial, 'tran': changed or transport}
                command.side_effect = [json.dumps({'blockdevices': [row]}) for row in (initial, recheck)]
                console.input.side_effect = ([] if pin else [identity]) + ['ERASE-AND-INSTALL '+identity]
                if admitted:
                    self.assertEqual(factory.target(installed, '/dev/boot', console), disk['name'])
                    self.assertTrue(factory.profile_allows(installed, recheck))
                else:
                    with self.assertRaises(ReleaseError):
                        factory.target(installed, '/dev/boot', console)
                    if not changed:
                        console.input.assert_not_called()
                self.assertTrue(all('TRAN' in call.args[0][call.args[0].index('--output') + 1]
                                    for call in command.call_args_list))

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
        state = {'type': factory.VAR_GUID, 'number': 8, 'device': '/dev/synthetic8',
                 'label': 'var', 'size': 64*1024**3}
        capacity = json.dumps({'blockdevices': [{'ro': False, 'log-sec': 512, 'size': 128*1024**3}]})
        with patch.object(factory, 'geometry', side_effect=[rows, rows+[state]]), \
                patch.object(factory, 'command', side_effect=[capacity, '']) as command, \
                patch.object(factory, 'repartition') as repartition:
            factory.prepare_state(installed, '/dev/synthetic', {2, 3})
            repartition.assert_called_once_with(installed, '/dev/synthetic', installed_root=True)
            self.assertEqual(command.call_args.args[0], ['cryptsetup', 'isLuks', '/dev/synthetic8'])
        with patch.object(factory, 'geometry', return_value=rows+[state]), \
                patch.object(factory, 'command', return_value='') as command, \
                patch.object(factory, 'repartition') as repartition:
            factory.prepare_state(installed, '/dev/synthetic', {2, 3})
            repartition.assert_not_called()
            command.assert_called_once_with(['cryptsetup', 'isLuks', '/dev/synthetic8'])
