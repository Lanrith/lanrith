"""Migration never retires a legacy slot before recovery, fallback and strong unseal."""

import base64
import copy
import hashlib
import json
import os
from pathlib import Path
import struct
import tempfile
import unittest
from unittest.mock import patch

from lanrith import early_failure, early_unlock, factory, measured_boot, release, tpm_migration as migration, update


class MigrationTests(unittest.TestCase):
    def fixture(self, phase='enforce'):
        public = b'synthetic migration policy authority\n'
        legacy = {'type': 'systemd-tpm2', 'keyslots': ['0'], 'tpm2-pcrs': [7],
                  'tpm2-pcr-bank': 'sha256', 'tpm2-blob': 'synthetic sealed blob'}
        fallback = {'sequence': 11, 'uki_name': 'lanrith_11.efi', 'uki_sha256': 'b'*64,
                    'partitions': {role: {'label': 'l_11_'+role.replace('-', '_'),
                        'uuid': f'12345678-1234-1234-1234-{i:012d}', 'size': 4096, 'sha256': 'c'*64}
                        for i, role in enumerate(migration.GUIDS)}}
        contract = {'schema': 1, 'phase': phase, 'luks_uuid': '12345678-1234-1234-1234-123456789abc',
                    'legacy_tokens': {'0': {'keyslot': '0', 'sha256': hashlib.sha256(release.canonical(legacy)).hexdigest()}},
                    'fallback': fallback if phase in ('enroll', 'enforce') else None}
        installed = {'deployment_sequence': 12, 'tpm_policy': early_unlock.policy(public), 'tpm_transition': contract}
        luks = {'tokens': {'0': legacy, '1': {'type': 'systemd-recovery', 'keyslots': ['1']}},
                'keyslots': {'0': {}, '1': {}}}
        strong = {'type': 'systemd-tpm2', 'keyslots': ['2'], 'tpm2-pcrs': [7, 15],
                  'tpm2-pcr-bank': 'sha256', 'tpm2_pubkey_pcrs': [11],
                  'tpm2_pubkey': base64.b64encode(public).decode()}
        return installed, luks, strong, public

    def test_prepare_preserves_only_the_bound_legacy_policy_and_existing_recovery(self):
        installed, luks, _, _ = self.fixture('prepare')
        self.assertEqual(migration.classify(installed, luks), {'legacy': ['0'], 'strong': []})
        for mutate in (lambda x: x['tokens']['0'].update(**{'tpm2-blob': 'different blob'}),
                       lambda x: x['tokens']['0'].update(**{'tpm2-pcrs': []}),
                       lambda x: x['tokens'].pop('1'),
                       lambda x: x['keyslots'].update({'3': {}}),
                       lambda x: x['tokens'].update({'3': {**x['tokens']['0'], 'keyslots': ['3']}})):
            invalid = copy.deepcopy(luks)
            mutate(invalid)
            with self.subTest(mutate=mutate), self.assertRaises(release.ReleaseError):
                migration.classify(installed, invalid)
        for malformed in (None, [], 'not metadata'):
            with self.subTest(malformed=malformed), self.assertRaises(release.ReleaseError):
                migration.classify(installed, malformed)

    def test_fallback_mount_cleanup_never_recurses_after_unmount_failure(self):
        installed, _, _, _ = self.fixture('enroll')
        bound = installed['tpm_transition']['fallback']
        rows = [{'type': migration.GUIDS[role], 'label': item['label'], 'uuid': item['uuid'],
                 'number': index, 'mounted': False, 'size': item['size'], 'device': f'/dev/test{index}'}
                for index, (role, item) in enumerate(bound['partitions'].items(), 1)]
        rows.append({'type': 'c12a7328-f81f-11d2-ba4b-00a0c93ec93b', 'device': '/dev/test9',
                     'disk': '/dev/test', 'mounted': False})
        with tempfile.TemporaryDirectory(prefix='lanrith-mount-cleanup-') as temporary:
            parent = Path(temporary)
            for fail in (False, True):
                mount = parent/('failed' if fail else 'success')
                mount.mkdir()
                sentinel = mount/'sentinel'
                if fail:
                    sentinel.write_text('must remain')
                is_mount = [True, True] if fail else [True, True, False]
                commands = [None, release.ReleaseError('synthetic unmount failure')] if fail else [None, None]
                with self.subTest(unmount_fails=fail), \
                        patch.object(migration, 'FALLBACK_MEASUREMENT_RUNTIME_QUALIFIED', True), \
                        patch.object(migration, 'FALLBACK_STATE_COMPATIBILITY_RUNTIME_QUALIFIED', True), \
                        patch.object(migration, 'require_default'), \
                        patch.object(migration, 'geometry', return_value=rows), \
                        patch.object(migration, 'partition_digest', return_value='c'*64), \
                        patch.object(migration, 'file_record', return_value={'sha256': 'b'*64}), \
                        patch.object(migration, 'bound_uki_roothash', return_value='d'*64), \
                        patch.object(migration, 'snapshot', return_value={'tokens': {}}), \
                        patch.object(migration, 'inspect_fallback_state'), \
                        patch.object(migration, 'verify_fallback_esp'), \
                        patch.object(measured_boot, 'verify'), \
                        patch.object(migration.tempfile, 'mkdtemp', return_value=str(mount)), \
                        patch.object(Path, 'is_mount', side_effect=is_mount), \
                        patch.object(migration, 'command', side_effect=commands) as command:
                    if fail:
                        with self.assertRaisesRegex(release.ReleaseError, 'synthetic unmount failure'):
                            migration.fallback(installed, '/dev/test', set(), '/dev/test8')
                    else:
                        migration.fallback(installed, '/dev/test', set(), '/dev/test8')
                    self.assertEqual(command.call_args_list[0].args[0],
                        ['mount', '-t', 'vfat', '-o', 'ro,nodev,nosuid,noexec', '--', '/dev/test9', str(mount)])
                    self.assertEqual(command.call_args_list[1].args[0], ['umount', '--', str(mount)])
                if fail:
                    self.assertEqual(sentinel.read_text(), 'must remain')
                else:
                    self.assertFalse(mount.exists())

    def test_unqualified_runtime_measurement_blocks_fallback(self):
        installed, _, _, _ = self.fixture('enroll')
        with self.assertRaisesRegex(release.ReleaseError, 'not qualified'):
            migration.fallback(installed, '/dev/test', set())

    def legacy_binding_fixture(self):
        installed, luks, _, _ = self.fixture('prepare')
        bound = self.fixture('enroll')[0]['tpm_transition']['fallback']
        installed.update({'image_id': 'lanrith', 'uki_name': 'lanrith_12.efi',
                          'state_directory': '/var/lib/lanrith'})
        binding = {'disk_by_id': '/dev/disk/by-id/test',
                   'esp_uuid': 'abcdefab-1234-1234-1234-123456789abc', 'release': bound}
        rows = [{'disk': '/dev/test', 'type': migration.GUIDS[role], 'label': item['label'],
                 'uuid': item['uuid'], 'number': index, 'mounted': False}
                for index, (role, item) in enumerate(bound['partitions'].items(), 1)]
        return installed, luks, binding, rows

    def test_legacy_fallback_has_an_independent_closed_gate(self):
        installed, _, binding, _ = self.legacy_binding_fixture()
        with patch.object(early_failure, 'inspect_bound_fallback') as inspect:
            with self.assertRaisesRegex(release.ReleaseError, 'not qualified'):
                migration.legacy_fallback(installed, binding, '/dev/test', set(), '/dev/test8')
            inspect.assert_not_called()

    def test_legacy_fallback_observes_bound_image_and_current_token_without_authority(self):
        installed, luks, binding, rows = self.legacy_binding_fixture()
        observed = {'sequence': 11, 'authorized_to_boot': False}
        with patch.object(migration, 'LEGACY_FALLBACK_RUNTIME_QUALIFIED', True), \
                patch.object(Path, 'resolve', return_value=Path('/dev/test')), \
                patch.object(migration, 'require_default') as default, \
                patch.object(migration, 'geometry', return_value=rows), \
                patch.object(migration, 'command', return_value=installed['tpm_transition']['luks_uuid']), \
                patch.object(early_failure, 'inspect_bound_fallback', return_value=observed) as inspect, \
                patch.object(migration, 'snapshot', return_value=luks), \
                patch.object(early_unlock, 'token_test', return_value=True) as probe:
            result = migration.legacy_fallback(installed, binding, '/dev/test', set(), '/dev/test8')
            self.assertEqual(result['scope'], 'legacy-fallback-observation')
            self.assertFalse(result['authorized_to_boot'])
            self.assertEqual(inspect.call_count, 2)
            self.assertEqual(default.call_count, 2)
            probe.assert_called_once_with('/dev/test8', '0')

    def test_legacy_fallback_rejects_changed_or_unusable_state_and_busy_slots(self):
        installed, luks, binding, rows = self.legacy_binding_fixture()
        changed = copy.deepcopy(luks)
        changed['tokens']['0']['tpm2-blob'] = 'different'
        for case in ('token-rejected', 'snapshot-changed', 'final-snapshot-changed', 'state-uuid-changed',
                     'slot-busy', 'binding-changed'):
            current_rows, current_binding = copy.deepcopy(rows), copy.deepcopy(binding)
            snapshots, token = [luks, luks, luks], True
            uuids = [installed['tpm_transition']['luks_uuid']]*3
            if case == 'token-rejected': token = False
            elif case == 'snapshot-changed': snapshots = [luks, changed]
            elif case == 'final-snapshot-changed': snapshots = [luks, luks, changed]
            elif case == 'state-uuid-changed': uuids[1] = '22345678-1234-1234-1234-123456789abc'
            elif case == 'slot-busy': current_rows[0]['mounted'] = True
            else: current_binding['release']['sequence'] = 12
            with self.subTest(case=case), \
                    patch.object(migration, 'LEGACY_FALLBACK_RUNTIME_QUALIFIED', True), \
                    patch.object(Path, 'resolve', return_value=Path('/dev/test')), \
                    patch.object(migration, 'require_default'), \
                    patch.object(migration, 'geometry', return_value=current_rows), \
                    patch.object(migration, 'command', side_effect=uuids), \
                    patch.object(early_failure, 'inspect_bound_fallback',
                                 return_value={'sequence': 11, 'authorized_to_boot': False}), \
                    patch.object(migration, 'snapshot', side_effect=snapshots), \
                    patch.object(early_unlock, 'token_test', return_value=token):
                with self.assertRaises(release.ReleaseError):
                    migration.legacy_fallback(installed, current_binding, '/dev/test', set(), '/dev/test8')

    def test_missing_candidate_root_never_accepts_a_busy_fallback_partition(self):
        installed, _, _, _ = self.fixture('enroll')
        bound = installed['tpm_transition']['fallback']
        original = [{'type': migration.GUIDS[role], 'label': item['label'], 'uuid': item['uuid'],
                     'number': index, 'mounted': False, 'size': item['size'], 'device': f'/dev/test{index}'}
                    for index, (role, item) in enumerate(bound['partitions'].items(), 1)]
        for index in range(len(original)):
            rows = copy.deepcopy(original)
            rows[index]['mounted'] = True
            with self.subTest(partition=index), \
                    patch.object(migration, 'FALLBACK_MEASUREMENT_RUNTIME_QUALIFIED', True), \
                    patch.object(migration, 'FALLBACK_STATE_COMPATIBILITY_RUNTIME_QUALIFIED', True), \
                    patch.object(migration, 'require_default'), \
                    patch.object(migration, 'geometry', return_value=rows), \
                    patch.object(migration, 'partition_digest', return_value='c'*64), \
                    patch.object(migration, 'command') as command:
                with self.assertRaisesRegex(release.ReleaseError, 'missing or in use'):
                    migration.fallback(installed, '/dev/test', set(), '/dev/test8')
                command.assert_not_called()

    def test_fallback_state_compatibility_has_an_independent_closed_gate(self):
        installed, _, _, _ = self.fixture('enroll')
        with patch.object(migration, 'FALLBACK_MEASUREMENT_RUNTIME_QUALIFIED', True), \
                patch.object(migration, 'command') as command:
            with self.assertRaisesRegex(release.ReleaseError, 'state and token compatibility'):
                migration.fallback(installed, '/dev/test', set())
            command.assert_not_called()

    def test_compare_fallback_state_rejects_different_contracts_and_inventory(self):
        installed, luks, strong, _ = self.fixture('enroll')
        installed.update({'image_id': 'lanrith', 'state_directory': '/var/lib/lanrith'})
        fallback = copy.deepcopy(installed)
        fallback['deployment_sequence'] = installed['tpm_transition']['fallback']['sequence']
        fallback['tpm_transition']['phase'] = 'prepare'
        fallback['tpm_transition']['fallback'] = None
        observed = migration.compare_fallback_state(installed, fallback, luks)
        self.assertEqual(observed, {'scope': 'contract-comparison', 'authorized_to_enroll': False,
                                    'authorized_to_rollback': False})
        with_strong = copy.deepcopy(luks)
        with_strong['tokens']['2'] = strong
        with_strong['keyslots']['2'] = {}
        self.assertFalse(migration.compare_fallback_state(installed, fallback, with_strong)['authorized_to_rollback'])
        changes = [lambda f: f['tpm_transition']['legacy_tokens']['0'].update(sha256='f'*64),
                   lambda f: f['tpm_transition'].update(luks_uuid='00000000-0000-0000-0000-000000000000'),
                   lambda f: f['tpm_policy'].update(public_key_sha256='f'*64),
                   lambda f: f.update(image_id='other'), lambda f: f.update(state_directory='/var/other'),
                   lambda f: f.update(deployment_sequence=10),
                   lambda f: f['tpm_transition'].update(phase='enforce')]
        for change in changes:
            invalid = copy.deepcopy(fallback)
            change(invalid)
            with self.subTest(change=change), self.assertRaises(release.ReleaseError):
                migration.compare_fallback_state(installed, invalid, luks)
        changed_luks = copy.deepcopy(luks)
        changed_luks['tokens']['0']['tpm2-blob'] = 'other'
        with self.assertRaises(release.ReleaseError):
            migration.compare_fallback_state(installed, fallback, changed_luks)

    def test_bound_uki_root_hash_requires_exact_digest_and_unambiguous_command_line(self):
        def image(cmdline):
            data = bytearray(1024)
            data[:2] = b'MZ'
            struct.pack_into('<I', data, 60, 128)
            data[128:132] = b'PE\0\0'
            struct.pack_into('<HH', data, 132, 0x8664, 1)
            struct.pack_into('<H', data, 148, 240)
            table = 128+24+240
            data[table:table+8] = b'.cmdline'
            struct.pack_into('<IIII', data, table+8, len(cmdline), 4096, 512, 512)
            data[512:512+len(cmdline)] = cmdline
            return bytes(data)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/'test.efi'
            data = image(b'roothash='+b'a'*64+b' console=ttyS0\0')
            path.write_bytes(data)
            self.assertEqual(migration.bound_uki_roothash(path, hashlib.sha256(data).hexdigest()), 'a'*64)
            with self.assertRaisesRegex(release.ReleaseError, 'differs'):
                migration.bound_uki_roothash(path, 'b'*64)
            for cmdline in (b'console=ttyS0', b'roothash='+b'a'*64+b' roothash='+b'b'*64,
                            b'roothash='+b'a'*64+b'\0trailing', b'roothash='+b'A'*64):
                data = image(cmdline)
                path.write_bytes(data)
                with self.subTest(cmdline=cmdline), self.assertRaises(release.ReleaseError):
                    migration.bound_uki_roothash(path, hashlib.sha256(data).hexdigest())

    def test_fallback_contract_read_rejects_links_and_duplicate_fields(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root/'usr/share/lanrith'
            target.mkdir(parents=True)
            metadata = target/'installed.json'
            metadata.write_text('{"schema":1}')
            self.assertEqual(migration.read_fallback_contract(root), {'schema': 1})
            metadata.write_text('{"schema":1,"schema":2}')
            with self.assertRaises(release.ReleaseError):
                migration.read_fallback_contract(root)
            metadata.unlink()
            metadata.symlink_to('/etc/passwd')
            with self.assertRaises(OSError):
                migration.read_fallback_contract(root)
            metadata.unlink()
            os.rmdir(target)
            target.symlink_to(root, target_is_directory=True)
            with self.assertRaises(OSError):
                migration.read_fallback_contract(root)

    def test_verified_fallback_root_unmounts_and_closes_after_comparison_failure(self):
        installed, luks, _, _ = self.fixture('enroll')
        with tempfile.TemporaryDirectory() as directory:
            mount = Path(directory)/'lanrith-fallback-root-abc123'
            mount.mkdir()
            calls = []
            def command(args, **_):
                calls.append(args)
                return ''
            with patch.object(migration.tempfile, 'mkdtemp', return_value=str(mount)), \
                    patch.object(migration, 'command', side_effect=command), \
                    patch.object(migration, 'verify_fallback_root_mount'), \
                    patch.object(migration, 'read_fallback_contract', return_value={}), \
                    patch.object(migration, 'compare_fallback_state',
                                 side_effect=release.ReleaseError('incompatible state')), \
                    patch.object(Path, 'is_mount', side_effect=[True, True, False]):
                with self.assertRaisesRegex(release.ReleaseError, 'incompatible state'):
                    migration.inspect_fallback_state(installed, luks, '/dev/test3', '/dev/test2', 'a'*64)
            self.assertEqual([args[0:2] for args in calls],
                             [['veritysetup', 'open'], ['mount', '-t'], ['umount', '--'],
                              ['veritysetup', 'close']])
            self.assertFalse(mount.exists())

    def test_pcr_key_preflight_checks_actual_tpm_before_enrollment(self):
        key = Path('/run/synthetic-pcr-public.pem')
        with patch.object(migration, 'command', side_effect=['Public-Key: (2048 bit)\n', '']) as command:
            migration.preflight_pcr_key(key)
            self.assertEqual(command.call_args_list[1].args[0],
                             ['tpm2_testparms', '-T', 'device:/dev/tpmrm0', 'rsa2048'])
        with patch.object(migration, 'command', side_effect=['Public-Key: (4096 bit)\n',
                                                           release.ReleaseError('synthetic TPM rejection')]):
            with self.assertRaisesRegex(release.ReleaseError, 'cannot validate'):
                migration.preflight_pcr_key(key)
        for text in ('Public-Key: (1024 bit)\n', 'not an RSA key\n',
                     'Public-Key: (2048 bit)\nPublic-Key: (4096 bit)\n'):
            with self.subTest(text=text), patch.object(migration, 'command', return_value=text) as command:
                with self.assertRaisesRegex(release.ReleaseError, 'supported RSA'):
                    migration.preflight_pcr_key(key)
                self.assertEqual(command.call_count, 1)

    def test_fallback_esp_requires_the_bound_disk_and_restricted_mount(self):
        mount = Path('/run/synthetic-fallback')
        with patch.object(update, 'boot_esp', return_value=mount) as boot, \
                patch.object(migration, 'command') as command:
            command.return_value = json.dumps({'filesystems': [{'target': str(mount),
                                                               'options': 'ro,nodev,nosuid,noexec'}]})
            migration.verify_fallback_esp(mount, '/dev/test')
            boot.assert_called_with({'esp': str(mount)}, disk='/dev/test')
            for options in ('rw,nodev,nosuid,noexec', 'ro,nodev,nosuid', 'ro,nodev,noexec'):
                command.return_value = json.dumps({'filesystems': [{'target': str(mount), 'options': options}]})
                with self.subTest(options=options), self.assertRaises(release.ReleaseError):
                    migration.verify_fallback_esp(mount, '/dev/test')
            boot.return_value = Path('/run/other')
            with self.assertRaises(release.ReleaseError):
                migration.verify_fallback_esp(mount, '/dev/test')

    def test_writable_state_cannot_choose_another_fallback_or_transition_operation(self):
        installed, _, _, _ = self.fixture()
        for change in ({'phase': 'repair'}, {'fallback': None}, {'command': 'shell'}, {'legacy_tokens': {}},
                       {'luks_uuid': '/dev/other'}):
            with self.subTest(change=change), self.assertRaises(release.ReleaseError):
                migration.validate({**installed['tpm_transition'], **change})

    def exercise(self, *, interrupt=None, unseal=True, phase='enforce'):
        installed, luks, strong, public = self.fixture(phase)
        events = []
        interrupted = False
        def command(args, **_):
            nonlocal interrupted
            if args[:2] == ['cryptsetup', 'luksUUID']:
                return installed['tpm_transition']['luks_uuid']
            if args[0] == 'systemd-cryptenroll':
                events.append('enroll')
                luks['tokens']['2'] = strong
                luks['keyslots']['2'] = {}
            elif args[:2] == ['cryptsetup', 'luksKillSlot']:
                events.append('kill-slot')
                self.assertIn('strong-unsealed', events)
                self.assertIn('fallback-verified', events)
                self.assertIn('1', luks['keyslots'])
                luks['keyslots'].pop('0')
                luks['tokens']['0']['keyslots'] = []
            elif args[:3] == ['cryptsetup', 'token', 'remove']:
                events.append('remove-token')
                luks['tokens'].pop('0')
            elif args == ['sync']:
                events.append('sync')
            else:
                raise AssertionError(args)
            if not interrupted and interrupt == events[-1]:
                interrupted = True
                raise RuntimeError('simulated power loss after header commit')
            return ''
        def token_test(*_):
            events.append('strong-unsealed' if unseal else 'strong-failed')
            return unseal
        with patch.object(early_unlock, 'in_initrd'), patch.object(early_unlock, 'token_test', side_effect=token_test), \
                patch.object(migration, 'snapshot', side_effect=lambda _: copy.deepcopy(luks)), \
                patch.object(migration, 'command', side_effect=command), patch.object(migration, 'read', return_value=public), \
                patch.object(migration, 'preflight_pcr_key'), \
                patch.object(migration, 'fallback', side_effect=lambda *_: events.append('fallback-verified')):
            if interrupt:
                with self.assertRaises(RuntimeError):
                    migration.migrate(installed, '/dev/synthetic8', '/dev/synthetic', {2, 3})
            if not unseal:
                with self.assertRaises(release.ReleaseError):
                    migration.migrate(installed, '/dev/synthetic8', '/dev/synthetic', {2, 3})
                self.assertIn('0', luks['keyslots'])
                self.assertNotIn('kill-slot', events)
            else:
                result = migration.migrate(installed, '/dev/synthetic8', '/dev/synthetic', {2, 3})
                if phase == 'prepare':
                    self.assertEqual(result['legacy'], ['0'])
                    self.assertEqual(events, [])
                elif phase == 'enroll':
                    self.assertEqual(result, {'legacy': ['0'], 'strong': ['2']})
                    self.assertEqual(set(luks['keyslots']), {'0', '1', '2'})
                    self.assertNotIn('kill-slot', events)
                    self.assertNotIn('remove-token', events)
                    self.assertEqual(events.count('enroll'), 1)
                else:
                    self.assertEqual(result, {'legacy': [], 'strong': ['2']})
                    factory.enrollment_tokens(luks, tpm_required=True, policy=installed['tpm_policy'])
                    self.assertEqual(set(luks['keyslots']), {'1', '2'})
                    self.assertEqual(events.count('enroll'), 1)
        return events

    def test_prepare_preserves_recovery(self):
        self.exercise(phase='prepare')

    def test_retirement_remains_blocked_even_if_an_enforcement_contract_is_supplied(self):
        installed, _, _, _ = self.fixture('enforce')
        with patch.object(early_unlock, 'in_initrd'), patch.object(migration, 'command') as command:
            with self.assertRaisesRegex(release.ReleaseError, 'retirement is blocked'):
                migration.migrate(installed, '/dev/synthetic8', '/dev/synthetic', {2, 3})
            command.assert_not_called()

    def test_enrollment_retains_legacy_and_recovery_through_interruption(self):
        self.exercise(phase='enroll')
        self.exercise(phase='enroll', interrupt='enroll')
        self.exercise(phase='enroll', interrupt='sync')
        self.exercise(phase='enroll', unseal=False)

    def test_unsupported_pcr_key_does_not_add_a_keyslot(self):
        installed, luks, _, public = self.fixture('enroll')
        with patch.object(early_unlock, 'in_initrd'), \
                patch.object(migration, 'snapshot', return_value=luks), \
                patch.object(migration, 'fallback'), patch.object(migration, 'read', return_value=public), \
                patch.object(migration, 'preflight_pcr_key', side_effect=release.ReleaseError('unsupported TPM')), \
                patch.object(migration, 'command', return_value=installed['tpm_transition']['luks_uuid']) as command:
            with self.assertRaisesRegex(release.ReleaseError, 'unsupported TPM'):
                migration.migrate(installed, '/dev/synthetic8', '/dev/synthetic', {2, 3})
            self.assertEqual([call.args[0][0] for call in command.call_args_list], ['cryptsetup'])
            self.assertEqual(set(luks['keyslots']), {'0', '1'})

    def test_enrollment_fails_if_legacy_method_has_already_disappeared(self):
        installed, luks, strong, _ = self.fixture('enroll')
        del luks['tokens']['0']
        del luks['keyslots']['0']
        luks['tokens']['2'] = strong
        luks['keyslots']['2'] = {}
        with patch.object(early_unlock, 'in_initrd'), \
                patch.object(migration, 'snapshot', return_value=luks), \
                patch.object(migration, 'command', return_value=installed['tpm_transition']['luks_uuid']):
            with self.assertRaisesRegex(release.ReleaseError, 'legacy TPM method'):
                migration.migrate(installed, '/dev/synthetic8', '/dev/synthetic', {2, 3})

    def test_initrd_unlock_after_interrupted_slot_retirement_selects_only_the_live_strong_token(self):
        installed, luks, strong, _ = self.fixture()
        luks['tokens']['2'] = strong
        luks['keyslots']['2'] = {}
        luks['keyslots'].pop('0')
        luks['tokens']['0']['keyslots'] = []
        self.assertEqual(migration.classify(installed, luks), {'legacy': ['0'], 'strong': ['2']})
        self.assertEqual(early_unlock.tpm_tokens(luks), ['2'])
        # Ordinary and prepare images must still reject that exceptional header.
        with self.assertRaises(release.ReleaseError):
            factory.enrollment_tokens(luks, tpm_required=True, policy=installed['tpm_policy'])
        installed['tpm_transition']['phase'] = 'prepare'
        installed['tpm_transition']['fallback'] = None
        with self.assertRaises(release.ReleaseError):
            migration.classify(installed, luks)


if __name__ == '__main__':
    unittest.main()
