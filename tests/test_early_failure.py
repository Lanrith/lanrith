"""The initrd returns only a failed candidate to a distinct older default."""

import copy
import json
from pathlib import Path
import stat
import tempfile
import hashlib
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from lanrith import early_failure, early_unlock, factory, release, repair, tpm_migration, update


class FailureFallbackTests(unittest.TestCase):
    identity = {'image_id': 'lanrith', 'deployment_sequence': 12, 'uki_name': 'lanrith_12.efi'}

    def bound_identity(self):
        binding = {'disk_by_id': '/dev/disk/by-id/synthetic-disk',
                   'esp_uuid': 'abcdefab-1234-1234-1234-123456789abc',
                   'release': {'sequence': 11, 'uki_name': 'lanrith_11.efi', 'uki_sha256': 'a'*64,
                               'partitions': {}}}
        for index, role in enumerate(update.PARTITION_ROLES, 1):
            binding['release']['partitions'][role] = {
                'label': f'l_11_{role.replace("-", "_")}',
                'uuid': f'12345678-1234-1234-1234-{index:012d}', 'size': 512, 'sha256': 'b'*64}
        return {**self.identity, 'fallback_binding': binding}

    def test_identity_is_minimal_and_rejects_ambiguous_names(self):
        self.assertEqual(early_failure.failure_identity(self.identity), self.identity)
        for value in ({**self.identity, 'uki_name': '../bad.efi'},
                      {**self.identity, 'deployment_sequence': 13},
                      {**self.identity, 'extra': 'unexpected'}):
            with self.subTest(value=value), self.assertRaises(release.ReleaseError):
                early_failure.failure_identity(value)

    def test_fallback_binding_is_strict_and_does_not_enable_selection(self):
        binding = {'disk_by_id': '/dev/disk/by-id/synthetic-disk',
                   'esp_uuid': 'abcdefab-1234-1234-1234-123456789abc',
                   'release': {'sequence': 11, 'uki_name': 'lanrith_11.efi', 'uki_sha256': 'a'*64,
                               'partitions': {}}}
        for index, role in enumerate(update.PARTITION_ROLES, 1):
            binding['release']['partitions'][role] = {
                'label': f'l_11_{role.replace("-", "_")}',
                'uuid': f'12345678-1234-1234-1234-{index:012d}', 'size': 512, 'sha256': 'b'*64}
        value = {**self.identity, 'fallback_binding': binding}
        self.assertEqual(early_failure.failure_identity(value), value)
        self.assertFalse(early_failure.FALLBACK_AUTHENTICATION_QUALIFIED)
        self.assertFalse(early_failure.ROLLBACK_COMPATIBILITY_QUALIFIED)
        cases = []
        bad = copy.deepcopy(binding); bad['disk_by_id'] = '/dev/disk/by-id/synthetic-part2'; cases.append(bad)
        bad = copy.deepcopy(binding); bad['release']['sequence'] = 12; cases.append(bad)
        bad = copy.deepcopy(binding); bad['release']['uki_sha256'] = 'not-a-digest'; cases.append(bad)
        bad = copy.deepcopy(binding); bad['release']['partitions']['root']['label'] = 'wrong'; cases.append(bad)
        bad = copy.deepcopy(binding); bad['release']['partitions']['root']['uuid'] = binding['esp_uuid']; cases.append(bad)
        bad = copy.deepcopy(binding); bad['release']['partitions']['root']['size'] = True; cases.append(bad)
        for bad in cases:
            with self.subTest(bad=bad), self.assertRaises(release.ReleaseError):
                early_failure.failure_identity({**self.identity, 'fallback_binding': bad})
        with self.assertRaises(release.ReleaseError):
            early_failure.failure_identity({**value, 'tpm_transition': {'fallback': {'uki_name': 'lanrith_10.efi'}}})

    def test_versioned_fallback_binding_preserves_exact_legacy_labels(self):
        value = self.bound_identity()
        fallback = value['fallback_binding']['release']
        version = '0.1.0-factory.11'
        fallback['uki_name'] = 'lanrith_'+version+'.efi'
        for role, item in fallback['partitions'].items():
            item['label'] = 'r_'+version+'_'+role.replace('-', '_')
        self.assertEqual(early_failure.failure_identity(value), value)
        mixed = copy.deepcopy(value)
        mixed['fallback_binding']['release']['partitions']['root']['label'] = 'l_11_root'
        with self.assertRaises(release.ReleaseError):
            early_failure.failure_identity(mixed)
        wrong = copy.deepcopy(value)
        wrong['fallback_binding']['release']['uki_name'] = 'lanrith_0.1.0-factory.10.efi'
        with self.assertRaises(release.ReleaseError):
            early_failure.failure_identity(wrong)
        for role in fallback['partitions']:
            changed = copy.deepcopy(value)
            changed['fallback_binding']['release']['partitions'][role]['label'] += '-other'
            with self.assertRaises(release.ReleaseError):
                early_failure.failure_identity(changed)

    def test_reboot_requires_the_selected_candidate_and_distinct_older_default(self):
        cases = (('lanrith_12+2-1.efi', 'lanrith_11.efi', True),
                 ('lanrith_12.efi', 'lanrith_12.efi', False),
                 ('lanrith_12.efi', 'lanrith_13.efi', False),
                 ('lanrith_12.efi', 'lanrith_10.efi', False),
                 ('lanrith_99.efi', 'lanrith_11.efi', False),
                 ('lanrith_12.efi', '../other.efi', False))
        for selected, default, allowed in cases:
            def read(path, _):
                name = selected if path.name.startswith('LoaderEntrySelected-') else default
                return bytes(4)+(name+'\0').encode('utf-16-le')
            with self.subTest(selected=selected, default=default), \
                    patch.object(early_failure.os, 'geteuid', return_value=0), \
                    patch.object(early_failure, 'FALLBACK_AUTHENTICATION_QUALIFIED', True), \
                    patch.object(early_failure, 'ROLLBACK_COMPATIBILITY_QUALIFIED', True), \
                    patch.object(Path, 'is_file', return_value=True), \
                    patch.object(early_failure, 'read', side_effect=read), \
                    patch.object(early_failure, 'inspect_bound_fallback',
                                 return_value={'sequence': 11, 'authorized_to_boot': False}), \
                    patch.object(early_failure, 'observe_rollback_compatibility',
                                 return_value={'authorized_to_boot': False}), \
                    patch.object(early_failure, 'command') as command:
                if allowed:
                    early_failure.failed_boot(self.bound_identity())
                    command.assert_called_once_with(['systemctl', '--force', 'reboot'])
                else:
                    with self.assertRaises(release.ReleaseError): early_failure.failed_boot(self.bound_identity())
                    command.assert_not_called()

    def test_missing_or_rejected_state_compatibility_cannot_reboot(self):
        with patch.object(early_failure.os, 'geteuid', return_value=0), \
                patch.object(Path, 'is_file', return_value=True), \
                patch.object(early_failure, 'FALLBACK_AUTHENTICATION_QUALIFIED', True), \
                patch.object(early_failure, 'ROLLBACK_COMPATIBILITY_QUALIFIED', True), \
                patch.object(early_failure, 'observe_failed_boot'), \
                patch.object(early_failure, 'command') as command:
            with self.assertRaisesRegex(release.ReleaseError, 'bound rollback state'):
                early_failure.failed_boot(self.bound_identity())
            command.assert_not_called()

    def state_identity(self):
        value = self.bound_identity()
        transition = {'schema': 1, 'phase': 'enroll', 'luks_uuid': '12345678-1234-1234-1234-123456789abc',
                      'legacy_tokens': {'0': {'sha256': 'c'*64, 'keyslot': '0'}},
                      'fallback': copy.deepcopy(value['fallback_binding']['release'])}
        value['rollback_state'] = {'state_directory': '/var/lib/lanrith',
                                   'tpm_policy': early_unlock.policy(b'test public key'),
                                   'tpm_transition': transition}
        return value

    def test_state_compatibility_is_bound_to_verified_disk_and_current_luks(self):
        value = self.state_identity()
        transition = value['rollback_state']['tpm_transition']
        early_failure.failure_identity(value)
        rows = [{'disk': '/dev/test', 'device': '/dev/test8', 'type': factory.VAR_GUID, 'label': 'var'}]
        with patch.object(Path, 'resolve', return_value=Path('/dev/test')), \
                patch.object(Path, 'is_dir', return_value=True), \
                patch.object(Path, 'is_symlink', return_value=False), \
                patch.object(Path, 'is_mount', return_value=True), \
                patch.object(factory, 'secure_boot'), \
                patch.object(factory, 'verified_root', return_value=('/dev/test', {2, 3})), \
                patch.object(update, 'geometry', return_value=rows), \
                patch.object(early_failure, 'command', return_value=transition['luks_uuid']), \
                patch.object(tpm_migration, 'fallback') as inspect:
            result = early_failure.observe_rollback_compatibility(value)
            self.assertFalse(result['authorized_to_boot'])
            self.assertEqual(inspect.call_args.args[1:], ('/dev/test', {2, 3}, '/dev/test8'))
        invalid = copy.deepcopy(value)
        invalid['rollback_state']['tpm_transition']['legacy_tokens']['0']['sha256'] = 'z'*64
        with self.assertRaises(release.ReleaseError):
            early_failure.failure_identity(invalid)
        invalid = copy.deepcopy(value)
        invalid['rollback_state']['tpm_transition']['fallback']['uki_sha256'] = 'b'*64
        with self.assertRaises(release.ReleaseError):
            early_failure.failure_identity(invalid)

    def test_absent_candidate_root_requires_its_own_qualification(self):
        value = self.state_identity()
        rows = [{'disk': '/dev/test', 'device': '/dev/test8', 'type': factory.VAR_GUID, 'label': 'var'}]
        with patch.object(Path, 'resolve', return_value=Path('/dev/test')), \
                patch.object(Path, 'is_dir', return_value=False), \
                patch.object(Path, 'exists', return_value=False), \
                patch.object(Path, 'is_symlink', return_value=False), \
                patch.object(Path, 'is_mount', return_value=False), \
                patch.object(factory, 'secure_boot'), \
                patch.object(factory, 'verified_root') as verified, \
                patch.object(early_failure, 'observe_boot_esp') as esp, \
                patch.object(update, 'geometry', return_value=rows), \
                patch.object(early_failure, 'command', return_value=value['rollback_state']['tpm_transition']['luks_uuid']), \
                patch.object(tpm_migration, 'fallback') as inspect:
            with self.assertRaisesRegex(release.ReleaseError, 'Missing candidate root fallback is not qualified'):
                early_failure.observe_rollback_compatibility(value)
            inspect.assert_not_called()
            with patch.object(early_failure, 'ROOT_ABSENT_FALLBACK_QUALIFIED', True):
                result = early_failure.observe_rollback_compatibility(value)
            self.assertFalse(result['authorized_to_boot'])
            self.assertEqual(inspect.call_args.args[1:], ('/dev/test', set(), '/dev/test8'))
            self.assertEqual(esp.call_count, 2)
            verified.assert_not_called()

    def test_prepare_identity_dispatches_only_to_gated_legacy_observer(self):
        value = self.state_identity()
        value['rollback_state']['tpm_transition']['phase'] = 'prepare'
        value['rollback_state']['tpm_transition']['fallback'] = None
        early_failure.failure_identity(value)
        invalid = copy.deepcopy(value)
        invalid['tpm_transition'] = {'fallback': {'uki_name': 'lanrith_11.efi'}}
        with self.assertRaises(release.ReleaseError):
            early_failure.failure_identity(invalid)
        rows = [{'disk': '/dev/test', 'device': '/dev/test8', 'type': factory.VAR_GUID, 'label': 'var'}]
        with patch.object(Path, 'resolve', return_value=Path('/dev/test')), \
                patch.object(Path, 'is_dir', return_value=True), \
                patch.object(Path, 'is_symlink', return_value=False), \
                patch.object(Path, 'is_mount', return_value=True), \
                patch.object(factory, 'secure_boot'), \
                patch.object(factory, 'verified_root', return_value=('/dev/test', {2, 3})), \
                patch.object(update, 'geometry', return_value=rows), \
                patch.object(early_failure, 'command', return_value=value['rollback_state']['tpm_transition']['luks_uuid']), \
                patch.object(tpm_migration, 'fallback') as normal, \
                patch.object(tpm_migration, 'legacy_fallback', return_value={
                    'scope': 'legacy-fallback-observation', 'authorized_to_boot': False}) as legacy:
            result = early_failure.observe_rollback_compatibility(value)
            self.assertFalse(result['authorized_to_boot'])
            legacy.assert_called_once()
            normal.assert_not_called()
            self.assertEqual(legacy.call_args.args[1:], (value['fallback_binding'], '/dev/test', {2, 3}, '/dev/test8'))

    def test_symlink_candidate_root_is_not_treated_as_absent(self):
        value = self.state_identity()
        with patch.object(Path, 'resolve', return_value=Path('/dev/test')), \
                patch.object(Path, 'is_symlink', return_value=True), \
                patch.object(factory, 'secure_boot'), \
                patch.object(early_failure, 'ROOT_ABSENT_FALLBACK_QUALIFIED', True), \
                patch.object(tpm_migration, 'fallback') as inspect:
            with self.assertRaisesRegex(release.ReleaseError, 'mountpoint is unsafe'):
                early_failure.observe_rollback_compatibility(value)
            inspect.assert_not_called()

    def test_missing_root_cannot_change_during_fallback_inspection(self):
        value = self.state_identity()
        rows = [{'disk': '/dev/test', 'device': '/dev/test8', 'type': factory.VAR_GUID, 'label': 'var'}]
        with patch.object(Path, 'resolve', return_value=Path('/dev/test')), \
                patch.object(Path, 'is_dir', return_value=True), \
                patch.object(Path, 'is_symlink', return_value=False), \
                patch.object(Path, 'is_mount', side_effect=[False, True]), \
                patch.object(factory, 'secure_boot'), \
                patch.object(factory, 'verified_root', return_value=('/dev/test', {2, 3})), \
                patch.object(early_failure, 'ROOT_ABSENT_FALLBACK_QUALIFIED', True), \
                patch.object(early_failure, 'observe_boot_esp'), \
                patch.object(update, 'geometry', return_value=rows), \
                patch.object(early_failure, 'command', return_value=value['rollback_state']['tpm_transition']['luks_uuid']), \
                patch.object(tpm_migration, 'fallback'):
            with self.assertRaisesRegex(release.ReleaseError, 'changed during inspection'):
                early_failure.observe_rollback_compatibility(value)

    def test_fallback_state_observation_requires_secure_boot(self):
        value = self.state_identity()
        with patch.object(factory, 'secure_boot', side_effect=release.ReleaseError('secure boot disabled')), \
                patch.object(tpm_migration, 'fallback') as inspect:
            with self.assertRaisesRegex(release.ReleaseError, 'secure boot disabled'):
                early_failure.observe_rollback_compatibility(value)
            inspect.assert_not_called()

    def test_fallback_observation_rechecks_secure_boot_after_state_read(self):
        value = self.state_identity()
        rows = [{'disk': '/dev/test', 'device': '/dev/test8', 'type': factory.VAR_GUID, 'label': 'var'}]
        with patch.object(Path, 'resolve', return_value=Path('/dev/test')), \
                patch.object(Path, 'is_dir', return_value=False), \
                patch.object(Path, 'exists', return_value=False), \
                patch.object(Path, 'is_symlink', return_value=False), \
                patch.object(Path, 'is_mount', return_value=False), \
                patch.object(factory, 'secure_boot', side_effect=[None, release.ReleaseError('secure boot changed')]), \
                patch.object(early_failure, 'ROOT_ABSENT_FALLBACK_QUALIFIED', True), \
                patch.object(early_failure, 'observe_boot_esp'), \
                patch.object(update, 'geometry', return_value=rows), \
                patch.object(early_failure, 'command', return_value=value['rollback_state']['tpm_transition']['luks_uuid']), \
                patch.object(tpm_migration, 'fallback') as inspect:
            with self.assertRaisesRegex(release.ReleaseError, 'secure boot changed'):
                early_failure.observe_rollback_compatibility(value)
            inspect.assert_called_once()

    def test_invalid_mounted_root_is_not_treated_as_absent(self):
        value = self.state_identity()
        with patch.object(Path, 'resolve', return_value=Path('/dev/test')), \
                patch.object(Path, 'is_dir', return_value=True), \
                patch.object(Path, 'is_symlink', return_value=False), \
                patch.object(Path, 'is_mount', return_value=True), \
                patch.object(factory, 'secure_boot'), \
                patch.object(factory, 'verified_root', side_effect=release.ReleaseError('invalid verity root')), \
                patch.object(early_failure, 'ROOT_ABSENT_FALLBACK_QUALIFIED', True), \
                patch.object(tpm_migration, 'fallback') as inspect:
            with self.assertRaisesRegex(release.ReleaseError, 'invalid verity root'):
                early_failure.observe_rollback_compatibility(value)
            inspect.assert_not_called()

    def test_changed_fallback_after_state_check_cannot_reboot(self):
        with patch.object(early_failure.os, 'geteuid', return_value=0), \
                patch.object(Path, 'is_file', return_value=True), \
                patch.object(early_failure, 'FALLBACK_AUTHENTICATION_QUALIFIED', True), \
                patch.object(early_failure, 'ROLLBACK_COMPATIBILITY_QUALIFIED', True), \
                patch.object(early_failure, 'observe_failed_boot',
                             side_effect=[{'authorized_to_boot': False}, release.ReleaseError('selection changed')]), \
                patch.object(early_failure, 'observe_rollback_compatibility',
                             return_value={'authorized_to_boot': False}), \
                patch.object(early_failure, 'command') as command:
            with self.assertRaisesRegex(release.ReleaseError, 'selection changed'):
                early_failure.failed_boot(self.bound_identity())
            command.assert_not_called()
        with patch.object(early_failure.os, 'geteuid', return_value=0), \
                patch.object(Path, 'is_file', return_value=True), \
                patch.object(early_failure, 'FALLBACK_AUTHENTICATION_QUALIFIED', True), \
                patch.object(early_failure, 'ROLLBACK_COMPATIBILITY_QUALIFIED', True), \
                patch.object(early_failure, 'observe_failed_boot'), \
                patch.object(early_failure, 'observe_rollback_compatibility',
                             side_effect=release.ReleaseError('incompatible state')), \
                patch.object(early_failure, 'command') as command:
            with self.assertRaisesRegex(release.ReleaseError, 'incompatible state'):
                early_failure.failed_boot(self.bound_identity())
            command.assert_not_called()

    def test_rollback_gate_and_changed_boot_selection_cannot_reboot(self):
        value = self.bound_identity()
        with patch.object(early_failure.os, 'geteuid', return_value=0), \
                patch.object(Path, 'is_file', return_value=True), \
                patch.object(early_failure, 'FALLBACK_AUTHENTICATION_QUALIFIED', True), \
                patch.object(early_failure, 'command') as command, \
                patch.object(early_failure, 'inspect_bound_fallback') as inspect, \
                self.assertRaisesRegex(release.ReleaseError, 'state and TPM rollback'):
            early_failure.failed_boot(value)
        command.assert_not_called()
        inspect.assert_not_called()
        def variable(path, _):
            name = 'lanrith_12.efi' if path.name.startswith('LoaderEntrySelected-') else 'lanrith_11.efi'
            return bytes(4)+(name+'\0').encode('utf-16-le')
        calls = [0]
        def changed(path, size):
            calls[0] += 1
            if calls[0] == 4:
                return bytes(4)+('lanrith_10.efi\0').encode('utf-16-le')
            return variable(path, size)
        with patch.object(early_failure.os, 'geteuid', return_value=0), \
                patch.object(Path, 'is_file', return_value=True), \
                patch.object(early_failure, 'read', side_effect=changed), \
                patch.object(early_failure, 'inspect_bound_fallback',
                             return_value={'sequence': 11, 'authorized_to_boot': False}), \
                self.assertRaisesRegex(release.ReleaseError, 'changed during fallback observation'):
            early_failure.observe_failed_boot(value)

    def test_boot_esp_observation_requires_bound_disk_identity_and_stable_geometry(self):
        uuid = '12345678-1234-1234-1234-123456789abc'
        rows = [{'disk': '/dev/synthetic', 'device': '/dev/synthetic1', 'size': 512,
                 'type': 'c12a7328-f81f-11d2-ba4b-00a0c93ec93b', 'uuid': uuid}]
        layout = {'sector': 512, 'extents': [(1, 2, '/dev/synthetic1')]}
        encoded = bytes(4)+(uuid+'\0').encode('utf-16-le')
        with patch.object(early_failure.os, 'geteuid', return_value=0), \
                patch.object(Path, 'is_file', return_value=True), \
                patch.object(Path, 'stat', return_value=SimpleNamespace(st_mode=stat.S_IFBLK)), \
                patch.object(early_failure, 'read', return_value=encoded), \
                patch.object(repair, 'disk_layout', return_value=layout), \
                patch.object(update, 'geometry', return_value=rows):
            observation = early_failure.observe_boot_esp('/dev/synthetic', uuid)
            self.assertFalse(observation['authorized_to_boot'])
            with self.assertRaises(release.ReleaseError):
                early_failure.observe_boot_esp('/dev/synthetic', 'abcdefab-1234-1234-1234-123456789abc')
        changed = {'sector': 512, 'extents': [(1, 3, '/dev/synthetic1')]}
        with patch.object(early_failure.os, 'geteuid', return_value=0), \
                patch.object(Path, 'is_file', return_value=True), \
                patch.object(Path, 'stat', return_value=SimpleNamespace(st_mode=stat.S_IFBLK)), \
                patch.object(early_failure, 'read', return_value=encoded), \
                patch.object(repair, 'disk_layout', side_effect=[layout, changed]), \
                patch.object(update, 'geometry', return_value=rows), self.assertRaises(release.ReleaseError):
            early_failure.observe_boot_esp('/dev/synthetic', uuid)

    def test_boot_esp_observation_rejects_ambiguous_uuid_and_malformed_firmware_data(self):
        uuid = '12345678-1234-1234-1234-123456789abc'
        rows = [{'disk': '/dev/synthetic', 'device': '/dev/synthetic1', 'size': 512,
                 'type': 'c12a7328-f81f-11d2-ba4b-00a0c93ec93b', 'uuid': uuid},
                {'disk': '/dev/synthetic', 'device': '/dev/synthetic2', 'size': 512,
                 'type': '4f68bce3-e8cd-4db1-96e7-fbcaf984b709', 'uuid': uuid}]
        layout = {'sector': 512, 'extents': [(1, 2, '/dev/synthetic1'), (2, 3, '/dev/synthetic2')]}
        encoded = bytes(4)+(uuid+'\0').encode('utf-16-le')
        for firmware, geometry in ((encoded, rows), (b'bad', rows[:1])):
            with self.subTest(firmware_valid=firmware == encoded), \
                    patch.object(early_failure.os, 'geteuid', return_value=0), \
                    patch.object(Path, 'is_file', return_value=True), \
                    patch.object(Path, 'stat', return_value=SimpleNamespace(st_mode=stat.S_IFBLK)), \
                    patch.object(early_failure, 'read', return_value=firmware), \
                    patch.object(repair, 'disk_layout', return_value=layout), \
                    patch.object(update, 'geometry', return_value=geometry), \
                    self.assertRaises(release.ReleaseError):
                early_failure.observe_boot_esp('/dev/synthetic', uuid)

    def test_unqualified_port_cannot_select_a_fallback(self):
        with patch.object(early_failure.os, 'geteuid', return_value=0), \
                patch.object(Path, 'is_file', return_value=True), \
                patch.object(early_failure, 'command') as command, \
                self.assertRaisesRegex(release.ReleaseError, 'blocked pending authenticated fallback'):
            early_failure.failed_boot(self.identity)
        command.assert_not_called()

    def test_bound_payload_observation_detects_modified_or_busy_slot(self):
        with tempfile.TemporaryDirectory() as tmp:
            esp = Path(tmp)
            folder = esp/'EFI/Linux'
            folder.mkdir(parents=True)
            (folder/'lanrith_11.efi').write_bytes(b'synthetic signed uki')
            binding = {'disk_by_id': '/dev/disk/by-id/synthetic-disk',
                       'esp_uuid': 'abcdefab-1234-1234-1234-123456789abc',
                       'release': {'sequence': 11, 'uki_name': 'lanrith_11.efi',
                                   'uki_sha256': hashlib.sha256(b'synthetic signed uki').hexdigest(),
                                   'partitions': {}}}
            rows = []
            extents = []
            for index, role in enumerate(update.PARTITION_ROLES, 1):
                uuid = f'12345678-1234-1234-1234-{index:012d}'
                label = f'l_11_{role.replace("-", "_")}'
                binding['release']['partitions'][role] = {'label': label, 'uuid': uuid,
                                                          'size': 512, 'sha256': 'b'*64}
                node = f'/dev/synthetic{index}'
                rows.append({'disk': '/dev/synthetic', 'device': node, 'number': index,
                             'size': 512, 'uuid': uuid, 'label': label,
                             'type': update.GUIDS[role], 'mounted': False})
                extents.append((index, index+1, node))
            value = {**self.identity, 'fallback_binding': binding}
            layout = {'sector': 512, 'extents': extents}
            resolve = Path.resolve
            resolved_disk = ['/dev/synthetic']
            def bound_resolve(path, *args, **kwargs):
                if str(path) == binding['disk_by_id']:
                    return Path(resolved_disk[0])
                return resolve(path, *args, **kwargs)
            with patch.object(Path, 'resolve', bound_resolve), \
                    patch.object(early_failure, 'observe_boot_esp') as boot, \
                    patch.object(update, 'boot_esp', return_value=esp), \
                    patch.object(repair, 'require_readonly_esp'), \
                    patch.object(repair, 'disk_layout', return_value=layout), \
                    patch.object(update, 'geometry', return_value=rows), \
                    patch.object(repair, 'partition_digest', return_value='b'*64) as digest:
                result = early_failure.observe_bound_fallback(value, esp)
                self.assertFalse(result['authorized_to_boot'])
                self.assertEqual(boot.call_count, 2)
                self.assertEqual(digest.call_count, len(update.PARTITION_ROLES))
                def changed_disk(*_):
                    resolved_disk[0] = '/dev/other'
                    return 'b'*64
                digest.side_effect = changed_disk
                with self.assertRaisesRegex(release.ReleaseError, 'changed during observation'):
                    early_failure.observe_bound_fallback(value, esp)
                resolved_disk[0] = '/dev/synthetic'
                def changed_entries(*_):
                    (folder/'lanrith_11+1.efi').write_bytes(b'synthetic signed uki')
                    return 'b'*64
                digest.side_effect = changed_entries
                with self.assertRaisesRegex(release.ReleaseError, 'changed during observation'):
                    early_failure.observe_bound_fallback(value, esp)
                (folder/'lanrith_11+1.efi').unlink()
                digest.side_effect = None
                digest.return_value = 'c'*64
                with self.assertRaisesRegex(release.ReleaseError, 'partition differs'):
                    early_failure.observe_bound_fallback(value, esp)
                digest.return_value = 'b'*64
                rows[0]['mounted'] = True
                with self.assertRaisesRegex(release.ReleaseError, 'busy'):
                    early_failure.observe_bound_fallback(value, esp)
                rows[0]['mounted'] = False
                duplicate = copy.deepcopy(rows[0])
                duplicate['device'] = '/dev/synthetic99'
                rows.append(duplicate)
                # Keep GPT/kernel geometry consistent so duplicate identities,
                # rather than a geometry mismatch, are the reason for rejection.
                layout['extents'].append((99, 100, duplicate['device']))
                with self.assertRaisesRegex(release.ReleaseError, 'absent or ambiguous'):
                    early_failure.observe_bound_fallback(value, esp)
                rows.pop()
                layout['extents'].pop()
                (folder/'lanrith_11+1.efi').write_bytes(b'synthetic signed uki')
                with self.assertRaisesRegex(release.ReleaseError, 'absent or ambiguous'):
                    early_failure.observe_bound_fallback(value, esp)
                (folder/'lanrith_11+1.efi').unlink()
                (folder/'lanrith_11.efi').write_bytes(b'modified uki')
                with self.assertRaisesRegex(release.ReleaseError, 'boot entry differs'):
                    early_failure.observe_bound_fallback(value, esp)

    def test_bound_esp_mount_is_restricted_and_cleaned_even_when_observation_fails(self):
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary)
            binding = {'disk_by_id': '/dev/disk/by-id/synthetic-disk',
                       'esp_uuid': 'abcdefab-1234-1234-1234-123456789abc',
                       'release': {'sequence': 11, 'uki_name': 'lanrith_11.efi', 'uki_sha256': 'a'*64,
                                   'partitions': {}}}
            for index, role in enumerate(update.PARTITION_ROLES, 1):
                binding['release']['partitions'][role] = {
                    'label': f'l_11_{role.replace("-", "_")}',
                    'uuid': f'12345678-1234-1234-1234-{index:012d}', 'size': 512, 'sha256': 'b'*64}
            value = {**self.identity, 'fallback_binding': binding}
            rows = [{'disk': '/dev/synthetic', 'device': '/dev/synthetic1', 'uuid': binding['esp_uuid'],
                     'type': 'c12a7328-f81f-11d2-ba4b-00a0c93ec93b', 'mounted': False}]
            native_resolve = Path.resolve
            def bound_resolve(path, *args, **kwargs):
                if str(path) == binding['disk_by_id']:
                    return Path('/dev/synthetic')
                return native_resolve(path, *args, **kwargs)
            for failing in (False, True):
                point = parent/('failure' if failing else 'success')
                point.mkdir()
                with self.subTest(failing=failing), patch.object(Path, 'resolve', bound_resolve), \
                        patch.object(Path, 'is_mount', side_effect=[True, True, False]), \
                        patch.object(early_failure.tempfile, 'mkdtemp', return_value=str(point)), \
                        patch.object(early_failure, 'observe_boot_esp'), \
                        patch.object(update, 'geometry', return_value=rows), \
                        patch.object(update, 'command') as command, \
                        patch.object(early_failure, 'observe_bound_fallback') as observe:
                    observe.return_value = {'authorized_to_boot': False}
                    if failing:
                        observe.side_effect = release.ReleaseError('synthetic rejection')
                        with self.assertRaisesRegex(release.ReleaseError, 'synthetic rejection'):
                            early_failure.inspect_bound_fallback(value)
                    else:
                        self.assertFalse(early_failure.inspect_bound_fallback(value)['authorized_to_boot'])
                    self.assertEqual(command.call_args_list[0].args[0],
                        ['mount', '-t', 'vfat', '-o', 'ro,nodev,nosuid,noexec', '--',
                         '/dev/synthetic1', str(point)])
                    self.assertEqual(command.call_args_list[1].args[0], ['umount', '--', str(point)])
                    self.assertFalse(point.exists())
            point = parent/'unmount-failure'
            point.mkdir()
            with patch.object(Path, 'resolve', bound_resolve), \
                    patch.object(Path, 'is_mount', side_effect=[True, True]), \
                    patch.object(early_failure.tempfile, 'mkdtemp', return_value=str(point)), \
                    patch.object(early_failure, 'observe_boot_esp'), \
                    patch.object(update, 'geometry', return_value=rows), \
                    patch.object(update, 'command', side_effect=[None, release.ReleaseError('unmount failed')]), \
                    patch.object(early_failure, 'observe_bound_fallback', return_value={'authorized_to_boot': False}), \
                    self.assertRaisesRegex(release.ReleaseError, 'unmount failed'):
                early_failure.inspect_bound_fallback(value)
            self.assertTrue(point.exists())
            rows[0]['mounted'] = True
            with patch.object(Path, 'resolve', bound_resolve), \
                    patch.object(early_failure, 'observe_boot_esp'), \
                    patch.object(update, 'geometry', return_value=rows), \
                    patch.object(update, 'command') as command, \
                    self.assertRaisesRegex(release.ReleaseError, 'already mounted'):
                early_failure.inspect_bound_fallback(value)
            command.assert_not_called()

    def test_factory_failure_uses_only_initrd_identity(self):
        payload = json.dumps(self.identity).encode()
        with patch.object(factory, 'read', return_value=payload) as read, \
                patch.object(early_failure, 'failed_boot') as failed:
            self.assertEqual(factory.main(['failed']), 0)
        read.assert_called_once_with(Path('/usr/share/lanrith/initrd-failure.json'), 65536)
        failed.assert_called_once_with(self.identity)

    def test_emergency_fallback_timeout_restores_signal_handler(self):
        import signal
        import time
        previous = signal.getsignal(signal.SIGALRM)
        with patch.object(factory, 'FALLBACK_DEADLINE_SECONDS', 0.05), \
                patch.object(early_failure, 'failed_boot', side_effect=lambda _: time.sleep(2)), \
                self.assertRaises(TimeoutError):
            factory.bounded_fallback(self.identity)
        self.assertEqual(signal.getitimer(signal.ITIMER_REAL), (0.0, 0.0))
        self.assertEqual(signal.getsignal(signal.SIGALRM), previous)

    def test_emergency_does_not_replace_an_existing_timer(self):
        import signal
        with patch.object(factory.signal, 'getitimer', return_value=(10.0, 0.0)), \
                patch.object(early_failure, 'failed_boot') as failed, \
                self.assertRaisesRegex(release.ReleaseError, 'existing process timer'):
            factory.bounded_fallback(self.identity)
        failed.assert_not_called()

    def test_emergency_holds_when_unqualified_fallback_is_denied(self):
        payload = json.dumps(self.identity).encode()
        with patch.object(factory.os, 'geteuid', return_value=0), \
                patch.object(Path, 'is_file', return_value=True), \
                patch.object(factory, 'read', return_value=payload), \
                patch.object(early_failure, 'failed_boot', side_effect=release.ReleaseError('denied')) as failed, \
                patch('time.sleep', side_effect=RuntimeError('stop test')), \
                patch('builtins.print') as output, \
                self.assertRaisesRegex(RuntimeError, 'stop test'):
            factory.main(['emergency'])
        failed.assert_called_once_with(self.identity)
        self.assertTrue(any('holding for recovery' in str(call) for call in output.call_args_list))

    def test_emergency_holds_after_a_fallback_timeout(self):
        payload = json.dumps(self.identity).encode()
        with patch.object(factory.os, 'geteuid', return_value=0), \
                patch.object(Path, 'is_file', return_value=True), \
                patch.object(factory, 'read', return_value=payload), \
                patch.object(factory, 'bounded_fallback', side_effect=TimeoutError('synthetic timeout')) as failed, \
                patch('time.sleep', side_effect=RuntimeError('stop test')), \
                patch('builtins.print') as output, self.assertRaises(RuntimeError):
            factory.main(['emergency'])
        failed.assert_called_once_with(self.identity)
        printed = ' '.join(str(call) for call in output.call_args_list)
        self.assertIn('holding for recovery', printed)
        self.assertNotIn('synthetic timeout', printed)

    def test_emergency_diagnostic_does_not_disclose_exception_text(self):
        payload = json.dumps(self.identity).encode()
        def fail_with_secret(value):
            raise release.ReleaseError('synthetic-secret-do-not-report')
        with patch.object(factory.os, 'geteuid', return_value=0), \
                patch.object(Path, 'is_file', return_value=True), \
                patch.object(factory, 'read', return_value=payload), \
                patch.object(early_failure, 'failed_boot', side_effect=fail_with_secret), \
                patch('time.sleep', side_effect=RuntimeError('stop test')), \
                patch('builtins.print') as output, self.assertRaises(RuntimeError):
            factory.main(['emergency'])
        printed = ' '.join(str(call) for call in output.call_args_list)
        self.assertIn('Automatic fallback diagnostic: verification', printed)
        self.assertNotIn('synthetic-secret-do-not-report', printed)

    def test_fallback_diagnostic_identifies_trusted_exception_location(self):
        namespace = {'ReleaseError': release.ReleaseError}
        source = compile("def check():\n    raise ReleaseError('synthetic secret')\n",
                         '/synthetic/lanrith/early_failure.py', 'exec')
        exec(source, namespace)
        try:
            namespace['check']()
        except release.ReleaseError as error:
            diagnostic = factory.fallback_diagnostic(error)
        self.assertEqual(diagnostic, 'Automatic fallback diagnostic: verification early_failure.py:check:2')
        self.assertNotIn('synthetic secret', diagnostic)

    def test_fallback_diagnostic_skips_shared_assertion_helper(self):
        namespace = {'require': release.require}
        source = compile("def check():\n    require(False, 'synthetic secret')\n",
                         '/synthetic/lanrith/early_failure.py', 'exec')
        exec(source, namespace)
        try:
            namespace['check']()
        except release.ReleaseError as error:
            diagnostic = factory.fallback_diagnostic(error)
        self.assertEqual(diagnostic, 'Automatic fallback diagnostic: verification early_failure.py:check:2')
        self.assertNotIn('synthetic secret', diagnostic)

    def test_fallback_diagnostic_identifies_migration_without_runtime_values(self):
        for module in ('tpm_migration.py', 'measured_boot.py'):
            with self.subTest(module=module):
                namespace = {'require': release.require}
                source = compile("def compare():\n    require(False, 'sensitive binding')\n",
                                 '/synthetic/lanrith/'+module, 'exec')
                exec(source, namespace)
                try:
                    namespace['compare']()
                except release.ReleaseError as error:
                    diagnostic = factory.fallback_diagnostic(error)
                self.assertEqual(diagnostic, f'Automatic fallback diagnostic: verification {module}:compare:2')
                self.assertNotIn('sensitive binding', diagnostic)

    def test_failure_handler_refuses_normal_userspace(self):
        with patch.object(early_failure.os, 'geteuid', return_value=1000), \
                patch.object(early_failure, 'command') as command, self.assertRaises(release.ReleaseError):
            early_failure.failed_boot(self.identity)
        command.assert_not_called()
