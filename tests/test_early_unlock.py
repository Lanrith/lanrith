"""The unlock boundary rejects partial policies, late access and probe failures."""

import json
import os
from pathlib import Path
import stat
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from lanrith import early_unlock as unlock, factory
from lanrith.release import ReleaseError


class EarlyUnlockTests(unittest.TestCase):
    def installed(self):
        return {'image_id': 'lanrith', 'deployment_sequence': 12,
                'tpm_policy': unlock.policy(b'synthetic policy authority'),
                'state_directory': '/var/lib/lanrith', 'boot': {'tpm': 'required'}}

    def test_default_policy_requires_all_three_pcr_controls(self):
        valid = self.installed()['tpm_policy']
        unlock.validate(valid)
        for change in ({'direct_pcrs': [7]}, {'direct_pcrs': [15]}, {'direct_pcrs': [7, 11, 15]},
                       {'signed_pcrs': []}, {'signed_pcrs': [11, 15]}, {'bank': 'sha1'},
                       {'early_boot_only': False}, {'early_boot_only': 1}, {'unknown': True}):
            with self.subTest(change=change), self.assertRaises(ReleaseError):
                unlock.validate({**valid, **change})

    def test_enrollment_reports_degraded_until_legacy_token_is_retired(self):
        from lanrith import security_profile
        installed = self.installed()
        installed['tpm_transition'] = {'phase': 'enroll'}
        with patch.object(security_profile, 'mount_options', return_value={'ro', 'nodev', 'nosuid', 'noexec'}), \
                patch.object(security_profile, 'mapped', return_value=True), \
                patch.object(security_profile, 'efi_flag', return_value=True):
            result = security_profile.observe(installed)
        self.assertEqual(result['status'], 'degraded')
        self.assertEqual(result['declared']['tpm_migration'], 'enroll')
        self.assertFalse(result['declared']['early_boot_only_unlock'])

    def test_evidence_creates_its_runtime_parents_before_ownership_validation(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary)/'run/lanrith/unlock/early-unlock.json'
            with patch.object(unlock, 'OBSERVATION', path):
                if os.geteuid() == 0:
                    unlock.record(self.installed(), ['0'])
                    self.assertTrue(path.is_file())
                else:
                    with self.assertRaisesRegex(ReleaseError, 'Unsafe early-unlock observation directory'):
                        unlock.record(self.installed(), ['0'])
            self.assertTrue(path.parent.is_dir())
            self.assertEqual(path.parent.stat().st_mode & 0o777, 0o700)

    def test_kernel_observations_are_bounded_without_artifact_size_assumptions(self):
        self.assertRegex(unlock.kernel_text(Path('/proc/sys/kernel/random/boot_id'), 64),
                         r'^[0-9a-f-]{36}$')
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary)/'pcr'
            for data in ('', '1'*300, 'invalid'):
                path.write_text(data)
                with self.subTest(data=len(data)), patch.object(unlock, 'PCR', path), self.assertRaises(ReleaseError):
                    unlock.pcr15()
            path.write_text(unlock.ZERO+'\n')
            with patch.object(unlock, 'PCR', path):
                self.assertEqual(unlock.pcr15(), unlock.ZERO)

    def test_late_or_non_initrd_enrollment_never_reaches_recovery_tools(self):
        with patch.object(unlock, 'in_initrd', side_effect=ReleaseError('closed')), \
                patch.object(factory, 'initialize') as initialize:
            with self.assertRaises(ReleaseError):
                factory.recovery(self.installed())
            initialize.assert_not_called()




    def test_bound_migration_cannot_enroll_a_replacement_recovery_method(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(factory, 'recovery') as recovery:
            root = Path(directory)
            with self.assertRaisesRegex(ReleaseError, 'Existing recovery enrollment'):
                unlock.ensure_recovery_marker(self.installed(), root, allow_enrollment=False)
            recovery.assert_not_called()
            marker = root/'var/lib/lanrith/recovery-key-enrolled'
            marker.parent.mkdir(parents=True)
            marker.touch()
            self.assertEqual(unlock.ensure_recovery_marker(self.installed(), root, allow_enrollment=False), marker)
            recovery.assert_not_called()

    def test_migration_recovery_marker_rejects_unsafe_metadata(self):
        directory = SimpleNamespace(st_mode=stat.S_IFDIR | 0o700, st_uid=0)
        record = SimpleNamespace(st_mode=stat.S_IFREG | 0o600, st_uid=0, st_nlink=1)
        marker = Path('/var/lib/lanrith/recovery-key-enrolled')
        with patch.object(Path, 'lstat', side_effect=[directory, record]):
            unlock.validate_existing_recovery_marker(marker)
        for bad_directory, bad_record in (
                (SimpleNamespace(st_mode=stat.S_IFLNK | 0o700, st_uid=0), record),
                (SimpleNamespace(st_mode=stat.S_IFDIR | 0o755, st_uid=0), record),
                (directory, SimpleNamespace(st_mode=stat.S_IFLNK | 0o600, st_uid=0, st_nlink=1)),
                (directory, SimpleNamespace(st_mode=stat.S_IFREG | 0o600, st_uid=1, st_nlink=1)),
                (directory, SimpleNamespace(st_mode=stat.S_IFREG | 0o600, st_uid=0, st_nlink=2))):
            with self.subTest(directory=bad_directory, record=bad_record), \
                    patch.object(Path, 'lstat', side_effect=[bad_directory, bad_record]), \
                    self.assertRaises(ReleaseError):
                unlock.validate_existing_recovery_marker(marker)


    def test_token_probe_does_not_turn_missing_tools_or_other_errors_into_denial_proof(self):
        for code, expected in ((0, True), (2, True), (-1, False)):
            result = subprocess.CompletedProcess([], 0, str(code).encode()+b'\n', b'')
            with patch.object(unlock.subprocess, 'run', return_value=result) as run:
                self.assertIs(unlock.token_test('/dev/synthetic8', '2'), expected)
                args = run.call_args.args[0]
                self.assertIn('-I', args)
                self.assertEqual(args[-2:], ['/dev/synthetic8', '2'])
                self.assertEqual(run.call_args.kwargs['timeout'], 30)
        for code in (-11, -13, -126, -131, 127):
            result = subprocess.CompletedProcess([], 0, str(code).encode()+b'\n', b'')
            with patch.object(unlock.subprocess, 'run', return_value=result), \
                    self.subTest(code=code), self.assertRaises(ReleaseError):
                unlock.token_test('/dev/synthetic8', '2')
        for identifier in ('-1', '32', 'all', '00', '1 --dump-volume-key'):
            with self.subTest(identifier=identifier), self.assertRaises(ReleaseError):
                unlock.native_probe('/dev/synthetic8', identifier)

    def transaction(self, *, late=False, barrier=None):
        installed = self.installed()
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        state = root/'var/lib/lanrith'
        state.mkdir(parents=True)
        (state/'recovery-key-enrolled').touch()
        metadata = {'tokens': {'0': {'type': 'systemd-tpm2', 'keyslots': ['0']},
                               '1': {'type': 'systemd-recovery'}}}
        events = []
        def command(args):
            events.append(args[0])
            return json.dumps(metadata) if args[:2] == ['cryptsetup', 'luksDump'] else ''
        with patch.object(unlock, 'SYSROOT', root), patch.object(unlock, 'OBSERVATION', root/'observation'), \
                patch.object(unlock, 'in_initrd'), patch.object(unlock, 'command', side_effect=command), \
                patch.object(factory, 'enrollment_tokens', return_value=['systemd-tpm2', 'systemd-recovery']), \
                patch.object(factory, 'initialize'), patch.object(factory, 'recovery') as recovery, \
                patch.object(unlock, 'token_test', side_effect=[True, True, late]), \
                patch.object(unlock, 'pcr15', side_effect=[unlock.ZERO, barrier or unlock.CLOSED]), \
                patch.object(unlock, 'record') as record:
            if late or barrier:
                with self.assertRaises(ReleaseError):
                    unlock.unlock(installed, '/dev/synthetic8', reporter=lambda name: events.append('stage:'+name))
                record.assert_not_called()
            else:
                unlock.unlock(installed, '/dev/synthetic8', reporter=lambda name: events.append('stage:'+name))
                record.assert_called_once_with(installed, ['0'])
            recovery.assert_not_called()
        return events

    def test_unlock_barrier_checks_real_probe_outcomes_before_recording_success(self):
        events = self.transaction()
        self.assertLess(events.index('mount'), events.index('/usr/lib/systemd/systemd-pcrextend'))
        self.assertLess(events.index('sync'), events.index('/usr/lib/systemd/systemd-pcrextend'))
        self.assertEqual([item for item in events if item.startswith('stage:')],
            ['stage:policy', 'stage:state-metadata', 'stage:token-preflight', 'stage:state-open',
             'stage:state-initialize', 'stage:recovery-verify', 'stage:pcr15-barrier',
             'stage:late-unseal-check', 'stage:record-observation'])
        self.transaction(late=True)
        self.transaction(barrier='b'*64)

    def test_prepare_checks_strong_denial_and_retained_legacy_after_barrier(self):
        from lanrith import tpm_migration
        installed = self.installed()
        installed['tpm_transition'] = {'phase': 'prepare', 'luks_uuid': 'synthetic'}
        metadata = {'tokens': {'0': {'type': 'systemd-tpm2', 'keyslots': ['0']},
                               '2': {'type': 'systemd-tpm2', 'keyslots': ['2']},
                               '1': {'type': 'systemd-recovery', 'keyslots': ['1']}}}
        for failure in (None, 'strong-still-unlocks', 'legacy-lost', 'legacy-retired'):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as directory:
                current = json.loads(json.dumps(metadata))
                if failure == 'legacy-retired':
                    current['tokens']['0']['keyslots'] = []
                root = Path(directory)
                marker = root/'var/lib/lanrith/recovery-key-enrolled'
                marker.parent.mkdir(parents=True)
                marker.touch()
                barrier = [False]
                def command(args):
                    if args[:2] == ['cryptsetup', 'luksDump']:
                        return json.dumps(current)
                    if args[:2] == ['cryptsetup', 'luksUUID']:
                        return 'synthetic'
                    if args[0].endswith('systemd-pcrextend'):
                        barrier[0] = True
                    return ''
                def probe(device, identifier):
                    if not barrier[0]:
                        return True
                    return (failure == 'strong-still-unlocks') if identifier == '2' else failure != 'legacy-lost'
                with patch.object(unlock, 'SYSROOT', root), patch.object(unlock, 'OBSERVATION', root/'observation'), \
                        patch.object(unlock, 'in_initrd'), patch.object(unlock, 'command', side_effect=command), \
                        patch.object(factory, 'state_tokens', return_value=['systemd-tpm2', 'systemd-recovery']), \
                        patch.object(factory, 'initialize'), patch.object(factory, 'verified_root', return_value=('/dev/test', set())), \
                        patch.object(tpm_migration, 'validate', return_value=installed['tpm_transition']), \
                        patch.object(tpm_migration, 'migrate'), \
                        patch.object(tpm_migration, 'classify', return_value={'strong': ['2'], 'legacy': ['0']}), \
                        patch.object(unlock, 'validate_existing_recovery_marker'), \
                        patch.object(unlock, 'token_test', side_effect=probe), \
                        patch.object(unlock, 'pcr15', side_effect=[unlock.ZERO, unlock.CLOSED]), \
                        patch.object(unlock, 'record') as record:
                    if failure in ('strong-still-unlocks', 'legacy-lost'):
                        with self.assertRaises(ReleaseError):
                            unlock.unlock(installed, '/dev/synthetic8')
                        record.assert_not_called()
                    else:
                        unlock.unlock(installed, '/dev/synthetic8')
                        record.assert_called_once_with(installed, ['2'], legacy=['0'])

    def test_profile_requires_current_boot_boundary_observation(self):
        installed = self.installed()
        with patch.object(unlock, 'OBSERVATION', Path('/missing/unlock-evidence')):
            from lanrith import security_profile
            with patch.object(security_profile, 'mount_options', return_value={'ro', 'nodev', 'nosuid', 'noexec'}), \
                    patch.object(security_profile, 'mapped', return_value=True), \
                    patch.object(security_profile, 'efi_flag', return_value=True):
                result = security_profile.observe(installed)
            self.assertTrue(result['declared']['early_boot_only_unlock'])
            self.assertFalse(result['observed']['early_boot_only_unlock'])
            self.assertEqual(result['status'], 'degraded')


if __name__ == '__main__':
    unittest.main()
