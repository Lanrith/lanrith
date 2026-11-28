"""Slot availability, observation freshness and durable initialization boundaries."""

from contextlib import ExitStack, redirect_stderr
import copy
import io
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from lanrith import factory, image_contract, image_operation, recovery_enrollment, release, runtime, slot_state, update


class Slots(unittest.TestCase):
    def setUp(self):
        resource = tempfile.TemporaryDirectory()
        self.addCleanup(resource.cleanup)
        self.directory = Path(resource.name)
        self.disk = '/dev/synthetic'
        self.active = {2, 3}
        self.policy = {'platform_version': '0.1.0', 'image_id': 'router', 'update_image_id': 'router', 'deployment_sequence': 10,
                       'configuration_sha256': 'f'*64, 'uki_name': 'router_10.efi', 'operator': 'operator',
                       'layout': 'ab-verity-v1', 'certificate': '/fixture.crt', 'boot': {'tpm': 'required'},
                       'state_directory': str(self.directory/'state'),
                       'active_labels': {role: 'l_10_'+role.replace('-', '_') for role in update.PARTITION_ROLES},
                       'payload_limits': {role: 8192 for role in (*update.PARTITION_ROLES, 'uki')}}
        self.rows = []
        self.manifest = {'purpose': 'update', 'architecture': 'x86-64', 'deployment_sequence': 11,
                         'image_id': 'router', 'artifacts': [{'role': 'uki', 'name': 'router_11.efi', 'size': 512}]}
        for n, role in enumerate(update.PARTITION_ROLES, 1):
            self.manifest['artifacts'].append({'role': role, 'name': f'router_11_{self.uuid(30+n)}.{role}.raw',
                                               'size': 512})
            for previous in (False, True):
                number = n + 3*previous
                self.rows.append({'number': number, 'size': 8192, 'mounted': False, 'type': update.GUIDS[role],
                    'disk': self.disk, 'disk_uuid': self.uuid(0), 'device': self.disk+str(number),
                    'start_bytes': number*1024**2, 'uuid': self.uuid(number),
                    'label': '_empty' if previous else self.policy['active_labels'][role]})
        self.state = {'type': factory.VAR_GUID, 'label': 'var', 'device': self.disk+'7', 'uuid': self.uuid(7),
                      'disk_uuid': self.uuid(0)}
        self.rows.append(self.state)
        self.contract = {'schema': 1, 'machine_id': '1'*32,
                         'state': {'dns': {'reads': ['v1'], 'writes': 'v1'}},
                         'trust': {'generation': 1, 'transition': 'steady', 'authorities':
                                   dict.fromkeys(image_contract.AUTHORITIES, None)}}

    @staticmethod
    def uuid(number):
        return f'aa000000-0000-0000-0000-{number:012d}'

    def test_both_layouts_and_staging_budgets(self):
        for label in ('_empty', 'previous'):
            for standby_role in update.PARTITION_ROLES:
                for problem in (None, 'short', 'busy', 'ambiguous'):
                    with self.subTest(label=label, role=standby_role, problem=problem):
                        rows = copy.deepcopy(self.rows)
                        for row in rows:
                            if row['label'] == '_empty':
                                row['label'] = label
                        target = next(row for row in rows if row['type'] == update.GUIDS[standby_role] and
                                      row['label'] == label)
                        if problem == 'short':
                            target['size'] = 4096  # Even a small fitting payload cannot restore the signed layout.
                        elif problem == 'busy':
                            target['mounted'] = True
                        elif problem == 'ambiguous':
                            rows.remove(target)
                        report = factory.slot_report(self.policy, rows, self.active)
                        self.assertTrue(report['active_verified'])
                        self.assertEqual(report['standby']['available'], problem is None)
                        arguments = (self.manifest, self.policy, rows)
                        options = {'disk': self.disk, 'active_partitions': self.active, 'esp_available': 1<<30}
                        if problem:
                            self.assertEqual(report['standby'][problem], [standby_role])
                            with self.assertRaises(release.ReleaseError):
                                update.plan(*arguments, **options)
                        else:
                            self.assertEqual(len(update.plan(*arguments, **options)['partitions']), 3)
        self.rows[0]['size'] = 4096
        report = factory.slot_report(self.policy, self.rows, self.active)
        self.assertEqual(report['active_short'], ['verity-sig'])
        self.assertTrue(report['standby']['available'])
        with self.assertRaises(release.ReleaseError):
            factory.slot_report(self.policy, self.rows, {2, 4})

    def test_profile_deadline(self):
        try:
            from lanrith import config
        except ModuleNotFoundError as error:
            if error.name != 'yaml':
                raise
            self.skipTest('Build-time PyYAML is absent from the native appliance fixture.')
        value = config.load(Path(__file__).resolve().parents[1]/'examples/minimal.yaml')
        for invalid in (0, 3601, True, '8'):
            value['hardware']['storage']['initialization_timeout_seconds'] = invalid
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                config.normalize(value)

    @unittest.skipUnless(os.geteuid() == 0, 'protected native metadata')
    def test_locked_stage_rechecks_targets_before_write(self):
        root = self.directory
        source = root/'state/update-inbox/11'
        source.mkdir(mode=0o700, parents=True)
        (root/'state').chmod(0o700)
        path = root/'installed.json'
        path.write_bytes(release.canonical(self.policy))
        esp = root/'esp'
        esp.mkdir()
        stable = esp/'EFI/Linux'/self.policy['uki_name']
        stable.parent.mkdir(parents=True)
        stable.touch()
        with patch.object(runtime, 'BOOT_OBSERVATION', root/'boot.json'):
            image_operation.save_accepted(self.policy)
            runtime.publish_boot(self.policy, stable, accepted=True)
            for change in ('mounted', 'size', 'start_bytes'):
                observed = copy.deepcopy(self.rows)
                observed[1][change] = True if change == 'mounted' else 1024
                def geometry(disk):
                    for name in (update.OPERATION_LOCK_NAME, 'lanrith-update.lock'):
                        with self.assertRaises(release.ReleaseError), update.image_lock(name):
                            pass
                    return next(views)
                views = iter([self.rows, observed])
                def command(args, **kwargs):
                    if args == ['bootctl', '--print-stub-path']:
                        return str(stable)
                    self.assertEqual(args, ['systemctl', 'start', 'lanrith-health.service'])
                    return ''
                with self.subTest(change=change), patch.object(update, 'IMAGE_LOCK_DIR', root), \
                        patch.object(update, 'boot_esp', return_value=esp), patch.object(update, 'command', command), \
                        patch.object(update, 'require_default'), patch.object(update, 'verify', return_value=self.manifest), \
                        patch.object(update, 'root_disk', return_value=(self.disk, self.active)), \
                        patch.object(update, 'geometry', geometry), patch.object(Path, 'is_mount', return_value=True), \
                        patch.object(update, 'writable_esp') as writable, \
                        self.assertRaisesRegex(release.ReleaseError, 'changed before staging'):
                    try:
                        update.stage(source, path)
                    finally:
                        writable.assert_not_called()

    @unittest.skipUnless(os.geteuid() == 0, 'protected native metadata')
    def test_retained_commit_and_retries(self):
        installed = {'image_contract': self.contract, 'state_directory': str(self.directory)}
        path = self.directory/'state-contract.json'
        image_contract.remember(installed)
        original = path.stat()
        with patch.object(slot_state, 'sync_directory') as flush, patch.object(slot_state, 'save') as save:
            image_contract.remember(installed)
            flush.assert_not_called()
            save.assert_not_called()
        self.assertEqual(path.stat().st_ino, original.st_ino)
        installed['image_contract'] = {**self.contract, 'state': {'dhcp': {'writes': 'v2', 'reads': ['v2']}}}
        previous = path.read_bytes()
        with patch.object(os, 'replace', side_effect=OSError('before rename')), self.assertRaises(OSError):
            image_contract.remember(installed)
        self.assertEqual(path.read_bytes(), previous)
        self.assertTrue((self.directory/'.state-contract.json.pending').exists())
        with patch.object(recovery_enrollment, 'sync_directory', side_effect=OSError('after rename')), \
                self.assertRaises(OSError):
            image_contract.remember(installed)
        self.assertEqual(set(json.loads(path.read_bytes())['state']), {'dhcp', 'dns'})
        inode = path.stat().st_ino
        with patch.object(slot_state, 'save') as save, \
                patch.object(slot_state, 'sync_directory', wraps=slot_state.sync_directory) as sync:
            image_contract.remember(installed)
            self.assertEqual(sync.call_count, 2)
            save.assert_not_called()
        self.assertEqual(path.stat().st_ino, inode)
        self.assertFalse((self.directory/'.state-contract.json.pending').exists())
        saved = path.read_bytes()
        installed['image_contract']['state']['dns'] = {'reads': ['v3'], 'writes': 'v3'}
        with self.assertRaisesRegex(release.ReleaseError, 'cannot read retained'):
            image_contract.remember(installed)
        self.assertEqual(path.read_bytes(), saved)
        installed['image_contract']['state'].pop('dns')
        self.directory.chmod(0o755)
        try:
            with self.assertRaisesRegex(release.ReleaseError, 'directory is unsafe'):
                image_contract.remember(installed)
        finally:
            self.directory.chmod(0o700)
        installed['image_contract']['machine_id'] = '2'*32
        with self.assertRaisesRegex(release.ReleaseError, 'target differs'):
            image_contract.remember(installed)
        self.assertEqual(path.read_bytes(), saved)
        path.chmod(0o644)
        with self.assertRaisesRegex(release.ReleaseError, 'not protected'):
            image_contract.remember(installed)
        path.chmod(0o600)
        path.write_bytes(b'{}')
        with self.assertRaises(release.ReleaseError):
            image_contract.remember(installed)
        self.assertEqual(path.read_bytes(), b'{}')

    @unittest.skipUnless(os.geteuid() == 0, 'protected native metadata')
    def test_live_gates_and_legacy_marker_repair(self):
        directory = Path(self.policy['state_directory'])
        directory.mkdir(mode=0o700)
        path = directory/'slots-initialized'
        health = self.directory/'run/slot-health.json'
        self.policy['tpm_policy'] = {}
        self.policy['image_contract'] = self.contract
        header = {'tokens': {}}
        calls = []
        def command(args):
            calls.append(args[:2])
            if args[0] == 'findmnt':
                return '/dev/mapper/state'
            if args[:2] == ['cryptsetup', 'status']:
                return '  device: '+self.state['device']
            return json.dumps(header) if 'luksDump' in args else ''
        with ExitStack() as checks:
            checks.enter_context(patch.object(factory, 'verified_root', return_value=(self.disk, self.active)))
            checks.enter_context(patch.object(factory, 'geometry', return_value=self.rows))
            checks.enter_context(patch.object(factory, 'command', command))
            checks.enter_context(patch.object(slot_state, 'HEALTH', health))
            tokens = checks.enter_context(patch.object(factory, 'state_tokens', return_value=[]))
            observation = checks.enter_context(patch('lanrith.early_unlock.observation'))
            path.write_bytes(b'{"schema":')
            path.chmod(0o600)
            self.assertIsNone(slot_state.marker(path))
            observation.side_effect = release.ReleaseError('missing PCR observation')
            with self.assertRaises(release.ReleaseError):
                factory.initialize(self.policy)
            self.assertEqual(path.read_bytes(), b'{"schema":')
            self.assertFalse(health.exists())
            observation.side_effect = None
            for old in (b'{"schema":', b'', release.canonical({'schema': 1, 'disk': '/dev/oldname'})):
                path.write_bytes(old)
                if old.startswith(b'{"disk"'):
                    self.assertEqual(slot_state.marker(path)['schema'], 1)
                factory.initialize(self.policy)
                valid = {'schema': 2, 'disk_uuid': self.uuid(0), 'state_partuuid': self.uuid(7)}
                self.assertEqual(slot_state.marker(path), valid)
                self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            inode = path.stat().st_ino
            self.rows[1]['mounted'] = True
            factory.initialize(self.policy)
            self.assertEqual(path.stat().st_ino, inode)
            self.assertEqual(slot_state.read_health(self.policy, max_age_seconds=5)['standby']['busy'], ['verity-sig'])
            self.assertEqual(tokens.call_count, 5)
            self.assertEqual(observation.call_count, 5)
            self.assertEqual(calls.count(['cryptsetup', 'luksDump']), 5)
            for changed in ({'boot_id': self.uuid(99)}, {'configuration_sha256': 'a'*64},
                            {'checked_monotonic_ns': 0}, {'checked_monotonic_ns': time.monotonic_ns()+10**12}):
                old = health.read_bytes()
                health.write_bytes(release.canonical({**json.loads(old), **changed}))
                with self.assertRaises(release.ReleaseError):
                    slot_state.read_health(self.policy, max_age_seconds=1)
                health.write_bytes(old)
            latest = slot_state.read_health(self.policy, max_age_seconds=5)
            earlier = factory.slot_report(self.policy, self.rows, self.active)
            earlier['standby'] = {'available': True, 'short': [], 'busy': [], 'ambiguous': []}
            slot_state.write_health(self.policy, earlier, latest['checked_monotonic_ns']-1)
            self.assertEqual(slot_state.read_health(self.policy, max_age_seconds=5), latest)
            health.unlink()
            warning = io.StringIO()
            with patch.object(slot_state, 'write_health', side_effect=OSError('fixture')), redirect_stderr(warning):
                self.assertEqual(factory.initialize(self.policy), (self.state['device'], []))
            self.assertIn('Could not publish verified slot health', warning.getvalue())
            self.assertFalse(health.exists())
            path.write_bytes(release.canonical({**valid, 'disk_uuid': self.uuid(23)}))
            with self.assertRaisesRegex(release.ReleaseError, 'another disk'):
                factory.initialize(self.policy)
            path.unlink()
            path.symlink_to(health)
            with self.assertRaisesRegex(release.ReleaseError, 'Unsafe slot'):
                factory.initialize(self.policy)


if __name__ == '__main__':
    unittest.main()
