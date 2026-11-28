"""Promotion interruption boundaries using real state files and a synthetic EFI variable."""

from contextlib import ExitStack
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import ANY, patch

from lanrith import image_operation as operation, release, runtime, steady_recovery, update


class PowerCut(BaseException):
    pass


class PromotionTests(unittest.TestCase):
    def setUp(self):
        stack = self.enterContext(ExitStack())
        self.root = Path(stack.enter_context(tempfile.TemporaryDirectory()))
        # Keep all state private to this process even when tests run as an ordinary user.
        original_stat = Path.stat

        def owned_stat(path, *args, **kwargs):
            info = original_stat(path, *args, **kwargs)
            if path.is_relative_to(self.root):
                fields = list(info)
                fields[4] = 0
                return os.stat_result(fields)
            return info

        stack.enter_context(patch.object(Path, 'stat', owned_stat))
        stack.enter_context(patch.object(Path, 'lstat', lambda path: owned_stat(path, follow_symlinks=False)))
        read = runtime.protected_read
        stack.enter_context(patch.object(runtime, 'protected_read',
            side_effect=lambda path, size: read(path, size, owner=os.geteuid())))
        self.previous = {'image_id': 'router', 'deployment_sequence': 8, 'configuration_sha256': 'a'*64,
                         'uki_name': 'router_8.efi', 'platform_version': '0.2.0', 'operator': 'admin',
                         'state_directory': str(self.root/'state')}
        self.current = {**self.previous, 'deployment_sequence': 10, 'uki_name': 'router_10.efi',
                        'configuration_sha256': 'b'*64}
        self.record = {'schema': 1, 'phase': 'rebooting', 'candidate': operation.identity(self.current),
                       'fallback': operation.identity(self.previous), 'digest': 'c'*64,
                       'executor_id': 'd'*32, 'error': None}
        self.installed = self.root/'installed.json'
        self.variable = self.root/'default'
        self.observation = self.root/'run'/'boot.json'
        self.boot(self.current)
        stack.enter_context(patch.object(runtime, 'BOOT_OBSERVATION', self.observation))
        stack.enter_context(patch.object(runtime, 'INSTALLED', self.installed))
        self.health = stack.enter_context(patch.object(runtime, 'health', side_effect=lambda: self.running))
        stack.enter_context(patch.object(runtime, 'installed', side_effect=lambda: self.running))
        stack.enter_context(patch.object(runtime.health_observation, 'status', return_value={'result': 'passed'}))
        def inspect_boot(args, **_):
            if args == ['systemctl', 'is-active', 'boot-complete.target']:
                return 'active'
            if args == ['bootctl', '--print-esp-path']:
                return str(self.root)
            if args == ['bootctl', '--print-stub-path']:
                return str(self.root/'EFI/Linux'/self.running['uki_name'])
            self.fail('Unexpected boot inspection')

        stack.enter_context(patch.object(runtime, 'command', side_effect=inspect_boot))
        entries = self.root/'EFI/Linux'
        entries.mkdir(parents=True)
        for value in (self.previous, self.current):
            (entries/value['uki_name']).touch()
        self.target = stack.enter_context(patch.object(runtime, 'complete_target'))
        stack.enter_context(patch.object(runtime, 'bless', side_effect=lambda value: self.root/value['uki_name']))
        stack.enter_context(patch.object(operation, 'operation_lock'))
        original_default = update.default_entry
        stack.enter_context(patch.object(update, 'default_entry', side_effect=lambda *args: original_default(self.variable)))
        self.write = stack.enter_context(patch.object(operation, 'command', side_effect=self.select))
        self.select(['bootctl', 'set-default', self.previous['uki_name']])

    def boot(self, value):
        self.running = value
        self.installed.write_text(json.dumps(value))

    def select(self, args):
        self.assertEqual(args[:2], ['bootctl', 'set-default'])
        self.variable.write_bytes(bytes(4)+(args[2]+'\0').encode('utf-16-le'))

    def stage(self):
        operation.save_accepted(self.previous)
        operation.save(self.current, self.record)

    def test_initial_repeated_and_explicit_manual_promotion(self):
        self.variable.unlink()
        self.boot(self.previous)
        self.assertFalse(runtime.publish()['accepted'])
        self.assertTrue(operation.complete(self.installed)['accepted'])
        self.assertTrue(operation.complete(self.installed)['accepted'])
        self.assertEqual(self.write.call_count, 1)
        self.boot(self.current)
        self.observation.unlink()  # volatile /run after a one-shot manual boot
        self.assertIsNone(operation.complete(self.installed))
        self.assertFalse(runtime.publish()['accepted'])
        with patch.object(runtime, 'installed', return_value=self.current):
            with self.assertRaises(release.ReleaseError):
                runtime.accept(11)
            self.assertTrue(runtime.accept(10)['accepted'])
        self.assertEqual(operation.visible_accepted(self.current), self.record['candidate'])
        self.assertTrue(runtime.publish()['accepted'])
        self.assertEqual(runtime.telemetry()['deployment_sequence'], 10)

    def test_target_retry_must_succeed_before_promotion(self):
        self.stage()
        self.target.side_effect = release.ReleaseError('local target still unavailable')
        with self.assertRaisesRegex(release.ReleaseError, 'target still unavailable'):
            operation.promote_running(self.current)
        self.health.assert_called_once()
        self.assertEqual(self.write.call_count, 0)
        self.assertEqual(operation.visible_accepted(self.current), operation.identity(self.previous))
        self.target.side_effect = None
        self.assertTrue(operation.promote_running(self.current)['accepted'])

    def test_selector_refusal_and_wrong_readback_keep_candidate_pending(self):
        self.stage()
        for effect in (release.ReleaseError('selector refused'), lambda args: None):
            with self.subTest(effect=effect):
                self.write.side_effect = effect
                with self.assertRaises(release.ReleaseError):
                    operation.promote_running(self.current)
                self.assertIsNone(operation.visible_accepted(self.current))
                self.assertFalse(runtime.publish()['accepted'])
                self.assertEqual(operation.load(self.current)['phase'], 'rebooting')
                with self.assertRaises(release.ReleaseError):
                    runtime.telemetry()

    def test_interruption_after_each_commit_step(self):
        for step in ('intent', 'selector', 'accepted-image', 'image-operation', 'unlink', 'publication'):
            with self.subTest(step=step):
                self.select(['bootctl', 'set-default', self.previous['uki_name']])
                self.observation.unlink(missing_ok=True)
                self.stage()
                with ExitStack() as faults:
                    def crash_after(fn, name):
                        def interrupted(*args, **kwargs):
                            result = fn(*args, **kwargs)
                            if step == name:
                                raise PowerCut
                            return result
                        return interrupted
                    real_atomic = operation.atomic
                    def atomic(path, value):
                        name = 'intent' if path.name == 'image-promotion.json' else path.stem
                        return crash_after(real_atomic, name)(path, value)
                    faults.enter_context(patch.object(operation, 'atomic', side_effect=atomic))
                    faults.enter_context(patch.object(operation, 'command', side_effect=crash_after(self.select, 'selector')))
                    faults.enter_context(patch.object(operation, 'finish_promotion',
                                                      side_effect=crash_after(operation.finish_promotion, 'unlink')))
                    faults.enter_context(patch.object(runtime, 'publish_boot',
                                                      side_effect=crash_after(runtime.publish_boot, 'publication')))
                    with self.assertRaises(PowerCut):
                        operation.complete(self.installed)
                if step != 'publication':
                    self.assertFalse(runtime.publish()['accepted'])
                    with self.assertRaises(release.ReleaseError):
                        runtime.telemetry()
                self.health.reset_mock()
                operation.fallback_boot(self.installed)
                self.assertTrue(self.health.called)
                self.assertEqual(operation.visible_accepted(self.current), self.record['candidate'])
                self.assertEqual(operation.load(self.current)['phase'], 'accepted')
                self.assertEqual(update.default_entry(), self.current['uki_name'])
                self.assertEqual(runtime.telemetry()['deployment_sequence'], 10)

    def test_stale_or_unknown_selection_cannot_authorize_restoration(self):
        self.stage()
        with patch.object(operation, 'command', side_effect=PowerCut), self.assertRaises(PowerCut):
            operation.promote_running(self.current)
        self.select(['bootctl', 'set-default', 'unknown.efi'])
        with self.assertRaisesRegex(release.ReleaseError, 'selector'):
            operation.promote_running(self.current)
        intent = operation.load_promotion(self.current)
        operation.atomic(operation.promotion_path(self.current), {**intent, 'operation': 'e'*64+'/'+ 'f'*32})
        with self.assertRaisesRegex(release.ReleaseError, 'intent'):
            operation.promote_running(self.current)
        self.write.assert_not_called()
        self.assertIsNone(runtime.status()['boot'])

    def test_new_authorized_operation_after_legacy_predecessor_fallback(self):
        self.stage()
        with patch.object(operation, 'command', side_effect=PowerCut), self.assertRaises(PowerCut):
            operation.promote_running(self.current)
        # The earlier slot could read and write the schema-1 records but did not
        # recognize the promotion sidecar when it booted back into itself.
        later = {**self.current, 'deployment_sequence': 12, 'uki_name': 'router_12.efi'}
        operation.save(later, {**self.record, 'candidate': operation.identity(later), 'executor_id': 'e'*32})
        self.boot(later)
        self.assertTrue(operation.complete(self.installed)['accepted'])
        self.assertEqual(update.default_entry(), later['uki_name'])
        self.assertIsNone(operation.load_promotion(later))

    def test_predecessor_boot_reconciles_candidate_intent(self):
        self.stage()
        with patch.object(operation, 'command', side_effect=PowerCut), self.assertRaises(PowerCut):
            operation.promote_running(self.current)
        self.boot(self.previous)
        self.assertTrue(operation.complete(self.installed)['accepted'])
        self.assertIsNone(operation.load_promotion(self.previous))
        self.assertEqual(operation.load(self.previous)['phase'], 'fallback')
        self.assertEqual(operation.visible_accepted(self.previous), self.record['fallback'])
        self.write.assert_not_called()

    def test_unhealthy_interrupted_candidate_requests_bound_rollback(self):
        self.current.update(image_contract={'recovery': {'binding': {'release': {
            'sequence': 8, 'uki_name': self.previous['uki_name']}}}}, recovery_state={})
        self.boot(self.current)
        self.stage()
        with patch.object(operation, 'save_accepted', side_effect=PowerCut), self.assertRaises(PowerCut):
            operation.promote_running(self.current)
        self.health.side_effect = release.ReleaseError('health refused')
        with patch.object(steady_recovery, 'runtime_fallback') as restore:
            operation.fallback_boot(self.installed)
        restore.assert_called_once_with(self.current, restore_promoted=True, restored=ANY)
        self.assertEqual(operation.load(self.current)['error'], 'readiness-failed')
        self.assertIsNone(runtime.status()['boot'])

    def test_verified_rollback_restores_then_reads_selector_before_reboot(self):
        from lanrith import early_failure, factory, measured_boot, tpm_migration
        disk = self.root/'disk'
        disk.touch()
        esp = self.root/'esp'
        uki = esp/'EFI/Linux'/self.previous['uki_name']
        uki.parent.mkdir(parents=True)
        uki.write_bytes(b'synthetic verified predecessor')
        partitions = {role: {'uuid': role, 'label': role, 'size': 17, 'sha256': 'a'*64}
                      for role in update.GUIDS}
        bound = {'sequence': 8, 'uki_name': uki.name, 'uki_sha256': release.file_record(uki)['sha256'],
                 'partitions': partitions}
        binding = {'release': bound, 'disk_by_id': str(disk)}
        self.current.update(image_contract={'recovery': {'sequence': 10, 'image_id': self.current['image_id'],
                                                        'binding': binding}}, recovery_state={}, tpm_policy={'test': True})
        self.boot(self.current)
        self.stage()
        # Simulate an interruption after the phase was recorded but before removing the intent.
        with patch.object(operation, 'finish_promotion', side_effect=PowerCut), self.assertRaises(PowerCut):
            operation.promote_running(self.current)
        self.health.side_effect = release.ReleaseError('health failed')
        rows = [{'disk': str(disk), 'device': role, 'type': guid, 'uuid': role, 'label': role,
                 'size': 17, 'number': i} for i, (role, guid) in enumerate(update.GUIDS.items())]
        events = []
        def command(args):
            if args[0] == 'bootctl':
                self.assertIn('retained', events)
                events.append('selector')
                self.select(args)
            else:
                self.assertEqual(args, ['systemctl', '--force', 'reboot'])
                self.assertEqual(update.default_entry(), self.previous['uki_name'])
                self.assertIsNone(operation.load_promotion(self.current))
                self.assertEqual(operation.accepted_identity(self.current), self.record['fallback'])
                events.append('reboot')
        with ExitStack() as checks:
            for module, fn, replacement in (
                (early_failure, 'failure_identity', None), (factory, 'secure_boot', None),
                (factory, 'state_metadata', (str(disk), 'state', {})), (factory, 'verified_root', ('/', {15})),
                (update, 'boot_esp', esp), (update, 'geometry', rows),
                (measured_boot, 'verify', {}), (tpm_migration, 'bound_uki_roothash', 'f'*64),
                (tpm_migration, 'partition_digest', 'a'*64)):
                checks.enter_context(patch.object(module, fn, return_value=replacement))
            inspect = checks.enter_context(patch.object(tpm_migration, 'inspect_fallback_state',
                                                        side_effect=release.ReleaseError('retained state refused')))
            checks.enter_context(patch.object(update, 'command', side_effect=command))
            with self.assertRaisesRegex(release.ReleaseError, 'retained state refused'):
                operation.fallback_boot(self.installed)
            self.assertEqual(events, [])
            self.assertEqual(update.default_entry(), self.current['uki_name'])
            inspect.side_effect = lambda *args: events.append('retained')
            with patch.object(update, 'command', return_value='') as refused:
                with self.assertRaisesRegex(release.ReleaseError, 'default'):
                    operation.fallback_boot(self.installed)
                refused.assert_called_once_with(['bootctl', 'set-default', uki.name])
            events.clear()
            operation.fallback_boot(self.installed)
        self.assertEqual(events, ['retained', 'selector', 'reboot'])
        self.boot(self.previous)
        self.health.side_effect = lambda: self.running
        self.assertTrue(operation.complete(self.installed)['accepted'])
        self.assertEqual(operation.load(self.previous)['phase'], 'fallback')
