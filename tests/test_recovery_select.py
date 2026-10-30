"""Tests for gated one-shot selection of the signed bound fallback."""
from contextlib import ExitStack, contextmanager
import json
import signal
import subprocess
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import Mock, patch

from lanrith import recovery_select as select
from lanrith.release import ReleaseError


class SelectTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='lanrith-select-')
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.esp = self.root/'esp'
        (self.esp/'EFI/Linux').mkdir(parents=True)
        self.entry = self.esp/'EFI/Linux/lanrith_9.efi'
        self.entry.write_bytes(b'synthetic signed fixture')
        self.variable = self.root/'oneshot'
        self.identity = {'fallback_binding': {'disk_by_id': '/dev/disk/by-id/test',
            'esp_uuid': '12345678-1234-1234-1234-123456789abc',
            'release': {'sequence': 9, 'uki_name': self.entry.name, 'uki_sha256': 'ab'*32}}}
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        def mock(obj, name, **kwargs):
            return self.stack.enter_context(patch.object(obj, name, **kwargs))
        mock(select, 'ONESHOT', new=self.variable)
        mock(select.os, 'geteuid', return_value=0)
        mock(Path, 'is_file', return_value=True)
        mock(select.factory, 'secure_boot')
        mock(select.early_failure, 'failure_identity')
        mock(select.early_failure, 'observe_boot_esp')
        self.observe = mock(select.early_failure, 'observe_bound_fallback',
                            return_value={'sequence': 9, 'authorized_to_boot': False})
        self.mounted = False
        def state_observation(*_):
            self.assertFalse(self.mounted, 'State verifier must inspect an unmounted ESP')
            return {'scope': 'rollback-compatibility-observation', 'authorized_to_boot': False}
        self.state = mock(select.early_failure, 'observe_rollback_compatibility', side_effect=state_observation)
        mock(select.recovery_inputs, 'canonical_disk', return_value='/dev/vda')
        mock(select.recovery_inputs, 'disk_snapshot', return_value=({}, []))
        mock(select.recovery_inputs, 'partition', return_value='/dev/vda1')
        mock(select.recovery_inputs, 'stable_snapshot')
        @contextmanager
        def mounted(*args):
            self.assertFalse(self.mounted)
            self.mounted = True
            try:
                yield self.esp
            finally:
                self.mounted = False
        mock(select.recovery_inputs, 'mounted', side_effect=mounted)
        def read(path, maximum):
            return self.variable.read_bytes() if path == self.variable else json.dumps(self.identity).encode()
        mock(select.release, 'read', side_effect=read)
        self.commands = []
        def command(args):
            self.commands.append(args)
            if args[-1] == 'list':
                return json.dumps([{'type': 'type2', 'source': 'esp', 'path': str(self.entry), 'id': self.entry.name}])
            if args[-2:] == ['set-oneshot', '']:
                self.variable.unlink(missing_ok=True)
                return ''
            if args[-2] == 'set-oneshot':
                self.variable.write_bytes(bytes(4)+(args[-1]+'\0').encode('utf-16-le'))
                return ''
            raise AssertionError('Unexpected command')
        mock(select.update, 'command', side_effect=command)

    def enable(self):
        self.stack.enter_context(patch.object(select, 'OPERATOR_SELECTION_QUALIFIED', True))
        self.stack.enter_context(patch.object(select.early_failure, 'FALLBACK_AUTHENTICATION_QUALIFIED', True))
        self.stack.enter_context(patch.object(select.early_failure, 'ROLLBACK_COMPATIBILITY_QUALIFIED', True))

    def test_unqualified_selection_does_not_call_bootctl(self):
        with self.assertRaises(ReleaseError):
            select.select_bound(confirm=lambda *_: '9')
        self.assertEqual(self.commands, [])
        self.assertFalse(self.variable.exists())

    def test_selects_only_verified_fallback_once_without_reboot(self):
        self.enable()
        result = select.select_bound(confirm=lambda sequence, digest: str(sequence))
        self.assertEqual(result['sequence'], 9)
        self.assertFalse(result['automatic_reboot'])
        self.assertFalse(result['default_changed'])
        self.assertEqual(self.commands[-1][-2:], ['set-oneshot', self.entry.name])
        self.assertGreaterEqual(self.observe.call_count, 3)
        self.assertEqual(self.state.call_count, 2)

    def test_missing_or_incompatible_state_never_selects_fallback(self):
        self.enable()
        self.state.side_effect = ReleaseError('unavailable verified root or incompatible state')
        with self.assertRaises(ReleaseError):
            select.select_bound(confirm=lambda *_: '9')
        self.assertEqual(self.commands, [])
        self.assertFalse(self.variable.exists())

    def test_state_must_still_match_after_operator_confirmation(self):
        self.enable()
        self.state.side_effect = [
            {'scope': 'rollback-compatibility-observation', 'authorized_to_boot': False},
            ReleaseError('state changed while awaiting confirmation'),
        ]
        with self.assertRaises(ReleaseError):
            select.select_bound(confirm=lambda *_: '9')
        self.assertEqual(self.commands, [])
        self.assertFalse(self.variable.exists())

    def test_unexpected_state_observation_cannot_authorize_selection(self):
        self.enable()
        self.state.side_effect = None
        self.state.return_value = {'scope': 'rollback-compatibility-observation', 'authorized_to_boot': True}
        with self.assertRaises(ReleaseError):
            select.select_bound(confirm=lambda *_: '9')
        self.assertEqual(self.commands, [])
        self.assertFalse(self.variable.exists())

    def test_verification_timeout_restores_signal_handler_and_never_selects(self):
        self.enable()
        prior = signal.getsignal(signal.SIGALRM)
        self.state.side_effect = TimeoutError('synthetic verification timeout')
        with self.assertRaises(TimeoutError):
            select.select_bound(confirm=lambda *_: '9')
        self.assertEqual(signal.getitimer(signal.ITIMER_REAL), (0.0, 0.0))
        self.assertEqual(signal.getsignal(signal.SIGALRM), prior)
        self.assertEqual(self.commands, [])
        self.assertFalse(self.variable.exists())

    def test_confirmation_does_not_run_under_verification_deadline(self):
        self.enable()
        def confirm(sequence, _digest):
            self.assertEqual(signal.getitimer(signal.ITIMER_REAL), (0.0, 0.0))
            return str(sequence)
        self.assertEqual(select.select_bound(confirm=confirm)['sequence'], 9)

    def test_initial_disk_observation_timeout_keeps_selection_unchanged(self):
        self.enable()
        prior = signal.getsignal(signal.SIGALRM)
        with patch.object(select, 'OBSERVATION_DEADLINE_SECONDS', 0.02), \
                patch.object(select.recovery_inputs, 'canonical_disk', side_effect=lambda *_: time.sleep(1)):
            with self.assertRaises(TimeoutError):
                select.select_bound(confirm=lambda *_: '9')
        self.assertEqual(signal.getitimer(signal.ITIMER_REAL), (0.0, 0.0))
        self.assertEqual(signal.getsignal(signal.SIGALRM), prior)
        self.assertEqual(self.commands, [])
        self.assertFalse(self.variable.exists())

    def test_existing_process_timer_is_not_replaced(self):
        callback = Mock()
        with patch.object(select.signal, 'getitimer', return_value=(10.0, 0.0)), \
                patch.object(select.signal, 'setitimer') as set_timer:
            with self.assertRaisesRegex(ReleaseError, 'existing timer'):
                select.bounded_observation(callback)
            callback.assert_not_called()
            set_timer.assert_not_called()

    def test_actual_observation_deadline_interrupts_a_stalled_check(self):
        prior = signal.getsignal(signal.SIGALRM)
        with patch.object(select, 'OBSERVATION_DEADLINE_SECONDS', 0.02):
            with self.assertRaises(TimeoutError):
                select.bounded_observation(lambda: time.sleep(1))
        self.assertEqual(signal.getitimer(signal.ITIMER_REAL), (0.0, 0.0))
        self.assertEqual(signal.getsignal(signal.SIGALRM), prior)

    def test_declined_confirmation_does_not_write_selection(self):
        self.enable()
        with self.assertRaises(ReleaseError):
            select.select_bound(confirm=lambda *_: 'no')
        self.assertEqual(self.commands, [])
        self.assertFalse(self.variable.exists())

    def test_failed_post_selection_validation_clears_own_one_shot(self):
        self.enable()
        with patch.object(select.recovery_inputs, 'stable_snapshot',
                          side_effect=[None, None, ReleaseError('synthetic topology change')]):
            with self.assertRaises(ReleaseError):
                select.select_bound(confirm=lambda *_: '9')
        self.assertFalse(self.variable.exists())
        self.assertEqual(self.commands[-1][-2:], ['set-oneshot', ''])

    def test_timed_out_set_clears_its_own_recorded_one_shot(self):
        self.enable()
        def command(args):
            if args[-1] == 'list':
                return json.dumps([{'type': 'type2', 'source': 'esp', 'path': str(self.entry), 'id': self.entry.name}])
            if args[-2:] == ['set-oneshot', '']:
                self.variable.unlink(missing_ok=True)
                return ''
            self.variable.write_bytes(bytes(4)+(self.entry.name+'\0').encode('utf-16-le'))
            raise subprocess.TimeoutExpired('bootctl', 30)
        with patch.object(select.update, 'command', side_effect=command):
            with self.assertRaises(subprocess.TimeoutExpired):
                select.select_bound(confirm=lambda *_: '9')
        self.assertFalse(self.variable.exists())

    def test_existing_selection_is_not_overwritten(self):
        self.enable()
        self.variable.write_bytes(b'old')
        with self.assertRaises(ReleaseError):
            select.select_bound(confirm=lambda *_: '9')
        self.assertEqual(self.variable.read_bytes(), b'old')
        self.assertEqual(self.commands, [])


if __name__ == '__main__':
    unittest.main()
