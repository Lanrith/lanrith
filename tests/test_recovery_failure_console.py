"""Fixed-menu and authentication boundaries for initrd failure recovery."""
import unittest
import io
import json
import subprocess
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from lanrith import recovery_failure_console as console, release


class FailureConsoleTests(unittest.TestCase):
    def test_automatic_fallback_requires_both_gates(self):
        for authentication, compatibility in ((False, False), (False, True), (True, False)):
            with self.subTest(authentication=authentication, compatibility=compatibility), \
                    patch.object(console.early_failure, 'FALLBACK_AUTHENTICATION_QUALIFIED', authentication), \
                    patch.object(console.early_failure, 'ROLLBACK_COMPATIBILITY_QUALIFIED', compatibility), \
                    patch.object(console.release, 'read', return_value=b'{}') as read, \
                    patch.object(console.factory, 'bounded_fallback') as fallback:
                self.assertFalse(console.automatic_fallback())
                read.assert_called_once()
                fallback.assert_not_called()

    def test_automatic_fallback_uses_bounded_verified_identity_and_fails_to_menu(self):
        identity = {'synthetic': 'identity'}
        with patch.object(console.early_failure, 'FALLBACK_AUTHENTICATION_QUALIFIED', True), \
                patch.object(console.early_failure, 'ROLLBACK_COMPATIBILITY_QUALIFIED', True), \
                patch.object(console.release, 'read', return_value=json.dumps(identity).encode()), \
                patch.object(console.early_failure, 'failure_identity', return_value=identity), \
                patch.object(console.factory, 'bounded_fallback') as fallback:
            self.assertTrue(console.automatic_fallback())
            fallback.assert_called_once_with(identity)
            fallback.side_effect = TimeoutError('private diagnostic')
            self.assertFalse(console.automatic_fallback())

    def test_successful_automatic_request_does_not_start_serial_selection(self):
        with patch.object(console.os, 'geteuid', return_value=0), \
                patch.object(Path, 'is_file', return_value=True), \
                patch.object(console.factory, 'secure_boot'), \
                patch.object(console, 'automatic_fallback', return_value=True), \
                patch.object(console, 'wait_for_reboot', return_value=0) as wait, \
                patch.object(console.recovery_console, 'protected_file') as protected:
            self.assertEqual(console.main(), 0)
            wait.assert_called_once()
            protected.assert_not_called()

    def test_automatic_failure_reports_sanitized_diagnostic_and_survives_output_error(self):
        identity = {'synthetic': 'identity'}
        for output_failure in (False, True):
            with self.subTest(output_failure=output_failure), \
                    patch.object(console.early_failure, 'FALLBACK_AUTHENTICATION_QUALIFIED', True), \
                    patch.object(console.early_failure, 'ROLLBACK_COMPATIBILITY_QUALIFIED', True), \
                    patch.object(console.release, 'read', return_value=json.dumps(identity).encode()), \
                    patch.object(console.early_failure, 'failure_identity', return_value=identity), \
                    patch.object(console.factory, 'bounded_fallback', side_effect=TimeoutError('secret fixture')), \
                    patch('builtins.print', side_effect=OSError('closed') if output_failure else None) as printed:
                self.assertFalse(console.automatic_fallback())
                printed.assert_called_once()
                self.assertNotIn('secret fixture', str(printed.call_args))
                self.assertIn('Automatic fallback diagnostic:', str(printed.call_args))

    def test_failed_automatic_attempt_reaches_authenticated_serial_menu(self):
        class Tty(io.StringIO):
            def isatty(self): return True
            def fileno(self): return 8
        stdin, stdout = Tty(), Tty()
        stdin.buffer = object()
        credential = 'scrypt:32768:8:1:'+'ab'*16+':'+'cd'*32
        identity, secret = {'synthetic': 'identity'}, bytearray(b'private')
        def protected(path, *args, **kwargs):
            return (json.dumps({'schema': 1, 'tty': 'ttyS0'}) if path == console.POLICY else credential).encode()
        with patch.object(console.os, 'geteuid', return_value=0), \
                patch.object(Path, 'is_file', return_value=True), \
                patch.object(Path, 'stat', return_value=SimpleNamespace(st_mode=0o020000, st_rdev=5)), \
                patch.object(console.os, 'fstat', return_value=SimpleNamespace(st_rdev=5)), \
                patch.object(console.factory, 'secure_boot'), \
                patch.object(console.early_failure, 'FALLBACK_AUTHENTICATION_QUALIFIED', True), \
                patch.object(console.early_failure, 'ROLLBACK_COMPATIBILITY_QUALIFIED', True), \
                patch.object(console.release, 'read', return_value=json.dumps(identity).encode()), \
                patch.object(console.early_failure, 'failure_identity', return_value=identity), \
                patch.object(console.factory, 'bounded_fallback', side_effect=TimeoutError('private fixture')) as fallback, \
                patch.object(console.recovery_console, 'protected_file', side_effect=protected), \
                patch.object(console.recovery_console, 'secret_from_tty', return_value=secret), \
                patch.object(console.recovery_console, 'verify_secret', return_value=True), \
                patch.object(console.sys, 'stdin', stdin), patch.object(console.sys, 'stdout', stdout), \
                patch.object(console, 'fixed_menu') as menu:
            self.assertEqual(console.main(), 0)
            fallback.assert_called_once_with(identity)
            menu.assert_called_once()
            self.assertFalse(any(secret))
            self.assertNotIn('private fixture', stdout.getvalue())

    def test_policy_accepts_only_explicit_serial_device(self):
        self.assertEqual(console.policy({'schema': 1, 'tty': 'ttyS0'})['tty'], 'ttyS0')
        for value in ({'schema': True, 'tty': 'ttyS0'}, {'schema': 1, 'tty': 'tty0'},
                      {'schema': 1, 'tty': '../ttyS0'}, {'schema': 1, 'tty': 'ttyS0', 'shell': True}):
            with self.assertRaises(release.ReleaseError):
                console.policy(value)

    def test_authentication_denies_after_three_attempts_and_erases_secrets(self):
        class Tty(io.StringIO):
            def isatty(self): return True
            def fileno(self): return 8
        stdin, stdout = Tty(), Tty()
        stdin.buffer = object()
        secrets = [bytearray(b'first'), bytearray(b'second'), bytearray(b'third')]
        credential = 'scrypt:32768:8:1:'+'ab'*16+':'+'cd'*32
        def protected(path, *args, **kwargs):
            return (json.dumps({'schema': 1, 'tty': 'ttyS0'}) if path == console.POLICY else credential).encode()
        with patch.object(console.os, 'geteuid', return_value=0), \
                patch.object(Path, 'is_file', return_value=True), \
                patch.object(Path, 'stat', return_value=SimpleNamespace(st_mode=0o020000, st_rdev=5)), \
                patch.object(console.os, 'fstat', return_value=SimpleNamespace(st_rdev=5)), \
                patch.object(console.factory, 'secure_boot'), \
                patch.object(console.recovery_console, 'protected_file', side_effect=protected), \
                patch.object(console.recovery_console, 'secret_from_tty', side_effect=secrets), \
                patch.object(console.recovery_console, 'verify_secret', return_value=False), \
                patch.object(console.sys, 'stdin', stdin), patch.object(console.sys, 'stdout', stdout), \
                patch.object(console.recovery_select, 'select_bound') as select:
            self.assertEqual(console.main(), 1)
            select.assert_not_called()
        self.assertEqual(stdout.getvalue().count('Authentication failed.'), 3)
        self.assertTrue(all(not any(secret) for secret in secrets))

    def test_reboot_requires_successful_selection_in_this_session(self):
        commands = iter(['reboot', 'exit'])
        outputs, reboots = [], []
        console.fixed_menu(read_command=lambda: next(commands), write=outputs.append,
                           select=lambda _: None, reboot=lambda: reboots.append(True))
        self.assertEqual(reboots, [])
        self.assertTrue(any('Select a fallback' in line for line in outputs))

    def test_fallback_requires_confirmation_then_explicit_reboot(self):
        commands = iter(['fallback', '9', 'reboot'])
        outputs, reboots = [], []
        def select(confirm):
            self.assertEqual(confirm(9, 'ab'*32), '9')
            return {'sequence': 9, 'default_changed': False, 'automatic_reboot': False}
        console.fixed_menu(read_command=lambda: next(commands), write=outputs.append,
                           select=select, reboot=lambda: reboots.append(True))
        self.assertEqual(reboots, [True])
        self.assertTrue(any('ab'*32 in line and 'deployment 9' in line for line in outputs))

    def test_failed_reboot_keeps_session_available_for_retry(self):
        commands = iter(['fallback', '9', 'reboot', 'status', 'reboot'])
        outputs, attempts = [], []
        def select(confirm):
            self.assertEqual(confirm(9, 'ab'*32), '9')
            return {'sequence': 9, 'default_changed': False, 'automatic_reboot': False}
        def reboot():
            attempts.append(True)
            if len(attempts) == 1:
                raise subprocess.TimeoutExpired('synthetic', 1)
        console.fixed_menu(read_command=lambda: next(commands), write=outputs.append, select=select, reboot=reboot)
        self.assertEqual(len(attempts), 2)
        self.assertTrue(any('one-shot selection may still be pending' in line for line in outputs))
        self.assertTrue(any('One-shot fallback selected' in line for line in outputs))

    def test_duplicate_fallback_does_not_replace_pending_selection(self):
        commands = iter(['fallback', '9', 'fallback', 'exit'])
        outputs, calls = [], []
        def select(confirm):
            calls.append(confirm(9, 'ab'*32))
            return {'sequence': 9, 'default_changed': False, 'automatic_reboot': False}
        console.fixed_menu(read_command=lambda: next(commands), write=outputs.append,
                           select=select, reboot=lambda: self.fail('unexpected reboot'))
        self.assertEqual(calls, ['9'])
        self.assertTrue(any('already selected' in line for line in outputs))

    def test_failed_selection_does_not_allow_reboot_or_echo_exception(self):
        commands = iter(['fallback', 'reboot', 'exit'])
        outputs, reboots = [], []
        def fail(_):
            raise release.ReleaseError('sensitive fixture')
        console.fixed_menu(read_command=lambda: next(commands), write=outputs.append,
                           select=fail, reboot=lambda: reboots.append(True))
        self.assertEqual(reboots, [])
        self.assertTrue(any('selection failed' in line for line in outputs))
        self.assertFalse(any('sensitive fixture' in line for line in outputs))

    def test_timed_out_selection_returns_to_menu_without_reboot(self):
        commands = iter(['fallback', 'reboot', 'exit'])
        outputs, reboots = [], []
        def fail(_):
            raise subprocess.TimeoutExpired('synthetic', 1)
        console.fixed_menu(read_command=lambda: next(commands), write=outputs.append,
                           select=fail, reboot=lambda: reboots.append(True))
        self.assertEqual(reboots, [])
        self.assertTrue(any('selection failed' in line for line in outputs))

    def test_unknown_command_is_not_executed(self):
        commands = iter(['rm -rf /', 'exit'])
        outputs = []
        console.fixed_menu(read_command=lambda: next(commands), write=outputs.append,
                           select=lambda _: self.fail('selection called'),
                           reboot=lambda: self.fail('reboot called'))
        self.assertTrue(any('Unknown command' in line for line in outputs))


if __name__ == '__main__':
    unittest.main()
