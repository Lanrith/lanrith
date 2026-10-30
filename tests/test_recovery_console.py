"""Recovery console accepts only a physical, authenticated, fixed command set."""

import hashlib
import io
import json
from pathlib import Path
import stat
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from lanrith import recovery_console as console, release


class ConsoleTests(unittest.TestCase):
    def policy(self):
        return {'schema': 1, 'tty': 'ttyS0', 'image_id': 'lanrith',
                'disk_by_id': '/dev/disk/by-id/synthetic-router-disk'}

    def hash(self):
        salt = bytes.fromhex('11'*16)
        digest = hashlib.scrypt(b'synthetic-passphrase', salt=salt, n=32768, r=8, p=1,
                                dklen=32, maxmem=64*1024*1024)
        return 'scrypt:32768:8:1:'+salt.hex()+':'+digest.hex()

    def test_policy_rejects_arbitrary_paths_unknown_fields_and_non_serial_ttys(self):
        self.assertEqual(console.policy(self.policy()), self.policy())
        for tty in ('ttyUSB0', 'ttyAMA1', 'hvc0'):
            self.assertEqual(console.policy({**self.policy(), 'tty': tty})['tty'], tty)
        for change in ({'tty': 'tty0'}, {'tty': '../../ttyS0'}, {'image_id': '../router'},
                       {'disk_by_id': '/dev/disk/by-id/..'}, {'disk_by_id': '/dev/sda'},
                       {'schema': True}, {'command': '/bin/sh'}, {'state_uuid': '../wrong'}):
            with self.subTest(change=change), self.assertRaises(release.ReleaseError):
                console.policy({**self.policy(), **change})
        state_uuid = '12345678-1234-1234-1234-123456789abc'
        self.assertEqual(console.policy({**self.policy(), 'state_uuid': state_uuid})['state_uuid'], state_uuid)

    def test_offline_inputs_require_bounded_distinct_disk_and_partition_bindings(self):
        inputs = {'release_disk_by_id': '/dev/disk/by-id/synthetic-release-disk',
                  'release_partition_uuid': '12345678-1234-1234-1234-123456789abc',
                  'target_esp_uuid': 'abcdefab-1234-1234-1234-123456789abc'}
        value = {**self.policy(), 'offline_inputs': inputs}
        self.assertEqual(console.policy(value), value)
        for change in ({'release_disk_by_id': self.policy()['disk_by_id']},
                       {'release_disk_by_id': '/dev/disk/by-id/synthetic-part1'},
                       {'release_disk_by_id': '/dev/sda'},
                       {'release_partition_uuid': '../bad'},
                       {'target_esp_uuid': inputs['release_partition_uuid']},
                       {'extra': 'unexpected'}):
            with self.subTest(change=change), self.assertRaises(release.ReleaseError):
                console.policy({**value, 'offline_inputs': {**inputs, **change}})
        with self.assertRaises(release.ReleaseError):
            console.policy({**self.policy(), 'disk_by_id': '/dev/disk/by-id/synthetic-part2'})

    def test_secret_verification_is_bounded_and_wrong_input_fails(self):
        stored = self.hash()
        self.assertTrue(console.verify_secret(bytearray(b'synthetic-passphrase'), stored))
        for secret, value in ((bytearray(b'wrong'), stored), (bytearray(b'a'*513), stored),
                              (bytearray(b'bad\0value'), stored), (bytearray(b'x'), 'malformed'),
                              (b'synthetic-passphrase', stored)):
            with self.subTest(value=value[:12]):
                self.assertFalse(console.verify_secret(secret, value))

    def test_fixed_menu_never_interprets_arbitrary_commands_or_authorizes_boot(self):
        messages = []
        commands = iter(['status', 'rm -rf /', 'inspect', 'exit'])
        calls = []
        def inspect(value):
            calls.append(value)
            return {'deployment_sequence': 17, 'authorized_to_boot': False}
        console.fixed_menu(self.policy(), read_command=lambda: next(commands), write=messages.append, inspect=inspect)
        self.assertEqual(calls, [self.policy()])
        self.assertTrue(any('Unknown command' in message for message in messages))
        self.assertTrue(any('Boot compatibility is not established' in message for message in messages))
        self.assertTrue(all('rm -rf' not in message for message in messages))
        messages.clear()
        commands = iter(['inspect', 'exit'])
        console.fixed_menu(self.policy(), read_command=lambda: next(commands), write=messages.append,
                           inspect=lambda _: {'deployment_sequence': 17, 'authorized_to_boot': True})
        self.assertTrue(any('inspection failed' in message for message in messages))

    def test_restore_policy_requires_same_target_and_state_identity(self):
        uuid = '12345678-1234-1234-1234-123456789abc'
        binding = {'schema': 1, 'target_disk_by_id': self.policy()['disk_by_id'],
                   'state_partuuid': '22345678-1234-1234-1234-123456789abc', 'state_uuid': uuid,
                   'backup_disk_by_id': '/dev/disk/by-id/synthetic-backup',
                   'backup_partuuid': '32345678-1234-1234-1234-123456789abc'}
        value = {**self.policy(), 'state_uuid': uuid, 'offline_backup': binding}
        self.assertEqual(console.policy(value), value)
        for changed in ({'target_disk_by_id': '/dev/disk/by-id/other'},
                        {'state_uuid': '42345678-1234-1234-1234-123456789abc'},
                        {'backup_disk_by_id': self.policy()['disk_by_id']}):
            with self.assertRaises(release.ReleaseError):
                console.policy({**value, 'offline_backup': {**binding, **changed}})

    def test_restore_is_not_offered_without_qualified_callback(self):
        commands = iter(['restore', 'exit'])
        messages = []
        console.fixed_menu({**self.policy(), 'offline_backup': {}}, read_command=lambda: next(commands),
                           write=messages.append, inspect=lambda _: None)
        self.assertTrue(any('Unknown command' in line for line in messages))
        self.assertTrue(any('No boot or disk writes' in line for line in messages))

    def test_backup_requires_confirmation_and_clears_key(self):
        binding = {'target_disk_by_id': '/dev/disk/by-id/synthetic-router',
                   'backup_disk_by_id': '/dev/disk/by-id/synthetic-backup'}
        value = {**self.policy(), 'offline_backup': binding}
        key = bytearray(b'synthetic-recovery-key')
        commands = iter(['backup', 'no', 'backup', 'BACKUP', 'exit'])
        calls, messages = [], []
        name = 'backup-'+'a'*32
        def backup(policy, secret):
            calls.append((policy, bytes(secret)))
            return {'backup_id': name, 'authorized_to_restore': False}
        console.fixed_menu(value, read_command=lambda: next(commands), write=messages.append, inspect=lambda _: None,
                           read_backup_key=lambda: key, backup=backup)
        self.assertEqual(calls, [(value, b'synthetic-recovery-key')])
        self.assertEqual(key, bytearray(len(key)))
        self.assertTrue(any('Backup cancelled' in line for line in messages))
        self.assertTrue(any(name in line and 'Backup created:' in line for line in messages))

    def test_backup_is_not_offered_without_qualified_callback(self):
        commands, messages = iter(['backup', 'exit']), []
        console.fixed_menu({**self.policy(), 'offline_backup': {}}, read_command=lambda: next(commands),
                           write=messages.append, inspect=lambda _: None)
        self.assertTrue(any('Unknown command' in line for line in messages))
        self.assertTrue(any('No boot or disk writes' in line for line in messages))

    def test_each_operation_requires_all_its_boolean_qualification_gates(self):
        backup = SimpleNamespace(BACKUP_WRITE_QUALIFIED=True)
        preflight = SimpleNamespace(READONLY_PREPARATION_QUALIFIED=True)
        restore = SimpleNamespace(RESTORE_WORKFLOW_QUALIFIED=True, BACKUP_FRESHNESS_QUALIFIED=True)
        target = SimpleNamespace(TARGET_CLAIM_QUALIFIED=True)
        transaction = SimpleNamespace(RESTORE_WRITE_QUALIFIED=True)
        modules = (backup, preflight, restore, target, transaction)
        self.assertEqual(console.qualified_operations(*modules), (True, True))
        for module, name, expected in (
            (backup, 'BACKUP_WRITE_QUALIFIED', (False, True)),
            (preflight, 'READONLY_PREPARATION_QUALIFIED', (False, False)),
            (restore, 'RESTORE_WORKFLOW_QUALIFIED', (True, False)),
            (restore, 'BACKUP_FRESHNESS_QUALIFIED', (True, False)),
            (target, 'TARGET_CLAIM_QUALIFIED', (True, False)),
            (transaction, 'RESTORE_WRITE_QUALIFIED', (True, False)),
        ):
            for unqualified in (False, 1, 'true'):
                with self.subTest(gate=name, value=unqualified), patch.object(module, name, unqualified):
                    self.assertEqual(console.qualified_operations(*modules), expected)

    def test_backup_failure_clears_key_and_hides_exception(self):
        value = {**self.policy(), 'offline_backup': {'target_disk_by_id': '/dev/disk/by-id/target',
                                                     'backup_disk_by_id': '/dev/disk/by-id/backup'}}
        key = bytearray(b'synthetic-recovery-key')
        commands, messages = iter(['backup', 'BACKUP', 'exit']), []
        def fail(*args):
            raise release.ReleaseError('synthetic-sensitive-details')
        console.fixed_menu(value, read_command=lambda: next(commands), write=messages.append, inspect=lambda _: None,
                           read_backup_key=lambda: key, backup=fail)
        self.assertEqual(key, bytearray(len(key)))
        self.assertTrue(any('Backup failed' in line for line in messages))
        self.assertFalse(any('synthetic-sensitive-details' in line for line in messages))

    def test_restore_displays_measurement_confirms_id_and_erases_key(self):
        name = 'backup-'+'a'*32
        key = bytearray(b'synthetic-recovery-key')
        commands = iter(['restore', name, name, 'exit'])
        messages, calls = [], []
        def restore(value, selected, secret, confirm):
            calls.append((selected, bytes(secret), confirm(selected, 'ab'*32)))
            return {'authorized_to_boot': False}
        console.fixed_menu({**self.policy(), 'offline_backup': {}}, read_command=lambda: next(commands),
                           write=messages.append, inspect=lambda _: None,
                           read_restore_key=lambda: key, restore=restore)
        self.assertEqual(calls, [(name, b'synthetic-recovery-key', name)])
        self.assertTrue(any('ab'*32 in line and 'replaces encrypted state' in line for line in messages))
        self.assertEqual(key, bytearray(len(key)))

    def test_restore_failure_erases_key_and_does_not_echo_exception(self):
        name = 'backup-'+'a'*32
        key = bytearray(b'synthetic-recovery-key')
        commands = iter(['restore', name, 'exit'])
        messages = []
        def fail(*args):
            raise release.ReleaseError('synthetic-sensitive-details')
        console.fixed_menu({**self.policy(), 'offline_backup': {}}, read_command=lambda: next(commands),
                           write=messages.append, inspect=lambda _: None,
                           read_restore_key=lambda: key, restore=fail)
        self.assertEqual(key, bytearray(len(key)))
        self.assertTrue(any('Restore failed' in line for line in messages))
        self.assertFalse(any('synthetic-sensitive-details' in line for line in messages))

    def test_slot_inspection_requires_a_verified_root_on_another_disk(self):
        value = self.policy()
        with patch.object(Path, 'resolve', return_value=Path('/dev/synthetic')), \
                patch.object(console.factory, 'secure_boot'), \
                patch.object(console.factory, 'verified_root', return_value=('/dev/recovery', [])) as verified, \
                patch.object(console.repair, 'inspect_slot', return_value={'authorized_to_boot': False}) as inspect:
            self.assertFalse(console.inspect_configured(value)['authorized_to_boot'])
            verified.assert_called_once_with('/sysroot')
            inspect.assert_called_once()
        with patch.object(Path, 'resolve', return_value=Path('/dev/synthetic')), \
                patch.object(console.factory, 'secure_boot'), \
                patch.object(console.factory, 'verified_root', return_value=('/dev/synthetic', [])), \
                patch.object(console.repair, 'inspect_slot') as inspect, self.assertRaises(release.ReleaseError):
            console.inspect_configured(value)
        inspect.assert_not_called()
        with patch.object(Path, 'resolve', return_value=Path('/dev/synthetic')), \
                patch.object(console.factory, 'secure_boot'), \
                patch.object(console.factory, 'verified_root', side_effect=release.ReleaseError('unverified')), \
                patch.object(console.repair, 'inspect_slot') as inspect, self.assertRaises(release.ReleaseError):
            console.inspect_configured(value)
        inspect.assert_not_called()
        with patch.object(Path, 'resolve', return_value=Path('/dev/synthetic')), \
                patch.object(console.factory, 'secure_boot', side_effect=release.ReleaseError('insecure')), \
                patch.object(console.repair, 'inspect_slot') as inspect, self.assertRaises(release.ReleaseError):
            console.inspect_configured(value)
        inspect.assert_not_called()

    def test_slot_inspection_uses_bound_offline_inputs_after_verified_boot(self):
        value = {**self.policy(), 'offline_inputs': {'release_disk_by_id': '/dev/disk/by-id/synthetic-release',
                 'release_partition_uuid': '12345678-1234-1234-1234-123456789abc',
                 'target_esp_uuid': 'abcdefab-1234-1234-1234-123456789abc'}}
        with patch.object(Path, 'resolve', return_value=Path('/dev/synthetic')), \
                patch.object(console.factory, 'secure_boot') as secure, \
                patch.object(console.factory, 'verified_root', return_value=('/dev/recovery', set())), \
                patch('lanrith.recovery_inputs.inspect', return_value={'authorized_to_boot': False}) as inspect:
            self.assertFalse(console.inspect_configured(value)['authorized_to_boot'])
            secure.assert_called_once()
            inspect.assert_called_once_with(value, target_disk='/dev/synthetic', recovery_disk='/dev/recovery',
                                            certificate=console.CERTIFICATE)

    def test_terminal_echo_is_restored_after_read_failure(self):
        stream = SimpleNamespace(fileno=lambda: 9, readline=lambda _: (_ for _ in ()).throw(OSError('read failure')))
        saved = [1, 2, 3, 15, 5, 6, []]
        output = io.StringIO()
        with patch.object(console.termios, 'tcgetattr', return_value=saved), \
                patch.object(console.termios, 'tcsetattr') as change:
            with self.assertRaises(OSError):
                console.secret_from_tty(stream, output)
        self.assertEqual(change.call_count, 2)
        self.assertFalse(change.call_args_list[0].args[2][3] & console.termios.ECHO)
        self.assertEqual(change.call_args_list[1].args[2], saved)

    def test_state_inspection_requires_a_binding_and_wipes_the_offline_key(self):
        value = {**self.policy(), 'state_uuid': '12345678-1234-1234-1234-123456789abc'}
        for fail in (False, True):
            secret = bytearray(b'synthetic-offline-key')
            messages = []
            commands = iter(['inspect-state', 'exit'])
            def inspect_state(actual, actual_secret):
                self.assertEqual(actual, value)
                self.assertIs(actual_secret, secret)
                if fail:
                    raise release.ReleaseError('sensitive synthetic detail')
                return 'available'
            console.fixed_menu(value, read_command=lambda: next(commands), write=messages.append,
                               inspect=lambda _: None, read_state_key=lambda: secret, inspect_state=inspect_state)
            self.assertFalse(any(secret))
            self.assertNotIn('synthetic-offline-key', ''.join(messages))
            self.assertNotIn('sensitive synthetic detail', ''.join(messages))
            self.assertTrue(any(('State inspection failed' if fail else 'opened read-only') in item for item in messages))
        commands = iter(['inspect-state', 'exit'])
        calls = []
        console.fixed_menu(self.policy(), read_command=lambda: next(commands), write=lambda _: None,
                           inspect=lambda _: None, read_state_key=lambda: calls.append('key'),
                           inspect_state=lambda *_: calls.append('inspect'))
        self.assertEqual(calls, [])

    def test_state_inspection_denies_a_disabled_secure_boot(self):
        value = {**self.policy(), 'state_uuid': '12345678-1234-1234-1234-123456789abc'}
        with patch.object(Path, 'resolve', return_value=Path('/dev/synthetic')), \
                patch.object(console.factory, 'secure_boot', side_effect=release.ReleaseError('insecure')), \
                patch('lanrith.recovery_state.open_readonly') as open_state, self.assertRaises(release.ReleaseError):
            console.inspect_state_configured(value, bytearray(b'synthetic-key'))
        open_state.assert_not_called()

    def test_state_failure_reports_only_allowlisted_stages(self):
        value = {**self.policy(), 'state_uuid': '12345678-1234-1234-1234-123456789abc'}
        for error, expected in (('Recovery key operation failed.', 'key or volume'),
                                ('Update command failed: mount', 'read-only filesystem mount'),
                                ('secret-shaped-data', None)):
            commands = iter(['inspect-state', 'exit'])
            messages = []
            def fail(*_):
                raise release.ReleaseError(error)
            console.fixed_menu(value, read_command=lambda: next(commands), write=messages.append,
                               inspect=lambda _: None, read_state_key=lambda: bytearray(b'test'), inspect_state=fail)
            if expected:
                self.assertIn(expected, ''.join(messages))
            else:
                self.assertNotIn(error, ''.join(messages))

    def test_terminal_echo_is_disabled_before_prompt_is_shown(self):
        stream = SimpleNamespace(fileno=lambda: 9, readline=lambda _: b'synthetic\n')
        saved = [1, 2, 3, 15, 5, 6, []]
        with patch.object(console.termios, 'tcgetattr', return_value=saved), \
                patch.object(console.termios, 'tcsetattr') as change:
            class Output(io.StringIO):
                def write(self, value):
                    if value.startswith('Recovery passphrase'):
                        self.assert_echo_disabled()
                    return super().write(value)
                def assert_echo_disabled(self):
                    if change.call_count != 1 or change.call_args.args[2][3] & console.termios.ECHO:
                        raise AssertionError('Prompt appeared before terminal echo was disabled.')
            self.assertEqual(console.secret_from_tty(stream, Output()), bytearray(b'synthetic'))

    def test_three_bad_credentials_cannot_invoke_inspection(self):
        class Input:
            buffer = object()
            def isatty(self): return True
            def fileno(self): return 4
        class Output(io.StringIO):
            def isatty(self): return True
            def fileno(self): return 5
        stored = self.hash().encode()
        protected = lambda path, *_args, **_kwargs: json.dumps(self.policy()).encode() if path == console.POLICY else stored
        terminal = SimpleNamespace(st_mode=stat.S_IFCHR | 0o600, st_rdev=10)
        wrong = [bytearray(b'wrong') for _ in range(3)]
        out = Output()
        with patch.object(console.os, 'geteuid', return_value=0), patch.object(Path, 'is_file', return_value=True), \
                patch.object(console.factory, 'secure_boot'), patch.object(console.factory, 'verified_root'), \
                patch.object(Path, 'stat', return_value=terminal), patch.object(console.os, 'fstat', return_value=terminal), \
                patch.object(console, 'protected_file', side_effect=protected), \
                patch.object(console, 'secret_from_tty', side_effect=wrong), \
                patch.object(console, 'inspect_configured') as inspect, \
                patch.object(console.sys, 'stdin', Input()), patch.object(console.sys, 'stdout', out):
            self.assertEqual(console.main(), 1)
        inspect.assert_not_called()
        self.assertTrue(all(not any(item) for item in wrong))
        self.assertNotIn('wrong', out.getvalue())

    def test_authenticated_session_can_only_run_the_read_only_inspector(self):
        class Input:
            buffer = object()
            def __init__(self): self.lines = iter(['inspect\n', 'exit\n'])
            def isatty(self): return True
            def fileno(self): return 4
            def readline(self, _): return next(self.lines)
        class Output(io.StringIO):
            def isatty(self): return True
            def fileno(self): return 5
        protected = lambda path, *_args, **_kwargs: json.dumps(self.policy()).encode() if path == console.POLICY else self.hash().encode()
        terminal = SimpleNamespace(st_mode=stat.S_IFCHR | 0o600, st_rdev=10)
        secret = bytearray(b'synthetic-passphrase')
        out = Output()
        with patch.object(console.os, 'geteuid', return_value=0), patch.object(Path, 'is_file', return_value=True), \
                patch.object(console.factory, 'secure_boot'), patch.object(console.factory, 'verified_root'), \
                patch.object(Path, 'stat', return_value=terminal), patch.object(console.os, 'fstat', return_value=terminal), \
                patch.object(console, 'protected_file', side_effect=protected), \
                patch.object(console, 'secret_from_tty', return_value=secret), \
                patch.object(console, 'inspect_configured', return_value={'deployment_sequence': 17,
                                                                          'authorized_to_boot': False}) as inspect, \
                patch.object(console.sys, 'stdin', Input()), patch.object(console.sys, 'stdout', out):
            self.assertEqual(console.main(), 0)
        inspect.assert_called_once_with(self.policy())
        self.assertFalse(any(secret))
        self.assertIn('Boot compatibility is not established', out.getvalue())
        self.assertNotIn('synthetic-passphrase', out.getvalue())

    def test_untrusted_recovery_environment_cannot_prompt(self):
        for failing in ('secure_boot', 'verified_root'):
            with self.subTest(failing=failing), \
                    patch.object(console.os, 'geteuid', return_value=0), \
                    patch.object(Path, 'is_file', return_value=True), \
                    patch.object(console.factory, 'secure_boot') as secure_boot, \
                    patch.object(console.factory, 'verified_root') as verified_root, \
                    patch.object(console, 'secret_from_tty') as prompt:
                (secure_boot if failing == 'secure_boot' else verified_root).side_effect = release.ReleaseError('untrusted')
                with self.assertRaises(release.ReleaseError):
                    console.main()
                prompt.assert_not_called()

    def test_wrong_terminal_cannot_prompt_or_inspect(self):
        class Terminal:
            def isatty(self): return True
            def fileno(self): return 4
        terminal = SimpleNamespace(st_mode=stat.S_IFCHR | 0o600, st_rdev=10)
        wrong_terminal = SimpleNamespace(st_mode=stat.S_IFCHR | 0o600, st_rdev=11)
        with patch.object(console.os, 'geteuid', return_value=0), patch.object(Path, 'is_file', return_value=True), \
                patch.object(console.factory, 'secure_boot'), patch.object(console.factory, 'verified_root'), \
                patch.object(Path, 'stat', return_value=terminal), patch.object(console.os, 'fstat', return_value=wrong_terminal), \
                patch.object(console, 'protected_file', return_value=json.dumps(self.policy()).encode()), \
                patch.object(console, 'secret_from_tty') as prompt, \
                patch.object(console.sys, 'stdin', Terminal()), patch.object(console.sys, 'stdout', Terminal()):
            with self.assertRaises(release.ReleaseError):
                console.main()
        prompt.assert_not_called()


if __name__ == '__main__':
    unittest.main()
