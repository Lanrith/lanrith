"""Runtime diagnostics identify the failure without exposing owner data."""

from contextlib import redirect_stderr
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from lanrith import runtime, update
from lanrith.release import ReleaseError


class RuntimeDiagnosticTests(unittest.TestCase):
    def test_seed_refresh_uses_only_the_verified_esp_and_restores_its_protection(self):
        with tempfile.TemporaryDirectory() as temporary:
            esp = Path(temporary)
            value = {'esp': str(esp)}
            for failure in (False, True):
                commands = []

                def command(arguments, **_):
                    commands.append(arguments)
                    if arguments[0] == 'bootctl' and failure:
                        raise ReleaseError('synthetic seed failure')
                    return ''

                with self.subTest(failure=failure), patch.object(runtime, 'installed', return_value=value), \
                        patch.object(runtime, 'boot_esp', return_value=esp) as verified, \
                        patch.object(runtime, 'command', side_effect=command), \
                        patch.object(update, 'command', side_effect=command), \
                        patch.object(Path, 'is_mount', return_value=True):
                    if failure:
                        with self.assertRaisesRegex(ReleaseError, 'synthetic seed failure'):
                            runtime.refresh_boot_seed()
                    else:
                        runtime.refresh_boot_seed()
                    verified.assert_called_once_with(value)
                    self.assertEqual(commands, [
                        ['mount', '--options', 'remount,rw,nodev,nosuid,noexec', '--', str(esp)],
                        ['bootctl', '--esp-path='+str(esp), '--graceful', 'random-seed'],
                        ['mount', '--options', 'remount,ro,nodev,nosuid,noexec', '--', str(esp)]])

    def test_seed_refresh_refuses_unprivileged_callers_and_unverified_esp(self):
        with patch.object(runtime.os, 'geteuid', return_value=1000), \
                patch.object(runtime, 'command') as command, \
                patch.object(runtime, 'writable_esp') as writable:
            with self.assertRaisesRegex(ReleaseError, 'requires root'):
                runtime.refresh_boot_seed()
            command.assert_not_called()
            writable.assert_not_called()
        with patch.object(runtime, 'installed', return_value={}), \
                patch.object(runtime, 'boot_esp', side_effect=ReleaseError('foreign ESP')), \
                patch.object(runtime, 'command') as command, \
                patch.object(runtime, 'writable_esp') as writable:
            with self.assertRaisesRegex(ReleaseError, 'foreign ESP'):
                runtime.refresh_boot_seed()
            command.assert_not_called()
            writable.assert_not_called()

    def test_telemetry_binds_heartbeat_to_accepted_boot_and_signed_configuration(self):
        value = {'image_id': 'lanrith', 'platform_version': '0.2.0', 'deployment_sequence': 14,
                 'configuration_sha256': 'a'*64, 'boot': {'schema': 1, 'accepted': True,
                     'boot_complete': True, 'boot_id': '12345678-1234-1234-1234-123456789abc',
                     'image_id': 'lanrith', 'platform_version': '0.2.0', 'deployment_sequence': 14,
                     'selected_entry': 'lanrith_14.efi'}}
        with patch.object(runtime, 'status', return_value=value), patch.object(runtime.time, 'monotonic_ns',
                return_value=123456789):
            self.assertEqual(runtime.telemetry(), {'schema': 1, 'event': 'lanrith-heartbeat',
                'boot_id': value['boot']['boot_id'], 'selected_entry': 'lanrith_14.efi',
                'image_id': 'lanrith', 'platform_version': '0.2.0', 'deployment_sequence': 14,
                'configuration_sha256': 'a'*64, 'monotonic_ns': 123456789})
        for change in ({'accepted': False}, {'boot_id': 'wrong'}, {'deployment_sequence': 13}):
            invalid = json.loads(json.dumps(value))
            invalid['boot'].update(change)
            with self.subTest(change=change), patch.object(runtime, 'status', return_value=invalid), \
                    self.assertRaises(Exception):
                runtime.telemetry()

    def test_blessing_opens_esp_only_for_an_unblessed_counted_entry(self):
        with tempfile.TemporaryDirectory() as temporary:
            esp = Path(temporary)
            entries = esp/'EFI/Linux'
            entries.mkdir(parents=True)
            pending = entries/'lanrith_9+3-0.efi'
            stable = entries/'lanrith_9.efi'
            pending.write_bytes(b'signed candidate')
            value = {'uki_name': stable.name}
            commands = []
            def command(arguments, **_):
                commands.append(arguments)
                if arguments[0] == 'systemctl':
                    return 'active\n'
                if arguments[0] == 'bootctl':
                    return str(pending)+'\n'
                if arguments[0].endswith('systemd-bless-boot'):
                    pending.rename(stable)
                    return ''
                raise AssertionError(arguments)
            class Writable:
                def __enter__(self):
                    commands.append(['writable-enter'])
                def __exit__(self, *_):
                    commands.append(['writable-exit'])
            with patch.object(runtime, 'command', side_effect=command), \
                    patch.object(runtime, 'boot_esp', return_value=esp), \
                    patch.object(runtime, 'writable_esp', return_value=Writable()):
                self.assertEqual(runtime.bless(value), stable)
                self.assertIn(['writable-enter'], commands)
                self.assertIn(['writable-exit'], commands)
                # The running stub path remains counted after its file is
                # renamed. A repeated observer validates without reopening it.
                self.assertEqual(runtime.bless(value), stable)
                self.assertEqual(commands.count(['writable-enter']), 1)

    def test_unexpected_failures_report_categories_without_paths_or_input(self):
        secret = 'private-owner-data-that-must-not-be-logged'
        for error in (FileNotFoundError(2, secret, '/private/'+secret), KeyError(secret), ValueError(secret)):
            with self.subTest(exception=type(error).__name__), patch.object(runtime, 'status', side_effect=error):
                output = io.StringIO()
                with redirect_stderr(output):
                    self.assertEqual(runtime.main(['status']), 1)
                message = output.getvalue()
                self.assertIn('operation=status', message)
                self.assertIn('exception='+type(error).__name__, message)
                if isinstance(error, OSError):
                    self.assertIn('errno=2', message)
                self.assertNotIn(secret, message)
                self.assertNotIn('/private/', message)
