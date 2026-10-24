"""Runtime diagnostics identify the failure without exposing owner data."""

from contextlib import redirect_stderr
import io
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from lanrith import runtime


class RuntimeDiagnosticTests(unittest.TestCase):
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
