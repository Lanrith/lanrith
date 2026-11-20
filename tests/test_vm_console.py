"""Slow qualification operations cannot back up the guest's serial console."""

import json
import socket
import subprocess
import threading
from types import SimpleNamespace
import unittest
from unittest.mock import Mock

from vm import Guest, SerialReader, boot, tpm_diagnostic
from lanrith.release import ReleaseError


class ConsoleTests(unittest.TestCase):
    def test_tpm_diagnostic_only_retains_known_categories_and_bounded_numeric_codes(self):
        data = (b'Failed to get or create SRK: private-error-detail\n'
                b'ERROR:esys:src/tss2-esys/api/Esys_ReadPublic.c:98:Esys_ReadPublic() '
                b'Esys Finish ErrorCode (0x0000018B)\n'
                b'Esys_ReadPublic() Esys Finish ErrorCode (private-secret)\n'
                b'Esys_ReadPublic() Esys Finish ErrorCode (0x00000000001)\n'
                b'private-recovery-key\n')
        value = tpm_diagnostic(data)
        self.assertEqual(value, {'errors': ['srk-get-or-create'], 'tss2_codes': ['0x0000018b']})
        self.assertNotIn('private-', json.dumps(value))
        self.assertEqual(tpm_diagnostic(b''), {'errors': [], 'tss2_codes': []})
        many = b''.join(('Esys_ReadPublic() Esys Finish ErrorCode (0x%08x)\n' % code).encode()
                        for code in range(100))
        self.assertEqual(len(tpm_diagnostic(many)['tss2_codes']), 16)

    def test_failed_unit_diagnostic_keeps_complete_names_and_excludes_private_text(self):
        guest = Guest.__new__(Guest)
        guest.ssh = Mock(return_value=SimpleNamespace(returncode=0, stdout=(
            b'systemd-hostnamed.socket loaded failed failed Hostname Service Socket\n'
            b'boot-complete.target loaded failed failed Boot Complete\n'
            b'disposable-recovery-key-never-log-this\n'), stderr=b'disposable-private-ssh-diagnostic'))
        value = guest.service_diagnostic()
        self.assertEqual(value, {'query_succeeded': True, 'failed_units': [
            'boot-complete.target', 'systemd-hostnamed.socket']})
        self.assertNotIn('disposable-', json.dumps(value))
        guest.ssh.assert_called_once_with(
            'systemctl list-units --failed --all --full --plain --no-legend --no-pager',
            success=False, timeout=10, agent=False)

    def test_unavailable_ssh_diagnostic_does_not_replace_the_original_boot_failure(self):
        guest = Guest.__new__(Guest)
        guest.ssh = Mock(side_effect=subprocess.TimeoutExpired('ssh', 10))
        self.assertEqual(guest.service_diagnostic(), {'query_succeeded': False, 'failed_units': []})

    def test_failed_service_exit_status_is_read_without_elevation_or_private_output(self):
        guest = Guest.__new__(Guest)
        guest.ssh = Mock(side_effect=[
            SimpleNamespace(returncode=0, stdout=b'systemd-tpm2-setup.service loaded failed failed TPM SRK Setup\n'),
            SimpleNamespace(returncode=0, stdout=(
                b'Id=systemd-tpm2-setup.service\nResult=exit-code\nExecMainCode=1\n'
                b'ExecMainStatus=1\nStatusErrno=5\n'), stderr=b'disposable-private-error')])
        value = guest.service_diagnostic()
        self.assertEqual(value['unit_status'], {'systemd-tpm2-setup.service': {
            'Result': 'exit-code', 'ExecMainCode': 1, 'ExecMainStatus': 1, 'StatusErrno': 5}})
        self.assertNotIn('disposable-', json.dumps(value))
        self.assertFalse(guest.ssh.call_args.kwargs['agent'])
        self.assertNotIn('sudo', guest.ssh.call_args.args[0])

    def test_private_malformed_or_unrequested_service_properties_are_not_published(self):
        valid = (b'Id=systemd-tpm2-setup.service\nResult=exit-code\nExecMainCode=1\n'
                 b'ExecMainStatus=1\nStatusErrno=0\n')
        for output in (valid.replace(b'Result=exit-code', b'Result=disposable-secret'),
                       valid.replace(b'ExecMainStatus=1', b'ExecMainStatus=disposable-secret'),
                       valid.replace(b'StatusErrno=0', b'StatusErrno=999999'),
                       valid.replace(b'systemd-tpm2-setup.service', b'disposable-secret.service'),
                       valid+b'Result=success\n', valid+b'StatusText=disposable-secret\n', b'x'*65537):
            with self.subTest(output=output[:40]):
                guest = Guest.__new__(Guest)
                guest.ssh = Mock(side_effect=[
                    SimpleNamespace(returncode=0, stdout=b'systemd-tpm2-setup.service loaded failed failed TPM\n'),
                    SimpleNamespace(returncode=0, stdout=output)])
                value = guest.service_diagnostic()
                self.assertEqual(value['unit_status'], {})
                self.assertNotIn('disposable-', json.dumps(value))

    def test_failed_property_query_keeps_the_original_failed_unit(self):
        guest = Guest.__new__(Guest)
        guest.ssh = Mock(side_effect=[
            SimpleNamespace(returncode=0, stdout=b'systemd-tpm2-setup.service loaded failed failed TPM\n'),
            subprocess.TimeoutExpired('ssh', 10)])
        self.assertEqual(guest.service_diagnostic(), {'query_succeeded': True,
            'failed_units': ['systemd-tpm2-setup.service'], 'unit_status': {}})

    def test_emergency_mode_stops_boot_before_sending_credentials_or_attempting_ssh(self):
        for manual, first in ((False, True), (True, True), (True, False)):
            with self.subTest(manual=manual, first=first):
                guest = Mock()
                guest.expect_any.return_value = 1
                guest.last_diagnostic = '{"flags":{"emergency-mode":true}}'
                with self.assertRaises(ReleaseError):
                    boot(guest, manual=manual, first=first)
                guest.serial.sendall.assert_not_called()
                guest.ready.assert_not_called()

    def test_consuming_a_recovery_prompt_preserves_only_safe_initrd_failure_categories(self):
        guest = Guest.__new__(Guest)
        guest.console = SimpleNamespace(condition=threading.Condition(), data=(
            b'Failed to start lanrith-factory.service\nFactory installation failed closed.\n'
            b'Failed to get or create SRK: private-tpm-detail\n'
            b'disposable-recovery-key-never-log-this\nType RECOVERY-KEY-STORED: '))
        guest.qmp = None
        guest.qmp_events = []
        guest.observed_diagnostics = {}
        guest.diagnostic()
        guest.buffer = b'Failed to start systemd-boot-check-no-failures.service\n'
        encoded = guest.diagnostic()
        value = json.loads(encoded)
        self.assertEqual(value['failed_units'], ['lanrith-factory.service',
                                                'systemd-boot-check-no-failures.service'])
        self.assertEqual(value['literal_errors'], ['Factory installation failed closed.'])
        self.assertTrue(value['flags']['recovery-prompt'])
        self.assertEqual(value['tpm']['errors'], ['srk-get-or-create'])
        self.assertNotIn('private-tpm-detail', encoded)
        self.assertNotIn('disposable-recovery-key', encoded)

    def test_serial_selection_diagnostic_keeps_only_allowlisted_command(self):
        guest = Guest.__new__(Guest)
        guest.console = SimpleNamespace(condition=threading.Condition(), data=(
            b'Synthetic serial selection diagnostic: release update.py:command:32 errno=2 command=bootctl\n'
            b'private-serial-input-do-not-log\n'))
        guest.qmp = None
        guest.qmp_events = []
        guest.observed_diagnostics = {}
        encoded = guest.diagnostic()
        self.assertIn('errno=2 command=bootctl', encoded)
        self.assertNotIn('private-serial-input', encoded)

    def test_console_drains_without_an_expect_call_and_retains_bounded_output(self):
        receiving, sending = socket.socketpair()
        receiving.settimeout(0.05)
        sending.settimeout(3)
        console = SerialReader(receiving)
        marker = b'disposable-console-end'
        try:
            # More than a socket buffer or the retained console history. A
            # synchronous reader would block this send during an SSH operation.
            sending.sendall(b'x'*(2*SerialReader.LIMIT)+marker)
            with console.condition:
                self.assertTrue(console.condition.wait_for(lambda: console.data.endswith(marker), timeout=3))
                self.assertLessEqual(len(console.data), SerialReader.LIMIT)
        finally:
            sending.close()
            console.close()
        self.assertFalse(console.thread.is_alive())
        self.assertEqual(console.data, b'')

    def test_console_eof_wakes_waiters_and_cleanup_is_idempotent(self):
        receiving, sending = socket.socketpair()
        receiving.settimeout(0.05)
        console = SerialReader(receiving)
        try:
            sending.shutdown(socket.SHUT_WR)
            with console.condition:
                self.assertTrue(console.condition.wait_for(lambda: console.closed, timeout=3))
        finally:
            sending.close()
            console.close()
        console.close()
        self.assertFalse(console.thread.is_alive())
