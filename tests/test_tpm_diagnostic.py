"""TPM setup evidence must never retain keys or arbitrary journal/status text."""
import json
from pathlib import Path
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from tpm_diagnostic import categories, journal_categories, prepare, status
from vm import Guest


class TpmDiagnosticTests(unittest.TestCase):
    def test_journal_reports_only_fixed_categories(self):
        raw=b'Failed to write SRK: Read-only file system\nprivate recovery key: 1234-abcdef\n'
        self.assertEqual(categories(raw), ['read-only', 'srk', 'write-key'])
        self.assertNotIn('1234', json.dumps(categories(raw)))
        self.assertEqual(categories(b'private-key-'+b'x'*65536), ['oversized-journal'])

    def test_status_rejects_free_text_and_retains_bounded_error_codes(self):
        raw=b'Result=exit-code\nExecMainCode=1\nExecMainStatus=1\nStatusErrno=30\nStatusText=private key\n'
        self.assertEqual(status(raw), {'Result':'exit-code','ExecMainCode':1,'ExecMainStatus':1,'StatusErrno':30})
        self.assertEqual(status(b'Result=private-key\nExecMainStatus=-1\nStatusErrno=99999999999\n'), {})
        self.assertEqual(status(b'x'*65537), {})

    def test_failed_tpm_unit_gets_read_only_properties_without_elevation_or_private_output(self):
        guest=Guest.__new__(Guest)
        guest.ssh=Mock(side_effect=[SimpleNamespace(returncode=0,stdout=b'systemd-tpm2-setup.service loaded failed failed TPM\n'),
            SimpleNamespace(returncode=0,stdout=b'Result=exit-code\nExecMainStatus=1\nStatusText=private recovery key\n')])
        report=guest.service_diagnostic()
        self.assertEqual(report['tpm_setup'],{'Result':'exit-code','ExecMainStatus':1})
        self.assertNotIn('private',json.dumps(report))
        self.assertEqual(guest.ssh.call_args.args[0], 'systemctl show systemd-tpm2-setup.service --property=Result,ExecMainCode,ExecMainStatus,StatusErrno')
        self.assertFalse(guest.ssh.call_args.kwargs['agent'])

    def test_failed_status_collection_does_not_replace_original_failure(self):
        guest=Guest.__new__(Guest)
        guest.ssh=Mock(side_effect=[SimpleNamespace(returncode=0,stdout=b'systemd-tpm2-setup.service loaded failed failed TPM\n'),subprocess.TimeoutExpired('ssh',10)])
        self.assertEqual(guest.service_diagnostic()['tpm_setup'],{})

    def test_only_disposable_image_overlay_gets_onfailure_diagnostics(self):
        with tempfile.TemporaryDirectory() as temporary:
            tree=Path(temporary);prepare(tree)
            unit=(tree/'etc/systemd/system/lanrith-qualification-tpm-diagnostic.service').read_text()
            self.assertIn('NoNewPrivileges=yes',unit)
            self.assertIn('MemoryMax=32M',unit)
            dropin=(tree/'etc/systemd/system/systemd-tpm2-setup.service.d/99-qualification-diagnostic.conf').read_text()
            self.assertEqual(dropin,'[Unit]\nOnFailure=lanrith-qualification-tpm-diagnostic.service\n')
            self.assertNotIn('ExecStart=',dropin)
            self.assertNotIn('SuccessExitStatus',dropin)

    def test_console_failure_retains_static_tpm_categories_without_private_journal_text(self):
        import threading
        guest=Guest.__new__(Guest)
        guest.console=SimpleNamespace(condition=threading.Condition(),data=(
            b'LANRITH_QA_TPM_read-only\nLANRITH_QA_TPM_failure\nprivate recovery material\n'))
        guest.qmp=None;guest.qmp_events=[];guest.observed_diagnostics={};guest.service_state=None
        encoded=guest.diagnostic();report=json.loads(encoded)
        self.assertTrue(report['flags']['qa-tpm-read-only'])
        self.assertTrue(report['flags']['qa-tpm-failure'])
        self.assertNotIn('private recovery',encoded)

    def test_structured_errno_preserves_the_cause_without_emitting_message_or_unknown_codes(self):
        raw=b'{"MESSAGE":"private SRK contents never emitted", "ERRNO":"30"}\n'
        self.assertEqual(journal_categories(raw), ['read-only','srk'])
        self.assertEqual(journal_categories(b'{"MESSAGE":"secret", "ERRNO":"123456789"}\n'), [])
        self.assertEqual(journal_categories(b'private invalid json'), ['malformed-journal'])
        self.assertEqual(journal_categories(b'x'*65537), ['oversized-journal'])
