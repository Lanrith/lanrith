"""Proposed compiler fixes must be authenticated and used by the real source scan."""
import subprocess
import tempfile
from pathlib import Path
import unittest
from unittest.mock import patch

from automation import inputs, proposal
from automation.common import MaintenanceError


class ProposalGoScanTests(unittest.TestCase):
    policy = {'go_branches': ['1.26', '1.27']}
    reason = {'type': 'security-fix', 'ecosystem': 'Go', 'package': 'stdlib',
              'installed': '1.27.3', 'fixed': '1.27.4', 'id': 'GO-2026-6859'}

    def scan(self, selected='1.27.4', *, reasons=None, reported=b'go1.27.4\n',
             compiler_code=0, scanner_code=0, authenticate=None):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root/'.go-version').write_text(selected+'\n')
            with patch.object(inputs, 'validate_reason', side_effect=authenticate) as validate, \
                    patch.object(proposal.subprocess, 'run') as command:
                command.side_effect = [subprocess.CompletedProcess([], compiler_code, reported, b'SDK diagnostic'),
                    subprocess.CompletedProcess([], scanner_code, b'Scanner result', b'Scanner diagnostic')]
                try:
                    proposal.scan_go(root, '1.27.3', [self.reason] if reasons is None else reasons, self.policy)
                finally:
                    self.calls = command.call_args_list
                    self.validations = validate.call_args_list

    def test_exact_security_patch_is_verified_before_execution_and_used_for_both_commands(self):
        self.scan()
        self.assertEqual([c.args[0] for c in self.calls], [['go', 'env', 'GOVERSION'], ['govulncheck', './...']])
        self.assertEqual(self.validations[0].args[0], self.reason)
        for call in self.calls:
            env = call.kwargs['env']
            self.assertEqual(env['GOTOOLCHAIN'], 'go1.27.4')
            self.assertEqual(env['GOPROXY'], 'https://proxy.golang.org')
            self.assertEqual(env['GOSUMDB'], 'sum.golang.org')
            self.assertEqual(env['GOWORK'], 'off')

    def test_unchanged_reviewed_compiler_still_scans_without_inventing_an_update_reason(self):
        self.scan('1.27.3', reasons=[], reported=b'go1.27.3\n')
        self.assertEqual(len(self.calls), 2)
        self.assertFalse(self.validations)

    def test_arbitrary_toolchains_or_unjustified_changes_never_execute(self):
        for selected in ('1.27.4+auto', '1.27rc1', '1.28.1', '1.26.11', '1.27.2'):
            with self.subTest(selected=selected), self.assertRaises(MaintenanceError):
                self.scan(selected)
            self.assertFalse(self.calls)
        with self.assertRaisesRegex(MaintenanceError, 'matching security-fix'):
            self.scan(reasons=[])
        self.assertFalse(self.calls)

    def test_changed_advisory_evidence_never_executes_the_proposed_sdk(self):
        with self.assertRaisesRegex(MaintenanceError, 'changed advisory'):
            self.scan(authenticate=MaintenanceError('changed advisory'))
        self.assertFalse(self.calls)

    def test_failed_download_or_wrong_actual_compiler_never_reaches_scanner(self):
        for reported, code in ((b'go1.27.3\n', 0), (b'go1.27.4\n', 1)):
            with self.subTest(reported=reported, code=code), self.assertRaisesRegex(MaintenanceError, 'exact verified'):
                self.scan(reported=reported, compiler_code=code)
            self.assertEqual(len(self.calls), 1)

    def test_reachable_vulnerability_and_incomplete_scan_both_block(self):
        for code in (1, 3):
            with self.subTest(code=code), self.assertRaisesRegex(MaintenanceError, 'Reachable Go vulnerability'):
                self.scan(scanner_code=code)
