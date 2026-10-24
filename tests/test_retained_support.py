"""Retirement cannot hide scanner outages or an unsafe newest release."""

import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from lanrith.release import ReleaseError

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('retained_security', ROOT/'scripts/security-audit.py')
audit = importlib.util.module_from_spec(spec)
spec.loader.exec_module(audit)


class RetainedSupportTests(unittest.TestCase):
    def test_an_unsafe_latest_release_cannot_retire_itself_or_an_older_release(self):
        newest = {'result': 'fail', 'scanner_errors': [], 'supported': True, 'platform_version': '1.0.2'}
        older = {'result': 'fail', 'scanner_errors': [], 'supported': True, 'platform_version': '1.0.1'}
        audit.support_decisions([(None, newest), (None, older)])
        self.assertTrue(newest['supported'])
        self.assertTrue(older['supported'])

    def test_a_fixed_new_release_retires_known_findings_but_keeps_unknown_coverage_blocking(self):
        newest = {'result': 'pass', 'scanner_errors': [], 'supported': True, 'platform_version': '1.0.3'}
        vulnerable = {'result': 'fail', 'scanner_errors': [], 'supported': True, 'platform_version': '1.0.2'}
        unavailable = {'result': 'fail', 'scanner_errors': ['alloy-embedded-java'], 'supported': True, 'platform_version': '1.0.1'}
        with tempfile.TemporaryDirectory() as temporary:
            audit.support_decisions([(None, newest), (Path(temporary), vulnerable), (None, unavailable)])
        self.assertFalse(vulnerable['supported'])
        self.assertEqual(vulnerable['result'], 'fail')
        self.assertEqual(vulnerable['superseded_by'], '1.0.3')
        self.assertTrue(unavailable['supported'])

    def test_dependency_findings_are_distinguished_from_service_or_schema_failure(self):
        with tempfile.TemporaryDirectory() as temporary:
            destination = Path(temporary)
            for name in ('pam-dependencies', 'alloy-embedded-java', 'alloy-ui-dependencies'):
                failures, errors = [], []
                with patch.object(audit.advisories, 'report', return_value={'findings': [{'advisories': ['CVE-test']}]}):
                    audit.dependency_scan([{}], name, destination, failures, errors)
                self.assertEqual(failures, [name])
                self.assertEqual(errors, [])
                failures, errors = [], []
                with patch.object(audit.advisories, 'report', side_effect=ReleaseError('Incomplete advisory coverage')):
                    audit.dependency_scan([{}], name, destination, failures, errors)
                self.assertEqual(failures, [name])
                self.assertEqual(errors, [name])
