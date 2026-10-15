"""Retain policy outcomes when extracting the existing Debian evaluator."""

import importlib.util
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
specification = importlib.util.spec_from_file_location('debian_gate', ROOT / 'security/audit-debian-vulnerabilities.py')
gate = importlib.util.module_from_spec(specification)
specification.loader.exec_module(gate)


class DebianPolicyTests(unittest.TestCase):
    def evaluate(self, status, urgency='low', installed='1.0-1', fixed=''):
        records = [{'source': 'synthetic', 'source_version': installed}]
        tracker = {'synthetic': {'CVE-EXAMPLE': {'releases': {'trixie': {
            'status': status, 'urgency': urgency, 'fixed_version': fixed}}}}}
        return gate.evaluate(records, tracker, 'trixie')[0]

    def test_available_backported_fix_blocks_older_debian_revision(self):
        self.assertTrue(self.evaluate('resolved', installed='1.0-1', fixed='1.0-1+deb13u1'))
        self.assertFalse(self.evaluate('resolved', installed='1.0-1+deb13u1', fixed='1.0-1+deb13u1'))

    def test_unresolved_medium_high_and_end_of_life_block(self):
        for urgency in ('medium', 'high', 'end-of-life'):
            with self.subTest(urgency=urgency):
                self.assertTrue(self.evaluate('open', urgency))
                self.assertTrue(self.evaluate('undetermined', urgency))
        self.assertFalse(self.evaluate('open', 'low'))

    def test_unknown_advisory_status_and_urgency_fail_closed(self):
        for status, urgency in (('unknown', 'low'), ('open', 'invented')):
            with self.subTest(status=status, urgency=urgency), self.assertRaises(SystemExit):
                self.evaluate(status, urgency)


if __name__ == '__main__':
    unittest.main()
