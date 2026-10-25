"""Retain policy outcomes when extracting the existing Debian evaluator."""

import importlib.util
from pathlib import Path
import copy
import tempfile
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


class SignedKernelTests(unittest.TestCase):
    def setUp(self):
        self.metadata = {'Package': 'linux-image-6.12.113+deb13-amd64', 'Version': '6.12.113-1',
            'Architecture': 'amd64', 'Source': 'linux-signed-amd64 (6.12.113+1)',
            'Built-Using': 'linux (= 6.12.113-1)'}
        self.record = {'package': self.metadata['Package'], 'version': self.metadata['Version'],
            'architecture': 'amd64', 'source': 'linux-signed-amd64',
            'source_version': '6.12.113+1', 'provenance': 'debian-metadata'}
        self.tracker = {'linux': {'CVE-KERNEL-EXAMPLE': {'releases': {'trixie': {
            'status': 'resolved', 'urgency': 'high', 'fixed_version': '6.12.114-1'}}}}}

    def test_fresh_signed_metadata_checks_underlying_source_and_kernel_advisories(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary)/'Packages'
            path.write_text(''.join(k+': '+v+'\n' for k, v in self.metadata.items()))
            records = gate.build_source_map([(self.metadata['Package'], '6.12.113-1', 'amd64')], path, {})
        self.assertEqual(records, [self.record])
        findings = gate.evaluate(records, self.tracker, 'trixie')[0]
        self.assertEqual(findings, [('CVE-KERNEL-EXAMPLE', 'linux', '6.12.113-1', '6.12.114-1', 'available-fix')])

    def test_retained_signed_map_is_evaluated_without_rewriting_its_provenance(self):
        original = copy.deepcopy(self.record)
        self.assertTrue(gate.evaluate([self.record], self.tracker, 'trixie')[0])
        self.assertEqual(self.record, original)
        fixed = dict(self.record, version='6.12.114-1', source_version='6.12.114+1')
        self.assertFalse(gate.evaluate([fixed], self.tracker, 'trixie')[0])

    def test_metapackage_wrapper_does_not_hide_or_conflict_with_the_payload(self):
        meta = dict(self.record, package='linux-image-amd64')
        self.assertEqual(gate.source_from_record(dict(self.metadata, Package='linux-image-amd64', **{'Built-Using': ''})),
                         ('linux-signed-amd64', '6.12.113+1'))
        findings, evaluated, _, _, tracked = gate.evaluate([meta, self.record], self.tracker, 'trixie')
        self.assertEqual((len(findings), evaluated, tracked), (1, 1, 1))

    def test_missing_ambiguous_or_conflicting_built_using_fails_closed(self):
        for value in ('', 'linux (= 6.12.114-1)', 'gcc-14 (= 14.2.0-1)', 'linux (6.12.113-1)',
                      'linux (= 6.12.113-1), linux (= 6.12.114-1)', 'linux (>= 6.12.113-1)'):
            with self.subTest(value=value), self.assertRaises(SystemExit):
                gate.source_from_record(dict(self.metadata, **{'Built-Using': value}))
        missing = dict(self.metadata)
        del missing['Source']
        with self.assertRaises(SystemExit):
            gate.source_from_record(missing)

    def test_binary_only_rebuild_revision_is_not_a_kernel_source_version(self):
        metadata = dict(self.metadata, Version='6.12.113-1+b7')
        self.assertEqual(gate.source_from_record(metadata), ('linux-signed-amd64', '6.12.113+1'))
        record = dict(self.record, version='6.12.113-1+b7')
        self.assertEqual(gate.advisory_source(record), ('linux', '6.12.113-1'))

    def test_unrecognised_payload_source_or_version_cannot_skip_the_kernel_scan(self):
        for source, version in (('untracked-kernel', '6.12.113-1'), ('linux-signed-amd64', 'latest'),
                                ('linux', '6.12.113-1')):
            record = dict(self.record, source=source, version=version)
            with self.subTest(source=source, version=version), self.assertRaises(SystemExit):
                gate.evaluate([record], self.tracker, 'trixie')

    def test_folded_built_using_is_read_and_duplicate_fields_are_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary)/'Packages'
            text = ''.join(k+': '+v+'\n' for k, v in self.metadata.items() if k != 'Built-Using')
            path.write_text(text+'Built-Using:\n linux (= 6.12.113-1)\n')
            self.assertEqual(gate.source_from_record(gate.deb822_records(path)[0]),
                             ('linux-signed-amd64', '6.12.113+1'))
            path.write_text(text+'Built-Using: linux (= 6.12.113-1)\nBuilt-Using: linux (= 6.12.114-1)\n')
            with self.assertRaises(SystemExit):
                gate.deb822_records(path)

    def test_missing_kernel_feed_cannot_report_a_successful_scan(self):
        for tracker in ({}, {'linux': {}}):
            with self.subTest(tracker=tracker), self.assertRaises(SystemExit):
                gate.evaluate([self.record], tracker, 'trixie')


if __name__ == '__main__':
    unittest.main()
