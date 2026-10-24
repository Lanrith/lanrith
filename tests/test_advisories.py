"""Malformed responses and missing Git dependency coverage fail security admission."""

import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from lanrith import advisories
from lanrith.release import ReleaseError


class AdvisoryTests(unittest.TestCase):
    def test_retained_source_coverage_rechecks_the_required_fix_not_only_the_id(self):
        feed = [{'ghsa_id': 'GHSA-example', 'vulnerabilities': [{'patched_versions': 'v0.9.0'}]}]
        fixes = {'GHSA-example': [{'fixed_tag': 'v0.9.0', 'fixed_commit': 'a'*40}]}
        self.assertTrue(advisories.source_coverage(feed, fixes))
        feed[0]['vulnerabilities'][0]['patched_versions'] = 'v0.11.0'
        with self.assertRaises(ReleaseError):
            advisories.source_coverage(feed, fixes)
        with self.assertRaises(ReleaseError):
            advisories.source_coverage(feed, {})

    def test_git_dependencies_get_both_package_and_commit_coverage(self):
        queries = advisories.cargo_queries({'package': [
            {'name': 'local-source', 'version': '0.1.0'},
            {'name': 'registry-dependency', 'version': '1.0.0', 'source': 'registry+https://example.invalid'},
            {'name': 'git-dependency', 'version': '2.0.0', 'source': 'git+https://example.invalid/source#'+'a'*40}]})
        self.assertEqual(len(queries), 3)
        self.assertEqual(queries[-1], {'commit': 'a'*40})
        with self.assertRaises(ReleaseError):
            advisories.cargo_queries({'package': [{'name': 'dependency', 'version': '1', 'source': 'git+floating'}]})

    def test_errors_truncation_pagination_and_findings_are_not_clean_results(self):
        queries = [{'package': {'ecosystem': 'Maven', 'name': 'example:component'}, 'version': '1.0.0'}]
        for value in ({'results': []}, {'results': [{'error': 'unavailable'}]},
                      {'results': [{'next_page_token': 'more'}]}, {'results': [{'vulns': False}]},
                      {'results': [{'vulns': [{'id': 'EXAMPLE-1'}]}]}):
            with self.subTest(value=value), patch('urllib.request.urlopen',
                    return_value=io.BytesIO(json.dumps(value).encode())), self.assertRaises(ReleaseError):
                advisories.assess(queries)
        with patch('urllib.request.urlopen', return_value=io.BytesIO(b'{"results":[{}]}')):
            self.assertEqual(len(advisories.assess(queries)), 64)

    def test_diagnostic_retains_query_coverage_advisory_ids_and_ranges(self):
        queries = [{'package': {'ecosystem': 'npm', 'name': 'synthetic'}, 'version': '1.0.0'}]
        vulnerability = {'id': 'OSV-SYNTHETIC-1', 'affected': [{'package': {
            'ecosystem': 'npm', 'name': 'synthetic'}, 'ranges': [{'type': 'SEMVER',
            'events': [{'introduced': '0'}, {'fixed': '1.0.1'}]}]}]}
        with tempfile.TemporaryDirectory() as temporary:
            record = Path(temporary)/'diagnostic.json'
            response = {'results': [{'vulns': [{'id': vulnerability['id']}]}]}
            with patch('urllib.request.urlopen', side_effect=(io.BytesIO(json.dumps(response).encode()),
                    io.BytesIO(json.dumps(vulnerability).encode()))), \
                    self.assertRaises(ReleaseError):
                advisories.assess(queries, diagnostic=record)
            value = json.loads(record.read_text())
            self.assertEqual(value['result'], 'fail')
            self.assertEqual(value['query_count'], 1)
            self.assertEqual(value['queries'], queries)
            self.assertEqual(value['advisory_ids'], ['OSV-SYNTHETIC-1'])
            self.assertTrue(value['advisory_details_complete'])
            self.assertEqual(value['advisories'][0]['affected'][0]['ranges'][0]['events'][-1],
                             {'fixed': '1.0.1'})
            self.assertEqual(record.stat().st_mode & 0o777, 0o600)

    def test_advisory_detail_failure_is_recorded_without_leaking_transport_details(self):
        queries = [{'package': {'ecosystem': 'npm', 'name': 'synthetic'}, 'version': '1.0.0'}]
        response = {'results': [{'vulns': [{'id': 'OSV-SYNTHETIC-1'}]}]}
        with tempfile.TemporaryDirectory() as temporary:
            record = Path(temporary)/'diagnostic.json'
            with patch('urllib.request.urlopen', side_effect=(io.BytesIO(json.dumps(response).encode()),
                    OSError('private proxy credential'))), self.assertRaises(ReleaseError):
                advisories.assess(queries, diagnostic=record)
            value = json.loads(record.read_text())
            self.assertFalse(value['advisory_details_complete'])
            self.assertEqual(value['advisories'],
                             [{'id': 'OSV-SYNTHETIC-1', 'result': 'error', 'error': 'OSError'}])
            self.assertNotIn('private proxy credential', record.read_text())

    def test_clean_and_transport_diagnostics_are_bounded_and_do_not_expose_errors(self):
        queries = [{'commit': 'a'*40}]
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            clean = root/'clean.json'
            with patch('urllib.request.urlopen', return_value=io.BytesIO(b'{"results":[{}]}')):
                advisories.assess(queries, diagnostic=clean)
            self.assertEqual(json.loads(clean.read_text())['result'], 'pass')
            failed = root/'failed.json'
            with patch('urllib.request.urlopen', side_effect=OSError('private credential detail')), \
                    self.assertRaises(OSError):
                advisories.assess(queries, diagnostic=failed)
            value = json.loads(failed.read_text())
            self.assertEqual(value['result'], 'error')
            self.assertEqual(value['error'], 'OSError')
            self.assertNotIn('private credential detail', failed.read_text())
