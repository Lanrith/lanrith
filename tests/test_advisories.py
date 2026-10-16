"""Malformed responses and missing Git dependency coverage fail security admission."""

import io
import json
import unittest
from unittest.mock import patch

from lanrith import advisories
from lanrith.release import ReleaseError


class AdvisoryTests(unittest.TestCase):
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
