"""Prebuild Java checks retain diagnostics before worker evidence exists."""

import importlib.util
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from lanrith.release import ReleaseError


spec = importlib.util.spec_from_file_location(
    'build_alloy', Path(__file__).resolve().parents[1]/'scripts/build-alloy.py')
builder = importlib.util.module_from_spec(spec)
spec.loader.exec_module(builder)


class AlloyDiagnosticTests(unittest.TestCase):
    queries = [{'package': {'ecosystem': 'Maven', 'name': 'example:component'}, 'version': '1.0.0'}]

    def test_clean_prebuild_check_creates_retained_diagnostic(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary)
            with patch('urllib.request.urlopen', return_value=io.BytesIO(b'{"results":[{}]}')):
                assessment, diagnostic = builder.assess_java(self.queries, output)
            self.assertEqual(len(assessment), 64)
            self.assertEqual(diagnostic, output/'security-diagnostics/java-osv.json')
            self.assertEqual(json.loads(diagnostic.read_text())['result'], 'pass')
            self.assertEqual(diagnostic.stat().st_mode & 0o777, 0o600)
            self.assertFalse((output/'evidence').exists())

    def test_findings_and_transport_errors_keep_their_original_failure(self):
        finding = {'id': 'OSV-SYNTHETIC-1', 'affected': []}
        responses = [io.BytesIO(b'{"results":[{"vulns":[{"id":"OSV-SYNTHETIC-1"}]}]}'),
                     io.BytesIO(json.dumps(finding).encode())]
        for side_effect, error, result in ((responses, ReleaseError, 'fail'),
                                           (OSError('private transport detail'), OSError, 'error')):
            with self.subTest(result=result), tempfile.TemporaryDirectory() as temporary:
                output = Path(temporary)
                with patch('urllib.request.urlopen', side_effect=side_effect), self.assertRaises(error):
                    builder.assess_java(self.queries, output)
                diagnostic = output/'security-diagnostics/java-osv.json'
                self.assertEqual(json.loads(diagnostic.read_text())['result'], result)
                self.assertNotIn('private transport detail', diagnostic.read_text())

    def test_symlinked_diagnostic_directory_remains_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary)
            destination = output/'elsewhere'
            destination.mkdir()
            (output/'security-diagnostics').symlink_to(destination, target_is_directory=True)
            with patch('urllib.request.urlopen', return_value=io.BytesIO(b'{"results":[{}]}')), \
                    self.assertRaises(ReleaseError):
                builder.assess_java(self.queries, output)
            self.assertEqual(list(destination.iterdir()), [])
