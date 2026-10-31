"""Release allocation must preserve versions reserved by incomplete drafts."""

import json
import os
from pathlib import Path
import runpy
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch


SCRIPT = Path(__file__).resolve().parents[1]/'scripts/next-version.py'


class ReleaseVersionTests(unittest.TestCase):
    def select(self, releases, desired='0.1.0'):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root/'VERSION').write_text(desired+'\n')
            output = root/'output'
            result = SimpleNamespace(stdout=json.dumps(releases))
            previous = Path.cwd()
            try:
                os.chdir(root)
                with patch.dict(os.environ, {'GITHUB_REPOSITORY': 'Lanrith/lanrith',
                        'RUNNER_TEMP': str(root), 'GITHUB_OUTPUT': str(output)}), \
                        patch('subprocess.run', return_value=result) as api:
                    runpy.run_path(str(SCRIPT), run_name='__main__')
                self.assertIn('repos/Lanrith/lanrith/releases?per_page=100', api.call_args.args[0])
                selected = (root/'lanrith-version').read_text().strip()
                self.assertEqual(output.read_text(), 'value='+selected+'\n')
                return selected
            finally:
                os.chdir(previous)

    def release(self, version, *, draft=False):
        return {'tag_name': version, 'draft': draft}

    def test_partial_upload_draft_cannot_reuse_the_next_published_patch(self):
        self.assertEqual(self.select([[self.release('v0.1.13'),
                                       self.release('v0.1.14', draft=True)]]), '0.1.15')

    def test_first_release_draft_also_reserves_its_version(self):
        self.assertEqual(self.select([[self.release('v0.1.0', draft=True)]]), '0.1.1')

    def test_all_same_series_drafts_across_pages_are_reserved(self):
        self.assertEqual(self.select([[self.release('v0.1.13')],
                                      [self.release('v0.1.16', draft=True)]]), '0.1.17')

    def test_future_major_draft_does_not_move_the_current_release_series(self):
        self.assertEqual(self.select([[self.release('v0.1.13'),
                                       self.release('v1.0.0', draft=True)]]), '0.1.14')

    def test_explicit_unallocated_version_and_audit_tags_are_preserved(self):
        self.assertEqual(self.select([[self.release('v0.1.13'),
            self.release('audit-decision-123-1'), self.release('v0.1.99-rc1', draft=True)]],
            desired='0.2.0'), '0.2.0')

    def test_malformed_enumeration_fails_instead_of_allocating_a_version(self):
        for value in ({'releases': []}, [None]):
            with self.subTest(value=value), self.assertRaises(ValueError):
                self.select(value)
