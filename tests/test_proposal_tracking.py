"""PR publication can reset its checkout; tracking must use the sealed artifact."""

import contextlib
import copy
import json
import os
from pathlib import Path
import runpy
import shlex
import sys
import tempfile
import unittest
from unittest.mock import patch

import yaml

from automation import evidence, releases
from automation.common import MaintenanceError, canonical


ROOT = Path(__file__).resolve().parents[1]
REPO = 'Lanrith/lanrith'


class ProposalTrackingTests(unittest.TestCase):
    def candidate(self, fixed='1.27.3'):
        reason = {'id': 'GO-2026-6809', 'type': 'security-fix', 'package': 'stdlib',
            'ecosystem': 'Go', 'installed': '1.27.2', 'fixed': fixed,
            'source': 'https://api.osv.dev/v1/vulns/GO-2026-6809', 'evidence_sha256': 'd'*64}
        return evidence.candidate(REPO, 'a'*40, b'{}',
            {'.go-version': b'1.27.2\n'}, {'.go-version': (fixed+'\n').encode()}, [reason], 'c'*40)

    def invoke_workflow_tracking(self, root):
        workflow = yaml.safe_load((ROOT/'.github/workflows/security-proposal.yml').read_text())
        step = next(s for s in workflow['jobs']['publish']['steps']
                    if s.get('name') == 'Link the proposal to its tracked remediation')
        command = step['run'].replace('\\\n', '')
        command = command[command.index('python3 '):]
        self.writes = []
        def write(endpoint, **kwargs):
            self.writes.append((endpoint, kwargs))
            return {'number': 41}
        environment = {'GITHUB_REPOSITORY': REPO, 'GITHUB_RUN_ID': '123',
            'PR_NUMBER': '14', 'RUNNER_TEMP': str(root/'runner temp'), 'LANRITH_EVIDENCE_DIR': ''}
        with patch.dict(os.environ, environment), contextlib.chdir(root), \
                patch.object(releases, 'pages', return_value=[]), patch.object(releases, 'api', side_effect=write):
            arguments = shlex.split(os.path.expandvars(command))
            self.assertEqual(arguments[:3], ['python3', 'tools/scripts/security-updates.py', 'track'])
            with patch.object(sys, 'argv', arguments[1:]):
                runpy.run_path(str(ROOT/'scripts/security-updates.py'), run_name='__main__')

    def fixture(self, root):
        (root/'owner/security').mkdir(parents=True)
        (root/'runner temp/proposal/security').mkdir(parents=True)
        record = self.candidate()
        artifact = root/'runner temp/proposal'/evidence.CANDIDATE
        evidence.write(artifact, record)
        return artifact, record

    def test_tracks_published_candidate_after_checkout_restores_main(self):
        for previous in (None, self.candidate('1.27.4')):
            with self.subTest(previous_main_candidate=previous is not None), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                _, expected = self.fixture(root)
                owner = root/'owner'/evidence.CANDIDATE
                if previous:
                    evidence.write(owner, previous)
                self.invoke_workflow_tracking(root)
                self.assertEqual(len(self.writes), 1)
                endpoint, call = self.writes[0]
                self.assertEqual((endpoint, call['method']), ('repos/'+REPO+'/issues', 'POST'))
                self.assertIn(expected['candidate_id'], call['payload']['body'])
                self.assertIn(expected['remediation_id'], call['payload']['title'])
                self.assertIn('Pull request: https://github.com/'+REPO+'/pull/14', call['payload']['body'])
                self.assertIn('proposed; not yet released', call['payload']['body'])
                self.assertEqual(json.loads(owner.read_text()) if owner.exists() else None, previous)

    def test_missing_or_symlinked_artifact_cannot_fall_back_to_main(self):
        for symlink in (False, True):
            with self.subTest(symlink=symlink), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                artifact, record = self.fixture(root)
                owner = root/'owner'/evidence.CANDIDATE
                evidence.write(owner, record)
                artifact.unlink()
                if symlink:
                    artifact.symlink_to(owner)
                with self.assertRaisesRegex(MaintenanceError, 'Evidence must be a regular file'):
                    self.invoke_workflow_tracking(root)
                self.assertEqual(self.writes, [])

    def test_modified_artifact_cannot_create_a_remediation(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            artifact, record = self.fixture(root)
            evidence.write(root/'owner'/evidence.CANDIDATE, record)
            changed = copy.deepcopy(record)
            changed['reasons'][0]['fixed'] = '1.27.4'
            artifact.write_bytes(canonical(changed))
            with self.assertRaisesRegex(MaintenanceError, 'Candidate identity does not cover'):
                self.invoke_workflow_tracking(root)
            self.assertEqual(self.writes, [])


if __name__ == '__main__':
    unittest.main()
