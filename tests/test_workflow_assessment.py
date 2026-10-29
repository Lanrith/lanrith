"""Assessment drift must block the cheap preflight before expensive package work."""
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


class WorkflowAssessmentPreflightTests(unittest.TestCase):
    def check(self, mutation=None):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            shutil.copytree(ROOT/'.github/workflows', root/'.github/workflows')
            (root/'security').mkdir()
            (root/'scripts').mkdir()
            shutil.copyfile(ROOT/'security/slsa-assessment.json', root/'security/slsa-assessment.json')
            shutil.copyfile(ROOT/'scripts/check-workflows.py', root/'scripts/check-workflows.py')
            if mutation:
                mutation(root)
            return subprocess.run([sys.executable, str(root/'scripts/check-workflows.py')],
                capture_output=True, text=True, timeout=20, check=False)

    def test_exact_reviewed_workflows_pass_the_preflight(self):
        result = self.check()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('Workflow trust boundaries verified.', result.stdout)

    def test_workflow_drift_fails_before_package_qualification_with_an_actionable_path(self):
        def change(root):
            path = root/'.github/workflows/build-base.yml'
            path.write_bytes(path.read_bytes()+b'\n# Unreviewed workflow change.\n')
        result = self.check(change)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('Assessed workflow hash differs: .github/workflows/build-base.yml', result.stderr)
        self.assertIn('before the package build', result.stderr)

    def test_deleting_an_assessed_workflow_cannot_bypass_the_preflight(self):
        def change(root):
            path = root/'security/slsa-assessment.json'
            value = json.loads(path.read_bytes())
            del value['reviewed_workflows']['.github/workflows/build-base.yml']
            path.write_text(json.dumps(value))
        result = self.check(change)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('reviewed workflow set is incomplete', result.stderr)
