"""Assessment drift must block the cheap preflight before expensive package work."""
import hashlib
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
            shutil.copyfile(ROOT/'scripts/publish-release.py', root/'scripts/publish-release.py')
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

    def changed_workflow(self, name, transform):
        def change(root):
            path = root/name
            path.write_text(transform(path.read_text()))
            assessment = root/'security/slsa-assessment.json'
            value = json.loads(assessment.read_text())
            value['reviewed_workflows'][name] = hashlib.sha256(path.read_bytes()).hexdigest()
            assessment.write_text(json.dumps(value))
        return self.check(change)

    def test_read_only_version_allocator_is_rejected_even_with_matching_assessment_hash(self):
        result = self.changed_workflow('.github/workflows/build-base.yml',
            lambda s:s.replace('      contents: write','      contents: read',1))
        self.assertNotEqual(result.returncode,0)

    def test_build_token_cannot_be_elevated_to_release_write(self):
        result = self.changed_workflow('.github/workflows/build-base.yml',
            lambda s:s.replace('timeout-minutes: 360\n    permissions:\n      contents: read',
                               'timeout-minutes: 360\n    permissions:\n      contents: write',1))
        self.assertNotEqual(result.returncode,0)

    def test_version_writer_rejects_moving_checkout_untrusted_events_or_extra_code(self):
        changes = (
            lambda s:s.replace('ref: ${{ job.workflow_sha }}','ref: main',1),
            lambda s:s.replace("github.ref == 'refs/heads/main' && ",'',1),
            lambda s:s.replace('run: python3 scripts/next-version.py',
                               'run: python3 scripts/build-base.py',1),
            lambda s:s.replace('  packages:\n','      - run: python3 release/untrusted.py\n  packages:\n',1),
        )
        for transform in changes:
            with self.subTest(transform=transform):
                self.assertNotEqual(self.changed_workflow('.github/workflows/build-base.yml',transform).returncode,0)

    def test_publisher_rejects_moving_checkout_or_artifact_supplied_executable(self):
        changes = (
            lambda s:s.replace('ref: ${{ job.workflow_sha }}','ref: main',1),
            lambda s:s.replace('python3 tools/scripts/publish-release.py','python3 release/publish-release.py',1),
            lambda s:s.replace("github.ref == 'refs/heads/main' && ",'',1),
        )
        for transform in changes:
            with self.subTest(transform=transform):
                self.assertNotEqual(self.changed_workflow('.github/workflows/publish-release.yml',transform).returncode,0)
