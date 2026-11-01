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
            shutil.copytree(ROOT/'lanrith', root/'lanrith', ignore=shutil.ignore_patterns('__pycache__'))
            (root/'security').mkdir()
            (root/'scripts').mkdir()
            (root/'automation').mkdir()
            shutil.copyfile(ROOT/'automation/capacity.py', root/'automation/capacity.py')
            shutil.copyfile(ROOT/'security/slsa-assessment.json', root/'security/slsa-assessment.json')
            shutil.copyfile(ROOT/'scripts/check-workflows.py', root/'scripts/check-workflows.py')
            shutil.copyfile(ROOT/'scripts/publish-release.py', root/'scripts/publish-release.py')
            shutil.copyfile(ROOT/'scripts/prepare-runner.py', root/'scripts/prepare-runner.py')
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

    def test_incomplete_platform_requirements_fail_the_preflight(self):
        for alteration in ('missing-requirement', 'unsatisfied-requirement', 'missing-evidence', 'wrong-specification'):
            def change(root):
                path = root/'security/slsa-assessment.json'
                value = json.loads(path.read_bytes())
                if alteration == 'missing-requirement':
                    del value['requirements']['isolated-signing']
                elif alteration == 'unsatisfied-requirement':
                    value['requirements']['isolated-signing']['result'] = 'not-assessed'
                elif alteration == 'missing-evidence':
                    del value['requirements']['isolated-signing']['evidence']
                else:
                    value['specification'] = 'unreviewed-specification'
                path.write_text(json.dumps(value))
            with self.subTest(alteration=alteration):
                result = self.check(change)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn('complete requirement assessment', result.stderr)

    def test_recovery_workflow_cannot_be_omitted_added_or_changed_after_assessment(self):
        for alteration in ('missing', 'extra', 'changed'):
            def change(root):
                path = root/'security/slsa-assessment.json'
                value = json.loads(path.read_bytes())
                if alteration == 'missing':
                    del value['reviewed_workflows']['.github/workflows/retry-runner-capacity.yml']
                elif alteration == 'extra':
                    value['reviewed_workflows']['.github/workflows/unreviewed.yml'] = 'a'*64
                else:
                    (root/'.github/workflows/retry-runner-capacity.yml').write_text('unreviewed authority')
                path.write_text(json.dumps(value))
            with self.subTest(alteration=alteration):
                result = self.check(change)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn('Assessed workflow hash differs' if alteration == 'changed' else
                              'reviewed workflow set is incomplete', result.stderr)

    def changed_workflow(self, name, transform):
        def change(root):
            path = root/name
            path.write_text(transform(path.read_text()))
            assessment = root/'security/slsa-assessment.json'
            value = json.loads(assessment.read_text())
            if name in value['reviewed_workflows']:
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

    def test_disk_preparation_cannot_be_skipped_even_with_matching_workflow_hash(self):
        for name in ('.github/workflows/build-base.yml','.github/workflows/package-check.yml'):
            with self.subTest(workflow=name):
                result = self.changed_workflow(name,lambda s:s.replace('python3 scripts/prepare-runner.py','true',1))
                self.assertNotEqual(result.returncode,0)
                self.assertIn('share the reviewed disk preparation',result.stderr)

    def test_failed_disk_preparation_cannot_hide_its_diagnostics(self):
        for name in ('.github/workflows/build-base.yml','.github/workflows/package-check.yml'):
            with self.subTest(workflow=name):
                result = self.changed_workflow(name,lambda s:s.replace('if: always()','if: success()',1))
                self.assertNotEqual(result.returncode,0)
                self.assertIn('retain bounded one-day diagnostics',result.stderr)

    def test_lowering_the_disk_budget_is_rejected_before_expensive_work(self):
        def change(root):
            path=root/'scripts/prepare-runner.py'
            path.write_text(path.read_text().replace('MINIMUM_FREE_BYTES = 60 *','MINIMUM_FREE_BYTES = 30 *'))
        result=self.check(change)
        self.assertNotEqual(result.returncode,0)
        self.assertIn('60 GiB build budget',result.stderr)

    def test_capacity_retry_cannot_skip_its_archive_or_use_untrusted_checkout(self):
        changes = (
            lambda s:s.replace('needs: [plan, archive-plan]','needs: plan',1),
            lambda s:s.replace('ref: ${{ job.workflow_sha }}','ref: main',1),
            lambda s:s.replace('python3 tools/scripts/retry-runner-capacity.py plan','python3 pr/scripts/retry-runner-capacity.py plan',1),
            lambda s:s.replace('      contents: read\n      actions: write','      contents: write\n      actions: write',1),
        )
        for transform in changes:
            with self.subTest(transform=transform):
                self.assertNotEqual(self.changed_workflow('.github/workflows/retry-runner-capacity.yml',transform).returncode,0)
