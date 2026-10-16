"""Production claims require exact native subjects and reviewed hosted workflows."""

import datetime
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

from lanrith import release

spec = importlib.util.spec_from_file_location('qualify_base', Path(__file__).parents[1]/'scripts/qualify-base.py')
qualification = importlib.util.module_from_spec(spec)
spec.loader.exec_module(qualification)


class QualificationTests(unittest.TestCase):
    def fixture(self, root):
        directory, project = root/'release', root/'project'
        directory.mkdir()
        (project/'tests').mkdir(parents=True)
        (project/'tests/vm.py').write_text('synthetic unit-test source')
        for name in ('lanrith-base.tar.gz', 'lanrith-initrd-base.tar.gz', 'inventory.json', 'inputs.json',
                     'tools.tar.gz', 'sbom.spdx.json'):
            (directory/name).write_bytes(b'synthetic unit-test subject: '+name.encode())
        now = datetime.datetime(2026, 1, 2, tzinfo=datetime.timezone.utc)
        native = {'schema': 1, 'result': 'pass', 'test': 'x86-64-uefi-factory-ab', 'assessed_at': now.isoformat(),
            'filesystem_sha256': release.file_record(directory/'lanrith-base.tar.gz')['sha256'],
            'initrd_sha256': release.file_record(directory/'lanrith-initrd-base.tar.gz')['sha256'],
            'source_sha256': release.file_record(project/'tests/vm.py')['sha256'],
            'profiles': [{'profile': name, 'result': 'pass', 'checks': sorted(checks)}
                         for name, checks in qualification.CHECKS.items()]}
        (directory/'native-qualification.json').write_bytes(release.canonical(native))
        (directory/'storage-qualification.json').write_bytes(release.canonical({'schema': 1, 'result': 'pass',
            'test': 'factory-slot-expansion', 'initial_partitions': 4, 'expanded_partitions': 8}))
        workflows = {}
        for name in ('.github/workflows/build-base.yml', '.github/workflows/release.yml', '.github/workflows/check.yml'):
            path = project/name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text('synthetic workflow fixture')
            workflows[name] = release.file_record(path)['sha256']
        (project/'security').mkdir()
        (project/'security/slsa-assessment.json').write_bytes(release.canonical({
            'schema': 1, 'specification': 'SLSA v1.2', 'target': 'Build L3', 'result': 'design-assessed',
            'reviewed_workflows': workflows, 'requirements': {name: {
                'result': 'satisfied-by-design', 'evidence': 'synthetic unit-test control'}
                for name in qualification.REQUIREMENTS}}))
        (directory/'security.json').write_bytes(release.canonical({'schema': 1, 'production_qualified': False,
            'custom': {'result': 'pass'}, 'assessed_at': now.isoformat(),
            'inventory_sha256': release.file_record(directory/'inventory.json')['sha256']}))
        manifest = release.unsigned_manifest(directory, purpose='base', version='0.1.0', sequence=0,
            configuration_sha256=release.file_record(directory/'inputs.json')['sha256'],
            files={'filesystem': 'lanrith-base.tar.gz', 'initrd-filesystem': 'lanrith-initrd-base.tar.gz',
                'inventory': 'inventory.json', 'security': 'security.json', 'inputs': 'inputs.json',
                'tools': 'tools.tar.gz', 'sbom': 'sbom.spdx.json'})
        (directory/'release.json').write_bytes(release.canonical(manifest))
        return directory, project, now, native

    def test_local_and_pull_request_results_cannot_claim_production_qualification(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory, project, now, _ = self.fixture(Path(temporary))
            for environment in ({}, {'GITHUB_ACTIONS': 'true', 'GITHUB_REF': 'refs/pull/1/merge'}):
                self.assertFalse(qualification.qualify(directory, project, environment, now=now))
                self.assertFalse(json.loads((directory/'security.json').read_text())['production_qualified'])
                self.assertFalse((directory/'qualification.json').exists())

    def test_hosted_main_claim_is_bound_to_native_subjects_and_the_new_security_manifest(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory, project, now, _ = self.fixture(Path(temporary))
            environment = {'GITHUB_ACTIONS': 'true', 'GITHUB_REF': 'refs/heads/main',
                'GITHUB_REPOSITORY': 'Lanrith/lanrith', 'RUNNER_ENVIRONMENT': 'github-hosted',
                'GITHUB_WORKFLOW_REF': 'Lanrith/lanrith/.github/workflows/release.yml@refs/heads/main',
                'LANRITH_REUSABLE_WORKFLOW_REPOSITORY': 'Lanrith/lanrith', 'LANRITH_REUSABLE_WORKFLOW_SHA': 'a'*40,
                'GITHUB_SHA': 'a'*40, 'GITHUB_RUN_ID': '123', 'GITHUB_RUN_ATTEMPT': '1'}
            self.assertTrue(qualification.qualify(directory, project, environment, now=now))
            security = json.loads((directory/'security.json').read_text())
            record = json.loads((directory/'qualification.json').read_text())
            self.assertEqual(record['native_sha256'], release.file_record(directory/'native-qualification.json')['sha256'])
            self.assertEqual(security['qualification']['record_sha256'], release.file_record(directory/'qualification.json')['sha256'])
            artifact = next(item for item in release.document((directory/'release.json').read_bytes())['artifacts']
                            if item['role'] == 'security')
            self.assertEqual(artifact['sha256'], release.file_record(directory/'security.json')['sha256'])
            self.assertEqual(artifact['size'], (directory/'security.json').stat().st_size)

    def test_incomplete_stale_and_wrong_subject_native_reports_are_rejected(self):
        for alteration in ('subject', 'stale', 'missing-failure-path'):
            with self.subTest(alteration=alteration), tempfile.TemporaryDirectory() as temporary:
                directory, project, now, native = self.fixture(Path(temporary))
                if alteration == 'subject':
                    native['filesystem_sha256'] = 'f'*64
                elif alteration == 'stale':
                    native['assessed_at'] = (now-datetime.timedelta(hours=7)).isoformat()
                else:
                    native['profiles'][0]['checks'].remove('interrupted-staging')
                (directory/'native-qualification.json').write_bytes(release.canonical(native))
                with self.assertRaises(release.ReleaseError):
                    qualification.qualify(directory, project, {}, now=now)

    def test_workflow_changes_invalidate_the_requirement_assessment(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory, project, now, _ = self.fixture(Path(temporary))
            (project/'.github/workflows/build-base.yml').write_text('unreviewed signing authority change')
            with self.assertRaises(release.ReleaseError):
                qualification.qualify(directory, project, {}, now=now)
