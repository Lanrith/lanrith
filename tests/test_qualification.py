"""Production claims require exact native subjects and reviewed hosted workflows."""

import datetime
import importlib.util
import json
import os
from pathlib import Path
import shutil
import tempfile
import traceback
import unittest
from unittest import mock

from lanrith import release

spec = importlib.util.spec_from_file_location('qualify_base', Path(__file__).parents[1]/'scripts/qualify-base.py')
qualification = importlib.util.module_from_spec(spec)
spec.loader.exec_module(qualification)


class QualificationTests(unittest.TestCase):
    def copy_repository_assessment(self, project):
        source = Path(__file__).resolve().parents[1]
        shutil.copytree(source/'.github/workflows', project/'.github/workflows', dirs_exist_ok=True)
        shutil.copyfile(source/'security/slsa-assessment.json', project/'security/slsa-assessment.json')

    def test_actual_repository_assessment_reaches_local_native_qualification(self):
        # Use the repository assessment and real workflow bytes. A synthetic
        # catalog can repeat a stale qualifier list and conceal this mismatch.
        with tempfile.TemporaryDirectory() as temporary:
            directory, project, now, _ = self.fixture(Path(temporary))
            self.copy_repository_assessment(project)
            self.assertFalse(qualification.qualify(directory, project, {}, now=now))
            self.assertFalse(json.loads((directory/'security.json').read_text())['production_qualified'])

    def test_assessment_errors_stop_before_native_evidence_is_read(self):
        for alteration in ('missing-recovery', 'extra-workflow', 'recovery-drift', 'missing-requirement',
                           'unsatisfied-requirement', 'missing-evidence', 'wrong-specification'):
            with self.subTest(alteration=alteration), tempfile.TemporaryDirectory() as temporary:
                directory, project, now, _ = self.fixture(Path(temporary))
                self.copy_repository_assessment(project)
                path = project/'security/slsa-assessment.json'
                assessment = json.loads(path.read_text())
                if alteration == 'missing-recovery':
                    del assessment['reviewed_workflows']['.github/workflows/retry-runner-capacity.yml']
                elif alteration == 'extra-workflow':
                    assessment['reviewed_workflows']['.github/workflows/unreviewed.yml'] = 'a'*64
                elif alteration == 'recovery-drift':
                    (project/'.github/workflows/retry-runner-capacity.yml').write_text('unreviewed authority')
                elif alteration == 'missing-requirement':
                    del assessment['requirements']['isolated-signing']
                elif alteration == 'unsatisfied-requirement':
                    assessment['requirements']['isolated-signing']['result'] = 'not-assessed'
                elif alteration == 'missing-evidence':
                    del assessment['requirements']['isolated-signing']['evidence']
                else:
                    assessment['specification'] = 'unreviewed-specification'
                path.write_bytes(release.canonical(assessment))
                with mock.patch.object(qualification, 'value', side_effect=AssertionError('Native evidence read')):
                    with self.assertRaises(release.ReleaseError):
                        qualification.qualify(directory, project, {}, now=now)

    def hosted_environment(self):
        return {'GITHUB_ACTIONS': 'true', 'GITHUB_REF': 'refs/heads/main',
            'GITHUB_REPOSITORY': 'Lanrith/lanrith', 'RUNNER_ENVIRONMENT': 'github-hosted',
            'GITHUB_WORKFLOW_REF': 'Lanrith/lanrith/.github/workflows/release.yml@refs/heads/main',
            'LANRITH_REUSABLE_WORKFLOW_REPOSITORY': 'Lanrith/lanrith', 'LANRITH_REUSABLE_WORKFLOW_SHA': 'a'*40,
            'GITHUB_SHA': 'a'*40, 'GITHUB_RUN_ID': '123', 'GITHUB_RUN_ATTEMPT': '1'}

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
        for name in qualification.REVIEWED_WORKFLOWS:
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
            environment = self.hosted_environment()
            self.assertTrue(qualification.qualify(directory, project, environment, now=now))
            security = json.loads((directory/'security.json').read_text())
            record = json.loads((directory/'qualification.json').read_text())
            self.assertEqual(record['native_sha256'], release.file_record(directory/'native-qualification.json')['sha256'])
            self.assertEqual(security['qualification']['record_sha256'], release.file_record(directory/'qualification.json')['sha256'])
            artifact = next(item for item in release.document((directory/'release.json').read_bytes())['artifacts']
                            if item['role'] == 'security')
            self.assertEqual(artifact['sha256'], release.file_record(directory/'security.json')['sha256'])
            self.assertEqual(artifact['size'], (directory/'security.json').stat().st_size)

    def test_hosted_main_publishes_non_writable_container_evidence(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            directory, project, now, _ = self.fixture(root)
            for name in ('security.json', 'release.json'):
                (directory/name).chmod(0o444)
            worker = os.geteuid()
            if worker == 0:
                # Reproduce root-owned container files in a directory owned by
                # the unprivileged workflow user, including actual UID changes.
                worker = 65534
                root.chmod(0o755)
                os.chown(directory, worker, worker)
                child = os.fork()
                if child == 0:
                    try:
                        os.setgroups([])
                        os.setgid(worker)
                        os.setuid(worker)
                        self.assertTrue(qualification.qualify(directory, project,
                            self.hosted_environment(), now=now))
                    except BaseException:
                        traceback.print_exc()
                        os._exit(1)
                    os._exit(0)
                _, status = os.waitpid(child, 0)
                self.assertEqual(os.waitstatus_to_exitcode(status), 0)
            else:
                self.assertTrue(qualification.qualify(directory, project,
                    self.hosted_environment(), now=now))
            self.assertTrue(json.loads((directory/'security.json').read_text())['production_qualified'])
            for name in ('security.json', 'release.json', 'qualification.json'):
                self.assertEqual((directory/name).stat().st_uid, worker)
            manifest = release.document((directory/'release.json').read_bytes())
            artifact = next(item for item in manifest['artifacts'] if item['role'] == 'security')
            self.assertEqual(artifact['sha256'], release.file_record(directory/'security.json')['sha256'])
            self.assertEqual(artifact['size'], (directory/'security.json').stat().st_size)

    def test_failed_evidence_publication_preserves_ineligible_security_and_manifest(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory, project, now, _ = self.fixture(Path(temporary))
            previous = {name: (directory/name).read_bytes() for name in ('security.json', 'release.json')}
            replace = os.replace
            def fail_security(source, destination):
                if Path(destination).name == 'security.json':
                    raise OSError('synthetic failed evidence publication')
                return replace(source, destination)
            with mock.patch.object(qualification.os, 'replace', side_effect=fail_security), self.assertRaises(OSError):
                qualification.qualify(directory, project, self.hosted_environment(), now=now)
            self.assertEqual(previous, {name: (directory/name).read_bytes() for name in previous})
            self.assertFalse(json.loads((directory/'security.json').read_text())['production_qualified'])
            self.assertEqual(list(directory.glob('.security.json.*')), [])

    def test_incomplete_stale_and_wrong_subject_native_reports_are_rejected(self):
        for alteration in ('subject', 'stale', 'missing-failure-path', 'missing-automatic-observation',
                           'missing-provisioning-failure-boundary', 'missing-firewall-failure-boundary'):
            with self.subTest(alteration=alteration), tempfile.TemporaryDirectory() as temporary:
                directory, project, now, native = self.fixture(Path(temporary))
                if alteration == 'subject':
                    native['filesystem_sha256'] = 'f'*64
                elif alteration == 'stale':
                    native['assessed_at'] = (now-datetime.timedelta(hours=7)).isoformat()
                elif alteration == 'missing-failure-path':
                    native['profiles'][0]['checks'].remove('interrupted-staging')
                elif alteration == 'missing-provisioning-failure-boundary':
                    native['profiles'][0]['checks'].remove('initrd-provisioning-failure-boundary')
                elif alteration == 'missing-firewall-failure-boundary':
                    native['profiles'][0]['checks'].remove('firewall-listener-failure-boundary')
                else:
                    native['profiles'][0]['checks'].remove('automatic-boot-observation')
                (directory/'native-qualification.json').write_bytes(release.canonical(native))
                with self.assertRaises(release.ReleaseError):
                    qualification.qualify(directory, project, {}, now=now)

    def test_workflow_changes_invalidate_the_requirement_assessment(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory, project, now, _ = self.fixture(Path(temporary))
            (project/'.github/workflows/build-base.yml').write_text('unreviewed signing authority change')
            with self.assertRaises(release.ReleaseError):
                qualification.qualify(directory, project, {}, now=now)
