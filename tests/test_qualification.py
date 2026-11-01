"""Production claims require exact native subjects and reviewed hosted workflows."""

import datetime
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import traceback
import unittest
from unittest import mock

from lanrith import release
from ids_fixture import report as ids_report, sources as ids_sources

spec = importlib.util.spec_from_file_location('qualify_base', Path(__file__).parents[1]/'scripts/qualify-base.py')
qualification = importlib.util.module_from_spec(spec)
spec.loader.exec_module(qualification)


class QualificationTests(unittest.TestCase):
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
        implementation = {}
        for name in ('lanrith/logs.py', 'lanrith/logs_runtime.py', 'lanrith/service_plane.py', 'lanrith/extension_observations.py', 'tests/logs_native.py'):
            path = project/name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text('synthetic logging source: '+name)
            implementation[name] = release.file_record(path)['sha256']
        (directory/'custom-security.json').write_bytes(release.canonical({
            'components': {'alloy': {'binary_sha256': 'e'*64}}}))
        (directory/'logs-qualification.json').write_bytes(release.canonical({
            'schema': 1, 'result': 'pass', 'test': 'offline-journal-https-outage', 'assessed_at': now.isoformat(),
            'source_sha256': implementation.pop('tests/logs_native.py'), 'implementation_sha256': implementation,
            'alloy_sha256': 'e'*64, 'checks': sorted(qualification.LOG_CHECKS),
            'queue_capacity_bytes': 67108864, 'queue_physical_bytes': 80*1024*1024,
            'overflow_records': 1000, 'delivered_batches': 8, 'local_output_bytes': 2000000,
            'local_output_files': 3, 'local_failed_records': 20}))
        implementation = {}
        for name in qualification.DIRECTORY_IMPLEMENTATION | {'tests/directory_native.py'}:
            path = project/name
            path.parent.mkdir(parents=True, exist_ok=True)
            if not path.exists():
                path.write_text('synthetic directory source: '+name)
            implementation[name] = release.file_record(path)['sha256']
        (directory/'directory-qualification.json').write_bytes(release.canonical({
            'schema': 1, 'result': 'pass', 'test': 'offline-directory-tls-egress', 'assessed_at': now.isoformat(),
            'source_sha256': implementation.pop('tests/directory_native.py'), 'implementation_sha256': implementation,
            'external_network': False, 'checks': sorted(qualification.DIRECTORY_CHECKS)}))
        implementation = {}
        for name in qualification.CREDENTIAL_IMPLEMENTATION | {'tests/credentials_native.py'}:
            path = project/name
            path.parent.mkdir(parents=True, exist_ok=True)
            if not path.exists():
                path.write_text('synthetic credential source: '+name)
            implementation[name] = release.file_record(path)['sha256']
        (directory/'credential-qualification.json').write_bytes(release.canonical({
            'schema': 1, 'result': 'pass', 'test': 'offline-systemd-credential-provisioning', 'assessed_at': now.isoformat(),
            'source_sha256': implementation.pop('tests/credentials_native.py'), 'implementation_sha256': implementation,
            'external_network': False, 'checks': sorted(qualification.CREDENTIAL_CHECKS), 'private_image_qualified': False,
            'container_cleanup': 'removed', 'builder_image_sha256': 'f'*64, 'container_runtime': 'docker'}))
        ids_sources(project)
        (directory/'ids-qualification.json').write_bytes(release.canonical(ids_report(
            release.file_record(directory/'lanrith-base.tar.gz')['sha256'], now, project)))
        workflows = {}
        for name in ('.github/workflows/build-base.yml', '.github/workflows/release.yml',
                     '.github/workflows/check.yml', '.github/workflows/restore-cache.yml',
                     '.github/workflows/publish-release.yml', '.github/workflows/archive-evidence.yml',
                     '.github/workflows/security-review.yml', '.github/workflows/security-proposal.yml'):
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
            self.assertEqual(record['logs_sha256'], release.file_record(directory/'logs-qualification.json')['sha256'])
            self.assertEqual(record['directory_sha256'], release.file_record(directory/'directory-qualification.json')['sha256'])
            self.assertEqual(record['credentials_sha256'], release.file_record(directory/'credential-qualification.json')['sha256'])
            self.assertEqual(record['ids_sha256'], release.file_record(directory/'ids-qualification.json')['sha256'])
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

    def test_missing_stale_altered_and_wrong_subject_log_results_are_rejected(self):
        for alteration in ('missing', 'binary', 'test-source', 'runtime-source', 'missing-check', 'stale',
                           'no-overflow', 'no-delivery', 'storage-limit', 'changed-capacity',
                           'no-local-rotation', 'local-storage-limit', 'no-local-failure', 'local-source', 'local-count-type'):
            with self.subTest(alteration=alteration), tempfile.TemporaryDirectory() as temporary:
                directory, project, now, _ = self.fixture(Path(temporary))
                path = directory/'logs-qualification.json'
                logs = json.loads(path.read_bytes())
                if alteration == 'missing':
                    path.unlink()
                else:
                    if alteration == 'binary':
                        logs['alloy_sha256'] = 'b'*64
                    elif alteration == 'test-source':
                        logs['source_sha256'] = 'b'*64
                    elif alteration == 'runtime-source':
                        (project/'lanrith/logs_runtime.py').write_text('changed after qualification')
                    elif alteration == 'missing-check':
                        logs['checks'].remove('own-journal-exclusion')
                    elif alteration == 'stale':
                        logs['assessed_at'] = (now-datetime.timedelta(hours=7)).isoformat()
                    elif alteration == 'no-overflow':
                        logs['overflow_records'] = 0
                    elif alteration == 'no-delivery':
                        logs['delivered_batches'] = 0
                    elif alteration == 'storage-limit':
                        logs['queue_physical_bytes'] = 161*1024*1024
                    elif alteration == 'changed-capacity':
                        logs['queue_capacity_bytes'] = 65536
                    elif alteration == 'no-local-rotation':
                        logs['local_output_files'] = 1
                    elif alteration == 'local-storage-limit':
                        logs['local_output_bytes'] = 3*1024*1024+1
                    elif alteration == 'no-local-failure':
                        logs['local_failed_records'] = 0
                    elif alteration == 'local-count-type':
                        logs['local_failed_records'] = True
                    elif alteration == 'local-source':
                        (project/'lanrith/extension_observations.py').write_text('changed observation admission')
                    path.write_bytes(release.canonical(logs))
                with self.assertRaises((release.ReleaseError, OSError)):
                    qualification.qualify(directory, project, {}, now=now)

    def test_directory_results_bind_failure_coverage_freshness_and_all_implementation_inputs(self):
        for alteration in ('missing', 'test-source', 'runtime-source', 'fixture-source', 'missing-check',
                           'extra-input', 'missing-input', 'stale', 'future', 'external-network'):
            with self.subTest(alteration=alteration), tempfile.TemporaryDirectory() as temporary:
                directory, project, now, _ = self.fixture(Path(temporary))
                path = directory/'directory-qualification.json'
                report = json.loads(path.read_bytes())
                if alteration == 'missing':
                    path.unlink()
                else:
                    if alteration == 'test-source':
                        report['source_sha256'] = 'b'*64
                    elif alteration == 'runtime-source':
                        (project/'lanrith/directory_runtime.py').write_text('changed after qualification')
                    elif alteration == 'fixture-source':
                        (project/'tests/test_directory.py').write_text('changed after qualification')
                    elif alteration == 'missing-check':
                        report['checks'].remove('expired-certificate-rejection')
                    elif alteration == 'extra-input':
                        report['implementation_sha256']['unreviewed.py'] = 'b'*64
                    elif alteration == 'missing-input':
                        report['implementation_sha256'].pop('lanrith/firewall.py')
                    elif alteration == 'stale':
                        report['assessed_at'] = (now-datetime.timedelta(hours=7)).isoformat()
                    elif alteration == 'future':
                        report['assessed_at'] = (now+datetime.timedelta(seconds=1)).isoformat()
                    elif alteration == 'external-network':
                        report['external_network'] = True
                    path.write_bytes(release.canonical(report))
                with self.assertRaises((release.ReleaseError, OSError)):
                    qualification.qualify(directory, project, {}, now=now)

    def test_credential_gate_requires_current_coverage_sources_isolation_and_cleanup(self):
        changes = ('missing', 'test-source', 'runtime-source', 'runner-source', 'missing-check', 'extra-input',
                   'missing-input', 'stale', 'future', 'naive-time', 'invalid-time', 'external-network',
                   'not-cleaned', 'wrong-builder', 'invalid-schema')
        for alteration in changes:
            with self.subTest(alteration=alteration), tempfile.TemporaryDirectory() as temporary:
                directory, project, now, _ = self.fixture(Path(temporary))
                path = directory/'credential-qualification.json'
                report = json.loads(path.read_bytes())
                if alteration == 'missing':
                    path.unlink()
                else:
                    if alteration == 'test-source':
                        report['source_sha256'] = 'b'*64
                    elif alteration in ('runtime-source', 'runner-source'):
                        selected = 'lanrith/credential_operation.py' if alteration == 'runtime-source' else 'scripts/qualify-credentials.py'
                        (project/selected).write_text('changed after qualification')
                    elif alteration == 'missing-check':
                        report['checks'].remove('native-loadcredential-bytes')
                    elif alteration == 'extra-input':
                        report['implementation_sha256']['unreviewed.py'] = 'b'*64
                    elif alteration == 'missing-input':
                        report['implementation_sha256'].pop('lanrith/credential_values.py')
                    elif alteration in ('stale', 'future'):
                        report['assessed_at'] = (now+datetime.timedelta(hours=-7 if alteration == 'stale' else 1)).isoformat()
                    elif alteration == 'naive-time':
                        report['assessed_at'] = now.replace(tzinfo=None).isoformat()
                    elif alteration == 'invalid-time':
                        report.pop('assessed_at')
                    elif alteration == 'external-network':
                        report['external_network'] = True
                    elif alteration == 'not-cleaned':
                        report['container_cleanup'] = 'pending'
                    elif alteration == 'wrong-builder':
                        report['builder_image_sha256'] = 'unbound-tag'
                    elif alteration == 'invalid-schema':
                        report['schema'] = True
                    path.write_bytes(release.canonical(report))
                with self.assertRaises((release.ReleaseError, OSError)):
                    qualification.qualify(directory, project, {}, now=now)

    def test_ids_gate_is_required_before_any_production_promotion(self):
        for alteration in ('missing', 'test-source', 'runtime-source', 'runner-source', 'missing-check',
                           'wrong-base', 'wrong-binary', 'no-match', 'stale', 'not-cleaned', 'invalid-schema'):
            with self.subTest(alteration=alteration), tempfile.TemporaryDirectory() as temporary:
                directory, project, now, _ = self.fixture(Path(temporary))
                path = directory/'ids-qualification.json'
                report = json.loads(path.read_bytes())
                if alteration == 'missing':
                    path.unlink()
                else:
                    if alteration == 'test-source':
                        report['source_sha256'] = 'd'*64
                    elif alteration in ('runtime-source', 'runner-source'):
                        selected = 'lanrith/ids.py' if alteration == 'runtime-source' else 'scripts/qualify-ids.py'
                        (project/selected).write_text('changed after native qualification')
                    elif alteration == 'missing-check':
                        report['checks'].remove('generated-command-root-working-directory')
                    elif alteration == 'wrong-base':
                        report['filesystem_sha256'] = 'd'*64
                    elif alteration == 'wrong-binary':
                        report['base_binary_sha256'] = 'd'*64
                    elif alteration == 'no-match':
                        report['base_binary_match'] = False
                    elif alteration == 'stale':
                        report['assessed_at'] = (now-datetime.timedelta(hours=7)).isoformat()
                    elif alteration == 'not-cleaned':
                        report['container_cleanup'] = 'pending'
                    elif alteration == 'invalid-schema':
                        report['schema'] = True
                    path.write_bytes(release.canonical(report))
                with self.assertRaises((release.ReleaseError, OSError)):
                    qualification.qualify(directory, project, self.hosted_environment(), now=now)
                self.assertFalse(json.loads((directory/'security.json').read_bytes())['production_qualified'])
                self.assertFalse((directory/'qualification.json').exists())
