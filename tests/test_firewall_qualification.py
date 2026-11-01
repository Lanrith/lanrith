"""Exact nft/library subjects and mandatory producer/consumer evidence."""

import copy
import datetime
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import tarfile
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

from lanrith import firewall_qualification as gate
from lanrith.release import canonical, file_record, ReleaseError
from firewall_fixture import report, sources
import test_admission as admission_tests
import test_qualification as qualification_tests


LIBRARY = 'usr/lib/x86_64-linux-gnu/libnftables.so.1.1.0'
NOW = admission_tests.NOW
spec = importlib.util.spec_from_file_location('firewall_runner', Path(__file__).parents[1]/'scripts/qualify-firewall.py')
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)


def archive(path, *, alteration=None):
    with tarfile.open(path, 'w:gz', format=tarfile.PAX_FORMAT) as stream:
        for name in (gate.NFT, LIBRARY):
            data = ('synthetic target '+name).encode()
            info = tarfile.TarInfo(name)
            info.size, info.mode = len(data), 0o755
            if (name == gate.NFT and alteration != 'library-mode') or alteration == 'library-mode' and name == LIBRARY:
                if alteration == 'duplicate':stream.addfile(info, io.BytesIO(data))
                if alteration == 'alias':info.name = '././'+name
                if alteration == 'absolute':info.name = '/'+name
                if alteration == 'traversal':info.name = '../'+name
                if alteration == 'owner':info.uid = 1000
                if alteration in ('mode', 'library-mode'):info.mode = 0o777
                if alteration == 'link':info.type, info.linkname, info.size = tarfile.LNKTYPE, 'other', 0
                if alteration == 'missing':continue
            stream.addfile(info, io.BytesIO(data) if info.isfile() else None)


class FirewallArchiveTests(unittest.TestCase):
    def test_only_the_fixed_executable_is_extracted_and_all_library_bytes_are_bound(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            path, destination = root/'base.tar.gz', root/'candidate'
            archive(path)
            destination.mkdir(mode=0o700)
            result = gate.subject(path, [LIBRARY], destination=destination)
            self.assertEqual(set(result), {gate.NFT, LIBRARY})
            self.assertEqual(result, gate.subject(path, [LIBRARY]))
            self.assertEqual(list(item.name for item in destination.iterdir()), ['nft'])
            self.assertEqual(file_record(destination/'nft')['sha256'], result[gate.NFT])
            with self.assertRaises(ReleaseError):gate.subject(path, destination=destination)

    def test_links_aliases_overlaps_and_unsafe_library_or_executable_metadata_fail(self):
        for alteration in ('duplicate', 'alias', 'absolute', 'traversal', 'owner', 'mode', 'link', 'missing', 'library-mode'):
            with self.subTest(alteration=alteration), tempfile.TemporaryDirectory() as temporary:
                path = Path(temporary)/'base.tar.gz'
                archive(path, alteration=alteration)
                with self.assertRaises(ReleaseError):gate.subject(path, [LIBRARY])

    def test_dependency_names_cannot_select_credentials_or_noncanonical_paths(self):
        for name in ('etc/shadow', '/'+LIBRARY, 'usr/lib/../private.so', 'usr/lib//libx.so',
                     'usr/lib/libx.so/../../secret', 'usr/lib/keys.json', 'usr/lib/libx.so\n', None):
            with self.subTest(name=name):self.assertFalse(gate.library_path(name))
        self.assertTrue(gate.library_path(LIBRARY))
        self.assertTrue(gate.library_path('usr/lib/aarch64-linux-gnu/ld-linux-aarch64.so.1'))


class FirewallEvidenceTests(unittest.TestCase):
    def test_producer_requires_current_complete_cleaned_and_exact_subject_evidence(self):
        helper = qualification_tests.QualificationTests()
        for alteration in ('missing', 'runtime-source', 'test-source', 'runner-source', 'checks', 'filesystem_sha256',
                           'builder_libraries_sha256', 'nft_sha256', 'schema', 'assessed_at', 'container_cleanup'):
            with self.subTest(alteration=alteration), tempfile.TemporaryDirectory() as temporary:
                directory, project, now, _ = helper.fixture(Path(temporary))
                path = directory/'firewall-qualification.json'
                value = json.loads(path.read_bytes())
                if alteration == 'missing':path.unlink()
                elif alteration.endswith('-source'):
                    selected = {'runtime-source': 'lanrith/firewall_observations_runtime.py',
                                'test-source': 'tests/firewall_service_native.py', 'runner-source': 'scripts/qualify-firewall.py'}[alteration]
                    (project/selected).write_text('changed after native test')
                else:
                    value[alteration] = {'checks': [], 'filesystem_sha256': 'a'*64, 'builder_libraries_sha256': {},
                        'nft_sha256': 'a'*64, 'schema': True, 'assessed_at': (now-datetime.timedelta(hours=7)).isoformat(),
                        'container_cleanup': 'pending'}[alteration]
                    path.write_bytes(canonical(value))
                with self.assertRaises((ReleaseError, OSError)):
                    qualification_tests.qualification.qualify(directory, project, helper.hosted_environment(), now=now)
                self.assertFalse((directory/'qualification.json').exists())
                self.assertFalse(json.loads((directory/'security.json').read_bytes())['production_qualified'])

    def test_consumer_rejects_bad_claims_even_if_all_artifact_hashes_are_rebound(self):
        helper = admission_tests.AdmissionTests()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            selection, record, security = helper.fixture(root)
            original = report(record['filesystem_sha256'], NOW)
            receiver = original['receiver']
            changes = [{'schema': True}, {'checks': []}, {'nft_sha256': 'a'*64}, {'builder_libraries_sha256': {}},
                {'base_userspace_sha256': {}}, {'filesystem_sha256': 'a'*64}, {'source_sha256': {}}, {'assembly_sha256': {}},
                {'container_cleanup': 'pending'}, {'receiver': 'malformed'}, {'receiver': {**receiver, 'uid': 0}},
                {'receiver': {**receiver, 'capabilities': {**receiver['capabilities'], 'CapPrm': '0000000000001000'}}},
                {'receiver': {**receiver, 'capabilities': {**receiver['capabilities'], 'NoNewPrivs': '0'}}},
                {'unconditional_forward_drops': 0}, {'allowed_echoes': True}, {'generated_service_tested': False},
                {'assessed_at': (NOW-datetime.timedelta(hours=7)).isoformat()},
                {'assessed_at': (NOW+datetime.timedelta(seconds=1)).isoformat()}]
            for changed in changes:
                (root/'firewall-qualification.json').write_bytes(canonical({**copy.deepcopy(original), **changed}))
                helper.bind(root, selection, record, security)
                from lanrith import admission
                with self.subTest(fields=sorted(changed)), self.assertRaises(ReleaseError):admission.assess(root, selection, NOW)


class FirewallRunnerTests(unittest.TestCase):
    def fixture(self, root, failure=None):
        project = root/'project'
        project.mkdir()
        sources(project)
        base = root/'base.tar.gz'
        archive(base)
        expected = gate.subject(base, [LIBRARY])
        result, calls, stage = root/'firewall-qualification.json', [], None
        def command(runtime, *args, **kwargs):
            nonlocal stage
            calls.append(args)
            if args[:2] == ('image', 'inspect'):
                return SimpleNamespace(returncode=0, stdout=('sha256:'+'a'*64+'\n').encode())
            if args[0] == 'run':
                stage = Path(next(item.removesuffix(':/output') for item in args if item.endswith(':/output')))
                if failure in ('launch', 'wrong-label'):raise subprocess.TimeoutExpired('synthetic launch', 30)
                return SimpleNamespace(returncode=0, stdout=('c'*64+'\n').encode())
            if args[0] == 'exec':
                if args[-1] == 'basic.target':return SimpleNamespace(returncode=0, stdout=b'')
                receipt = report(file_record(base)['sha256'], datetime.datetime.now(datetime.timezone.utc), project)
                receipt.update(nft_sha256=expected[gate.NFT], builder_libraries_sha256={LIBRARY: expected[LIBRARY]},
                               base_userspace_sha256=expected)
                if failure == 'incomplete':receipt['checks'] = []
                (stage/'native.json').write_bytes(canonical(receipt))
                if failure == 'source':(project/'lanrith/firewall_metadata.py').write_text('changed during execution')
                if failure == 'base':base.write_bytes(b'changed during execution')
                if failure == 'native':raise ReleaseError('synthetic execution failure')
                return SimpleNamespace(returncode=0, stdout=b'')
            if args[0] == 'inspect':
                return SimpleNamespace(returncode=0, stdout=canonical({'io.lanrith.firewall-gate': 'd'*32 if failure == 'wrong-label' else 'b'*32}))
            if args[0] == 'rm':
                if failure == 'cleanup':raise ReleaseError('synthetic cleanup failure')
                self.assertFalse(result.exists())
                return SimpleNamespace(returncode=0, stdout=b'')
            raise AssertionError(args)
        return project, base, result, calls, command

    def test_success_publishes_after_cleanup_and_uses_no_network_or_mutable_builder_tag(self):
        for runtime in ('docker', 'podman'):
            with self.subTest(runtime=runtime), tempfile.TemporaryDirectory() as temporary:
                project, base, result, calls, command = self.fixture(Path(temporary))
                with mock.patch.object(runner, 'command', side_effect=command), mock.patch.object(runner.uuid, 'uuid4', return_value=SimpleNamespace(hex='b'*32)):
                    value = runner.qualify(project, 'synthetic:builder', base, result, runtime=runtime)
                self.assertEqual(value['container_cleanup'], 'removed')
                self.assertEqual(value['builder_image_sha256'], 'a'*64)
                invocation = next(args for args in calls if args[0] == 'run')
                self.assertIn('--network=none', invocation)
                self.assertIn('sha256:'+'a'*64, invocation)
                self.assertFalse(any(root.name.startswith('.firewall-native-') for root in Path(temporary).iterdir()))

    def test_failures_cannot_publish_a_passing_receipt_or_leave_owned_staging(self):
        for failure in ('native', 'incomplete', 'source', 'base', 'cleanup', 'launch', 'wrong-label'):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                project, base, result, calls, command = self.fixture(root, failure)
                with mock.patch.object(runner, 'command', side_effect=command), mock.patch.object(runner.uuid, 'uuid4', return_value=SimpleNamespace(hex='b'*32)):
                    with self.assertRaises((ReleaseError, subprocess.TimeoutExpired)):
                        runner.qualify(project, 'synthetic:builder', base, result, runtime='podman')
                self.assertFalse(result.exists())
                self.assertFalse(any(item.name.startswith('.firewall-native-') for item in root.iterdir()))


if __name__ == '__main__':
    unittest.main()
