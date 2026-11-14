"""Exact DNS base subjects, stale/partial evidence and cleanup failures close admission."""

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

from lanrith import dns_qualification as gate
from lanrith.release import canonical, file_record, ReleaseError
from dns_fixture import report, sources
import test_admission as admission_tests
import test_qualification as qualification_tests

NOW = admission_tests.NOW
qualification = qualification_tests.qualification


spec = importlib.util.spec_from_file_location('dns_runner', Path(__file__).parents[1]/'scripts/qualify-dns.py')
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)


def archive(path, *, alteration=None):
    with tarfile.open(path, 'w:gz', format=tarfile.PAX_FORMAT) as stream:
        for name in sorted(gate.BINARIES):
            data = ('synthetic executable '+name).encode()
            info = tarfile.TarInfo(name)
            info.size, info.mode = len(data), 0o755
            if name.endswith('/unbound'):
                if alteration == 'duplicate':
                    stream.addfile(info, io.BytesIO(data))
                if alteration == 'alias':
                    info.name = '././'+name
                if alteration == 'absolute':
                    info.name = '/'+name
                if alteration == 'traversal':
                    info.name = '../'+name
                if alteration == 'owner':
                    info.uid = 1000
                if alteration == 'mode':
                    info.mode = 0o777
                if alteration == 'link':
                    info.type, info.linkname, info.size = tarfile.LNKTYPE, 'other', 0
                if alteration == 'missing':
                    continue
            stream.addfile(info, io.BytesIO(data) if info.isfile() else None)


class DnsArchiveTests(unittest.TestCase):
    def test_only_fixed_regular_executables_are_extracted_and_hashed(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            path, destination = root/'base.tar.gz', root/'candidate'
            archive(path)
            destination.mkdir(mode=0o700)
            actual = gate.binaries(path, destination=destination)
            self.assertEqual(actual, gate.binaries(path))
            self.assertEqual({item.name for item in destination.iterdir()}, {'unbound', 'unbound-checkconf'})
            for name, digest in actual.items():
                target = destination/Path(name).name
                self.assertEqual(digest, file_record(target)['sha256'])
                self.assertEqual(target.stat().st_mode & 0o7777, 0o755)
            with self.assertRaises(ReleaseError):
                gate.binaries(path, destination=destination)

    def test_ambiguous_unsafe_and_incomplete_subjects_are_rejected(self):
        for alteration in ('duplicate', 'alias', 'absolute', 'traversal', 'owner', 'mode', 'link', 'missing'):
            with self.subTest(alteration=alteration), tempfile.TemporaryDirectory() as temporary:
                path = Path(temporary)/'base.tar.gz'
                archive(path, alteration=alteration)
                with self.assertRaises(ReleaseError):
                    gate.binaries(path)


class DnsEvidenceTests(unittest.TestCase):
    def test_producer_rejects_missing_stale_incomplete_or_changed_dns_subjects(self):
        helper = qualification_tests.QualificationTests()
        for alteration in ('missing', 'runtime-source', 'test-source', 'runner-source', 'checks', 'filesystem_sha256',
                           'unbound_sha256', 'unbound_checkconf_sha256', 'schema', 'assessed_at', 'container_cleanup'):
            with self.subTest(alteration=alteration), tempfile.TemporaryDirectory() as temporary:
                directory, project, now, _ = helper.fixture(Path(temporary))
                path = directory/'dns-qualification.json'
                value = json.loads(path.read_bytes())
                if alteration == 'missing':
                    path.unlink()
                elif alteration.endswith('-source'):
                    selected = {'runtime-source': 'lanrith/dns_metadata.py', 'test-source': 'tests/dns_observations_native.py',
                                'runner-source': 'scripts/qualify-dns.py'}[alteration]
                    (project/selected).write_text('changed after native tests')
                else:
                    value[alteration] = {'checks': [], 'filesystem_sha256': 'a'*64, 'unbound_sha256': 'a'*64,
                        'unbound_checkconf_sha256': 'a'*64, 'schema': True,
                        'assessed_at': (now-datetime.timedelta(hours=7)).isoformat(), 'container_cleanup': 'pending'}[alteration]
                    path.write_bytes(canonical(value))
                with self.assertRaises((ReleaseError, OSError)):
                    qualification.qualify(directory, project, helper.hosted_environment(), now=now)
                self.assertFalse((directory/'qualification.json').exists())
                self.assertFalse(json.loads((directory/'security.json').read_bytes())['production_qualified'])

    def test_consumer_checks_claims_even_with_self_consistent_artifact_hashes(self):
        helper = admission_tests.AdmissionTests()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            selection, record, security = helper.fixture(root)
            original = report(record['filesystem_sha256'], NOW)
            for changed in ({'schema': True}, {'checks': []}, {'unbound_sha256': 'e'*64},
                            {'unbound_checkconf_sha256': 'e'*64}, {'filesystem_sha256': 'e'*64},
                            {'source_sha256': {}}, {'assembly_sha256': {}}, {'container_cleanup': 'pending'}, {'collector_uid': 0},
                            {'effective_capabilities': 1}, {'no_new_privileges': False},
                            {'assessed_at': (NOW-datetime.timedelta(hours=7)).isoformat()}):
                (root/'dns-qualification.json').write_bytes(canonical({**copy.deepcopy(original), **changed}))
                helper.bind(root, selection, record, security)
                from lanrith import admission
                with self.subTest(fields=sorted(changed)), self.assertRaises(ReleaseError):
                    admission.assess(root, selection, NOW)


class DnsRunnerTests(unittest.TestCase):
    def fixture(self, root, failure=None):
        project = root/'project'
        project.mkdir()
        sources(project)
        base = root/'base.tar.gz'
        archive(base)
        expected = gate.binaries(base)
        result, calls, stage = root/'dns-qualification.json', [], None
        def command(runtime, *args, **kwargs):
            nonlocal stage
            calls.append(args)
            if args[:2] == ('image', 'inspect'):
                return SimpleNamespace(returncode=0, stdout=('sha256:'+'a'*64+'\n').encode())
            if args[0] == 'run':
                stage = Path(next(item.removesuffix(':/output') for item in args if item.endswith(':/output')))
                if failure in ('launch', 'wrong-label'):
                    raise subprocess.TimeoutExpired('synthetic launch', 30)
                return SimpleNamespace(returncode=0, stdout=('c'*64+'\n').encode())
            if args[0] == 'exec':
                if args[-1] == 'basic.target':
                    return SimpleNamespace(returncode=0, stdout=b'')
                receipt = report(file_record(base)['sha256'], datetime.datetime.now(datetime.timezone.utc), project)
                receipt.update(base_binaries_sha256=expected, unbound_sha256=expected['usr/sbin/unbound'],
                               unbound_checkconf_sha256=expected['usr/sbin/unbound-checkconf'])
                if failure == 'incomplete':
                    receipt['checks'] = []
                (stage/'native.json').write_bytes(canonical(receipt))
                if failure == 'source':
                    (project/'lanrith/dns_metadata.py').write_text('changed during native tests')
                if failure == 'base':
                    base.write_bytes(b'changed during native tests')
                if failure == 'native':
                    raise ReleaseError('synthetic execution failure')
                return SimpleNamespace(returncode=0, stdout=b'')
            if args[0] == 'inspect':
                return SimpleNamespace(returncode=0, stdout=canonical({'io.lanrith.dns-gate': 'd'*32 if failure == 'wrong-label' else 'b'*32}))
            if args[0] == 'rm':
                if failure == 'cleanup':
                    raise ReleaseError('synthetic cleanup failure')
                self.assertFalse(result.exists())
                return SimpleNamespace(returncode=0, stdout=b'')
            raise AssertionError(args)
        return project, base, result, calls, command

    def test_success_uses_sealed_inputs_and_publishes_only_after_cleanup(self):
        for runtime in ('docker', 'podman'):
            with self.subTest(runtime=runtime), tempfile.TemporaryDirectory() as temporary:
                project, base, result, calls, command = self.fixture(Path(temporary))
                with mock.patch.object(runner, 'command', side_effect=command), \
                        mock.patch.object(runner.uuid, 'uuid4', return_value=SimpleNamespace(hex='b'*32)):
                    value = runner.qualify(project, 'fixture:builder', base, result, runtime=runtime)
                self.assertEqual(value['container_cleanup'], 'removed')
                self.assertEqual(value['builder_image_sha256'], 'a'*64)
                launch = next(args for args in calls if args[0] == 'run')
                for item in ('--network=none', '--pull=never', '--memory=1g', '--pids-limit=256',
                             str(project)+':/source:ro', str(base)+':/subject/base.tar.gz:ro', 'sha256:'+'a'*64):
                    self.assertIn(item, launch)
                self.assertFalse(any('docker.sock' in arg or '/dev/:' in arg for arg in launch))
                stage = Path(next(item.removesuffix(':/output') for item in launch if item.endswith(':/output')))
                self.assertFalse(stage.exists())
                self.assertTrue(result.exists())

    def test_failure_cleans_owned_fixture_and_never_publishes_a_pass(self):
        for failure in ('native', 'source', 'base', 'incomplete', 'cleanup', 'launch', 'wrong-label'):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as temporary:
                project, base, result, calls, command = self.fixture(Path(temporary), failure)
                with mock.patch.object(runner, 'command', side_effect=command), \
                        mock.patch.object(runner.uuid, 'uuid4', return_value=SimpleNamespace(hex='b'*32)):
                    with self.assertRaises((ReleaseError, subprocess.TimeoutExpired)):
                        runner.qualify(project, 'fixture:builder', base, result)
                self.assertFalse(result.exists())
                self.assertFalse(list(result.parent.glob('.dns-native-*')))
                self.assertEqual(any(args[0] == 'rm' for args in calls), failure != 'wrong-label')
