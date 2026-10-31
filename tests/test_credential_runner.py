"""The native fixture runner binds an immutable image and always cleans up."""

import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

from lanrith.release import ReleaseError, canonical

spec = importlib.util.spec_from_file_location('credential_runner', Path(__file__).parents[1]/'scripts/qualify-credentials.py')
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)


class CredentialRunnerTests(unittest.TestCase):
    def fixture(self, root, failure=None):
        project = root/'project'
        project.mkdir()
        result = root/'credential-qualification.json'
        calls = []
        def command(runtime, *args, **kwargs):
            calls.append((runtime, args, kwargs))
            if args[:2] == ('image', 'inspect'):
                return SimpleNamespace(returncode=0, stdout=('sha256:'+'a'*64+'\n').encode())
            if args[0] == 'run':
                if failure == 'launch':
                    raise subprocess.TimeoutExpired('synthetic runtime', 30)
                return SimpleNamespace(returncode=0, stdout=('c'*64+'\n').encode())
            if args[0] == 'exec' and 'systemctl' in args:
                return SimpleNamespace(returncode=0, stdout=b'')
            if args[0] == 'exec':
                path = root/Path(args[-1]).name
                path.write_bytes(canonical({'schema': 1, 'result': 'pass', 'test': 'offline-systemd-credential-provisioning'}))
                if failure == 'native':
                    raise ReleaseError('synthetic native failure')
                return SimpleNamespace(returncode=0, stdout=b'')
            if args[0] == 'inspect':
                return SimpleNamespace(returncode=0, stdout=canonical({'io.lanrith.credential-gate': 'b'*32}))
            if args[0] == 'rm':
                if failure == 'cleanup':
                    raise ReleaseError('synthetic cleanup failure')
                return SimpleNamespace(returncode=0, stdout=b'')
            raise AssertionError(args)
        return project, result, calls, command

    def test_success_uses_a_resolved_image_no_network_and_publishes_only_after_cleanup(self):
        for runtime in ('docker', 'podman'):
            with self.subTest(runtime=runtime), tempfile.TemporaryDirectory() as temporary:
                project, result, calls, command = self.fixture(Path(temporary))
                with mock.patch.object(runner, 'command', side_effect=command), \
                        mock.patch.object(runner.uuid, 'uuid4', return_value=SimpleNamespace(hex='b'*32)):
                    value = runner.qualify(project, 'reviewed-builder:fixture', result, runtime=runtime)
                self.assertEqual(value['container_cleanup'], 'removed')
                self.assertEqual(value['builder_image_sha256'], 'a'*64)
                launch = next(args for _, args, _ in calls if args[0] == 'run')
                self.assertIn('sha256:'+'a'*64, launch)
                self.assertEqual(launch[launch.index('--network')+1], 'none')
                self.assertIn('--cgroupns=private', launch)
                self.assertEqual('--systemd=always' in launch, runtime == 'podman')
                self.assertEqual(launch[launch.index('-v')+1], str(project)+':/source:ro')
                self.assertFalse(any('/sys/fs/cgroup:' in arg or 'docker.sock' in arg for arg in launch))
                self.assertEqual(calls[-1][1], ('rm', '--force', 'c'*64))
                self.assertEqual(json.loads(result.read_bytes()), value)
                self.assertEqual(list(result.parent.glob('.credentials-*')), [])

    def test_native_failure_and_failed_cleanup_cannot_publish_a_passing_result(self):
        for failure in ('native', 'cleanup', 'launch'):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as temporary:
                project, result, calls, command = self.fixture(Path(temporary), failure)
                with mock.patch.object(runner, 'command', side_effect=command), \
                        mock.patch.object(runner.uuid, 'uuid4', return_value=SimpleNamespace(hex='b'*32)), \
                        self.assertRaises((ReleaseError, subprocess.TimeoutExpired)):
                    runner.qualify(project, 'reviewed-builder:fixture', result)
                self.assertFalse(result.exists())
                self.assertEqual(list(result.parent.glob('.credentials-*')), [])
                self.assertEqual(sum(args[0] == 'rm' for _, args, _ in calls), 1)

    def test_existing_or_symlinked_results_are_never_overwritten(self):
        with tempfile.TemporaryDirectory() as temporary:
            project, result, _, _ = self.fixture(Path(temporary))
            result.write_bytes(b'previous evidence')
            with mock.patch.object(runner, 'command') as command, self.assertRaises(ReleaseError):
                runner.qualify(project, 'reviewed-builder:fixture', result)
            command.assert_not_called()
            self.assertEqual(result.read_bytes(), b'previous evidence')
            result.unlink()
            result.symlink_to(result.with_name('missing'))
            with self.assertRaises(ReleaseError):
                runner.qualify(project, 'reviewed-builder:fixture', result)

    def test_transient_observation_timeout_rechecks_same_live_handle_without_restart(self):
        calls = []
        def command(runtime, *args, **kwargs):
            calls.append(args)
            if args[0] == 'exec' and len(calls) == 1:
                raise subprocess.TimeoutExpired('synthetic observation', 5)
            return SimpleNamespace(returncode=0, stdout=canonical({'Running': True}))
        with mock.patch.object(runner, 'command', side_effect=command), mock.patch.object(runner.time, 'sleep'):
            runner.wait_systemd('docker', 'c'*64)
        self.assertEqual([args[0] for args in calls], ['exec', 'inspect', 'exec'])
        self.assertTrue(all('c'*64 in args for args in calls))

    def test_stopped_container_and_readiness_deadline_are_qualification_failures(self):
        for stopped in (True, False):
            def command(runtime, *args, **kwargs):
                return SimpleNamespace(returncode=1 if args[0] == 'exec' else 0,
                    stdout=canonical({'Running': not stopped}))
            with self.subTest(stopped=stopped), mock.patch.object(runner, 'command', side_effect=command), \
                    mock.patch.object(runner.time, 'monotonic', side_effect=[0, 1, 2, 61]), \
                    mock.patch.object(runner.time, 'sleep'), self.assertRaises(ReleaseError):
                runner.wait_systemd('docker', 'c'*64)


if __name__ == '__main__':
    unittest.main()
