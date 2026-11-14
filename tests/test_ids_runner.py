"""The native IDS gate binds inputs and publishes only after verified cleanup."""

import datetime
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

from lanrith.release import ReleaseError, canonical, file_record
from ids_fixture import report, sources

spec = importlib.util.spec_from_file_location('ids_runner', Path(__file__).parents[1]/'scripts/qualify-ids.py')
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)


class IDSRunnerTests(unittest.TestCase):
    def fixture(self, root, failure=None):
        project = root/'project'
        project.mkdir()
        sources(project)
        base = root/'base.tar.gz'
        base.write_bytes(b'synthetic base interface subject')
        result, calls, stage = root/'ids-qualification.json', [], None
        def command(runtime, *args, **kwargs):
            nonlocal stage
            calls.append((runtime, args, kwargs))
            if args[:2] == ('image', 'inspect'):
                return SimpleNamespace(returncode=0, stdout=('sha256:'+'a'*64+'\n').encode())
            if args[0] == 'run':
                stage = Path(next(value.removesuffix(':/output') for value in args if value.endswith(':/output')))
                if failure in ('launch', 'wrong-cleanup-label'):
                    raise subprocess.TimeoutExpired('synthetic launch', 30)
                return SimpleNamespace(returncode=0, stdout=('c'*64+'\n').encode())
            if args[0] == 'exec':
                receipt = report(file_record(base)['sha256'], datetime.datetime.now(datetime.timezone.utc), project)
                path = stage/Path(args[-1]).name
                if failure == 'incomplete':
                    receipt['checks'] = []
                path.write_bytes(canonical(receipt))
                if failure == 'source':
                    (project/'lanrith/ids.py').write_text('changed after native execution')
                if failure == 'base':
                    base.write_bytes(b'changed base after native execution')
                if failure == 'native':
                    raise ReleaseError('synthetic native failure')
                return SimpleNamespace(returncode=0, stdout=b'')
            if args[0] == 'inspect':
                return SimpleNamespace(returncode=0, stdout=canonical({'io.lanrith.ids-gate':
                    'd'*32 if failure == 'wrong-cleanup-label' else 'b'*32}))
            if args[0] == 'rm':
                if failure == 'cleanup':
                    raise ReleaseError('synthetic cleanup failure')
                return SimpleNamespace(returncode=0, stdout=b'')
            raise AssertionError(args)
        return project, base, result, calls, command

    def test_success_pins_image_and_base_read_only_and_publishes_after_removal(self):
        for runtime in ('docker', 'podman'):
            with self.subTest(runtime=runtime), tempfile.TemporaryDirectory() as temporary:
                project, base, result, calls, command = self.fixture(Path(temporary))
                with mock.patch.object(runner, 'command', side_effect=command), \
                        mock.patch.object(runner.uuid, 'uuid4', return_value=SimpleNamespace(hex='b'*32)):
                    value = runner.qualify(project, 'reviewed-builder:fixture', base, result, runtime=runtime)
                self.assertEqual(value['container_cleanup'], 'removed')
                self.assertEqual(value['builder_image_sha256'], 'a'*64)
                self.assertEqual(value['filesystem_sha256'], file_record(base)['sha256'])
                launch = next(args for _, args, _ in calls if args[0] == 'run')
                self.assertEqual(launch[launch.index('--network')+1], 'none')
                self.assertIn('--pull=never', launch)
                self.assertNotIn('--privileged', launch)
                for capability in ('NET_ADMIN', 'SYS_ADMIN', 'NET_RAW'):
                    self.assertIn('--cap-add='+capability, launch)
                self.assertIn('sha256:'+'a'*64, launch)
                self.assertIn(str(project)+':/source:ro', launch)
                self.assertIn(str(base)+':/subject/base.tar.gz:ro', launch)
                stage = Path(next(value.removesuffix(':/output') for value in launch if value.endswith(':/output')))
                self.assertEqual(stage.parent, result.parent)
                self.assertNotEqual(stage, result.parent)
                self.assertFalse(stage.exists())
                self.assertFalse(any('docker.sock' in arg or '/dev/:' in arg for arg in launch))
                self.assertEqual(calls[-1][1], ('rm', '--force', 'c'*64))
                self.assertEqual(json.loads(result.read_bytes()), value)
                self.assertEqual(list(result.parent.glob('.ids-*')), [])

    def test_input_changes_native_failure_or_incomplete_receipts_cannot_publish(self):
        for failure in ('source', 'base', 'native', 'incomplete', 'cleanup', 'launch'):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as temporary:
                project, base, result, calls, command = self.fixture(Path(temporary), failure)
                with mock.patch.object(runner, 'command', side_effect=command), \
                        mock.patch.object(runner.uuid, 'uuid4', return_value=SimpleNamespace(hex='b'*32)), \
                        self.assertRaises((ReleaseError, subprocess.TimeoutExpired)):
                    runner.qualify(project, 'reviewed-builder:fixture', base, result)
                self.assertFalse(result.exists())
                self.assertEqual(list(result.parent.glob('.ids-*')), [])
                self.assertEqual(sum(args[0] == 'rm' for _, args, _ in calls), 1)

    def test_failed_launch_cannot_remove_a_different_container(self):
        with tempfile.TemporaryDirectory() as temporary:
            project, base, result, calls, command = self.fixture(Path(temporary), 'wrong-cleanup-label')
            with mock.patch.object(runner, 'command', side_effect=command), \
                    mock.patch.object(runner.uuid, 'uuid4', return_value=SimpleNamespace(hex='b'*32)), \
                    self.assertRaises(ReleaseError):
                runner.qualify(project, 'reviewed-builder:fixture', base, result)
            self.assertFalse(result.exists())
            self.assertFalse(any(args[0] == 'rm' for _, args, _ in calls))

    def test_existing_or_symlinked_inputs_and_results_fail_before_container_operations(self):
        with tempfile.TemporaryDirectory() as temporary:
            project, base, result, _, _ = self.fixture(Path(temporary))
            result.write_bytes(b'retained evidence')
            with mock.patch.object(runner, 'command') as command, self.assertRaises(ReleaseError):
                runner.qualify(project, 'reviewed-builder:fixture', base, result)
            command.assert_not_called()
            self.assertEqual(result.read_bytes(), b'retained evidence')
            result.unlink()
            result.symlink_to(result.with_name('missing'))
            with mock.patch.object(runner, 'command') as command, self.assertRaises(ReleaseError):
                runner.qualify(project, 'reviewed-builder:fixture', base, result)
            command.assert_not_called()
            result.unlink()
            alias = base.with_name('alias.tar.gz')
            alias.symlink_to(base)
            with mock.patch.object(runner, 'command') as command, self.assertRaises(ReleaseError):
                runner.qualify(project, 'reviewed-builder:fixture', alias, result)
            command.assert_not_called()
