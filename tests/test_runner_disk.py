"""Disk preparation must preserve its budget, diagnostics and cleanup boundary."""

import contextlib
import datetime
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import yaml

from automation import cleanup

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('prepare_runner', ROOT/'scripts/prepare-runner.py')
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)
GIB = 1024**3


class RunnerDiskTests(unittest.TestCase):
    def environment(self, temporary):
        return {'GITHUB_ACTIONS':'true','RUNNER_ENVIRONMENT':'github-hosted','RUNNER_OS':'Linux',
                'RUNNER_TEMP':str(temporary),'ImageVersion':'synthetic-image',
                'GH_TOKEN':'private-canary-must-not-appear-in-diagnostics'}

    def evaluate(self, temporary, after, *, command_error=None):
        usage = lambda free: SimpleNamespace(total=100*GIB,used=100*GIB-free,free=free)
        with patch.dict(os.environ,self.environment(temporary)), \
                patch.object(runner.shutil,'disk_usage',side_effect=[usage(18*GIB),usage(after)]), \
                patch.object(runner.subprocess,'run',side_effect=command_error) as command, \
                contextlib.redirect_stdout(io.StringIO()) as output:
            try:
                value = runner.prepare()
                return value,command,output.getvalue()
            finally:
                self.last_command=command

    def test_cleanup_reclaims_space_and_keeps_only_public_diagnostics(self):
        with tempfile.TemporaryDirectory() as temporary:
            value,command,output=self.evaluate(temporary,66*GIB)
            report=json.loads((Path(temporary)/'runner-disk.json').read_text())
            self.assertEqual(value,report)
            self.assertEqual(value['result'],'pass')
            self.assertEqual(value['before']['free_bytes'],18*GIB)
            self.assertEqual(value['after']['free_bytes'],66*GIB)
            self.assertEqual(value['minimum_free_bytes'],60*GIB)
            self.assertIn('66.00 GiB free',output)
            self.assertNotIn('private-canary',json.dumps(value))
            self.assertEqual(value['runner']['ImageVersion'],'synthetic-image')
            self.assertTrue(command.call_args.kwargs['check'])

    def test_insufficient_space_fails_with_actual_measurement_and_retained_report(self):
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaisesRegex(RuntimeError,'59.00 GiB free.*60.00 GiB'):
                self.evaluate(temporary,59*GIB)
            report=json.loads((Path(temporary)/'runner-disk.json').read_text())
            self.assertEqual(report['result'],'fail')
            self.assertEqual(report['after']['free_bytes'],59*GIB)
            self.assertIn('60.00 GiB',report['error'])

    def test_exact_original_budget_passes_and_one_byte_less_fails(self):
        for available in (60*GIB,60*GIB-1):
            with self.subTest(available=available), tempfile.TemporaryDirectory() as temporary:
                if available==60*GIB:
                    self.assertEqual(self.evaluate(temporary,available)[0]['result'],'pass')
                else:
                    with self.assertRaises(RuntimeError): self.evaluate(temporary,available)

    def test_cleanup_failure_does_not_claim_space_reclaimed_or_pass(self):
        with tempfile.TemporaryDirectory() as temporary:
            error=subprocess.CalledProcessError(1,['sudo','rm'])
            with self.assertRaises(subprocess.CalledProcessError):
                self.evaluate(temporary,80*GIB,command_error=error)
            report=json.loads((Path(temporary)/'runner-disk.json').read_text())
            self.assertEqual(report['result'],'fail')
            self.assertNotIn('after',report)
            self.assertIn('error',report)

    def test_local_or_self_hosted_execution_never_runs_privileged_cleanup(self):
        for key,value in (('GITHUB_ACTIONS','false'),('RUNNER_ENVIRONMENT','self-hosted'),('RUNNER_OS','Windows')):
            with self.subTest(key=key), tempfile.TemporaryDirectory() as temporary:
                environment=self.environment(temporary)|{key:value}
                with patch.dict(os.environ,environment), patch.object(runner.subprocess,'run') as command, \
                        patch.object(runner.shutil,'disk_usage') as usage:
                    with self.assertRaisesRegex(RuntimeError,'disposable GitHub-hosted Linux'):
                        runner.prepare()
                    command.assert_not_called();usage.assert_not_called()
                    self.assertFalse((Path(temporary)/'runner-disk.json').exists())

    def test_diagnostics_symlink_cannot_redirect_privileged_preparation(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary);target=root/'keep.json';target.write_text('keep')
            (root/'runner-disk.json').symlink_to(target)
            with patch.dict(os.environ,self.environment(root)), patch.object(runner.subprocess,'run') as command:
                with self.assertRaisesRegex(RuntimeError,'regular file'):
                    runner.prepare()
                command.assert_not_called()
            self.assertEqual(target.read_text(),'keep')

    def test_runner_temp_alias_can_be_used_without_changing_cleanup_targets(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary);actual=root/'actual';actual.mkdir();alias=root/'alias';alias.symlink_to(actual,target_is_directory=True)
            value,_,_=self.evaluate(alias,64*GIB)
            self.assertEqual(value['after']['path'],str(actual))
            self.assertEqual(json.loads((actual/'runner-disk.json').read_text())['result'],'pass')

    def test_cleanup_is_fixed_sdk_only_and_cannot_follow_environment_overrides(self):
        with tempfile.TemporaryDirectory() as temporary:
            marker=Path(temporary)/'keep-source';marker.write_text('unchanged')
            with patch.dict(os.environ,{'GHCUP_INSTALL_BASE_PREFIX':temporary,'SWIFT_PATH':temporary,'GITHUB_WORKSPACE':temporary}):
                _,command,_=self.evaluate(temporary,64*GIB)
            argv=command.call_args.args[0]
            self.assertNotIn(temporary,argv)
            self.assertNotIn('shell',command.call_args.kwargs)
            self.assertIn('--one-file-system',argv)
            self.assertIn('/usr/share/swift',argv)
            self.assertIn('/usr/local/.ghcup',argv)
            for protected in ('/opt/hostedtoolcache','/var/lib/docker','/home/runner/work','/usr/local/go','/usr/bin'):
                self.assertNotIn(protected,argv)
            self.assertEqual(marker.read_text(),'unchanged')


class RunnerDiskHandoffTests(unittest.TestCase):
    def test_every_compiler_and_native_job_prepares_disk_before_artifact_download(self):
        for name in ('build-base.yml','package-check.yml'):
            workflow=yaml.safe_load((ROOT/'.github/workflows'/name).read_text())
            for job in ('packages','build'):
                with self.subTest(workflow=name,job=job):
                    steps=workflow['jobs'][job]['steps']
                    prepared=next(i for i,s in enumerate(steps) if s.get('id')=='runner-disk')
                    downloaded=next(i for i,s in enumerate(steps) if s.get('uses','').startswith('actions/download-artifact@'))
                    self.assertLess(prepared,downloaded)
                    self.assertEqual(steps[prepared]['run'],'python3 scripts/prepare-runner.py')
                    report=steps[prepared+1]
                    self.assertEqual(report['if'],'always()')
                    self.assertEqual(report['with']['path'],'${{ runner.temp }}/runner-disk.json')
                    self.assertEqual(report['with']['retention-days'],1)

    def test_only_completed_known_disk_reports_enter_short_artifact_cleanup(self):
        clock=datetime.datetime(2026,11,1,13,tzinfo=datetime.timezone.utc)
        artifacts=[{'id':i,'name':name,'size_in_bytes':1024,'expired':False,'workflow_run':{'id':i}}
                   for i,name in enumerate(('runner-disk-packages-1','runner-disk-native-1','runner-disk-private-key-1'),1)]
        def get(endpoint,**kwargs):
            if kwargs.get('paginate'):return [{'artifacts':artifacts}]
            return {'name':'Release','status':'completed','updated_at':(clock-datetime.timedelta(hours=3)).isoformat()}
        result=cleanup.plan('Lanrith/lanrith',get=get,clock=clock)
        self.assertEqual([a['id'] for a in result['artifacts']],[1,2])
        self.assertEqual(result['bytes'],2048)
