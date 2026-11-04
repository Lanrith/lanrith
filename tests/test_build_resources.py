"""Compiler resource limits preserve the hosted runner and fail closed."""
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch
import uuid

from lanrith import build_resources as resources

ROOT = Path(__file__).resolve().parents[1]
GIB = 1024**3


class BuildResourceTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.groups = self.root/'cgroups'
        self.groups.mkdir()
        self.environment = {'GITHUB_ACTIONS':'true', 'RUNNER_ENVIRONMENT':'github-hosted',
            'RUNNER_OS':'Linux', 'GITHUB_JOB':'packages', 'GITHUB_RUN_ID':'10', 'GITHUB_RUN_ATTEMPT':'1',
            'RUNNER_TEMP':str(self.root), 'GH_TOKEN':'private-canary-never-retain'}
        for manager in (patch.dict(os.environ,self.environment), patch.object(resources,'CGROUP_ROOT',self.groups)):
            manager.start(); self.addCleanup(manager.stop)
        self.measured = {'memory_total_bytes':16*GIB, 'memory_available_bytes':12*GIB,
                         'swap_total_bytes':4*GIB, 'cpus':4}

    def group(self, unit, budget):
        root = self.groups/unit
        root.mkdir()
        for name, value in {'memory.max':budget['memory_bytes'], 'memory.swap.max':0,
                'pids.max':budget['tasks'], 'cpu.max':str(100000*budget['cpus'])+' 100000',
                'memory.current':1234, 'memory.peak':4567, 'pids.current':1, 'pids.peak':12,
                'memory.events':'low 0\nhigh 0\nmax 2\noom 1\noom_kill 1',
                'cpu.stat':'usage_usec 2000\nnr_throttled 1\nprivate-untrusted-text ignored'}.items():
            (root/name).write_text(str(value)+'\n')

    def prepare(self):
        with patch.object(resources,'host',return_value=self.measured), \
                patch.object(resources,'create_group',side_effect=self.group):
            return resources.prepare()

    def test_budget_reserves_memory_and_cpu_instead_of_using_all_reported_ram(self):
        self.assertEqual(resources.limits(self.measured), {'memory_bytes':8*GIB,'cpus':2,'tasks':2048,'swap_bytes':0})
        smaller = self.measured | {'memory_total_bytes':8*GIB, 'memory_available_bytes':6*GIB, 'cpus':2}
        self.assertEqual(resources.limits(smaller)['memory_bytes'],4*GIB)
        self.assertEqual(resources.limits(smaller)['cpus'],1)
        for measured in (smaller | {'memory_available_bytes':6*GIB-1}, smaller | {'cpus':1},
                         smaller | {'memory_available_bytes':True}, smaller | {'memory_available_bytes':9*GIB}):
            with self.subTest(measured=measured), self.assertRaises(RuntimeError): resources.limits(measured)

    def test_created_group_is_scoped_and_arguments_share_its_aggregate_limit(self):
        report = self.prepare()
        self.assertEqual(report,resources.configuration())
        self.assertEqual(resources.arguments(),['--cgroup-parent','lanrithbuild10a1.slice'])
        self.assertEqual(resources.compiler_environment(),{'GOMAXPROCS':'2','GOMEMLIMIT':'2048MiB','GOFLAGS':'-p=1'})
        self.assertNotIn('private-canary',json.dumps(report))
        with self.assertRaises(RuntimeError):resources.arguments('podman')
        with self.assertRaises(RuntimeError):self.prepare()

    def test_real_creation_uses_only_a_fresh_scoped_transient_unit(self):
        unit = resources.unit_name(); budget = resources.limits(self.measured)
        calls = []
        def run(argv, **kwargs):
            calls.append(argv)
            self.assertTrue(kwargs['check']);self.assertEqual(kwargs['timeout'],30)
            if argv[:2] == ['sudo','systemd-run']:self.group(unit,budget)
            return subprocess.CompletedProcess(argv,0)
        with patch.object(resources.subprocess,'run',side_effect=run):resources.create_group(unit,budget)
        self.assertIn('--slice='+unit,calls[0]);self.assertIn('MemoryMax='+str(8*GIB),calls[1])
        self.assertIn('MemorySwapMax=0',calls[1]);self.assertIn('CPUQuota=200%',calls[1])
        with patch.object(resources.subprocess,'run') as command:
            for target in (unit,'system.slice','../system.slice','foreign;command.slice'):
                with self.subTest(target=target), self.assertRaises(RuntimeError):resources.create_group(target,budget)
            command.assert_not_called()

    def test_missing_or_tampered_limits_cannot_fall_back_to_an_unbounded_build(self):
        with self.assertRaises(OSError):resources.arguments()
        self.prepare(); path=self.root/'runner-build-resources.json'; original=path.read_text()
        for change in (lambda v:v.update(unit='system.slice'),lambda v:v['limits'].update(memory_bytes=16*GIB),
                       lambda v:v.update(extra='private-canary'),lambda v:v['policy'].update(maximum_tasks=99999)):
            value=json.loads(original);change(value);path.write_text(json.dumps(value))
            with self.subTest(change=change),self.assertRaises(RuntimeError):resources.arguments()
        path.write_text(original)
        for field,bad in [('memory.max','max'),('memory.swap.max','max'),('pids.max','max'),('cpu.max','max 100000')]:
            target=self.groups/resources.unit_name()/field;old=target.read_text();target.write_text(bad)
            with self.subTest(field=field),self.assertRaises(RuntimeError):resources.arguments()
            target.write_text(old)

    def test_foreign_ids_and_symlinked_records_never_run_privileged_commands(self):
        for key,bad in [('GITHUB_RUN_ID','10;unexpected'),('GITHUB_RUN_ATTEMPT','../../foreign')]:
            with patch.dict(os.environ,{key:bad}),patch.object(resources.subprocess,'run') as command:
                with self.assertRaises(RuntimeError):resources.unit_name()
                command.assert_not_called()
        destination=self.root/'runner-build-resources.json'; target=self.root/'keep';target.write_text('keep')
        destination.symlink_to(target)
        with patch.object(resources.subprocess,'run') as command:
            with self.assertRaises(RuntimeError):self.prepare()
            command.assert_not_called()
        self.assertEqual(target.read_text(),'keep')

    def test_diagnostic_hardlink_is_rejected_before_existing_contents_are_truncated(self):
        target=self.root/'keep';target.write_text('keep')
        destination=self.root/'hardlink';os.link(target,destination)
        with self.assertRaises(RuntimeError):resources.write(destination,{'private':'not-written'})
        self.assertEqual(target.read_text(),'keep')

    def test_duplicate_configuration_is_rejected_and_oom_cannot_be_silently_qualified(self):
        self.prepare();path=self.root/'runner-build-resources.json';original=path.read_text()
        path.write_text(original.rstrip()[:-1]+',"schema":1}')
        with self.assertRaisesRegex(RuntimeError,'Duplicate'):resources.configuration()
        path.write_text(original)
        with self.assertRaisesRegex(RuntimeError,'killed by its resource limit'):
            with resources.recording(self.root/'resources.json'):pass

    def test_runtime_native_and_local_contexts_never_create_host_resource_groups(self):
        for change in ({'GITHUB_ACTIONS':'false'},{'RUNNER_ENVIRONMENT':'self-hosted'},
                       {'RUNNER_OS':'Windows'},{'GITHUB_JOB':'build'}):
            with patch.dict(os.environ,change),patch.object(resources.subprocess,'run') as command:
                self.assertIsNone(resources.configuration());self.assertEqual(resources.arguments(),[])
                self.assertEqual(resources.prepare(),{'state':'not-a-hosted-compiler-job'})
                command.assert_not_called()

    def test_failure_keeps_safe_counters_and_the_original_error(self):
        self.prepare(); target=self.root/'diagnostics/resources.json'
        with self.assertRaisesRegex(ValueError,'original failure'):
            with resources.recording(target):raise ValueError('original failure')
        value=json.loads(target.read_text())
        self.assertTrue(value['build_failed']);self.assertEqual(value['counters']['memory.events']['oom_kill'],1)
        self.assertNotIn('private',target.read_text())
        with patch.object(resources,'counters',side_effect=RuntimeError('private-error')):
            with self.assertRaisesRegex(ValueError,'original failure'):
                with resources.recording(target):raise ValueError('original failure')
            self.assertNotIn('private-error',target.read_text())
            with self.assertRaisesRegex(RuntimeError,'private-error'):
                with resources.recording(target):pass

    def test_the_sdk_builder_actually_receives_the_enforced_parent_group(self):
        self.prepare()
        spec=importlib.util.spec_from_file_location('resource_test_base',ROOT/'scripts/build-base.py')
        base=importlib.util.module_from_spec(spec);spec.loader.exec_module(base)
        with patch.object(base.build_cache,'reuse_image',return_value=False), \
                patch.object(base.build_cache,'image_arguments',return_value=[]), \
                patch.object(base.build_cache,'record_image'), patch.object(base,'run') as command:
            base.image('mkosi',self.root,{})
        argv=command.call_args.args
        self.assertEqual(argv[:2],('docker','build'))
        self.assertEqual(argv[argv.index('--cgroup-parent')+1],'lanrithbuild10a1.slice')
        self.assertNotIn('--privileged',argv)


@unittest.skipUnless(os.environ.get('GITHUB_ACTIONS') == 'true' and
    os.environ.get('RUNNER_ENVIRONMENT') == 'github-hosted' and os.environ.get('RUNNER_OS') == 'Linux',
    'Requires the disposable hosted Linux Docker worker')
class HostedCgroupEnforcementTests(unittest.TestCase):
    def test_buildkit_run_oom_is_contained_while_the_host_and_diagnostics_survive(self):
        # Use a small, fixed 96 MiB allocation; no source, credentials or host
        # device is mounted. First prove the same instruction works unbounded.
        spec=importlib.util.spec_from_file_location('resource_probe_base',ROOT/'scripts/build-base.py')
        base=importlib.util.module_from_spec(spec);spec.loader.exec_module(base)
        image=base.locks(ROOT/'builders/build-inputs.lock')['MKOSI_BUILDER_OCI']
        nonce=uuid.uuid4().hex[:16];unit=resources.unit_name()[:-6]+'probe'+nonce+'.slice'
        tag='lanrith-resource-probe:'+nonce
        budget={'memory_bytes':64*1024**2,'cpus':1,'tasks':128,'swap_bytes':0}
        configured=False
        try:
            with tempfile.TemporaryDirectory(prefix='lanrith-resource-probe.') as temporary:
                root=Path(temporary)
                (root/'Dockerfile').write_text('FROM '+image+'\nRUN dd if=/dev/zero of=/dev/shm/probe bs=1M count=96 && rm /dev/shm/probe\n')
                command=['docker','build','--network','none','--shm-size','128m','--no-cache','--tag',tag]
                positive=subprocess.run([*command,str(root)],capture_output=True,timeout=240)
                self.assertEqual(positive.returncode,0,'The bounded synthetic control allocation did not run.')
                resources.create_group(unit,budget);configured=True
                negative=subprocess.run([*command,'--cgroup-parent',unit,str(root)],capture_output=True,timeout=180)
                self.assertNotEqual(negative.returncode,0,'BuildKit ignored the compiler cgroup memory cap.')
                value={'unit':unit,'limits':budget}
                observed=resources.counters(value)
                self.assertGreaterEqual(observed['memory.events']['oom_kill'],1,
                    'Build failure did not exercise the actual kernel OOM boundary.')
                self.assertGreater(int(Path('/proc/self/stat').read_text().split()[0]),0)
                print('BuildKit cgroup probe: identical 96 MiB instruction passes normally; 64 MiB parent contains OOM; host survives.',flush=True)
        finally:
            subprocess.run(['docker','image','rm',tag],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=30)
            if configured or (resources.CGROUP_ROOT/unit).exists():
                subprocess.run(['sudo','systemctl','stop',unit[:-6]+'anchor.service',unit],check=False,timeout=30)
