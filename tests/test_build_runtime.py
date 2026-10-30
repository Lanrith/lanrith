"""Exercise installed code after removing the compiler input and dependencies."""

import copy
import importlib.machinery
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from lanrith import boot_health, build, config, policy_runtime, runtime_plan
from lanrith.release import ReleaseError
from test_intent import minimal
from nat64_native import declaration as nat64_declaration


ROOT = Path(__file__).resolve().parents[1]


class CompiledRuntimeTests(unittest.TestCase):
    def test_policy_runtime_uses_only_private_compiled_json_and_systemd_credentials(self):
        from test_policy_agent import declaration
        value = declaration()
        value['networks']['home']['vlan'] = 1
        selected = '/var/lib/private-owner/directory-bind'
        value['runtime'] = {'credentials': {'directory_bind': selected}}
        files = config.render(value)
        raw = files['etc/router-policy-agent/runtime/runtime.json']
        contract = json.loads(raw)
        self.assertEqual(contract['schema_version'], 1)
        self.assertNotIn('access', raw)
        self.assertNotIn('groups', raw)
        self.assertNotIn('networks', raw)
        self.assertNotIn(selected, raw)
        unit = files['usr/lib/systemd/system/lanrith-policy-bootstrap.service']
        self.assertIn('LoadCredential=directory_bind:'+selected, unit)
        self.assertNotIn('Password=', unit)
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary)/'runtime.json'
            path.write_text(raw)
            path.chmod(0o600)
            self.assertEqual(policy_runtime.load_contract(path, owner=os.getuid()), contract)
            path.write_text(raw+'\n')
            path.chmod(0o644)
            with self.assertRaises(ValueError):
                policy_runtime.load_contract(path, owner=os.getuid())

    def test_nat64_runtime_contract_is_private_compiled_json_not_source_intent(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            output = root/'output'
            config.write(nat64_declaration(), output)
            directory = output/'etc/router-policy-agent/nat64-runtime'
            manifest = directory/'runtime.json'
            self.assertEqual(directory.stat().st_mode & 0o777, 0o700)
            self.assertEqual(manifest.stat().st_mode & 0o777, 0o600)
            value = json.loads(manifest.read_bytes())
            self.assertEqual(set(value), {'schema_version', 'components'})
            self.assertTrue(all(set(component) == {'id', 'status_directory', 'configuration_file',
                                                    'executable', 'username'}
                                for component in value['components']))
            self.assertNotIn('networks', manifest.read_text())
            self.assertFalse(any(path.suffix in ('.yaml', '.yml') for path in output.rglob('*')))

    def test_root_and_initrd_run_without_source_yaml_or_compiler(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root/'owner.yaml'
            source.write_bytes((ROOT/'examples/minimal.yaml').read_bytes())
            value = config.load(source)
            source.unlink()
            base = root/'base.tar'
            base.write_bytes(b'synthetic-test-input')
            workspace = root/'work'
            build.assembly(value, base, workspace, version='0.1.0', sequence=12)
            for tree in (workspace/'mkosi.extra', workspace/'mkosi.images/initrd/mkosi.extra'):
                library = tree/'usr/lib/lanrith'
                package = library/'lanrith'
                self.assertFalse((tree/'usr/share/lanrith/resolved.json').exists())
                self.assertFalse(any(path.suffix in ('.yaml', '.yml') for path in package.rglob('*')))
                for module in ('config', 'intent', 'runtime_plan', 'hardware_config', 'cli', 'build',
                               'discovery', 'logs', 'radius'):
                    self.assertFalse((package/(module+'.py')).exists())
                # -I -S removes the checkout, site-packages and PYTHONPATH. Every
                # installed module must import with only the standard library.
                program = '''
import importlib, json, pathlib, sys
sys.path.insert(0, sys.argv[1])
for path in pathlib.Path(sys.argv[1], 'lanrith').glob('*.py'):
    importlib.import_module('lanrith.'+path.stem)
assert not any(name == 'yaml' or name.startswith('yaml.') for name in sys.modules)
assert not any(name in sys.modules for name in ('lanrith.config', 'lanrith.intent', 'lanrith.build'))
from lanrith import boot_health
from unittest.mock import patch
plan = json.loads(sys.argv[2])
def command(args):
    if args[:2] == ['systemctl', 'is-active']: return 'active'
    name = args[-1]
    return json.dumps([{'addr_info': [{'local': a} for item in plan['interfaces']
                                    if item['name'] == name for a in item['addresses']]}])
with patch.object(boot_health, 'command', command): boot_health.check(plan)
'''
                result = subprocess.run([sys.executable, '-I', '-S', '-c', program, str(library),
                                         json.dumps(runtime_plan.health(value))], cwd=root,
                                        capture_output=True, text=True, timeout=15)
                self.assertEqual(result.returncode, 0, result.stderr)
            manifest = json.loads((workspace/'mkosi.extra/usr/share/lanrith/administration.json').read_bytes())
            self.assertNotIn('authorized_keys', manifest)
            self.assertNotIn('networks', manifest)

    def test_final_tree_gate_rejects_inputs_and_dormant_compiler_imports(self):
        spec = importlib.util.spec_from_file_location('runtime_boundary', ROOT/'scripts/runtime-boundary.py')
        boundary = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(boundary)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            base = root/'base.tar'
            base.write_bytes(b'synthetic-test-input')
            build.assembly(config.normalize(minimal()), base, root/'work', version='0.1.0', sequence=12)
            tree = root/'work/mkosi.extra'
            boundary.check(tree)
            for name, data in (
                    ('usr/share/lanrith/resolved.json', '{}'),
                    ('usr/share/lanrith/hardware-facts.json', '{}'),
                    ('etc/lanrith/translation-allocations.json', '{}'),
                    ('etc/lanrith/config.yaml', 'schema: 1'),
                    ('usr/lib/lanrith-build/policy-baseline.json', '{}'),
                    ('usr/lib/lanrith/lanrith/config.py', 'pass'),
                    ('usr/lib/lanrith/lanrith/owner_inputs.py', 'pass'),
                    ('usr/lib/lanrith/lanrith/discovery.py', 'pass'),
                    ('usr/lib/lanrith/lanrith/logs.py', 'pass'),
                    ('usr/lib/lanrith/lanrith/radius.py', 'pass'),
                    ('usr/lib/lanrith/lanrith/other.py', 'def dormant():\n    import yaml\n'),
                    ('usr/lib/lanrith/lanrith/other.py', 'def dormant():\n    from . import config\n')):
                path = tree/name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(data)
                with self.subTest(name=name, data=data), self.assertRaises(ValueError):
                    boundary.check(tree)
                # mkosi exposes the script at /work/finalize. No sibling source
                # file is mounted there: the emitted hook must be self-contained.
                remapped = root/'remapped-finalize'
                remapped.write_bytes((root/'work/mkosi.finalize').read_bytes())
                result = subprocess.run([sys.executable, '-I', '-S', str(remapped)],
                                        env={'BUILDROOT': str(tree)}, capture_output=True, text=True, timeout=10)
                self.assertNotEqual(result.returncode, 0)
                self.assertTrue('configuration' in result.stderr or 'compiler' in result.stderr, result.stderr)
                self.assertNotIn('FileNotFoundError', result.stderr)

                path.unlink()
                if path.parent == tree/'usr/lib/lanrith-build':
                    path.parent.rmdir()
                boundary.check(tree)

    def test_custom_gateway_addresses_are_compiled_once(self):
        value = minimal()
        value['networks']['home']['ipv4'] = {'subnet': '192.168.10.0/24', 'address': '192.168.10.11'}
        value['networks']['home']['ipv6'] = {'subnet_id': 16, 'ra': False, 'gua': False}
        value['networks']['home']['additional_subnets'] = ['fd42:1234:5678:ffff::60/124']
        files = config.render(value)
        plan = json.loads(files['usr/share/lanrith/health.json'])
        self.assertEqual(plan['interfaces'], [{'name': 'lan', 'addresses':
            ['192.168.10.11', 'fd42:1234:5678:10::1', 'fd42:1234:5678:ffff::61']}])

    def test_inactive_service_or_missing_gateway_fails_acceptance(self):
        plan = runtime_plan.health(config.normalize(minimal()))
        for missing in ('service', 'gateway'):
            with self.subTest(missing=missing):
                def command(args):
                    if args[0] == 'systemctl':
                        return 'inactive' if missing == 'service' else 'active'
                    return '[{"addr_info": []}]'
                with patch.object(boot_health, 'command', command), self.assertRaises(ReleaseError):
                    boot_health.check(plan)

    def test_invalid_boot_contract_does_not_invoke_tools(self):
        plan = runtime_plan.health(config.normalize(minimal()))
        for key, bad in (('units', ['--help']*3), ('units', plan['units']+plan['units']),
                         ('probes', ['unknown']), ('schema', 2), ('interfaces', [])):
            selected = copy.deepcopy(plan)
            selected[key] = bad
            with self.subTest(key=key, bad=bad), patch.object(boot_health, 'command') as command:
                with self.assertRaises(ReleaseError):
                    boot_health.check(selected)
                command.assert_not_called()

    def test_serial_helpers_consume_only_the_generated_admin_contract(self):
        value = config.normalize(minimal())
        value['administration']['username'] = 'operator'
        value['administration']['serial'] = {'enabled': True, 'tty': 'ttyS1', 'timeout_seconds': 45}
        data = runtime_plan.render(value)['usr/share/lanrith/administration.json']
        def read(path, *args, **kwargs):
            self.assertEqual(str(path), '/usr/share/lanrith/administration.json')
            return data
        for name in ('verify-serial-passphrase', 'serial-idle-watchdog'):
            path = ROOT/'mkosi/base/mkosi.extra/usr/lib/lanrith'/name
            loader = importlib.machinery.SourceFileLoader('compiled_serial_helper', str(path))
            spec = importlib.util.spec_from_loader(loader.name, loader)
            module = importlib.util.module_from_spec(spec)
            with patch.dict(sys.modules, {loader.name: module}), patch.object(Path, 'read_text', read):
                loader.exec_module(module)
                if name == 'verify-serial-passphrase':
                    environment = {'PAM_TYPE': 'auth', 'PAM_SERVICE': 'login', 'PAM_USER': 'operator', 'PAM_TTY': 'ttyS1'}
                    self.assertTrue(module.permitted_context(environment))
                    self.assertFalse(module.permitted_context({**environment, 'PAM_TTY': 'ttyS0'}))
                    self.assertFalse(module.permitted_context({**environment, 'PAM_RHOST': 'remote'}))
                    self.assertFalse(module.permitted_context({**environment, 'PAM_USER': 'admin'}))
                else:
                    self.assertEqual(module.UNIT, 'serial-getty@ttyS1.service')
                    state, expired = module.advance(module.State(), 24, True, 10, 100)
                    self.assertFalse(expired)
                    self.assertTrue(module.advance(state, 24, True, 10, 145)[1])
                    self.assertFalse(module.advance(state, 24, True, 11, 145)[1])
