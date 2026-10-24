"""Exercise thermal policy and safety using synthetic sysfs; never touch hardware."""

import copy
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from lanrith import build, config, fancontrol_config, fancontrol_runtime as runtime, runtime_plan
from lanrith.release import ReleaseError, canonical


ROOT = Path(__file__).resolve().parents[1]


def declaration():
    value = config.load(ROOT/'examples/minimal.yaml')
    value['hardware']['interfaces']['wan']['name'] = 'uplink0'
    value['hardware']['fancontrol'] = {
        'enabled': True,
        'sensors': {
            'cpu': {'hwmon': {'name': 'cpu_sensor'}, 'minimum_c': 40, 'maximum_c': 80},
            'nic': {'interface': 'wan', 'minimum_c': 45, 'maximum_c': 85},
        },
        'fans': {'chassis': {'hwmon': {'name': 'board_fan'}, 'pwm': 'pwm1',
                             'sensors': ['cpu', 'nic'], 'minimum_pwm': 100,
                             'tachometer': 'fan1_input', 'minimum_rpm': 500}},
    }
    return value


class FakeHwmon:
    def __init__(self, root):
        self.root = root
        (root/'class/hwmon').mkdir(parents=True)
        (root/'class/net/uplink0').mkdir(parents=True)
        self.cpu = self.chip(7, 'cpu_sensor', 'platform/cpu.0',
                             {'temp1_input': 40000, 'temp2_input': 42000})
        self.nic = self.chip(9, 'nic_sensor', 'pci0000:00/0000:00:01.0', {'temp1_input': 45000})
        self.fan = self.chip(2, 'board_fan', 'platform/fan.0',
                             {'pwm1': 190, 'pwm1_enable': 2, 'fan1_input': 1200})
        (root/'class/net/uplink0/device').symlink_to(self.nic.parent.parent)

    def chip(self, number, name, device, attributes):
        path = self.root/'devices'/device/'hwmon'/('hwmon'+str(number))
        path.mkdir(parents=True)
        (path/'name').write_text(name+'\n')
        (path/'device').symlink_to(path.parent.parent)
        for attribute, value in attributes.items():
            (path/attribute).write_text(str(value)+'\n')
        (self.root/'class/hwmon'/path.name).symlink_to(path)
        return path

    def value(self, path, value):
        path.write_text(str(value)+'\n')

    def pwm(self):
        return int((self.fan/'pwm1').read_text().strip())


class FancontrolConfigTests(unittest.TestCase):
    def test_optional_component_does_not_change_existing_normalization_or_firewall(self):
        original = config.load(ROOT/'examples/minimal.yaml')
        self.assertNotIn('fancontrol', config.normalize(original)['hardware'])
        for setting in (None, {'enabled': False}):
            value = copy.deepcopy(original)
            if setting is not None:
                value['hardware']['fancontrol'] = setting
            files = config.render(value)
            self.assertFalse(any('fancontrol' in path for path in files))
            self.assertNotIn('lanrith-fancontrol.service', runtime_plan.required_units(value))
        value = config.normalize(declaration())
        without = copy.deepcopy(value)
        without['hardware'].pop('fancontrol')
        self.assertEqual(config.render(value)['etc/nftables.conf'], config.render(without)['etc/nftables.conf'])

    def test_compiler_resolves_nic_name_and_emits_only_scoped_json_and_required_unit(self):
        value = config.normalize(declaration())
        self.assertEqual(value, config.normalize(value))
        files = config.render(value)
        manifest = json.loads(files['usr/share/lanrith/fancontrol.json'])
        self.assertEqual(manifest['sensors']['nic']['interface'], 'uplink0')
        self.assertNotIn('enabled', manifest)
        self.assertEqual(manifest['sensors']['cpu']['inputs'], 'all')
        self.assertNotIn('networks', manifest)
        self.assertIn('lanrith-fancontrol.service', json.loads(files['usr/share/lanrith/health.json'])['units'])
        self.assertFalse(any(path.endswith(('.yaml', '.yml')) for path in files))
        unit = files['usr/lib/systemd/system/lanrith-fancontrol.service']
        for line in ('Type=notify', 'WatchdogSec=30s', 'CapabilityBoundingSet=CAP_SETUID CAP_SETGID',
                     'NoNewPrivileges=yes', 'ProtectSystem=strict', 'PrivateDevices=yes',
                     'RestrictAddressFamilies=AF_UNIX', 'MemoryMax=64M',
                     'ExecStopPost=/usr/lib/lanrith/fancontrol-runtime failsafe'):
            self.assertIn(line, unit)

    def test_invalid_and_dangerous_inputs_fail_before_rendering(self):
        mutations = (
            lambda p: p.update(enabled='true'),
            lambda p: p.update(enabled=False),
            lambda p: p.update(unknown=True),
            lambda p: p.update(schema=1),
            lambda p: p.update(interval_seconds=True),
            lambda p: p.update(interval_seconds=11),
            lambda p: p.update(startup_seconds=0),
            lambda p: p.update(hysteresis_c=-1),
            lambda p: p['sensors']['cpu'].update(hwmon={'name': 'cpu\nInjection=yes'}),
            lambda p: p['sensors']['cpu']['hwmon'].update(device='../etc'),
            lambda p: p['sensors']['cpu']['hwmon'].update(device='/sys/devices/platform/cpu.0'),
            lambda p: p['sensors']['cpu']['hwmon'].update(device='platform/./cpu.0'),
            lambda p: p['sensors']['cpu']['hwmon'].update(device='platform/cpu.0/hwmon/hwmon7'),
            lambda p: p['sensors']['cpu'].update(interface='wan'),
            lambda p: p['sensors']['nic'].update(interface='not-declared'),
            lambda p: p['sensors']['cpu'].update(inputs=['../../pwm1']),
            lambda p: p['sensors']['cpu'].update(inputs=['temp1_input', 'temp1_input']),
            lambda p: p['sensors']['cpu'].update(minimum_c=80),
            lambda p: p['sensors']['cpu'].update(maximum_c=151),
            lambda p: p['sensors']['cpu'].update(inputs=[]),
            lambda p: p['fans']['chassis'].update(pwm='pwm1_enable'),
            lambda p: p['fans']['chassis'].update(pwm='../../a'),
            lambda p: p['fans']['chassis'].update(minimum_pwm=0),
            lambda p: p['fans']['chassis'].update(minimum_pwm=255),
            lambda p: p['fans']['chassis'].update(sensors=['missing']),
            lambda p: p['fans']['chassis'].update(sensors=['cpu']),
            lambda p: p['fans']['chassis'].update(tachometer='pwm1'),
        )
        for mutation in mutations:
            value = declaration()
            mutation(value['hardware']['fancontrol'])
            with self.subTest(mutation=mutation), self.assertRaises(ReleaseError):
                config.render(value)

    def test_vpp_owned_nic_cannot_claim_unavailable_kernel_telemetry(self):
        value = declaration()
        value['hardware']['interfaces']['wan']['owner'] = 'vpp'
        with self.assertRaises(ReleaseError):
            config.normalize(value)

    def test_comments_and_map_order_do_not_change_compiled_contract(self):
        value = declaration()
        first = config.render(value)
        reordered = copy.deepcopy(value)
        selected = reordered['hardware']['fancontrol']
        selected['sensors'] = dict(reversed(list(selected['sensors'].items())))
        selected['fans']['chassis']['hwmon'] = {'name': 'board_fan'}
        self.assertEqual(first, config.render(reordered))
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary)/'input.yaml'
            source.write_text('# Description only.\n'+json.dumps(reordered, indent=2)+'\n# Another comment.\n')
            self.assertEqual(first, config.render(config.load(source)))

    def test_enabled_assembly_runs_without_yaml_or_compiler_and_has_native_activation(self):
        value = config.normalize(declaration())
        value['administration']['root_access'] = 'disabled'
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            base = root/'base.tar'
            base.write_bytes(b'synthetic')
            build.assembly(value, base, root/'work', version='0.1.0', sequence=1)
            overlay = root/'work/mkosi.extra'
            self.assertTrue((overlay/'usr/lib/systemd/system/multi-user.target.wants/lanrith-fancontrol.service').is_symlink())
            self.assertTrue((overlay/'etc/systemd/system/lanrith-fancontrol.service').is_symlink())
            spec = importlib.util.spec_from_file_location('boundary', ROOT/'scripts/runtime-boundary.py')
            boundary = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(boundary)
            boundary.check(overlay)
            program = '''
import sys
from pathlib import Path
sys.path.insert(0, sys.argv[1])
from lanrith.fancontrol_runtime import load
assert load(Path(sys.argv[2]), owner=__import__('os').getuid())['schema'] == 1
assert 'yaml' not in sys.modules and 'lanrith.config' not in sys.modules
'''
            result = subprocess.run([sys.executable, '-I', '-S', '-c', program,
                str(overlay/'usr/lib/lanrith'), str(overlay/'usr/share/lanrith/fancontrol.json')],
                cwd=root, capture_output=True, text=True, timeout=15)
            self.assertEqual(result.returncode, 0, result.stderr)


class FancontrolRuntimeTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.fake = FakeHwmon(Path(self.directory.name)/'sys')
        self.hwmon = runtime.Hwmon(self.fake.root)
        self.policy = fancontrol_config.manifest(config.normalize(declaration()))

    def controller(self):
        controller = runtime.Controller(self.policy, self.hwmon)
        self.addCleanup(controller.close)
        controller.open()
        controller.prepare_inputs()
        return controller

    def test_hottest_cpu_core_and_nic_drive_one_fan(self):
        controller = self.controller()
        self.assertEqual(self.fake.pwm(), 255)
        controller.tick()
        self.assertEqual(self.fake.pwm(), 108)  # Hottest CPU core: 42 C.
        self.fake.value(self.fake.nic/'temp1_input', 75000)
        controller.tick()
        self.assertEqual(self.fake.pwm(), 217)  # NIC demand exceeds CPU demand.
        self.fake.value(self.fake.cpu/'temp1_input', 80000)
        controller.tick()
        self.assertEqual(self.fake.pwm(), 255)

    def test_separate_fans_obey_their_own_sources(self):
        self.fake.value(self.fake.fan/'pwm2', 190)
        self.fake.value(self.fake.fan/'pwm2_enable', 2)
        self.policy['fans']['processor'] = {'hwmon': {'name': 'board_fan'}, 'pwm': 'pwm2',
            'sensors': ['cpu'], 'minimum_pwm': 100}
        controller = self.controller()
        self.fake.value(self.fake.nic/'temp1_input', 85000)
        controller.tick()
        self.assertEqual(self.fake.pwm(), 255)
        self.assertEqual(int((self.fake.fan/'pwm2').read_text()), 108)

    def test_hysteresis_holds_small_cooling_changes_but_heating_is_immediate(self):
        controller = self.controller()
        self.fake.value(self.fake.cpu/'temp2_input', 60000)
        controller.tick()
        previous = self.fake.pwm()
        self.fake.value(self.fake.cpu/'temp2_input', 58000)
        controller.tick()
        self.assertEqual(self.fake.pwm(), previous)
        self.fake.value(self.fake.cpu/'temp2_input', 57000)
        controller.tick()
        self.assertLess(self.fake.pwm(), previous)
        self.fake.value(self.fake.cpu/'temp2_input', 61000)
        controller.tick()
        self.assertGreater(self.fake.pwm(), previous)

    def test_missing_faulted_malformed_and_alarm_sources_force_full_speed(self):
        for failure in ('missing', 'malformed', 'fault', 'alarm', 'out-of-range'):
            with self.subTest(failure=failure):
                controller = self.controller()
                controller.tick()
                path = self.fake.nic/'temp1_input'
                flag = self.fake.nic/'temp1_fault'
                alarm = self.fake.nic/'temp1_crit_alarm'
                try:
                    if failure == 'missing':
                        path.unlink()
                    elif failure == 'malformed':
                        path.write_text('not a number\n')
                    elif failure == 'fault':
                        flag.write_text('1\n')
                    elif failure == 'alarm':
                        alarm.write_text('1\n')
                    else:
                        path.write_text('151000\n')
                    with self.assertRaises((OSError, ReleaseError)):
                        controller.tick()
                    self.assertEqual(self.fake.pwm(), 255)
                finally:
                    self.fake.value(path, 45000)
                    flag.unlink(missing_ok=True)
                    alarm.unlink(missing_ok=True)
                    controller.close()

    def test_missing_temperature_at_startup_still_sets_fan_full(self):
        (self.fake.nic/'temp1_input').unlink()
        controller = runtime.Controller(self.policy, self.hwmon)
        self.addCleanup(controller.close)
        controller.open()
        with self.assertRaises(ReleaseError):
            controller.prepare_inputs()
        self.assertEqual(self.fake.pwm(), 255)

    def test_stalled_or_missing_tachometer_sets_full_speed(self):
        for missing in (False, True):
            controller = self.controller()
            controller.tick()
            path = self.fake.fan/'fan1_input'
            if missing:
                path.unlink()
            else:
                path.write_text('0\n')
            with self.assertRaises((OSError, ReleaseError)):
                controller.tick()
            self.assertEqual(self.fake.pwm(), 255)
            path.write_text('1200\n')
            controller.close()

    def test_shutdown_leaves_full_speed_without_restoring_a_low_original_duty(self):
        controller = self.controller()
        controller.tick()
        controller.close()
        self.assertEqual(self.fake.pwm(), 255)
        self.assertEqual((self.fake.fan/'pwm1_enable').read_text().strip(), '1')

    def test_stable_device_selection_survives_hwmon_renumbering(self):
        self.policy['fans']['chassis']['hwmon']['device'] = 'platform/fan.0'
        previous = self.fake.fan
        previous.rename(previous.parent/'hwmon77')
        self.fake.fan = previous.parent/'hwmon77'
        (self.fake.root/'class/hwmon/hwmon2').unlink()
        (self.fake.root/'class/hwmon/hwmon77').symlink_to(self.fake.fan)
        controller = self.controller()
        controller.tick()
        self.assertEqual(self.fake.pwm(), 108)

    def test_ambiguous_fan_selection_is_rejected_but_temperatures_can_span_chips(self):
        self.fake.chip(15, 'cpu_sensor', 'platform/cpu.1', {'temp1_input': 70000})
        controller = self.controller()
        controller.tick()
        self.assertEqual(self.fake.pwm(), 217)
        controller.close()
        other = self.fake.chip(16, 'board_fan', 'platform/fan.1', {'pwm1': 200})
        with self.assertRaises(ReleaseError):
            runtime.Controller(self.policy, self.hwmon).open()
        self.assertEqual((other/'pwm1').read_text(), '200\n')

    def test_duplicate_physical_pwm_and_sysfs_escape_are_rejected(self):
        self.policy['fans']['duplicate'] = copy.deepcopy(self.policy['fans']['chassis'])
        controller = runtime.Controller(self.policy, self.hwmon)
        self.addCleanup(controller.close)
        with self.assertRaises(ReleaseError):
            controller.open()
        external = Path(self.directory.name)/'external'
        external.mkdir()
        (self.fake.root/'class/hwmon/hwmon99').symlink_to(external)
        with self.assertRaises(ReleaseError):
            self.hwmon.chips()

    def test_inspect_is_read_only_and_does_not_load_owner_configuration(self):
        inventory = self.hwmon.inspect()
        self.assertEqual(self.fake.pwm(), 190)
        self.assertEqual({chip['name'] for chip in inventory}, {'cpu_sensor', 'nic_sensor', 'board_fan'})
        cpu = next(chip for chip in inventory if chip['name'] == 'cpu_sensor')
        self.assertEqual(cpu['device'], 'platform/cpu.0')
        self.assertEqual(len(cpu['temperatures']), 2)

    def test_contract_rejects_unprotected_noncanonical_duplicate_and_incomplete_input(self):
        path = Path(self.directory.name)/'contract.json'
        path.write_bytes(canonical(self.policy))
        path.chmod(0o644)
        self.assertEqual(runtime.load(path, owner=os.getuid()), self.policy)
        for data in (canonical(self.policy)+b'\n', b'{"schema":1,"schema":1}', b'{"schema":1}'):
            path.write_bytes(data)
            with self.assertRaises((ReleaseError, ValueError)):
                runtime.load(path, owner=os.getuid())
        path.write_bytes(canonical(self.policy))
        path.chmod(0o666)
        with self.assertRaises(ReleaseError):
            runtime.load(path, owner=os.getuid())

    def test_nonroot_run_and_failsafe_are_denied_before_loading_or_writing(self):
        for action in ('run', 'failsafe'):
            with patch.object(runtime.os, 'getuid', return_value=1000), \
                    patch.object(runtime.os, 'geteuid', return_value=1000), \
                    patch.object(runtime, 'load') as load, patch('sys.stderr'):
                self.assertEqual(runtime.main([action]), 1)
                load.assert_not_called()
        self.assertEqual(self.fake.pwm(), 190)

    def test_preopened_outputs_work_without_authority_to_open_new_writable_attributes(self):
        if os.geteuid() == 0:
            self.skipTest('This check requires an ordinary unprivileged test runner.')
        controller = self.controller()
        pwm = self.fake.fan/'pwm1'
        mode = self.fake.fan/'pwm1_enable'
        pwm.chmod(0o444)
        mode.chmod(0o444)
        with self.assertRaises(PermissionError):
            os.open(pwm, os.O_WRONLY)
        with self.assertRaises(PermissionError):
            os.open(mode, os.O_WRONLY)
        controller.tick()
        self.assertEqual(self.fake.pwm(), 108)
        controller.close()
        self.assertEqual(self.fake.pwm(), 255)

    def test_one_broken_output_does_not_prevent_other_fans_reaching_full_speed(self):
        self.fake.value(self.fake.fan/'pwm2', 190)
        self.policy['fans']['second'] = {'hwmon': {'name': 'board_fan'}, 'pwm': 'pwm2',
                                       'sensors': ['cpu'], 'minimum_pwm': 100}
        controller = self.controller()
        controller.tick()
        broken = controller.outputs['chassis']
        with patch.object(broken, 'full', side_effect=OSError('simulated output failure')):
            with self.assertRaises(ReleaseError):
                controller.full()
        self.assertEqual(int((self.fake.fan/'pwm2').read_text()), 255)

    def test_missing_tachometer_at_boot_cannot_block_full_speed_fallback(self):
        (self.fake.fan/'fan1_input').unlink()
        controller = self.controller()
        self.assertEqual(self.fake.pwm(), 255)
        with self.assertRaises(FileNotFoundError):
            controller.tick()
        self.assertEqual(self.fake.pwm(), 255)

    def test_bootstrap_discards_all_ids_supplementary_groups_and_capabilities(self):
        account = SimpleNamespace(pw_uid=500, pw_gid=500, pw_shell='/usr/sbin/nologin')
        group = SimpleNamespace(gr_gid=500, gr_mem=[])
        with patch.object(runtime.os, 'getuid', return_value=0), \
                patch.object(runtime.os, 'geteuid', return_value=0), \
                patch.object(runtime.pwd, 'getpwnam', return_value=account), \
                patch.object(runtime.pwd, 'getpwall', return_value=[account]), \
                patch.object(runtime.grp, 'getgrnam', return_value=group), \
                patch.object(runtime.os, 'setgroups') as groups, \
                patch.object(runtime.os, 'setresgid') as gid, \
                patch.object(runtime.os, 'setresuid') as uid, \
                patch.object(runtime.os, 'getresuid', return_value=(500,)*3), \
                patch.object(runtime.os, 'getresgid', return_value=(500,)*3), \
                patch.object(runtime.os, 'getgroups', return_value=[]), \
                patch.object(runtime.Path, 'read_text', return_value='CapEff:\t0000000000000000\nCapPrm:\t0\n'):
            runtime.drop_privileges()
            groups.assert_called_once_with([])
            gid.assert_called_once_with(500, 500, 500)
            uid.assert_called_once_with(500, 500, 500)

    def test_runtime_fault_and_process_shutdown_always_invoke_fallback(self):
        controller = self.controller()
        # Reuse the simulated controller but preserve run's real finally path.
        with patch.object(runtime.os, 'getuid', return_value=0), \
                patch.object(runtime.os, 'geteuid', return_value=0), \
                patch.object(runtime, 'Controller', return_value=controller), \
                patch.object(runtime, 'Hwmon'), patch.object(runtime, 'drop_privileges'), \
                patch.object(runtime.signal, 'signal'), \
                patch.object(runtime.threading, 'Event') as event, \
                patch.object(runtime, 'notify') as notify:
            event.return_value.wait.side_effect = [False, False]
            original = controller.tick
            def tick():
                original()
                self.fake.value(self.fake.nic/'temp1_input', 'failed')
            with patch.object(controller, 'tick', side_effect=tick), self.assertRaises(ReleaseError):
                runtime.run(self.policy)
            self.assertEqual(self.fake.pwm(), 255)
            notify.assert_called_once()


if __name__ == '__main__':
    unittest.main()
