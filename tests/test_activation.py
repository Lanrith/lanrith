"""Unselected daemons remain masked when final assembly reapplies presets."""

import os
from pathlib import Path
import runpy
import shutil
import subprocess
import tempfile
import unittest
from unittest import mock

from lanrith import build, config


class OptionalActivationTests(unittest.TestCase):
    @unittest.skipUnless(shutil.which('systemctl'), 'Native systemd preset verification needs systemctl.')
    def test_distribution_presets_cannot_remove_the_boot_failure_gate(self):
        value = config.load(Path(__file__).parents[1]/'examples/minimal.yaml')
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            base = directory/'base.tar'
            base.write_bytes(b'synthetic-assembly-input')
            build.assembly(value, base, directory/'work', version='0.1.0', sequence=9)
            root = directory/'work/mkosi.extra'
            name = 'systemd-boot-check-no-failures.service'
            (root/'usr/lib/systemd/system'/name).write_text('[Unit]\nDescription=Synthetic failure gate\n'
                '[Service]\nType=oneshot\nExecStart=/bin/true\n[Install]\nRequiredBy=boot-complete.target\n')
            preset = root/'usr/lib/systemd/system-preset/90-test.preset'
            preset.parent.mkdir(parents=True)
            preset.write_text('disable '+name+'\n')
            result = subprocess.run(['systemctl', '--root', str(root), 'preset-all'],
                                    capture_output=True, text=True, timeout=15)
            self.assertEqual(result.returncode, 0, result.stderr)
            required = root/'usr/lib/systemd/system/boot-complete.target.requires'
            for unit in (name, 'lanrith-health.service'):
                self.assertEqual((required/unit).readlink(), Path('/usr/lib/systemd/system')/unit)

    @unittest.skipUnless(shutil.which('systemctl'), 'Native systemd preset verification needs systemctl.')
    def test_component_units_cannot_be_reenabled_by_package_presets(self):
        names = ('discovery-bridge-collector.service', 'discovery-bridge-publisher.service',
                 'discovery-bridge-dns.service', 'dpdk.service', 'lanrith-policy-reader.service',
                 'chronyd-restricted.service', 'chrony-wait.service',
                 'cron.service', 'systemd-hostnamed.service', 'ssh.socket', 'sshd@.service',
                 'systemd-sysupdate.service', 'systemd-sysupdate.timer',
                 'systemd-sysupdate-reboot.service', 'systemd-sysupdate-reboot.timer')
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for name, text in {
                'usr/share/lanrith/platform-version': '0.1.0\n',
                'usr/lib/os-release': 'ID=debian\n',
                'etc/passwd': 'root:x:0:0:root:/root:/bin/sh\n',
                'usr/lib/systemd/system-preset/90-test.preset': 'enable *\n',
            }.items():
                path = root/name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(text)
            units = root/'usr/lib/systemd/system'
            units.mkdir(parents=True)
            for name in names:
                body = ('[Timer]\nOnBootSec=15min\n' if name.endswith('.timer') else
                        '[Service]\nType=oneshot\nExecStart=/bin/true\n')
                (units/name).write_text('[Unit]\nDescription=Synthetic optional unit\n'+body+
                    '[Install]\nWantedBy=multi-user.target\n')
                link = root/'etc/systemd/system/multi-user.target.wants'/name
                link.parent.mkdir(parents=True, exist_ok=True)
                link.symlink_to('/usr/lib/systemd/system/'+name)
            script = Path(__file__).parents[1]/'mkosi/base/mkosi.finalize'
            output = root/'build-output'
            output.mkdir()
            (output/'lanrith-base.container-pruning.json').write_text(
                '{"schema":1,"removed_bytes":0,"removed_paths":0}\n')
            with mock.patch.dict(os.environ, {'BUILDROOT': str(root), 'OUTPUTDIR': str(output)}), mock.patch(
                    'subprocess.run', return_value=subprocess.CompletedProcess([], 0, b'Package: synthetic\n')):
                runpy.run_path(str(script), run_name='__main__')
            result = subprocess.run(['systemctl', '--root', str(root), 'preset-all'],
                                    capture_output=True, text=True, timeout=15)
            self.assertEqual(result.returncode, 0, result.stderr)
            for name in names:
                with self.subTest(unit=name):
                    self.assertEqual((root/'etc/systemd/system'/name).readlink(), Path('/dev/null'))
                    enabled = subprocess.run(['systemctl', '--root', str(root), 'is-enabled', name],
                                             capture_output=True, text=True, timeout=15)
                    self.assertEqual(enabled.returncode, 1, enabled.stderr)
                    self.assertEqual(enabled.stdout.strip(), 'masked')
