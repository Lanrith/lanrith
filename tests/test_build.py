"""Assembly consumes an existing package tree and emits bounded boot policy."""

from pathlib import Path
import json
import shutil
import subprocess
import tempfile
import unittest

from lanrith import build, config
from lanrith.release import ReleaseError


class AssemblyTests(unittest.TestCase):
    def test_watchdog_policy_survives_initrd_handover_and_explicit_disable(self):
        value = config.load(Path(__file__).resolve().parents[1]/'examples/minimal.yaml')
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            base = root/'base.tar'
            base.write_bytes(b'synthetic-test-input')
            for mode in ('auto', 'required', 'disabled'):
                value['hardware']['watchdog'] = {'mode': mode, 'device': '/dev/watchdog1', 'timeout_seconds': 90}
                build.assembly(value, base, root/mode, version='0.1.0', sequence=9)
                relative = 'usr/lib/systemd/system.conf.d/60-lanrith-watchdog.conf'
                main = (root/mode/'mkosi.extra'/relative).read_text()
                initrd = (root/mode/'mkosi.images/initrd/mkosi.extra'/relative).read_text()
                self.assertEqual(main, initrd)
                self.assertIn('WatchdogDevice=/dev/watchdog1\n', main)
                self.assertIn('RuntimeWatchdogSec='+('off' if mode == 'disabled' else '90s')+'\n', main)
                installed = json.loads((root/mode/'mkosi.extra/usr/share/lanrith/installed.json').read_bytes())
                self.assertEqual(installed['watchdog']['mode'], mode)

    def test_selected_serial_administration_activates_its_recovery_guarded_watchdog(self):
        value = config.load(Path(__file__).resolve().parents[1]/'examples/minimal.yaml')
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            base = root/'base.tar'
            base.write_bytes(b'synthetic-test-input')
            build.assembly(value, base, root/'disabled', version='0.1.0', sequence=9)
            unit = 'lanrith-serial-idle-watchdog.service'
            self.assertFalse((root/'disabled/mkosi.extra/etc/systemd/system'/unit).is_symlink())
            value['administration']['serial'] = {'enabled': True, 'tty': 'ttyS0'}
            provision = root/'serial.hash'
            provision.write_text('scrypt:32768:8:1:'+'1'*32+':'+'2'*64+'\n')
            provision.chmod(0o600)
            build.assembly(value, base, root/'enabled', version='0.1.0', sequence=10, serial_hash=provision)
            overlay = root/'enabled/mkosi.extra'
            self.assertEqual((overlay/'etc/systemd/system'/unit).readlink(), Path('/usr/lib/systemd/system')/unit)
            self.assertIn(unit, (overlay/'usr/lib/systemd/system/lanrith-health.service').read_text())
            self.assertIn('After=lanrith-recovery-key.service', (overlay/'usr/lib/systemd/system'/unit).read_text())

    def test_root_access_policy_is_embedded_in_finalizer_not_read_from_owner_yaml(self):
        value = config.load(Path(__file__).resolve().parents[1]/'examples/minimal.yaml')
        value['administration']['root_access'] = 'disabled'
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            base = root/'base.tar'
            base.write_bytes(b'synthetic-test-input')
            build.assembly(value, base, root/'rootless', version='0.1.0', sequence=11)
            workspace = root/'rootless'
            finalizer = (workspace/'mkosi.finalize').read_text()
            self.assertIn('ROOT_ACCESS = "disabled"', finalizer)
            self.assertIn('apply_root_access(root, username, ROOT_ACCESS)', finalizer)
            self.assertFalse(any(path.suffix in ('.yaml', '.yml')
                                 for path in (workspace/'mkosi.extra').rglob('*')))
            self.assertFalse((workspace/'mkosi.extra/etc/sudoers.d/60-lanrith').exists())

    def test_esp_is_read_only_and_non_executable_outside_admitted_mutations(self):
        value = config.load(Path(__file__).resolve().parents[1]/'examples/minimal.yaml')
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            base = root/'base.tar'
            base.write_bytes(b'synthetic-test-input')
            workspace = root/'work'
            build.assembly(value, base, workspace, version='0.1.0', sequence=12)
            for mount in ('efi', 'boot'):
                policy = workspace/f'mkosi.extra/etc/systemd/system/{mount}.mount.d/10-lanrith-read-only.conf'
                self.assertEqual(policy.read_text(),
                                 '[Mount]\nOptions=umask=0077,ro,nodev,nosuid,noexec\n')
            blessing = workspace/'mkosi.extra/etc/systemd/system/systemd-bless-boot.service.d/10-lanrith-esp.conf'
            self.assertEqual(blessing.read_text(),
                             '[Service]\nExecStart=\nExecStart=/usr/bin/lanrith-runtime bless\n')

    @unittest.skipUnless(shutil.which('mkosi'), 'Run in the matching mkosi builder for native configuration checks.')
    def test_pinned_mkosi_accepts_root_and_initrd_configuration(self):
        value = config.load(Path(__file__).resolve().parents[1]/'examples/minimal.yaml')
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            base = root/'base.tar'
            base.write_bytes(b'synthetic-summary-input')
            build.assembly(value, base, root/'work', version='0.1.0', sequence=9)
            result = subprocess.run(['mkosi', '--directory', str(root/'work'), 'summary'], capture_output=True)
            self.assertEqual(result.returncode, 0, result.stderr.decode())
            self.assertEqual(result.stderr, b'')

    def test_successive_deployments_have_distinct_signature_partition_identities(self):
        value = config.load(Path(__file__).resolve().parents[1]/'examples/minimal.yaml')
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            base = root/'base.tar'
            base.write_bytes(b'synthetic-test-input')
            identities = []
            for sequence in (9, 10):
                workspace = root/str(sequence)
                build.assembly(value, base, workspace, version='0.1.0', sequence=sequence)
                lines = (workspace/'mkosi.repart/10-verity-sig.conf').read_text().splitlines()
                identities.append(next(line for line in lines if line.startswith('UUID=')))
            self.assertNotEqual(*identities)

    def test_offline_configuration_only_assembly(self):
        value = config.load(Path(__file__).resolve().parents[1] / 'examples/minimal.yaml')
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            base = root / 'base.tar'
            base.write_bytes(b'synthetic-test-input')
            workspace = root / 'work'
            identity = build.assembly(value, base, workspace, version='0.1.0', sequence=9)
            text = (workspace / 'mkosi.conf').read_text()
            self.assertNotIn('Packages=', text)
            self.assertNotIn('Script=', text)
            self.assertIn('BaseTrees=', text)
            self.assertEqual((workspace/'mkosi.machine-id').read_text().strip(), value['hardware']['machine_id'])
            self.assertEqual((workspace/'mkosi.images/initrd/mkosi.extra/etc/machine-id').read_text(),
                             (workspace/'mkosi.extra/etc/machine-id').read_text())
            self.assertEqual((workspace/'mkosi.images/initrd/mkosi.machine-id').read_text(),
                             (workspace/'mkosi.machine-id').read_text())
            self.assertNotIn('[Distribution]', (workspace/'mkosi.images/initrd/mkosi.conf').read_text())
            self.assertEqual((workspace/'mkosi.extra/etc/systemd/system/systemd-repart.service').readlink(), Path('/dev/null'))
            self.assertEqual(identity['deployment_sequence'], 9)
            self.assertTrue((workspace / 'mkosi.extra/usr/lib/systemd/system/boot-complete.target.requires/lanrith-health.service').is_symlink())
            initrd_units = workspace/'mkosi.images/initrd/mkosi.extra/usr/lib/systemd/system'
            boundary = (initrd_units/'initrd-switch-root.service.d/60-lanrith-provisioning.conf').read_text()
            self.assertIn('Requires=lanrith-factory.service\n', boundary)
            self.assertIn('After=lanrith-factory.service\n', boundary)
            provision = (initrd_units/'lanrith-factory.service').read_text()
            self.assertIn('OnFailureJobMode=isolate\n', provision)
            self.assertIn('RemainAfterExit=yes\n', provision)
            with self.assertRaises(ReleaseError):
                build.assembly(value, base, workspace, version='0.1.0', sequence=10)

    def test_missing_declared_integrations_fail_before_mkosi(self):
        value = config.load(Path(__file__).resolve().parents[1] / 'examples/minimal.yaml')
        value['extensions'] = ['policy']
        value['services']['policy'] = {'enabled': True, 'configuration': 'policy'}
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            base = root / 'base.tar'
            base.write_bytes(b'synthetic-test-input')
            with self.assertRaises(ReleaseError):
                build.assembly(value, base, root / 'work', version='0.1.0', sequence=9)
