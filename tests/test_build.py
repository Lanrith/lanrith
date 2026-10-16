"""Assembly consumes an existing package tree and emits bounded boot policy."""

from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

from lanrith import build, config
from lanrith.release import ReleaseError


class AssemblyTests(unittest.TestCase):
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
            self.assertTrue((workspace / 'mkosi.extra/etc/systemd/system/boot-complete.target.requires/lanrith-health.service').is_symlink())
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
