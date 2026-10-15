"""Assembly consumes an existing package tree and emits bounded boot policy."""

from pathlib import Path
import tempfile
import unittest

from lanrith import build, config
from lanrith.release import ReleaseError


class AssemblyTests(unittest.TestCase):
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
