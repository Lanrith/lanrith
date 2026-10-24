"""Verify ownership admission and binding against synthetic PCI state only."""

import copy
import hashlib
import io
import json
from pathlib import Path
import shutil
import tempfile
import unittest
from contextlib import redirect_stderr
from unittest.mock import Mock, patch

from lanrith import build, cli, config, hardware, hardware_config
from lanrith.release import ReleaseError
import test_hardware as hardware_fixtures


def declaration():
    value = config.load(Path(__file__).resolve().parents[1]/'examples/minimal.yaml')
    value['hardware']['interfaces']['core'] = {'name': 'port0', 'owner': 'vpp', 'state': 'down',
                                              'match': {'mac': '02:00:00:00:05:01'}}
    facts = {'interfaces': [{'name': 'port0', 'mac': '02:00:00:00:05:01', 'pci': '0000:05:00.0',
                            'driver': 'virtio-pci', 'iommu_group': 7, 'iommu_members': ['0000:05:00.0']}],
             'hugepages': {'page_size_mib': 1024, 'pages': 2}}
    return config.normalize(value), facts


class OwnershipTests(unittest.TestCase):
    def fixture(self, root):
        device = hardware_fixtures.HardwareTests().fixture(root)
        pages = root/'kernel/mm/hugepages/hugepages-1048576kB/nr_hugepages'
        pages.parent.mkdir(parents=True)
        pages.write_text('2\n')
        return device, pages

    def test_assembly_binds_facts_and_preserves_one_gib_geometry(self):
        value, facts = declaration()
        value['hardware']['storage']['root_mib'] = 2048
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            base = root/'base.tar'
            base.write_bytes(b'synthetic-test-input')
            workspace = root/'work'
            with self.assertRaisesRegex(ReleaseError, 'verified VPP'):
                build.assembly(value, base, workspace, version='0.1.0', sequence=9)
            self.assertFalse(workspace.exists())
            result = build.assembly(value, base, workspace, version='0.1.0', sequence=9, target_facts=facts)
            overlay = workspace/'mkosi.extra'
            unit = 'lanrith-hardware-ownership.service'
            self.assertTrue((overlay/'etc/systemd/system'/unit).is_symlink())
            self.assertIn(unit, (overlay/'usr/lib/systemd/system/lanrith-health.service').read_text())
            self.assertEqual(json.loads((overlay/'usr/share/lanrith/ownership.json').read_bytes()),
                             hardware_config.ownership_manifest(value, facts))
            self.assertIn('default_hugepagesz=1G hugepagesz=1G hugepages=2', (workspace/'mkosi.conf').read_text())
            self.assertNotIn('hugepagesz=2M', (workspace/'mkosi.conf').read_text())
            self.assertIn('ActivationPolicy=always-down',
                          (overlay/'etc/systemd/network/15-core-disabled.network').read_text())
            installed = json.loads((overlay/'usr/share/lanrith/installed.json').read_bytes())
            self.assertEqual(installed['payload_limits']['root'], 2048*1024*1024)
            self.assertEqual(result['configuration_sha256'], config.effective_digest(value, {}, target_facts=facts))
            altered = copy.deepcopy(facts)
            altered['interfaces'][0]['driver'] = 'igb'
            self.assertNotEqual(result['configuration_sha256'], config.effective_digest(value, {}, target_facts=altered))

    def test_binding_rechecks_memory_identity_and_isolation_before_mutation(self):
        value, facts = declaration()
        manifest = hardware_config.ownership_manifest(value, facts)
        for failure in ('memory', 'mac', 'shared-group', 'manifest'):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                device, pages = self.fixture(root)
                selected = copy.deepcopy(manifest)
                if failure == 'memory':
                    pages.write_text('1\n')
                elif failure == 'mac':
                    (root/'class/net/port0/address').write_text('02:00:00:00:05:02\n')
                elif failure == 'shared-group':
                    (root/'kernel/iommu_groups/7/devices/0000:05:00.1').touch()
                else:
                    selected['facts_sha256'] = '0'*64
                run = Mock()
                with patch.object(Path, 'write_text') as write, self.assertRaises(ReleaseError):
                    hardware.bind_owned(selected, sysfs=root, run=run)
                run.assert_not_called()
                write.assert_not_called()
                self.assertEqual((device/'driver').resolve().name, 'virtio-pci')

    def test_binding_is_idempotent_and_health_rechecks_vfio_and_memory(self):
        value, facts = declaration()
        manifest = hardware_config.ownership_manifest(value, facts)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            device, pages = self.fixture(root)
            original = Path.write_text

            def write(path, data, *args, **kwargs):
                result = original(path, data, *args, **kwargs)
                if path.name == 'drivers_probe':
                    (device/'driver').unlink()
                    (device/'driver').symlink_to(root/'bus/pci/drivers/vfio-pci')
                    shutil.rmtree(device/'net')
                return result

            run = Mock()
            with patch.object(Path, 'write_text', write):
                hardware.bind_owned(manifest, sysfs=root, run=run)
                hardware.bind_owned(manifest, sysfs=root, run=run)
            self.assertEqual(run.call_count, 2)
            hardware.ownership_status(manifest, sysfs=root)
            pages.write_text('1\n')
            with self.assertRaisesRegex(ReleaseError, 'hugepage allocation'):
                hardware.ownership_status(manifest, sysfs=root)

    def test_overlapping_linux_selectors_and_explicit_acceleration_are_rejected(self):
        value, facts = declaration()
        for selector in ({'driver': 'virtio*'}, {'path': 'pci-*'}):
            changed = copy.deepcopy(value)
            changed['hardware']['interfaces']['wan']['match'] = selector
            with self.subTest(selector=selector), self.assertRaisesRegex(ReleaseError, 'selector may match'):
                config.render(changed, target_facts=facts)
        value['hardware']['acceleration'] = {'pci': ['0000:05:00.0'], 'hugepages_mib': 2048}
        with self.assertRaisesRegex(ReleaseError, 'derived and explicit'):
            config.render(value, target_facts=facts)

    def test_cli_requires_matching_reviewed_facts_digest(self):
        value, facts = declaration()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            owner, snapshot = root/'owner.json', root/'facts.json'
            owner.write_text(json.dumps(value))
            snapshot.write_text(json.dumps(facts))
            args = ['render', str(owner), '--output', str(root/'rendered'), '--hardware-facts', str(snapshot)]
            with redirect_stderr(io.StringIO()):
                self.assertEqual(cli.main(args), 1)
                self.assertEqual(cli.main(args+['--hardware-facts-sha256', '0'*64]), 1)
            self.assertFalse((root/'rendered').exists())
            with patch('builtins.print'):
                self.assertEqual(cli.main(args+['--hardware-facts-sha256',
                                 hashlib.sha256(snapshot.read_bytes()).hexdigest()]), 0)


if __name__ == '__main__':
    unittest.main()
