"""Exercise hardware guards against synthetic sysfs; never touch host devices."""

import json
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import Mock, patch

from lanrith import config, hardware, hardware_config
from lanrith.release import ReleaseError


class HardwareTests(unittest.TestCase):
    def fixture(self, root, driver='virtio-pci'):
        bdf = '0000:05:00.0'
        device = root/'bus/pci/devices'/bdf
        group = root/'kernel/iommu_groups/7'
        (device/'net/port0').mkdir(parents=True)
        (group/'devices').mkdir(parents=True)
        (group/'devices'/bdf).symlink_to(device)
        (device/'iommu_group').symlink_to(group)
        for name in (driver, 'vfio-pci'):
            path = root/'bus/pci/drivers'/name
            path.mkdir(parents=True)
            (path/'unbind').touch()
        (device/'driver').symlink_to(root/'bus/pci/drivers'/driver)
        interface = root/'class/net/port0'
        interface.mkdir(parents=True)
        (interface/'address').write_text('02:00:00:00:05:01\n')
        return device

    def test_multiple_declared_drivers_bind_without_a_model_default(self):
        for driver in ('virtio-pci', 'igb', 'mlx5_core'):
            with self.subTest(driver=driver), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                device = self.fixture(root, driver)
                original = Path.write_text
                writes = []

                def write(path, data, *args, **kwargs):
                    writes.append(path)
                    result = original(path, data, *args, **kwargs)
                    if path.name == 'drivers_probe':
                        (device/'driver').unlink()
                        (device/'driver').symlink_to(root/'bus/pci/drivers/vfio-pci')
                        shutil.rmtree(device/'net')
                    return result

                run = Mock()
                with patch.object(Path, 'write_text', write):
                    hardware.bind_device(device.name, '7', 'port0', '02:00:00:00:05:01',
                                         driver, sysfs=root, run=run)
                self.assertEqual(run.call_count, 2)
                self.assertEqual(len(writes), 3)
                hardware.vfio_device(device.name, '7', sysfs=root)

    def test_shared_group_wrong_identity_and_driver_fail_before_any_mutation(self):
        for change in ('shared', 'group', 'mac', 'driver', 'path'):
            with self.subTest(change=change), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                device = self.fixture(root)
                if change == 'shared':
                    (root/'kernel/iommu_groups/7/devices/0000:05:00.1').touch()
                run = Mock()
                with patch.object(Path, 'write_text') as write, self.assertRaises((ReleaseError, OSError)):
                    hardware.bind_device('../bad' if change == 'path' else device.name,
                        '8' if change == 'group' else '7', 'port0',
                        '02:00:00:00:05:02' if change == 'mac' else '02:00:00:00:05:01',
                        'igb' if change == 'driver' else 'virtio-pci', sysfs=root, run=run)
                run.assert_not_called()
                write.assert_not_called()

    def test_status_needs_only_declared_interfaces_and_hugepage_budget(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            interface = root/'class/net/port0'
            interface.mkdir(parents=True)
            (interface/'address').write_text('02:00:00:00:05:01\n')
            value = {'hardware': {'interfaces': {'edge': {'name': 'port0',
                'match': {'mac': '02:00:00:00:05:01'}}}}, 'services': {}}
            hardware.network_status(hardware_config.manifest(value), sysfs=root)
            value['hardware']['acceleration'] = {'pci': ['0000:05:00.0'], 'hugepages_mib': 6}
            pages = root/'kernel/mm/hugepages/hugepages-2048kB/nr_hugepages'
            pages.parent.mkdir(parents=True)
            pages.write_text('3\n')
            hardware.network_status(hardware_config.manifest(value), sysfs=root)
            pages.write_text('2\n')
            with self.assertRaisesRegex(ReleaseError, 'hugepage allocation'):
                hardware.network_status(hardware_config.manifest(value), sysfs=root)

    def test_acceleration_rejects_duplicate_devices_and_fractional_pages(self):
        value = config.load(Path(__file__).resolve().parents[1]/'examples/minimal.yaml')
        for acceleration in ({'pci': ['0000:05:00.0']*2, 'hugepages_mib': 4},
                             {'pci': ['0000:05:00.0'], 'hugepages_mib': 3}):
            value['hardware']['acceleration'] = acceleration
            with self.assertRaises(ReleaseError):
                config.normalize(value)
