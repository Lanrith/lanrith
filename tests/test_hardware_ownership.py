"""Verify ownership admission and binding against synthetic PCI state only."""

import copy
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from contextlib import redirect_stderr
from unittest.mock import Mock, patch

from lanrith import build, cli, config, hardware, hardware_config, hardware_diagnostics
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


class InterruptedErrorForTest(BaseException):
    """Simulated process termination between sysfs operations."""


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
            self.assertTrue((overlay/'usr/lib/systemd/system/multi-user.target.wants'/unit).is_symlink())
            command = next(line.removeprefix('ExecStart=').split() for line in
                           (overlay/'usr/lib/systemd/system'/unit).read_text().splitlines() if line.startswith('ExecStart='))
            help_result = subprocess.run([*command, '--help'], cwd=root,
                                    env={'PYTHONPATH': str(overlay/'usr/lib/lanrith')},
                                    check=True, capture_output=True, text=True)
            self.assertIn('bind-owned', help_result.stdout)
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
        for failure in ('memory', 'excess-memory', 'mac', 'shared-group', 'manifest'):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                device, pages = self.fixture(root)
                selected = copy.deepcopy(manifest)
                if failure == 'memory':
                    pages.write_text('1\n')
                elif failure == 'excess-memory':
                    pages.write_text('3\n')
                elif failure == 'mac':
                    (root/'class/net/port0/address').write_text('02:00:00:00:05:02\n')
                elif failure == 'shared-group':
                    (root/'kernel/iommu_groups/7/devices/0000:05:00.1').touch()
                else:
                    selected['facts_sha256'] = '0'*64
                run = Mock()
                with patch.object(Path, 'write_text') as write, self.assertRaises(ReleaseError):
                    hardware.bind_owned(selected, sysfs=root, state=root/'state', run=run)
                run.assert_not_called()
                write.assert_not_called()
                self.assertEqual((device/'driver').resolve().name, 'virtio-pci')

    def test_binding_is_idempotent_and_health_rechecks_vfio_and_memory(self):
        value, facts = declaration()
        manifest = hardware_config.ownership_manifest(value, facts)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            device, pages = self.fixture(root)
            run = Mock()
            with patch.object(Path, 'write_text', hardware_fixtures.emulate_drivers(device)):
                hardware.bind_owned(manifest, sysfs=root, state=root/'state', run=run)
                hardware.bind_owned(manifest, sysfs=root, state=root/'state', run=run)
            self.assertEqual(run.call_count, 2)
            hardware.ownership_status(manifest, sysfs=root)
            pages.write_text('1\n')
            with self.assertRaisesRegex(ReleaseError, 'hugepage allocation'):
                hardware.ownership_status(manifest, sysfs=root)

    def test_recovery_only_for_matching_interrupted_binding(self):
        for change in ('none', 'no-record', 'boot', 'manifest', 'device', 'pci-id', 'group',
                       'extra-member', 'other-override', 'missing-override', 'other-driver', 'mode',
                       'prepared', 'bound', 'linux-reclaimed', 'private-record'):
            with self.subTest(change=change), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                device, _ = self.fixture(root)
                manifest = hardware_config.ownership_manifest(*declaration())
                state = root/'state'
                run = Mock()
                effect = hardware_fixtures.emulate_drivers(device)

                def interrupt(path, data):
                    effect(path, data)
                    if path.name == 'unbind':
                        raise InterruptedErrorForTest()

                with patch.object(Path, 'write_text', interrupt), self.assertRaises(InterruptedErrorForTest):
                    hardware.bind_owned(manifest, sysfs=root, state=state, run=run)
                record = state/(device.name+'.json')
                data = json.loads(record.read_bytes())
                self.assertEqual(state.stat().st_mode & 0o777, 0o700)
                self.assertEqual(record.stat().st_mode & 0o777, 0o600)
                self.assertEqual(data['phase'], 'pending')
                self.assertEqual(data['attempts'], 0)
                self.assertEqual(data['prior_override'], '')
                if change == 'none':
                    with patch.object(Path, 'write_text', effect):
                        hardware.bind_owned(manifest, sysfs=root, state=state, run=run)
                    self.assertEqual(hardware.driver_name(device), 'vfio-pci')
                    continue
                if change == 'no-record':
                    record.unlink()
                elif change == 'boot':
                    data['identity']['boot_id'] = 'another-boot'
                    record.write_text(json.dumps(data))
                elif change == 'manifest':
                    manifest['facts']['interfaces'].append({'unselected': True})
                    manifest['facts_sha256'] = hashlib.sha256(hardware.canonical(manifest['facts'])).hexdigest()
                elif change in ('device', 'group'):
                    obj = device if change == 'device' else (device/'iommu_group').resolve()
                    previous = obj.with_name(obj.name+'.old')
                    obj.rename(previous)
                    shutil.copytree(previous, obj, symlinks=True)
                elif change == 'pci-id':
                    (device/'vendor').write_text('0xabcd')
                elif change == 'extra-member':
                    (device/'iommu_group/devices/0000:05:00.1').touch()
                elif change in ('other-override', 'missing-override'):
                    (device/'driver_override').write_text('other' if change == 'other-override' else '(null)')
                elif change == 'other-driver':
                    foreign = root/'bus/pci/drivers/other'
                    foreign.mkdir()
                    (device/'driver').symlink_to(foreign)
                elif change == 'linux-reclaimed':
                    effect(root/'bus/pci/drivers/virtio-pci/bind', device.name+'\n')
                    data['attempts'] = 1
                    record.write_text(json.dumps(data))
                elif change in ('prepared', 'bound'):
                    data['phase'] = change
                    record.write_text(json.dumps(data))
                elif change == 'private-record':
                    record.chmod(0o644)
                else:
                    state.chmod(0o755)
                run.reset_mock()
                with patch.object(Path, 'write_text') as write, self.assertRaises(ReleaseError):
                    hardware.bind_owned(manifest, sysfs=root, state=state, run=run)
                write.assert_not_called()
                run.assert_not_called()

    def test_exhausted_retry_resumes_linux_restore_after_override_clear(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            device, _ = self.fixture(root)
            (device/'driver_override').write_text('virtio-pci')
            manifest = hardware_config.ownership_manifest(*declaration())
            kwargs = {'sysfs': root, 'state': root/'state', 'run': Mock()}
            record = root/'state'/(device.name+'.json')
            effect = hardware_fixtures.emulate_drivers(device)

            def fail(path, data):
                if path.name == 'bind' and path.parent.name == 'vfio-pci':
                    raise InterruptedErrorForTest()
                effect(path, data)
                if path.name == 'driver_override' and data.strip() == 'virtio-pci':
                    raise InterruptedErrorForTest()

            for attempt in (1, 2, 2):
                with patch.object(Path, 'write_text', fail), self.assertRaises(InterruptedErrorForTest):
                    hardware.bind_owned(manifest, **kwargs)
                self.assertEqual(json.loads(record.read_bytes())['attempts'], attempt)
            self.assertEqual(json.loads(record.read_bytes())['phase'], 'restoring')
            with patch.object(Path, 'write_text', effect), self.assertRaisesRegex(ReleaseError, 'Restored'):
                hardware.bind_owned(manifest, **kwargs)
            self.assertEqual(json.loads(record.read_bytes())['phase'], 'restored')
            self.assertEqual(hardware.driver_name(device), 'virtio-pci')
            self.assertEqual(hardware.override(device), 'virtio-pci')
            kwargs['run'].assert_called_with(['ip', 'link', 'set', 'dev', 'port0', 'down'], check=True, timeout=15)
            with self.assertRaises(ReleaseError):
                hardware.ownership_status(manifest, sysfs=root)

    def test_complete_record_cannot_authorize_an_unrelated_detach(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            device, _ = self.fixture(root)
            manifest = hardware_config.ownership_manifest(*declaration())
            run = Mock()
            with patch.object(Path, 'write_text', hardware_fixtures.emulate_drivers(device)):
                hardware.bind_owned(manifest, sysfs=root, state=root/'state', run=run)
            (device/'driver').unlink()
            run.reset_mock()
            with patch.object(Path, 'write_text') as write, self.assertRaises(ReleaseError):
                hardware.bind_owned(manifest, sysfs=root, state=root/'state', run=run)
            write.assert_not_called()
            run.assert_not_called()

    def test_invalid_second_binding_and_foreign_override_make_no_changes(self):
        for failure in ('second-device', 'foreign-override'):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                device, _ = self.fixture(root)
                value, facts = declaration()
                if failure == 'second-device':
                    value['hardware']['interfaces']['extra'] = {'name': 'port1', 'owner': 'vpp', 'state': 'down',
                                                                'match': {'mac': '02:00:00:00:05:02'}}
                    facts['interfaces'].append({'name': 'port1', 'mac': '02:00:00:00:05:02', 'pci': '0000:06:00.0',
                                                'driver': 'igb', 'iommu_group': 8, 'iommu_members': ['0000:06:00.0']})
                else:
                    (device/'driver_override').write_text('external-owner')
                manifest = hardware_config.ownership_manifest(value, facts)
                run = Mock()
                with patch.object(Path, 'write_text') as write, self.assertRaises(ReleaseError):
                    hardware.bind_owned(manifest, sysfs=root, state=root/'state', run=run)
                write.assert_not_called()
                run.assert_not_called()
                self.assertEqual(list((root/'state').iterdir()), [])

    def test_shared_group_has_no_attributed_consumer(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            device, _ = self.fixture(root)
            (device/'driver').unlink()
            (device/'driver').symlink_to(root/'bus/pci/drivers/vfio-pci')
            shutil.rmtree(device/'net')
            (device/'iommu_group/devices/0000:05:00.1').touch()
            (root/'dev/vfio').mkdir(parents=True)
            (root/'dev/vfio/7').symlink_to('/dev/null')
            (root/'proc/42/fd').mkdir(parents=True)
            (root/'proc/42/fd/5').symlink_to('/dev/null')
            value, facts = declaration()
            with patch.object(os, 'geteuid', return_value=0):
                sample = hardware_diagnostics.collect(hardware_config.manifest(value),
                    hardware_config.ownership_manifest(value, facts), sysfs=root,
                    proc=root/'proc', devfs=root/'dev', state=root/'state')
            row, = sample['pci']
            self.assertEqual(len(row['iommu_members']), 2)
            self.assertIsNone(row['pre_bind'])
            self.assertEqual(row['vfio_descriptors']['scan'], 'unknown')
            self.assertEqual(row['vfio_descriptors']['observed_pids'], [])

    def test_descriptor_sample_is_scoped_and_marks_unreadable_observations(self):
        with tempfile.TemporaryDirectory() as temporary:
            proc = Path(temporary)
            for pid, char in (('42', '/dev/null'), ('43', '/dev/zero')):
                descriptors = proc/pid/'fd'
                descriptors.mkdir(parents=True)
                (descriptors/'3').symlink_to(char)
            cdev = proc/'device/vfio-dev/vfio2/dev'
            cdev.parent.mkdir(parents=True)
            number = os.stat('/dev/null').st_rdev
            cdev.write_text(f'{os.major(number)}:{os.minor(number)}\n')
            selections = {'selected': hardware_diagnostics.character_devices(proc/'device', '7', proc/'dev')}
            self.assertEqual(selections['selected'], {number})
            receipt = hardware_diagnostics.holders(selections, proc)['selected']
            self.assertEqual((receipt['scan'], receipt['observed_pids']), ('complete', [42]))
            original_scan = os.scandir

            def denied(path):
                if path == proc/'43/fd':
                    raise PermissionError
                return original_scan(path)

            with patch.object(os, 'scandir', denied):
                receipt = hardware_diagnostics.holders(selections, proc)['selected']
            self.assertEqual((receipt['scan'], receipt['observed_pids']), ('unknown', [42]))
            self.assertIn('sampled_at', receipt)
            self.assertEqual(hardware_diagnostics.holders({'selected': set()}, proc)['selected']['scan'], 'unknown')

    def test_two_binders_cannot_mutate_concurrently(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.fixture(root)
            run = Mock()
            with hardware.binding_lock(root/'state'), self.assertRaises(BlockingIOError):
                hardware.bind_owned(hardware_config.ownership_manifest(*declaration()), sysfs=root,
                                    state=root/'state', run=run)
            run.assert_not_called()

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
