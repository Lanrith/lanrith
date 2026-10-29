import copy
import hashlib
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from lanrith import factory, recovery_slot as slot, release, update


class SlotRepairTests(unittest.TestCase):
    def fixture(self):
        artifacts = [{'role': 'uki', 'name': 'router_9.efi', 'size': 128, 'sha256': 'a'*64}]
        rows = []
        for index, (role, guid) in enumerate(update.GUIDS.items(), 1):
            uuid = f'aaaaaaaa-1234-1234-1234-{index:012d}'
            artifacts.append({'role': role, 'name': f'router_9_{uuid}.{role}.raw', 'size': 512, 'sha256': 'a'*64})
            rows.append({'device': f'/dev/vdb{index}', 'disk': '/dev/vdb', 'type': guid, 'uuid': uuid,
                         'label': 'l_9_'+role.replace('-', '_'), 'size': 1024, 'mounted': False})
        esp_uuid = 'bbbbbbbb-1234-1234-1234-123456789abc'
        rows += [{'device': '/dev/vdb4', 'disk': '/dev/vdb', 'type': slot.recovery_inputs.ESP_GUID,
                  'uuid': esp_uuid, 'size': 4096, 'mounted': False},
                 {'device': '/dev/vdb5', 'disk': '/dev/vdb', 'type': factory.VAR_GUID,
                  'uuid': 'cccccccc-1234-1234-1234-123456789abc', 'label': 'var', 'size': 4096, 'mounted': False}]
        manifest = {'purpose': 'update', 'architecture': 'x86-64', 'image_contract': {},
                    'deployment_sequence': 9, 'image_id': 'router', 'artifacts': artifacts}
        return manifest, rows, esp_uuid

    def test_plan_selects_only_the_exact_signed_slot_and_preserves_state(self):
        manifest, rows, esp = self.fixture()
        with patch.object(slot.recovery_inputs, 'partition', return_value='/dev/vdb4'):
            selected, _, state = slot.plan(manifest, rows, '/dev/vdb', esp)
            self.assertEqual(set(selected), set(update.GUIDS))
            self.assertNotIn(state, selected.values())
            for mutation in ('uuid', 'mounted', 'size', 'label', 'duplicate'):
                changed = copy.deepcopy(rows)
                if mutation == 'duplicate':
                    changed.append({**changed[0], 'device': '/dev/vdb9'})
                else:
                    changed[0][mutation] = {'uuid': esp, 'mounted': True, 'size': 1, 'label': 'l_10_root'}[mutation]
                with self.subTest(mutation=mutation), self.assertRaises(release.ReleaseError):
                    slot.plan(manifest, changed, '/dev/vdb', esp)

    def test_regular_file_cannot_be_used_as_a_production_repair_target(self):
        with tempfile.TemporaryFile() as target, self.assertRaises(release.ReleaseError):
            slot.require_target(target.fileno(), '/nonexistent', 512)

    def test_bounded_copy_verifies_written_bytes_and_does_not_extend_the_partition(self):
        with tempfile.TemporaryDirectory() as temporary:
            source, target = Path(temporary)/'source', Path(temporary)/'target'
            source.write_bytes(b'new signed OS slot'*8192)
            data = source.read_bytes()
            target.write_bytes(bytes(len(data))+b'outside-signed-image')
            record = {'size': len(data), 'sha256': hashlib.sha256(data).hexdigest()}
            checks = []
            with patch.object(slot, 'require_target') as bound:
                slot.copy_partition(source, str(target), record, check=lambda: checks.append(True))
                bound.assert_called_once()
            self.assertEqual(target.read_bytes(), data+b'outside-signed-image')
            self.assertGreaterEqual(len(checks), 2)
            source.write_bytes(b'changed')
            with patch.object(slot, 'require_target'), self.assertRaises(release.ReleaseError):
                slot.copy_partition(source, str(target), record, check=lambda: None)

    def test_other_partitions_stay_readonly_during_the_write_window(self):
        rows = [{'device': '/dev/vdb1'}, {'device': '/dev/vdb2'}, {'device': '/dev/vdb3'}]
        with patch.object(slot.update, 'command') as command:
            with slot.writable('/dev/vdb', rows, {'/dev/vdb1'}):
                calls = [call.args[0] for call in command.call_args_list]
                self.assertNotIn(['blockdev', '--setrw', '/dev/vdb2'], calls)
                self.assertNotIn(['blockdev', '--setrw', '/dev/vdb3'], calls)
            self.assertEqual(command.call_args_list[-1].args[0], ['blockdev', '--setro', '/dev/vdb'])
