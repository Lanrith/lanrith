import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from lanrith import media, release


class RecoveryMediaTests(unittest.TestCase):
    def test_recovery_readback_rejects_byte_or_partition_identity_changes(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            original, target = root/'recovery.raw', root/'usb.raw'
            original.write_bytes(bytes(range(256))*12)
            target.write_bytes(original.read_bytes())
            manifest = {'image_id': 'lanrith', 'artifacts': [{'role': 'disk', 'name': original.name}]}
            layout = {'label': 'gpt', 'id': 'synthetic-guid', 'sectorsize': 512,
                      'partitions': [{'start': index, 'size': 1, 'uuid': str(index), 'type': 'synthetic',
                                      'name': str(index)} for index in range(1, 5)]}
            with patch.object(media.release, 'verify', return_value=manifest) as verify, \
                    patch.object(media, 'command', return_value=json.dumps({'partitiontable': layout})) as command:
                media.verify_recovery(str(target), root, root/'independent.crt', manifest)
                self.assertEqual(verify.call_args.kwargs['purpose'], 'recovery')
                with target.open('r+b') as stream:
                    stream.seek(1024)
                    stream.write(b'changed')
                with self.assertRaisesRegex(release.ReleaseError, 'read-back'):
                    media.verify_recovery(str(target), root, root/'independent.crt', manifest)
                target.write_bytes(original.read_bytes())
                changed = copy.deepcopy(layout)
                changed['partitions'][1]['uuid'] = 'another-partition'
                command.side_effect = [json.dumps({'partitiontable': layout}), json.dumps({'partitiontable': changed})]
                with self.assertRaisesRegex(release.ReleaseError, 'identities differ'):
                    media.verify_recovery(str(target), root, root/'independent.crt', manifest)
