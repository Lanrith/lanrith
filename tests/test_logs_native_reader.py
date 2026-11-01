"""Native qualification must observe log recovery across actual file rotation."""

import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

import logs_native as native


def document(row):
    return json.dumps({'resourceLogs': [{'scopeLogs': [{'logRecords': [row]}]}]}).encode()+b'\n'


class NativeLogReaderTests(unittest.TestCase):
    def test_unlinked_rotation_keeps_the_surviving_recovery_record(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            rotated, active = root/'events-old.jsonl', root/'events.jsonl'
            rotated.write_bytes(document({'timeUnixNano': '1'}))
            recovered = {'timeUnixNano': '2', 'body': {'stringValue': 'journal message withheld'}}
            active.write_bytes(document(recovered)+b'{unfinished')
            read_bytes = Path.read_bytes
            def rotating_read(path):
                if path == rotated:
                    path.unlink()
                return read_bytes(path)
            with mock.patch.object(native.logs_runtime, 'LOCAL', root), \
                    mock.patch.object(Path, 'read_bytes', autospec=True, side_effect=rotating_read):
                self.assertEqual(native.local_records(), [recovered])
            self.assertFalse(rotated.exists())

    def test_removing_every_observed_file_supplies_no_recovery_record(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root/'events-old.jsonl').write_bytes(document({'timeUnixNano': '1'}))
            read_bytes = Path.read_bytes
            def rotating_read(path):
                path.unlink()
                return read_bytes(path)
            with mock.patch.object(native.logs_runtime, 'LOCAL', root), \
                    mock.patch.object(Path, 'read_bytes', autospec=True, side_effect=rotating_read):
                self.assertEqual(native.local_records(), [])

    def test_permission_failures_remain_qualification_errors(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root/'events.jsonl').write_bytes(document({'timeUnixNano': '1'}))
            with mock.patch.object(native.logs_runtime, 'LOCAL', root), \
                    mock.patch.object(Path, 'read_bytes', side_effect=PermissionError):
                with self.assertRaises(PermissionError):
                    native.local_records()


if __name__ == '__main__':
    unittest.main()
