import json
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import patch

from lanrith import build_inputs, release


class BuildInputTests(unittest.TestCase):
    def test_unknown_partial_or_relative_build_inputs_are_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary)/'inputs.json'
            for value in ({'command': 'anything'}, {'pcr_key': '/private/key'},
                          {'recovery_hash': '../credential'}, {'fallback_release': '/release'}):
                path.write_text(json.dumps(value))
                with self.subTest(value=value), self.assertRaises(release.ReleaseError):
                    build_inputs.load(path)

    def test_preflight_records_credential_bytes_and_staging_rechecks_them(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root/'recovery.hash'
            source.write_text('synthetic-first-hash')
            options = {'recovery_hash': source}
            record = build_inputs.record(options, certificate=root/'unread-cert', image_id='router', sequence=12)
            self.assertEqual(record['image_id'], 'router')
            private = root/'private'
            private.mkdir()
            source.write_text('synthetic-replaced-hash')
            def private_copy(src, dst, maximum):
                self.assertEqual(maximum, 512)
                shutil.copyfile(src, dst)
                dst.chmod(0o600)
            with self.assertRaisesRegex(release.ReleaseError, 'changed after preflight'):
                build_inputs.stage(options, record, private=private, work=root, private_copy=private_copy)

    def test_fallback_snapshot_cannot_follow_a_substituted_payload_link(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source, private = root/'source', root/'private'
            source.mkdir(); private.mkdir()
            (source/'release.json').write_bytes(b'{}\n')
            (source/'release.json.sig').write_bytes(b'synthetic-signature')
            outside = root/'outside'
            outside.write_bytes(b'synthetic-private-content')
            (source/'payload.raw').symlink_to(outside)
            manifest = {'artifacts': [{'name': 'payload.raw', 'size': 1, 'sha256': 'a'*64}]}
            expected = {'image_id': 'router',
                        'fallback_manifest_sha256': release.file_record(source/'release.json')['sha256']}
            with patch.object(release, 'verify', return_value=manifest) as verify, self.assertRaises(OSError):
                build_inputs.stage({'fallback_release': source}, expected, private=private, work=root,
                                   private_copy=lambda *_: None)
            verify.assert_called_once()
            self.assertFalse((root/'fallback/payload.raw').exists())
