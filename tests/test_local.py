"""Local signing starts only after exact input admission."""

import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from lanrith import local, release


class LocalBuildTests(unittest.TestCase):
    def test_consumer_enumerates_assessment_releases_across_pages(self):
        import subprocess
        module = local.consumer()
        inventory = 'a'*64
        latest = 'assessment-20261016T040000Z-'+inventory[:12]
        pages = [[{'draft': False, 'tag_name': 'v0.1.0'}], [{'draft': False, 'tag_name': latest}]]
        calls = []
        def run(*args, **kwargs):
            calls.append(args)
            return subprocess.CompletedProcess(args, 0, json.dumps(pages) if args[1] == 'api' else '')
        with tempfile.TemporaryDirectory() as temporary, patch.object(module, 'run', side_effect=run), \
                patch.object(module.trust, 'verify', return_value='verified-builder'), \
                patch.object(module.trust, 'verify_builder'), patch.object(module.admission, 'assess'):
            selection = {'version': 'v0.1.0', 'files': {'inventory.json': inventory}}
            self.assertEqual(module.fetch(selection, Path(temporary)/'bundle'), 'verified-builder')
        self.assertTrue(any('--paginate' in args for args in calls))
        self.assertTrue(any(latest in args for args in calls))

    def test_changed_inputs_fail_before_any_private_file_or_workspace_is_opened(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            request = root/'request.json'
            request.write_text(json.dumps({'deployment_sequence': 9, 'configuration_sha256': 'a'*64}))
            with patch.object(local, 'admit', return_value={'deployment_sequence': 9,
                                                          'configuration_sha256': 'b'*64}), \
                    patch.object(local, 'private_copy') as private_copy:
                with self.assertRaises(release.ReleaseError):
                    local.assemble(root, root, request, root/'work', root/'output',
                                   key=root/'unread-key', certificate=root/'unread-cert')
                private_copy.assert_not_called()
            self.assertFalse((root/'work').exists())
            self.assertFalse((root/'output').exists())

    def test_private_inputs_reject_links_shared_files_and_open_permissions(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root/'private'
            source.write_bytes(b'disposable-test-input')
            source.chmod(0o644)
            with self.assertRaises(release.ReleaseError):
                local.private_copy(source, root/'copy', 64)
            source.chmod(0o600)
            link = root/'link'
            link.symlink_to(source)
            with self.assertRaises(OSError):
                local.private_copy(link, root/'copy', 64)
            hard = root/'hard'
            os.link(source, hard)
            with self.assertRaises(release.ReleaseError):
                local.private_copy(source, root/'copy', 64)
            hard.unlink()
            local.private_copy(source, root/'copy', 64)
            self.assertEqual((root/'copy').read_bytes(), source.read_bytes())
            self.assertEqual((root/'copy').stat().st_mode & 0o777, 0o600)

    def test_unknown_container_state_retains_private_tmpfs_for_managed_recovery(self):
        import subprocess
        result = subprocess.CompletedProcess([], 125, b'', b'engine unavailable')
        private = None
        try:
            with patch.object(local.subprocess, 'run', return_value=result):
                with self.assertRaises(release.ReleaseError):
                    with local.signing_space('podman', 'lanrith-local-disposable-test') as private:
                        (private/'test-only').write_bytes(b'disposable-test-input')
            self.assertTrue(private.is_dir())
        finally:
            if private is not None:
                import shutil
                shutil.rmtree(private)
