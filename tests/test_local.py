"""Local signing starts only after exact input admission."""

import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import yaml

from lanrith import config, local, release


PROJECT = Path(__file__).resolve().parents[1]


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
                shutil.rmtree(private)

    def test_confirmed_missing_container_removes_private_tmpfs_for_supported_exit_codes(self):
        for code in (1, 125):
            with self.subTest(code=code):
                result = subprocess.CompletedProcess([], code, b'', b'Error: no such container')
                with patch.object(local.subprocess, 'run', return_value=result):
                    with local.signing_space('podman', 'lanrith-local-disposable-test') as private:
                        (private/'test-only').write_bytes(b'disposable-test-input')
                self.assertFalse(private.exists())

    def test_owned_container_is_removed_before_private_tmpfs(self):
        inspected = subprocess.CompletedProcess([], 0, b'lanrith-local-disposable-test\n', b'')
        removed = subprocess.CompletedProcess([], 0, b'', b'')
        with patch.object(local.subprocess, 'run', side_effect=(inspected, removed)) as run:
            with local.signing_space('podman', 'lanrith-local-disposable-test') as private:
                (private/'test-only').write_bytes(b'disposable-test-input')
        self.assertFalse(private.exists())
        self.assertEqual(run.call_args_list[1].args[0],
                         ['podman', 'rm', '--force', 'lanrith-local-disposable-test'])

    def test_ownership_mismatch_and_inspect_timeout_retain_private_tmpfs(self):
        failures = (
            subprocess.CompletedProcess([], 0, b'another-transaction\n', b''),
            subprocess.TimeoutExpired(['podman', 'inspect'], 30),
        )
        for failure in failures:
            private = None
            try:
                effect = failure if isinstance(failure, BaseException) else None
                kwargs = {'side_effect': effect} if effect else {'return_value': failure}
                with self.subTest(failure=type(failure).__name__), patch.object(local.subprocess, 'run', **kwargs):
                    with self.assertRaises((release.ReleaseError, subprocess.TimeoutExpired)):
                        with local.signing_space('podman', 'lanrith-local-disposable-test') as private:
                            (private/'test-only').write_bytes(b'disposable-test-input')
                self.assertTrue(private.is_dir())
            finally:
                if private is not None:
                    shutil.rmtree(private)

    def test_build_error_is_not_masked_when_cleanup_is_uncertain(self):
        result = subprocess.CompletedProcess([], 125, b'', b'engine unavailable')
        private = None
        try:
            with patch.object(local.subprocess, 'run', return_value=result):
                with self.assertRaisesRegex(RuntimeError, 'original build failure') as caught:
                    with local.signing_space('podman', 'lanrith-local-disposable-test') as private:
                        raise RuntimeError('original build failure')
            self.assertTrue(any('cleanup also failed' in note.lower()
                                for note in getattr(caught.exception, '__notes__', ())))
            self.assertTrue(private.is_dir())
        finally:
            if private is not None:
                shutil.rmtree(private)

    def test_local_inputs_bind_effective_configuration_with_and_without_serial_material(self):
        selection = {'files': {'tools.tar.gz': 'a'*64}, 'manifest_sha256': 'b'*64,
                     'source_commit': 'c'*40, 'builder': 'example.invalid/builder',
                     'builder_digest': 'd'*64}
        for serial_enabled in (False, True):
            with self.subTest(serial_enabled=serial_enabled), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                owner, platform = root/'owner', root/'platform'
                (owner/'trust').mkdir(parents=True)
                platform.mkdir()
                value = yaml.safe_load((PROJECT/'examples/minimal.yaml').read_text())
                if serial_enabled:
                    value['administration']['serial'] = {'enabled': True}
                (owner/'config.yaml').write_text(yaml.safe_dump(value))
                (owner/'platform.lock').write_text('{}\n')
                (owner/'trust/boot.crt').write_text('synthetic certificate\n')
                serial_hash = None
                if serial_enabled:
                    serial_hash = root/'serial.hash'
                    serial_hash.write_text('synthetic serial hash\n')
                normalized = config.load(owner/'config.yaml')
                serial_digest = release.file_record(serial_hash)['sha256'] if serial_hash else None
                with patch.object(local.trust, 'lock', return_value=selection), \
                        patch.object(local.release, 'public_key'), \
                        patch.object(local, 'consumer', return_value=SimpleNamespace(
                            integration_pins=lambda *_: {})):
                    actual = local.inputs(owner, platform, 1, serial_hash)
                self.assertEqual(actual['serial_provisioning_sha256'], serial_digest)
                self.assertEqual(actual['effective_configuration_sha256'],
                                 config.effective_digest(normalized, {}, serial_digest))
