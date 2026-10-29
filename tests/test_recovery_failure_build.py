"""Build-time boundaries for the unqualified failure serial console."""
import json
import io
import tarfile
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest.mock import patch

from lanrith import recovery_failure_build as build
from lanrith.release import ReleaseError


class FailureBuildTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='lanrith-failure-build-')
        self.addCleanup(self.tmp.cleanup)
        self.workspace = Path(self.tmp.name)/'workspace'
        root = self.workspace/'mkosi.images/initrd/mkosi.extra'
        self.library = root/'usr/lib/lanrith/lanrith'
        self.library.mkdir(parents=True)
        self.settings = root/'usr/share/lanrith'
        self.settings.mkdir(parents=True)
        self.emergency = root/'usr/lib/systemd/system/emergency.service.d/60-lanrith-recovery.conf'
        self.emergency.parent.mkdir(parents=True)
        self.original = '[Service]\nExecStart=/usr/bin/lanrith-factory emergency\n'
        self.emergency.write_text(self.original)
        self.credential = Path(self.tmp.name)/'credential'
        self.credential.write_text('scrypt:32768:8:1:'+'ab'*16+':'+'cd'*32+'\n')
        self.credential.chmod(0o600)
        self.patcher = patch.object(build, 'admitted_bootctl', return_value=b'synthetic-bootctl')
        self.patcher.start()
        self.addCleanup(self.patcher.stop)
        self.base = Path('/synthetic/base')
        self.initrd = Path('/synthetic/initrd')

    def test_gate_denies_build_before_modification(self):
        with self.assertRaises(ReleaseError):
            build.prepare(self.workspace, credential=self.credential, tty='ttyS0', base=self.base, initrd_base=self.initrd)
        self.assertEqual(self.emergency.read_text(), self.original)
        self.assertEqual(list(self.library.iterdir()), [])

    def test_installs_only_compiled_policy_and_protected_hash(self):
        with patch.object(build, 'FAILURE_CONSOLE_BUILD_QUALIFIED', True):
            build.prepare(self.workspace, credential=self.credential, tty='ttyS0', base=self.base, initrd_base=self.initrd)
        self.assertEqual(json.loads((self.settings/'failure-console.json').read_text()), {'schema': 1, 'tty': 'ttyS0'})
        self.assertEqual((self.settings/'failure-console.hash').read_bytes(), self.credential.read_bytes())
        self.assertEqual((self.settings/'failure-console.hash').stat().st_mode & 0o777, 0o600)
        self.assertEqual({p.name for p in self.library.iterdir()}, set(build.MODULES))
        self.assertIn('ExecStart=/usr/bin/lanrith-failure-console', self.emergency.read_text())
        self.assertIn('TTYPath=/dev/ttyS0', self.emergency.read_text())

    def test_explicit_emergency_dropin_is_confined_to_service_directory(self):
        legacy = self.emergency.with_name('60-legacy-security.conf')
        self.emergency.rename(legacy)
        with patch.object(build, 'FAILURE_CONSOLE_BUILD_QUALIFIED', True):
            with self.assertRaises(ReleaseError):
                build.prepare(self.workspace, credential=self.credential, tty='ttyS0', base=self.base, initrd_base=self.initrd,
                              emergency_dropin='../../outside.conf')
            build.prepare(self.workspace, credential=self.credential, tty='ttyS0', base=self.base, initrd_base=self.initrd,
                          emergency_dropin='60-legacy-security.conf')
        self.assertIn('ExecStart=/usr/bin/lanrith-failure-console', legacy.read_text())

    def test_selected_library_prefix_is_bounded_and_written_into_entrypoint(self):
        custom = self.library.parent.parent/'synthetic-router/lanrith'
        custom.mkdir(parents=True)
        with patch.object(build, 'FAILURE_CONSOLE_BUILD_QUALIFIED', True):
            with self.assertRaises(ReleaseError):
                build.prepare(self.workspace, credential=self.credential, tty='ttyS0', base=self.base, initrd_base=self.initrd,
                              library_prefix='usr/lib/../../outside')
            build.prepare(self.workspace, credential=self.credential, tty='ttyS0', base=self.base, initrd_base=self.initrd,
                          library_prefix='usr/lib/synthetic-router')
        self.assertEqual({p.name for p in custom.iterdir()}, set(build.MODULES))
        entry = self.workspace/'mkosi.images/initrd/mkosi.extra/usr/bin/lanrith-failure-console'
        self.assertIn("'/usr/lib/synthetic-router'", entry.read_text())

    def test_changed_credential_is_rejected_before_any_module_copy(self):
        initial = self.credential.stat()
        names = ('st_dev', 'st_ino', 'st_size', 'st_mtime_ns', 'st_ctime_ns', 'st_mode', 'st_uid', 'st_nlink')
        changed = SimpleNamespace(**{name: getattr(initial, name) for name in names})
        changed.st_ino += 1
        with patch.object(build, 'FAILURE_CONSOLE_BUILD_QUALIFIED', True), \
                patch.object(build.os, 'fstat', side_effect=[initial, changed]), self.assertRaises(ReleaseError):
            build.prepare(self.workspace, credential=self.credential, tty='ttyS0', base=self.base, initrd_base=self.initrd)
        self.assertEqual(list(self.library.iterdir()), [])
        self.assertEqual(self.emergency.read_text(), self.original)

    def test_existing_settings_are_rejected_before_any_module_copy(self):
        (self.settings/'failure-console.json').write_text('existing')
        with patch.object(build, 'FAILURE_CONSOLE_BUILD_QUALIFIED', True), self.assertRaises(ReleaseError):
            build.prepare(self.workspace, credential=self.credential, tty='ttyS0', base=self.base, initrd_base=self.initrd)
        self.assertEqual(list(self.library.iterdir()), [])
        self.assertEqual(self.emergency.read_text(), self.original)
        self.assertEqual((self.settings/'failure-console.json').read_text(), 'existing')

    def test_bad_credential_or_terminal_fails_before_modification(self):
        with patch.object(build, 'FAILURE_CONSOLE_BUILD_QUALIFIED', True):
            with self.assertRaises(ReleaseError):
                build.prepare(self.workspace, credential=self.credential, tty='tty0', base=self.base, initrd_base=self.initrd)
            self.credential.chmod(0o644)
            with self.assertRaises(ReleaseError):
                build.prepare(self.workspace, credential=self.credential, tty='ttyS0', base=self.base, initrd_base=self.initrd)
        self.assertEqual(self.emergency.read_text(), self.original)
        self.assertEqual(list(self.library.iterdir()), [])


class BootctlArchiveTests(unittest.TestCase):
    def test_matching_admitted_libraries_and_mismatch_rejection(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            binary = bytearray(64)
            binary[:6] = b'\x7fELF\x02\x01'
            binary[18:20] = (62).to_bytes(2, 'little')
            binary += b'libsystemd-shared-257.so\0libcrypto.so.3\0'
            libraries = {'usr/lib/x86_64-linux-gnu/systemd/libsystemd-shared-257.so': b'systemd',
                         'usr/lib/x86_64-linux-gnu/libcrypto.so.3': b'crypto',
                         'usr/lib/x86_64-linux-gnu/libc.so.6': b'libc'}
            def archive(path, entries):
                with tarfile.open(path, 'w') as tar:
                    for name, data in entries.items():
                        info = tarfile.TarInfo('./'+name)
                        info.uid = info.gid = 0
                        info.mode = 0o755 if name == build.BOOTCTL else 0o644
                        info.size = len(data)
                        tar.addfile(info, io.BytesIO(data))
            base, initrd = root/'base.tar', root/'initrd.tar'
            archive(base, {**libraries, build.BOOTCTL: bytes(binary)})
            archive(initrd, libraries)
            self.assertEqual(build.admitted_bootctl(base, initrd), bytes(binary))
            archive(initrd, {**libraries, 'usr/lib/x86_64-linux-gnu/libcrypto.so.3': b'changed'})
            with self.assertRaises(ReleaseError):
                build.admitted_bootctl(base, initrd)

    def test_archive_rejects_duplicate_or_unowned_utility(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary)/'archive.tar'
            data = b'synthetic'
            def member(tar, owner):
                info = tarfile.TarInfo('./'+build.BOOTCTL)
                info.uid = owner
                info.gid = 0
                info.mode = 0o755
                info.size = len(data)
                tar.addfile(info, io.BytesIO(data))
            with tarfile.open(path, 'w') as tar:
                member(tar, 0)
                member(tar, 0)
            with self.assertRaises(ReleaseError):
                build.archive_members(path, {build.BOOTCTL})
            with tarfile.open(path, 'w') as tar:
                member(tar, 1000)
            with self.assertRaises(ReleaseError):
                build.archive_members(path, {build.BOOTCTL})



if __name__ == '__main__':
    unittest.main()
