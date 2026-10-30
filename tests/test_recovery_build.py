"""A recovery experiment cannot be confused with an update or factory image."""

import ast
import json
import os
from pathlib import Path
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from lanrith import build, config, recovery_build, release


class RecoveryAssemblyTests(unittest.TestCase):
    def test_experimental_initrd_replaces_installer_and_blocks_normal_exports(self):
        with tempfile.TemporaryDirectory(prefix='lanrith-recovery-assembly-') as temporary:
            root = Path(temporary)
            base = root/'base.tar'
            base.write_bytes(b'synthetic-base')
            credential = root/'recovery.hash'
            credential.write_text('scrypt:32768:8:1:'+'1'*32+':'+'2'*64+'\n')
            credential.chmod(0o600)
            key, cert = root/'key', root/'cert'
            subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
                            '-subj', '/CN=synthetic-recovery-build', '-keyout', str(key), '-out', str(cert)],
                           check=True, capture_output=True)
            key.chmod(0o600)
            value = config.load(Path(__file__).resolve().parents[1]/'examples/minimal.yaml')
            value['hardware']['boot']['recovery_console'] = 'ttyS0'
            workspace = root/'assembly'
            identity = build.assembly(value, base, workspace, version='0.1.0', sequence=27,
                                      certificate=cert, private_key=key)
            state_uuid = '12345678-1234-1234-1234-123456789abc'
            offline_inputs = {'release_disk_by_id': '/dev/disk/by-id/synthetic-release-disk',
                              'release_partition_uuid': 'abcdefab-1234-1234-1234-123456789abc',
                              'target_esp_uuid': 'fedcba98-1234-1234-1234-123456789abc'}
            factory = workspace/'mkosi.images/initrd/mkosi.extra/usr/lib/lanrith/lanrith/factory.py'
            held_factory = factory.with_suffix('.held')
            factory.rename(held_factory)
            with self.assertRaisesRegex(release.ReleaseError, 'prerequisites'):
                recovery_build.prepare(workspace, disk_by_id='/dev/disk/by-id/synthetic-disk',
                                       credential=credential, state_uuid=state_uuid, offline_inputs=offline_inputs)
            self.assertFalse((workspace/'RECOVERY-ASSEMBLY').exists())
            held_factory.rename(factory)
            recovery_build.prepare(workspace, disk_by_id='/dev/disk/by-id/synthetic-disk',
                                   credential=credential, state_uuid=state_uuid.upper(),
                                   offline_inputs={name: item.upper() if name.endswith('_uuid') else item
                                                   for name, item in offline_inputs.items()})
            initrd = workspace/'mkosi.images/initrd/mkosi.extra'
            unit = (initrd/'usr/lib/systemd/system/lanrith-factory.service').read_text()
            self.assertIn('ExecStart=/usr/bin/lanrith-recovery\n', unit)
            self.assertIn('Type=oneshot\n', unit)
            self.assertIn('LimitCORE=0\nNoNewPrivileges=yes\n', unit)
            self.assertNotIn('lanrith-factory provision', unit)
            self.assertFalse((initrd/'usr/bin/lanrith-factory').exists())
            self.assertIn('ExecStart=/usr/bin/lanrith-recovery-hold\n',
                          (initrd/'usr/lib/systemd/system/emergency.service.d/60-lanrith-recovery.conf').read_text())
            policy = json.loads((initrd/'usr/share/lanrith/recovery-console.json').read_text())
            self.assertEqual(policy['disk_by_id'], '/dev/disk/by-id/synthetic-disk')
            self.assertEqual(policy['tty'], 'ttyS0')
            self.assertEqual(policy['state_uuid'], state_uuid)
            self.assertEqual(policy['offline_inputs'], offline_inputs)
            self.assertEqual((initrd/'usr/share/lanrith/recovery-console.hash').stat().st_mode & 0o777, 0o600)
            self.assertTrue((initrd/'usr/lib/lanrith/lanrith/recovery_console.py').is_file())
            self.assertTrue((initrd/'usr/lib/lanrith/lanrith/recovery_state.py').is_file())
            self.assertTrue((initrd/'usr/lib/lanrith/lanrith/recovery_inputs.py').is_file())
            self.assertFalse(any(p.suffix in ('.yaml', '.yml') for p in initrd.rglob('*')))
            ast.parse((initrd/'usr/bin/lanrith-recovery').read_text())
            with self.assertRaisesRegex(release.ReleaseError, 'cannot be exported as an update'):
                build.update_payload(workspace, identity, root/'update')
            with self.assertRaisesRegex(release.ReleaseError, 'cannot be exported as factory'):
                build.factory_payload(workspace, identity, root/'none', root/'factory')

    def test_restore_modules_require_build_gate_and_remain_unqualified(self):
        with tempfile.TemporaryDirectory(prefix='lanrith-recovery-restore-') as temporary:
            root = Path(temporary)
            base = root/'base.tar'
            base.write_bytes(b'synthetic-base')
            credential = root/'recovery.hash'
            credential.write_text('scrypt:32768:8:1:'+'1'*32+':'+'2'*64+'\n')
            credential.chmod(0o600)
            key, cert = root/'key', root/'cert'
            subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
                            '-subj', '/CN=synthetic-recovery-build', '-keyout', str(key), '-out', str(cert)],
                           check=True, capture_output=True)
            key.chmod(0o600)
            value = config.load(Path(__file__).resolve().parents[1]/'examples/minimal.yaml')
            value['administration']['root_access'] = 'disabled'
            value['hardware']['boot']['recovery_console'] = 'ttyS0'
            workspace = root/'assembly'
            identity = build.assembly(value, base, workspace, version='0.1.0', sequence=27,
                                      certificate=cert, private_key=key)
            state_uuid = '12345678-1234-1234-1234-123456789abc'
            disk = '/dev/disk/by-id/synthetic-disk'
            binding = {'schema': 1, 'target_disk_by_id': disk, 'state_uuid': state_uuid,
                       'state_partuuid': '22345678-1234-1234-1234-123456789abc',
                       'backup_disk_by_id': '/dev/disk/by-id/synthetic-backup',
                       'backup_partuuid': '32345678-1234-1234-1234-123456789abc'}
            with self.assertRaisesRegex(release.ReleaseError, 'not qualified'):
                recovery_build.prepare(workspace, disk_by_id=disk, credential=credential,
                                       state_uuid=state_uuid, offline_backup=binding)
            self.assertFalse((workspace/'RECOVERY-ASSEMBLY').exists())
            with patch.object(recovery_build, 'RESTORE_RECOVERY_BUILD_QUALIFIED', True):
                with self.assertRaisesRegex(release.ReleaseError, 'differs from the recovery target'):
                    recovery_build.prepare(workspace, disk_by_id=disk, credential=credential,
                                           state_uuid=state_uuid,
                                           offline_backup={**binding, 'target_disk_by_id': '/dev/disk/by-id/other'})
                self.assertFalse((workspace/'RECOVERY-ASSEMBLY').exists())
                recovery_build.prepare(workspace, disk_by_id=disk, credential=credential,
                                       state_uuid=state_uuid, offline_backup=binding)
            initrd = workspace/'mkosi.images/initrd/mkosi.extra'
            self.assertEqual(json.loads((initrd/'usr/share/lanrith/recovery-console.json').read_bytes())['offline_backup'], binding)
            library = initrd/'usr/lib/lanrith/lanrith'
            self.assertTrue(all((library/name).is_file() for name in recovery_build.RESTORE_MODULES))
            self.assertIn('BACKUP_WRITE_QUALIFIED = False', (library/'recovery_backup_device.py').read_text())
            self.assertIn('READONLY_PREPARATION_QUALIFIED = False', (library/'recovery_backup_preflight.py').read_text())
            self.assertIn('RESTORE_WORKFLOW_QUALIFIED = False', (library/'recovery_restore.py').read_text())
            self.assertIn('BACKUP_FRESHNESS_QUALIFIED = False', (library/'recovery_restore.py').read_text())
            self.assertIn('TARGET_CLAIM_QUALIFIED = False', (library/'recovery_restore_target.py').read_text())
            self.assertIn('RESTORE_WRITE_QUALIFIED = False', (library/'recovery_restore_transaction.py').read_text())
            subprocess.run(['python3', '-I', '-B', '-c',
                            'import sys; sys.path.insert(0, sys.argv[1]); from lanrith import recovery_restore',
                            str(library.parent)], check=True, capture_output=True)
            self.assertFalse(any(p.suffix in ('.yaml', '.yml') for p in initrd.rglob('*')))
            with self.assertRaisesRegex(release.ReleaseError, 'cannot be exported as an update'):
                build.update_payload(workspace, identity, root/'update')

    def test_invalid_credential_fails_before_export_barrier_or_mutation(self):
        with tempfile.TemporaryDirectory(prefix='lanrith-recovery-invalid-') as temporary:
            root = Path(temporary)
            credential = root/'credential'
            credential.write_text('bad')
            credential.chmod(0o600)
            with self.assertRaisesRegex(release.ReleaseError, 'credential format'):
                recovery_build.prepare(root, disk_by_id='/dev/disk/by-id/synthetic', credential=credential)
            self.assertFalse((root/'RECOVERY-ASSEMBLY').exists())

    def test_linked_or_changed_credential_is_rejected_before_build_mutation(self):
        with tempfile.TemporaryDirectory(prefix='lanrith-recovery-credential-') as temporary:
            root = Path(temporary)
            credential = root/'credential'
            credential.write_text('scrypt:32768:8:1:'+'1'*32+':'+'2'*64+'\n')
            credential.chmod(0o600)
            linked = root/'linked'
            os.link(credential, linked)
            with self.assertRaisesRegex(release.ReleaseError, 'protected file'):
                recovery_build.prepare(root, disk_by_id='/dev/disk/by-id/synthetic', credential=credential)
            linked.unlink()
            initial = credential.stat()
            names = ('st_dev', 'st_ino', 'st_size', 'st_mtime_ns', 'st_ctime_ns', 'st_mode', 'st_uid', 'st_nlink')
            changed = SimpleNamespace(**{name: getattr(initial, name) for name in names})
            changed.st_ino += 1
            with patch.object(recovery_build.os, 'fstat', side_effect=[initial, changed]), \
                    self.assertRaisesRegex(release.ReleaseError, 'changed during read'):
                recovery_build.prepare(root, disk_by_id='/dev/disk/by-id/synthetic', credential=credential)
            self.assertFalse((root/'RECOVERY-ASSEMBLY').exists())

    def test_root_disabled_policy_is_retained(self):
        value = config.load(Path(__file__).resolve().parents[1]/'examples/minimal.yaml')
        value['administration']['root_access'] = 'disabled'
        self.assertEqual(config.normalize(value)['administration']['root_access'], 'disabled')
        for invalid in (False, 'sometimes'):
            value['administration']['root_access'] = invalid
            with self.subTest(invalid=invalid), self.assertRaises(release.ReleaseError):
                config.normalize(value)
        value['administration']['root_access'] = 'disabled'
        value['administration']['serial'] = {'enabled': True}
        with self.assertRaises(release.ReleaseError):
            config.normalize(value)


if __name__ == '__main__':
    unittest.main()
