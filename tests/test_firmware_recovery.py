import base64
import copy
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from lanrith import build, config, early_unlock, firmware_recovery as firmware, recovery_build, recovery_console, recovery_enrollment as enrollment, release


class FirmwareRecoveryTests(unittest.TestCase):
    def setUp(self):
        self.policy = early_unlock.policy(b'fixture-key')
        self.tpm = {'type': 'systemd-tpm2', 'keyslots': ['0'], 'tpm2-pcr-bank': 'sha256',
                    'tpm2-pcrs': [7, 15], 'tpm2_pubkey_pcrs': [11],
                    'tpm2_pubkey': base64.b64encode(b'fixture-key').decode()}
        self.luks = {'tokens': {'0': self.tpm, '1': enrollment.recovery_token('1')},
                     'keyslots': {'0': {'fixture': 'tpm'}, '1': {'fixture': 'recovery'}}}
        self.binding = {'state_partuuid': '00000000-1111-4444-9999-123456789abc', 'pcr7_sha256': 'a'*64,
                        'old_token': '0', 'old_slot': '0', 'inventory': enrollment.inventory(self.luks)}
        self.profile = {'schema': 1, 'tty': 'ttyS0', 'image_id': 'lanrith', 'disk_by_id': '/dev/disk/by-id/fixture',
                        'state_uuid': 'ffffffff-1111-4444-9999-123456789abc',
                        'operations': ['reenroll-tpm'], 'firmware_transition': self.binding}

    def test_recovery_build_embeds_the_binding_and_native_dependencies_in_its_verified_initrd(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            cert, key = root/'cert', root/'key'
            subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
                '-subj', '/CN=Firmware fixture', '-keyout', str(key), '-out', str(cert)], check=True, capture_output=True)
            base = root/'base'
            base.write_bytes(b'synthetic-base')
            value = config.load(Path(__file__).resolve().parents[1]/'examples/minimal.yaml')
            value['hardware']['boot'].update(recovery_console='ttyS0', removable_shim_sha256='e'*64)
            workspace = root/'assembly'
            build.assembly(value, base, workspace, version='0.1.0', sequence=17, certificate=cert, private_key=key)
            self.assertIn('ShimBootloader=signed\n', (workspace/'mkosi.conf').read_text())
            credential = root/'recovery.hash'
            credential.write_text('scrypt:32768:8:1:'+'1'*32+':'+'2'*64+'\n')
            credential.chmod(0o600)
            recovery_build.prepare(workspace, disk_by_id=self.profile['disk_by_id'], credential=credential,
                state_uuid=self.profile['state_uuid'], operations=['reenroll-tpm'], transition=self.binding)
            initrd = workspace/'mkosi.images/initrd/mkosi.extra'
            stored = json.loads((initrd/'usr/share/lanrith/recovery-console.json').read_bytes())
            self.assertEqual(stored['firmware_transition'], self.binding)
            self.assertEqual(stored['operations'], ['reenroll-tpm'])
            library = initrd/'usr/lib/lanrith'
            subprocess.run(['python3', '-I', '-c', 'import sys;sys.path.insert(0,sys.argv[1]);'
                            'from lanrith.firmware_recovery import reenroll', str(library)], check=True)
            self.assertFalse((workspace/'mkosi.extra/usr/lib/lanrith/lanrith/firmware_recovery.py').exists())

    def test_interruption_shapes_require_the_bound_predecessor_and_an_unchanged_recovery_key(self):
        firmware.validate(self.binding)
        luks = copy.deepcopy(self.luks)
        for stage in ('prior', 'added', 'tagged', 'untagged', 'retired'):
            with self.subTest(stage=stage):
                state = firmware.layout(luks, self.binding, self.policy)
                self.assertEqual(state.new_slot, '2')
                self.assertEqual(state.new_tagged, stage in ('tagged', 'untagged', 'retired'))
                changed = copy.deepcopy(luks)
                changed['keyslots']['1']['fixture'] = 'replaced'
                with self.assertRaisesRegex(release.ReleaseError, 'inventory'):
                    firmware.layout(changed, self.binding, self.policy)
                if stage == 'prior':
                    luks['keyslots']['2'] = {'fixture': 'new'}
                if stage == 'added':
                    luks['tokens']['2'] = {**self.tpm, 'keyslots': ['2']}
                if stage == 'tagged':
                    del luks['tokens']['0']
                if stage == 'untagged':
                    del luks['keyslots']['0']

    def test_wrong_firmware_or_unapproved_operation_stops_before_a_write_window(self):
        with patch.object(early_unlock, 'kernel_text', return_value='b'*64):
            with self.assertRaisesRegex(release.ReleaseError, 'destination'):
                firmware.require_firmware(self.binding)
        with patch.object(firmware.recovery_authority, 'permits', return_value=False), \
                patch.object(firmware.recovery_slot, 'writable') as write:
            with self.assertRaisesRegex(release.ReleaseError, 'not authorized'):
                firmware.reenroll(self.profile, bytearray(b'fixture'))
            write.assert_not_called()
        for field in ('state_uuid', 'firmware_transition', 'operations'):
            changed = {k: v for k, v in self.profile.items() if k != field}
            with self.assertRaises(release.ReleaseError):
                recovery_console.policy(changed)

    def test_unapproved_firmware_cannot_prompt_for_the_offline_key(self):
        commands = iter(['reenroll-tpm', 'exit'])
        with patch.object(firmware, 'approved_destination', side_effect=release.ReleaseError('different firmware')) as check, \
                patch.object(firmware, 'reenroll') as change, patch.object(enrollment, 'recorded_key') as prompt:
            recovery_console.fixed_menu(self.profile, read_command=lambda: next(commands), write=lambda _: None,
                inspect=lambda _: None, read_state_key=prompt, reenroll=change, firmware_preflight=check)
            prompt.assert_not_called()
            change.assert_not_called()

    def test_fixed_console_requires_confirmation_and_clears_the_key(self):
        value = recovery_console.policy(self.profile)
        for accepted in (False, True):
            key = bytearray(b'synthetic')
            commands = iter(['reenroll-tpm', 'REENROLL' if accepted else 'cancel', 'exit'])
            with patch.object(firmware, 'reenroll') as action:
                recovery_console.fixed_menu(value, read_command=lambda: next(commands), write=lambda _: None,
                    inspect=lambda _: None, read_state_key=lambda: key, reenroll=action, firmware_preflight=lambda _: None)
                self.assertEqual(action.called, accepted)
                if accepted:
                    self.assertFalse(any(key))
