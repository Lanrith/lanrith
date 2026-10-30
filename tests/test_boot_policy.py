import copy
import json
import io
from pathlib import Path
import subprocess
import tempfile
import tarfile
import unittest
from unittest.mock import patch

from lanrith import boot_policy, build, config, image_contract, release, steady_recovery


class BootPolicyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory()
        cls.root = Path(cls.temporary.name)
        cls.key, cls.cert = cls.root/'key.pem', cls.root/'cert.pem'
        subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
            '-subj', '/CN=Disposable test authority', '-keyout', str(cls.key), '-out', str(cls.cert)],
            check=True, capture_output=True)
        cls.key.chmod(0o600)

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def test_signed_tpm_build_uses_pcr_7_11_15_without_shipping_signing_material(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            base = root/'base.tar'
            base.write_bytes(b'synthetic-base')
            value = config.load(Path(__file__).resolve().parents[1]/'examples/minimal.yaml')
            value['hardware']['boot'] = {'secure_boot': True, 'console': 'ttyS0,115200n8', 'recovery_console': 'ttyS0'}
            output = root/'assembly'
            build.assembly(value, base, output, version='0.1.0', sequence=10,
                           certificate=self.cert, private_key=self.key)
            installed = json.loads((output/'mkosi.extra/usr/share/lanrith/installed.json').read_bytes())
            self.assertEqual(installed['tpm_policy']['direct_pcrs'], [7, 15])
            self.assertEqual(installed['tpm_policy']['signed_pcrs'], [11])
            self.assertEqual(installed['image_contract']['recovery'], None)
            self.assertIn('SignExpectedPcr=yes\n', (output/'mkosi.conf').read_text())
            self.assertIn('TimeoutStartSec=300s\n',
                (output/'mkosi.images/initrd/mkosi.extra/usr/lib/systemd/system/lanrith-factory.service').read_text())
            secret = self.key.read_bytes()
            for tree in (output/'mkosi.extra', output/'mkosi.images/initrd/mkosi.extra'):
                for path in tree.rglob('*'):
                    if path.is_file() and not path.is_symlink():
                        self.assertNotIn(path.suffix, ('.yaml', '.yml'))
                        self.assertNotIn(secret, path.read_bytes())

    def test_private_pcr_key_permissions_are_enforced(self):
        key = self.root/'unsafe.pem'
        key.write_bytes(self.key.read_bytes())
        key.chmod(0o644)
        with self.assertRaisesRegex(release.ReleaseError, 'protected'):
            boot_policy.public_key(key, self.cert)

    def test_build_paths_cannot_inject_mkosi_configuration(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            base = root/'base'
            base.write_bytes(b'synthetic')
            value = config.load(Path(__file__).resolve().parents[1]/'examples/minimal.yaml')
            with self.assertRaisesRegex(release.ReleaseError, 'Build paths'):
                build.assembly(value, base, root/'unsafe\n[Content]', version='0.1.0', sequence=9)

    def test_opaque_state_rejects_base_or_authority_change(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            base = root/'base'
            base.write_bytes(b'one')
            value = {'hardware': {'machine_id': 'a'*32}}
            before = boot_policy.contract(value, base, self.cert, b'public', {})
            image_contract.compatible(before, copy.deepcopy(before))
            base.write_bytes(b'two')
            after = boot_policy.contract(value, base, self.cert, b'public', {})
            with self.assertRaisesRegex(release.ReleaseError, 'state'):
                image_contract.compatible(before, after)
            changed = copy.deepcopy(before)
            changed['trust']['authorities']['pcr_policy'] = 'b'*64
            with self.assertRaisesRegex(release.ReleaseError, 'Trust'):
                image_contract.compatible(before, changed)

    def test_declared_formats_allow_compatible_base_updates_and_reject_format_changes(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            def archive(name, version, extra):
                path = root/name
                with tarfile.open(path, 'w') as output:
                    payload = json.dumps({'schema': 1, 'consumers': {
                        'platform': {'writes': version, 'reads': [version]}}}).encode()
                    info = tarfile.TarInfo('usr/share/lanrith/state-formats.json')
                    info.size = len(payload); info.mode = 0o644
                    output.addfile(info, io.BytesIO(payload))
                    info = tarfile.TarInfo('usr/share/changed-package')
                    info.size = len(extra)
                    output.addfile(info, io.BytesIO(extra))
                return path
            first = archive('base-1.tar', 'platform-v1', b'package revision one')
            second = archive('base-2.tar', 'platform-v1', b'package revision two')
            third = archive('base-3.tar', 'platform-v2', b'changed persistent format')
            value = {'hardware': {'machine_id': 'a'*32}}
            before = boot_policy.contract(value, first, self.cert, b'public', {})
            image_contract.compatible(before, boot_policy.contract(value, second, self.cert, b'public', {}))
            with self.assertRaises(release.ReleaseError):
                image_contract.compatible(before, boot_policy.contract(value, third, self.cert, b'public', {}))

    def test_steady_contract_cannot_disguise_a_weaker_pcr_authority(self):
        base = {'schema': 1, 'machine_id': 'a'*32, 'state': {'platform': {'writes': 'v1', 'reads': ['v1']}},
                'trust': {'generation': 1, 'transition': 'steady', 'authorities': {
                    'manifest': 'a'*64, 'secure_boot': 'a'*64, 'verity': 'a'*64, 'pcr_policy': 'b'*64}}}
        value = {'image_contract': base, 'fallback_contract': copy.deepcopy(base),
                 'state_directory': '/var/lib/lanrith', 'tpm_policy': None}
        with self.assertRaisesRegex(release.ReleaseError, 'PCR authority'):
            steady_recovery.validate(value)

    def test_fallback_runtime_must_match_the_signed_state_and_default_tpm_policy(self):
        from lanrith import early_unlock
        policy = early_unlock.policy(b'synthetic-public-key')
        contract = {'schema': 1, 'machine_id': 'a'*32, 'state': {'platform': {'writes': 'v1', 'reads': ['v1']}},
            'trust': {'generation': 1, 'transition': 'steady', 'authorities': {
                'manifest': 'a'*64, 'secure_boot': 'a'*64, 'verity': 'a'*64,
                'pcr_policy': policy['public_key_sha256']}}}
        steady = {'image_contract': contract, 'fallback_contract': copy.deepcopy(contract),
                  'state_directory': '/var/lib/lanrith', 'tpm_policy': policy}
        installed = {'image_id': 'router', 'steady_state': steady,
                     'fallback_binding': {'release': {'sequence': 9, 'uki_name': 'router_9.efi'}}}
        previous = {'layout': 'ab-verity-v1', 'image_id': 'router', 'deployment_sequence': 9,
                    'uki_name': 'router_9.efi', 'machine_id': 'a'*32, 'image_contract': contract,
                    'state_directory': '/var/lib/lanrith', 'tpm_policy': copy.deepcopy(policy), 'boot': {}}
        with patch.object(steady_recovery.factory, 'enrollment_tokens',
                          return_value=['systemd-tpm2', 'systemd-recovery']) as tokens:
            self.assertFalse(steady_recovery.compare(installed, previous, {})['authorized_to_boot'])
            tokens.assert_called_once_with({}, tpm_required=True, policy=policy)
            previous['tpm_policy']['direct_pcrs'] = [7]
            with self.assertRaises(release.ReleaseError):
                steady_recovery.compare(installed, previous, {})
