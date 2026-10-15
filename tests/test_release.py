"""Use real signatures to exercise release identity, tamper and replay rejection."""

import copy
import json
from pathlib import Path
import subprocess
import tempfile
import unittest

from lanrith import release


class ReleaseTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.keys = tempfile.TemporaryDirectory(prefix='lanrith-test-keys.')
        cls.addClassCleanup(cls.keys.cleanup)
        cls.key = Path(cls.keys.name) / 'fixture.key'
        cls.certificate = Path(cls.keys.name) / 'fixture.crt'
        subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
                        '-subj', '/CN=synthetic-lanrith-release-test', '-keyout', str(cls.key),
                        '-out', str(cls.certificate)], check=True, capture_output=True)
        cls.key.chmod(0o600)

    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='lanrith-release-test.')
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        files = {role: f'synthetic.{role}' for role in ('uki', 'root', 'verity', 'verity-sig')}
        for role, name in files.items():
            (self.root / name).write_bytes(('synthetic-' + role).encode())
        self.value = release.unsigned_manifest(self.root, purpose='update', version='0.1.0', sequence=17,
                                               configuration_sha256='a' * 64, files=files)
        self.write_manifest(self.value)

    def write_manifest(self, value):
        (self.root / 'release.json').write_bytes(release.canonical(value))
        (self.root / 'release.json.sig').unlink(missing_ok=True)
        release.sign(self.root, self.key)

    def verify(self, **options):
        return release.verify(self.root, self.certificate, purpose='update', image_id='lanrith', **options)

    def test_real_signature_and_expected_identity(self):
        self.assertEqual(self.verify(minimum_sequence=16, expected_version='0.1.0',
                                     expected_configuration='a' * 64), self.value)

    def test_tampering_manifest_artifact_and_signature_is_rejected(self):
        for name in ('release.json', 'synthetic.root', 'release.json.sig'):
            with self.subTest(name=name):
                path = self.root / name
                original = path.read_bytes()
                path.write_bytes(original + b'x')
                with self.assertRaises(release.ReleaseError):
                    self.verify()
                path.write_bytes(original)

    def test_replay_wrong_config_wrong_version_wrong_authority_and_extra_files_are_rejected(self):
        for options in ({'minimum_sequence': 17}, {'expected_configuration': 'b' * 64},
                        {'expected_version': '9.0.0'}):
            with self.subTest(options=options), self.assertRaises(release.ReleaseError):
                self.verify(**options)
        changed = copy.deepcopy(self.value)
        changed['image_id'] = 'other-image'
        self.write_manifest(changed)
        with self.assertRaises(release.ReleaseError):
            self.verify()
        self.write_manifest(self.value)
        (self.root / 'unmanifested').write_text('extra')
        with self.assertRaises(release.ReleaseError):
            self.verify()

    def test_symlink_and_hardlink_payloads_are_rejected(self):
        path = self.root / 'synthetic.root'
        original = path.read_bytes()
        path.unlink()
        path.symlink_to(self.root / 'synthetic.verity')
        with self.assertRaises((release.ReleaseError, OSError)):
            self.verify()
        path.unlink()
        path.write_bytes(original)
        (self.root / 'linked').hardlink_to(path)
        with self.assertRaises(release.ReleaseError):
            self.verify()

    def test_duplicate_fields_unsafe_names_incomplete_roles_and_boolean_sequence_are_rejected(self):
        with self.assertRaises(release.ReleaseError):
            release.document(b'{"schema":1,"schema":2}')
        mutations = (
            lambda value: value.update(deployment_sequence=True),
            lambda value: value['artifacts'][0].update(name='../outside'),
            lambda value: value['artifacts'][0].update(name='release.json'),
            lambda value: value['artifacts'].pop(),
            lambda value: value['artifacts'][0].update(role=value['artifacts'][1]['role']),
        )
        for mutate in mutations:
            value = copy.deepcopy(self.value)
            mutate(value)
            with self.subTest(value=value), self.assertRaises(release.ReleaseError):
                release.document(json.dumps(value).encode())


if __name__ == '__main__':
    unittest.main()
