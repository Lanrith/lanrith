"""Security campaign evidence is complete, candidate-bound and signed."""

import json
from pathlib import Path
import subprocess
import tempfile
import unittest

from lanrith import evidence_bundle
from lanrith.release import canonical, ReleaseError


class EvidenceBundleTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.authority = tempfile.TemporaryDirectory(prefix='lanrith-evidence-authority.')
        cls.addClassCleanup(cls.authority.cleanup)
        cls.key = Path(cls.authority.name)/'evidence.key'
        cls.certificate = Path(cls.authority.name)/'evidence.crt'
        subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
                        '-subj', '/CN=synthetic-evaluation-authority', '-keyout', str(cls.key),
                        '-out', str(cls.certificate)], check=True, capture_output=True)
        cls.key.chmod(0o600)
        cls.wrong_key = Path(cls.authority.name)/'wrong.key'
        cls.wrong_certificate = Path(cls.authority.name)/'wrong.crt'
        subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
                        '-subj', '/CN=wrong-evaluation-authority', '-keyout', str(cls.wrong_key),
                        '-out', str(cls.wrong_certificate)], check=True, capture_output=True)

    def fixture(self):
        temporary = tempfile.TemporaryDirectory(prefix='lanrith-evidence-bundle.')
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name).resolve()
        (root/'harness').mkdir()
        (root/'evidence/network').mkdir(parents=True)
        (root/'report.md').write_text('# Synthetic independent report\n')
        (root/'harness/probe.py').write_text('print("synthetic probe")\n')
        (root/'evidence/network/oracle.json').write_text('{"result":"pass"}\n')
        binding = {'schema': 1, 'campaign_id': 'synthetic-campaign-1', 'candidate': {
            'source_commit': 'a'*40, 'image_id': 'lanrith', 'platform_version': '0.2.0',
            'deployment_sequence': 9, 'configuration_sha256': 'b'*64,
            'factory_release_sha256': 'c'*64, 'owner_configuration_sha256': 'd'*64,
            'local_patch_sha256': 'e'*64, 'lab_certificate_sha256': 'f'*64},
            'environment': {'hardware_profile': 'qemu-ovmf', 'firmware_sha256': '1'*64,
                'secure_boot_variables_sha256': '2'*64, 'disk_baseline_sha256': '3'*64,
                'tpm_baseline_sha256': '4'*64},
            'updates': [{'deployment_sequence': 10, 'release_sha256': '5'*64}],
            'clones': [{'id': 'baseline-1', 'disk_sha256': '6'*64,
                'efi_variables_sha256': '7'*64, 'tpm_state_sha256': '8'*64}],
            'deviations': [], 'required_paths': ['campaign.json', 'report.md', 'harness/probe.py',
                                                'evidence/network/oracle.json']}
        (root/'campaign.json').write_bytes(canonical(binding))
        return root

    def test_real_signature_binds_every_file_and_candidate_identity(self):
        root = self.fixture()
        sealed = evidence_bundle.seal(root, self.key)
        self.assertEqual(evidence_bundle.verify(root, self.certificate), sealed)
        self.assertEqual({item['name'] for item in sealed['files']}, {
            'campaign.json', 'report.md', 'harness/probe.py', 'evidence/network/oracle.json'})

    def test_altered_missing_extra_wrong_authority_and_links_fail(self):
        for change in ('altered', 'missing', 'extra', 'wrong-authority', 'link'):
            root = self.fixture()
            evidence_bundle.seal(root, self.key)
            if change == 'altered':
                (root/'report.md').write_text('changed\n')
            elif change == 'missing':
                (root/'report.md').unlink()
            elif change == 'extra':
                (root/'unlisted').write_text('extra\n')
            elif change == 'link':
                (root/'report.md').unlink()
                (root/'report.md').symlink_to(root/'campaign.json')
            certificate = self.certificate
            if change == 'wrong-authority':
                certificate = self.wrong_certificate
            with self.subTest(change=change), self.assertRaises((ReleaseError, OSError, ValueError)):
                evidence_bundle.verify(root, certificate)

    def test_incomplete_or_ambiguous_campaign_binding_fails_before_signing(self):
        for change in ('missing-report', 'duplicate-json', 'old-update', 'bad-clone'):
            root = self.fixture()
            value = json.loads((root/'campaign.json').read_text())
            if change == 'missing-report':
                value['required_paths'].remove('report.md')
            elif change == 'duplicate-json':
                (root/'campaign.json').write_text('{"schema":1,"schema":1}\n')
            elif change == 'old-update':
                value['updates'][0]['deployment_sequence'] = 9
            else:
                value['clones'][0]['disk_sha256'] = 'wrong'
            if change != 'duplicate-json':
                (root/'campaign.json').write_bytes(canonical(value))
            with self.subTest(change=change), self.assertRaises((ReleaseError, ValueError)):
                evidence_bundle.seal(root, self.key)
