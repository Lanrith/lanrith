"""Authenticated but stale, revoked or unqualified releases remain ineligible."""

import copy
import datetime
from pathlib import Path
import tempfile
import unittest

from lanrith import admission, release
from ids_fixture import report as ids_report


NOW = datetime.datetime(2026, 1, 2, tzinfo=datetime.timezone.utc)


class AdmissionTests(unittest.TestCase):
    def fixture(self, root):
        # Synthetic authenticated-interface data; no actual build, signature or
        # production qualification is established by this fixture.
        selection = {'source_commit': 'a'*40, 'files': {}}
        record = {'schema': 1, 'result': 'pass', 'specification': 'SLSA v1.2', 'build_level': 3,
                  'assessed_at': NOW.isoformat(), 'source_commit': selection['source_commit'],
                  'runner_environment': 'github-hosted', 'workflow': 'Lanrith/lanrith/.github/workflows/build-base.yml'}
        for field, name in (('filesystem_sha256', 'lanrith-base.tar.gz'), ('initrd_sha256', 'lanrith-initrd-base.tar.gz'),
                            ('logs_sha256', 'logs-qualification.json'), ('directory_sha256', 'directory-qualification.json'),
                            ('credentials_sha256', 'credential-qualification.json'), ('storage_sha256', 'storage-qualification.json')):
            (root/name).write_bytes(b'synthetic unit-test evidence: '+name.encode())
            record[field] = selection['files'][name] = release.file_record(root/name)['sha256']
        (root/'native-qualification.json').write_bytes(release.canonical({'result': 'pass',
            'filesystem_sha256': record['filesystem_sha256'], 'initrd_sha256': record['initrd_sha256']}))
        record['native_sha256'] = selection['files']['native-qualification.json'] = release.file_record(root/'native-qualification.json')['sha256']
        (root/'ids-qualification.json').write_bytes(release.canonical(ids_report(record['filesystem_sha256'], NOW)))
        (root/'inventory.json').write_bytes(b'{"synthetic":true}\n')
        digest = selection['files']['inventory.json'] = release.file_record(root/'inventory.json')['sha256']
        security = {'schema': 1, 'inventory_sha256': digest, 'assessed_at': NOW.isoformat(), 'production_qualified': True,
                    'slsa_build_level': 3, 'slsa_spec': '1.2', 'qualification': {'result': 'pass'}}
        self.bind(root, selection, record, security)
        return selection, record, security

    def bind(self, root, selection, record, security):
        record['ids_sha256'] = selection['files']['ids-qualification.json'] = release.file_record(root/'ids-qualification.json')['sha256']
        (root/'qualification.json').write_bytes(release.canonical(record))
        digest = selection['files']['qualification.json'] = release.file_record(root/'qualification.json')['sha256']
        security['qualification']['record_sha256'] = digest
        (root/'security.json').write_bytes(release.canonical(security))

    def test_qualification_freshness_inventory_and_revocation_are_independent_gates(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            selection, record, security = self.fixture(root)
            security['production_qualified'] = False
            (root/'security.json').write_bytes(release.canonical(security))
            with self.assertRaises(release.ReleaseError):
                admission.assess(root, selection, NOW)
            security['production_qualified'] = True
            self.bind(root, selection, record, security)
            admission.assess(root, selection, NOW)
            for name in ('credential-qualification.json', 'ids-qualification.json'):
                path = root/name
                previous = path.read_bytes()
                path.write_bytes(b'substituted evidence')
                with self.subTest(name=name), self.assertRaises(release.ReleaseError):
                    admission.assess(root, selection, NOW)
                path.unlink()
                with self.assertRaises((release.ReleaseError, OSError)):
                    admission.assess(root, selection, NOW)
                path.write_bytes(previous)
            with self.assertRaises(release.ReleaseError):
                admission.assess(root, selection, NOW+datetime.timedelta(hours=25))
            digest = selection['files']['inventory.json']
            assessment = {'schema': 1, 'inventory_sha256': digest, 'assessed_at': NOW.isoformat(),
                          'result': 'pass', 'revoked_sha256': [digest]}
            (root/'security-assessment.json').write_bytes(release.canonical(assessment))
            with self.assertRaises(release.ReleaseError):
                admission.assess(root, selection, NOW)
            assessment['revoked_sha256'] = []
            assessment['inventory_sha256'] = 'f'*64
            (root/'security-assessment.json').write_bytes(release.canonical(assessment))
            with self.assertRaises(release.ReleaseError):
                admission.assess(root, selection, NOW)

    def test_fresh_security_reassessment_retains_historical_native_evidence_for_the_same_base(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            selection, _, _ = self.fixture(root)
            later = NOW+datetime.timedelta(days=30)
            (root/'security-assessment.json').write_bytes(release.canonical({'schema': 1,
                'inventory_sha256': selection['files']['inventory.json'], 'assessed_at': later.isoformat(),
                'result': 'pass', 'revoked_sha256': []}))
            admission.assess(root, selection, later)

    def test_self_consistent_hashes_cannot_admit_invalid_native_ids_claims(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            selection, record, security = self.fixture(root)
            original = ids_report(record['filesystem_sha256'], NOW)
            for changed in ({'schema': True}, {'checks': []}, {'base_binary_match': False},
                            {'filesystem_sha256': 'd'*64}, {'binary_sha256': 'd'*64},
                            {'implementation_sha256': {}}, {'container_cleanup': 'unverified'},
                            {'assessed_at': (NOW-datetime.timedelta(hours=7)).isoformat()}):
                (root/'ids-qualification.json').write_bytes(release.canonical({**copy.deepcopy(original), **changed}))
                self.bind(root, selection, record, security)
                with self.subTest(fields=sorted(changed)), self.assertRaises(release.ReleaseError):
                    admission.assess(root, selection, NOW)

    def test_invalid_or_future_original_qualification_time_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            selection, record, security = self.fixture(root)
            for changed in ('invalid', NOW.replace(tzinfo=None).isoformat(), (NOW+datetime.timedelta(seconds=1)).isoformat()):
                record['assessed_at'] = changed
                self.bind(root, selection, record, security)
                with self.subTest(timestamp=changed), self.assertRaises(release.ReleaseError):
                    admission.assess(root, selection, NOW)
