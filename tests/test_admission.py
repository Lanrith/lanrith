"""Authenticated but stale, revoked or unqualified releases remain ineligible."""

import datetime
from pathlib import Path
import tempfile
import unittest

from lanrith import admission, release


class AdmissionTests(unittest.TestCase):
    def test_qualification_freshness_inventory_and_revocation_are_independent_gates(self):
        now = datetime.datetime(2026, 1, 2, tzinfo=datetime.timezone.utc)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root/'inventory.json').write_bytes(b'{"synthetic":true}\n')
            digest = release.file_record(root/'inventory.json')['sha256']
            selection = {'source_commit': 'a'*40, 'files': {'inventory.json': digest}}
            value = {'schema': 1, 'inventory_sha256': digest, 'assessed_at': now.isoformat(),
                     'production_qualified': False}
            (root/'security.json').write_bytes(release.canonical(value))
            with self.assertRaises(release.ReleaseError):
                admission.assess(root, selection, now)
            # A synthetic qualification record exercises the admission interface only.
            record = {'schema': 1, 'result': 'pass', 'specification': 'SLSA v1.2', 'build_level': 3,
                      'source_commit': selection['source_commit'], 'runner_environment': 'github-hosted',
                      'workflow': 'Lanrith/lanrith/.github/workflows/build-base.yml'}
            for field, name in (('filesystem_sha256', 'lanrith-base.tar.gz'),
                                ('initrd_sha256', 'lanrith-initrd-base.tar.gz'),
                                ('logs_sha256', 'logs-qualification.json'),
                                ('directory_sha256', 'directory-qualification.json'),
                                ('credentials_sha256', 'credential-qualification.json'),
                                ('storage_sha256', 'storage-qualification.json')):
                (root/name).write_bytes(b'synthetic unit-test evidence')
                record[field] = selection['files'][name] = release.file_record(root/name)['sha256']
            (root/'native-qualification.json').write_bytes(release.canonical({'result': 'pass',
                'filesystem_sha256': record['filesystem_sha256'], 'initrd_sha256': record['initrd_sha256']}))
            record['native_sha256'] = selection['files']['native-qualification.json'] = \
                release.file_record(root/'native-qualification.json')['sha256']
            (root/'qualification.json').write_bytes(release.canonical(record))
            selection['files']['qualification.json'] = release.file_record(root/'qualification.json')['sha256']
            value.update(production_qualified=True, slsa_build_level=3, slsa_spec='1.2',
                         qualification={'result': 'pass', 'record_sha256': selection['files']['qualification.json']})
            (root/'security.json').write_bytes(release.canonical(value))
            admission.assess(root, selection, now)
            credential_report = root/'credential-qualification.json'
            previous = credential_report.read_bytes()
            credential_report.write_bytes(b'substituted credential evidence')
            with self.assertRaises(release.ReleaseError):
                admission.assess(root, selection, now)
            credential_report.unlink()
            with self.assertRaises((release.ReleaseError, OSError)):
                admission.assess(root, selection, now)
            credential_report.write_bytes(previous)
            with self.assertRaises(release.ReleaseError):
                admission.assess(root, selection, now+datetime.timedelta(hours=25))
            assessment = {'schema': 1, 'inventory_sha256': digest, 'assessed_at': now.isoformat(),
                          'result': 'pass', 'revoked_sha256': [digest]}
            (root/'security-assessment.json').write_bytes(release.canonical(assessment))
            with self.assertRaises(release.ReleaseError):
                admission.assess(root, selection, now)
            assessment['revoked_sha256'] = []
            assessment['inventory_sha256'] = 'f'*64
            (root/'security-assessment.json').write_bytes(release.canonical(assessment))
            with self.assertRaises(release.ReleaseError):
                admission.assess(root, selection, now)
