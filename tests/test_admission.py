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
            selection = {'files': {'inventory.json': digest}}
            value = {'schema': 1, 'inventory_sha256': digest, 'assessed_at': now.isoformat(),
                     'production_qualified': False}
            (root/'security.json').write_bytes(release.canonical(value))
            with self.assertRaises(release.ReleaseError):
                admission.assess(root, selection, now)
            # A synthetic qualification record exercises the admission interface only.
            value.update(production_qualified=True, slsa_build_level=3, slsa_spec='1.2',
                         qualification={'result': 'pass'})
            (root/'security.json').write_bytes(release.canonical(value))
            admission.assess(root, selection, now)
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
