"""Private provenance uses independent trust and binds every subject and origin."""

import json
from pathlib import Path
import subprocess
import tempfile
import unittest

from lanrith import evidence, release


class EvidenceTests(unittest.TestCase):
    def test_real_dsse_signature_origin_subjects_and_tampering(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            key, certificate = root/'authority.key', root/'authority.crt'
            subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
                            '-subj', '/CN=Synthetic Test Authority', '-keyout', str(key), '-out', str(certificate)],
                           check=True, capture_output=True)
            key.chmod(0o600)
            subjects = root/'subjects'
            subjects.mkdir()
            (subjects/'update.tar.gz').write_bytes(b'synthetic payload')
            context = {'repository': 'example/router-config', 'source_commit': 'a'*40,
                       'workflow_commit': 'b'*40}
            statement = evidence.predicate(subjects, **context, invocation='7', inputs={'synthetic': True})
            envelope = subjects/'provenance.dsse.json'
            evidence.sign(statement, key, certificate, envelope)
            evidence.verify(envelope, subjects, certificate, **context)
            with self.assertRaises(release.ReleaseError):
                evidence.verify(envelope, subjects, certificate, **{**context, 'source_commit': 'c'*40})
            (subjects/'extra').write_bytes(b'unattested')
            with self.assertRaises(release.ReleaseError):
                evidence.verify(envelope, subjects, certificate, **context)
            (subjects/'extra').unlink()
            original = envelope.read_bytes()
            value = json.loads(original)
            value['payload'] = value['payload'][:-8]+'AAAAAAAA'
            envelope.write_bytes(release.canonical(value))
            with self.assertRaises((release.ReleaseError, ValueError)):
                evidence.verify(envelope, subjects, certificate, **context)
            envelope.write_bytes(original)
            (subjects/'update.tar.gz').write_bytes(b'changed payload')
            with self.assertRaises(release.ReleaseError):
                evidence.verify(envelope, subjects, certificate, **context)
