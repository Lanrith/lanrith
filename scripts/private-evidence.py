#!/usr/bin/env python3
"""Sign private provenance on a fresh runner without executing build outputs."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import sys
import tarfile
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from lanrith import config, evidence, release, trust

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--owner', type=Path, required=True)
parser.add_argument('--artifacts', type=Path, required=True)
args = parser.parse_args()
owner, artifacts = args.owner.resolve(), args.artifacts.resolve()
release.require({p.name for p in artifacts.iterdir()} == {'update.tar.gz', 'deployment.json'},
                'Unexpected signing-job output set.')
value = config.load(owner/'config.yaml')
selection = trust.lock(owner/'platform.lock')
deployment = json.loads(release.read(artifacts/'deployment.json', 65536), object_pairs_hook=release.unique)
expected = {'configuration_sha256': hashlib.sha256(release.canonical(value)).hexdigest(),
            'integration_digests': json.loads(release.read(owner/'extensions.lock',65536)) if value['extensions'] else {},
            'platform_lock_sha256': release.file_record(owner/'platform.lock')['sha256'],
            'boot_certificate_sha256': release.file_record(owner/'trust/boot.crt')['sha256'],
            'evidence_certificate_sha256': release.file_record(owner/'trust/evidence.crt')['sha256'],
            'repository': os.environ['GITHUB_REPOSITORY'], 'source_commit': os.environ['GITHUB_SHA'],
            'workflow_commit': os.environ['LANRITH_WORKFLOW_COMMIT']}
release.require(all(deployment.get(key) == value for key, value in expected.items()),
                'Build output differs from the immutable workflow inputs.')
# Authenticity is checked against owner-reviewed certificates, never one from the artifact.
with tempfile.TemporaryDirectory(prefix='lanrith-subject-check.') as temporary:
    root = Path(temporary)
    with tarfile.open(artifacts/'update.tar.gz') as archive:
        members = archive.getmembers()
        release.require(len(members) == 6 and all(m.isfile() and '/' not in m.name and
                        re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._+-]{0,191}', m.name) and
                        m.size <= 3*1024*1024*1024 for m in members) and
                        sum(m.size for m in members) <= 4*1024*1024*1024,
                        'Unsafe update evidence archive.')
        archive.extractall(root, filter='data')
    manifest = release.verify(root, owner/'trust/boot.crt', purpose='update',
        image_id=value.get('release', {}).get('image_id', 'lanrith'),
        expected_version=selection['version'][1:])
    release.require(manifest == deployment['release'] and
                    manifest['deployment_sequence'] == value.get('release', {}).get('sequence_floor', 0)+int(os.environ['GITHUB_RUN_NUMBER']),
                    'Signed deployment identity differs from the qualified workflow.')
statement = evidence.predicate(artifacts, repository=expected['repository'], source_commit=expected['source_commit'],
    workflow_commit=expected['workflow_commit'], invocation=os.environ['GITHUB_RUN_ID'],
    inputs={'platform': selection, 'configuration_sha256': expected['configuration_sha256']})
with tempfile.TemporaryDirectory(prefix='lanrith-evidence.', dir='/dev/shm') as temporary:
    private = Path(temporary)
    private.chmod(0o700)
    for name, variable in (('key', 'LANRITH_EVIDENCE_KEY'), ('certificate', 'LANRITH_EVIDENCE_CERTIFICATE')):
        data = os.environ.pop(variable, '')
        release.require(data, 'Protected evidence material is missing.')
        (private/name).write_text(data)
        (private/name).chmod(0o600)
    release.require(release.public_key(private/'certificate') == release.public_key(owner/'trust/evidence.crt'),
                    'Evidence authority differs from owner trust.')
    evidence.sign(statement, private/'key', private/'certificate', artifacts/'provenance.dsse.json')
    evidence.verify(artifacts/'provenance.dsse.json', artifacts, owner/'trust/evidence.crt',
                    repository=expected['repository'], source_commit=expected['source_commit'],
                    workflow_commit=expected['workflow_commit'])
print('Private artifact provenance signed and verified.')
