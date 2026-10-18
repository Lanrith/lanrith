#!/usr/bin/env python3
"""Sign private provenance on a fresh runner without executing build outputs."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from lanrith import archive as handoff, config, evidence, release, trust
from consumer import signing_profile

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--owner', type=Path, required=True)
parser.add_argument('--artifacts', type=Path, required=True)
args = parser.parse_args()
owner, artifacts = args.owner.resolve(), args.artifacts.resolve()
release.require({p.name for p in artifacts.iterdir()} == {'update.tar.gz', 'factory.tar.gz', 'deployment.json'},
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
            'workflow_commit': os.environ['LANRITH_WORKFLOW_COMMIT'], 'signing_profile': signing_profile()}
release.require(all(deployment.get(key) == value for key, value in expected.items()),
                'Build output differs from the immutable workflow inputs.')
# Authenticity is checked against owner-reviewed certificates, never one from the artifact.
with tempfile.TemporaryDirectory(prefix='lanrith-subject-check.') as temporary:
    root = Path(temporary)
    members = handoff.extract(artifacts/'update.tar.gz', root, entries=6,
        maximum_file=3*1024*1024*1024, maximum_size=4*1024*1024*1024)
    release.require(len(members) == 6, 'Incomplete update evidence archive.')
    manifest = release.verify(root, owner/'trust/boot.crt', purpose='update',
        image_id=value.get('release', {}).get('image_id', 'lanrith'),
        expected_version=selection['version'][1:])
    release.require(manifest == deployment['release'] and
                    manifest['deployment_sequence'] == value.get('release', {}).get('sequence_floor', 0)+int(os.environ['GITHUB_RUN_NUMBER']),
                    'Signed deployment identity differs from the qualified workflow.')
with tempfile.TemporaryDirectory(prefix='lanrith-factory-check.') as temporary:
    root=Path(temporary)
    storage=value['hardware']['storage']
    budget=(storage['esp_mib']+3*storage['root_mib']+1024)*1024*1024
    members=handoff.extract(artifacts/'factory.tar.gz',root,entries=8,maximum_file=budget,maximum_size=budget)
    release.require(len(members)==8, 'Incomplete factory evidence archive.')
    factory=release.verify(root,owner/'trust/boot.crt',purpose='factory',image_id=manifest['image_id'],
                           expected_version=manifest['platform_version'],
                           configuration_sha256=manifest['configuration_sha256'])
    release.require(factory==deployment['factory'] and factory['deployment_sequence']==manifest['deployment_sequence'],
                    'Factory identity differs from the signed update.')
    common={a['role']:a for a in factory['artifacts'] if a['role'] in release.ROLES['update']}
    release.require(common=={a['role']:a for a in manifest['artifacts']},
                    'Factory and update do not contain the same verified-root triplet and UKI.')
statement = evidence.predicate(artifacts, repository=expected['repository'], source_commit=expected['source_commit'],
    workflow_commit=expected['workflow_commit'], invocation=os.environ['GITHUB_RUN_ID'],
    inputs={'platform': selection, 'configuration_sha256': expected['configuration_sha256'],
            'signing_profile': expected['signing_profile'],
            'protected_signing': expected['signing_profile'] == 'protected'})
with tempfile.TemporaryDirectory(prefix='lanrith-evidence.', dir='/dev/shm') as temporary:
    private = Path(temporary)
    private.chmod(0o700)
    for name, variable in (('key', 'LANRITH_EVIDENCE_KEY'), ('certificate', 'LANRITH_EVIDENCE_CERTIFICATE')):
        data = os.environ.pop(variable, '')
        release.require(data, 'Private evidence material is missing.')
        (private/name).write_text(data)
        (private/name).chmod(0o600)
    release.require(release.public_key(private/'certificate') == release.public_key(owner/'trust/evidence.crt'),
                    'Evidence authority differs from owner trust.')
    evidence.sign(statement, private/'key', private/'certificate', artifacts/'provenance.dsse.json')
    evidence.verify(artifacts/'provenance.dsse.json', artifacts, owner/'trust/evidence.crt',
                    repository=expected['repository'], source_commit=expected['source_commit'],
                    workflow_commit=expected['workflow_commit'])
print('Private artifact provenance signed and verified.')
