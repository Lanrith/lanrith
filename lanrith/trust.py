"""Verify public build inputs before a compiler or builder is executed."""

import json
from pathlib import Path
import re
import subprocess

from .release import HEX, file_record, read, require, unique
from . import release


REPOSITORY = 'Lanrith/lanrith'
WORKFLOW = 'Lanrith/lanrith/.github/workflows/build-base.yml'


def lock(path):
    value = json.loads(read(path, 65536), object_pairs_hook=unique)
    require(isinstance(value, dict) and set(value) == {
        'schema', 'repository', 'version', 'source_commit', 'signer_commit', 'manifest_sha256',
        'builder', 'builder_digest', 'files', 'security_workflow_commit'}, 'Platform lock fields differ.')
    require(value['schema'] == 1 and value['repository'] == REPOSITORY,
            'Unapproved platform repository.')
    require(isinstance(value['version'], str) and re.fullmatch(r'v[0-9]+\.[0-9]+\.[0-9]+', value['version']),
            'Invalid platform release selection.')
    for field in ('source_commit', 'signer_commit', 'security_workflow_commit'):
        require(isinstance(value[field], str) and re.fullmatch(r'[0-9a-f]{40}', value[field]),
                'Invalid source or trusted workflow commit.')
    for field in ('manifest_sha256', 'builder_digest'):
        require(isinstance(value[field], str) and HEX.fullmatch(value[field]), 'Invalid locked digest.')
    require(value['builder'] == 'ghcr.io/lanrith/lanrith-builder', 'Unapproved builder image.')
    require(isinstance(value['files'], dict) and value['files'] and len(value['files']) <= 64,
            'Platform lock has no file inventory.')
    for name, digest in value['files'].items():
        require(isinstance(name, str) and re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._+-]{0,191}', name) and
                isinstance(digest, str) and HEX.fullmatch(digest), 'Invalid locked artifact.')
    return value


def verify(directory, selection):
    require(directory.is_dir() and not directory.is_symlink() and directory.resolve() == directory.absolute(),
            'Platform bundle directory must be canonical.')
    require(file_record(directory / 'release.json')['sha256'] == selection['manifest_sha256'],
            'Platform manifest differs from the reviewed lock.')
    manifest = release.document(read(directory/'release.json',65536))
    require(manifest['purpose']=='base' and manifest['image_id']=='lanrith' and
            manifest['architecture']=='x86-64' and manifest['deployment_sequence']==0 and
            manifest['platform_version']==selection['version'][1:], 'Unsupported platform manifest identity.')
    for artifact in manifest['artifacts']:
        require(selection['files'].get(artifact['name'])==artifact['sha256'] and
                file_record(directory/artifact['name'])['size']==artifact['size'],
                'Platform role differs from the reviewed artifact inventory.')
    inputs = next(a for a in manifest['artifacts'] if a['role']=='inputs')
    require(inputs['sha256']==manifest['configuration_sha256'], 'Platform input identity differs from its manifest.')
    for name, expected in selection['files'].items():
        require(file_record(directory / name)['sha256'] == expected, 'Platform input differs from the reviewed lock.')
        bundle = directory / (name + '.intoto.jsonl')
        read(bundle, 4 * 1024 * 1024)
        result = subprocess.run([
            'gh', 'attestation', 'verify', str(directory / name), '--bundle', str(bundle),
            '--repo', REPOSITORY, '--signer-workflow', WORKFLOW,
            '--signer-digest', selection['signer_commit'], '--source-digest', selection['source_commit'],
            '--cert-oidc-issuer', 'https://token.actions.githubusercontent.com',
            '--source-ref', 'refs/heads/main', '--deny-self-hosted-runners', '--predicate-type', 'https://slsa.dev/provenance/v1',
        ], capture_output=True, timeout=60)
        require(result.returncode == 0, 'Platform provenance verification failed.')
    if (directory/'security-assessment.json').exists():
        result = subprocess.run([
            'gh', 'attestation', 'verify', str(directory/'security-assessment.json'),
            '--bundle', str(directory/'security-assessment.json.intoto.jsonl'), '--repo', REPOSITORY,
            '--signer-workflow', REPOSITORY+'/.github/workflows/security-audit.yml',
            '--signer-digest', selection['security_workflow_commit'],
            '--source-digest', selection['security_workflow_commit'],
            '--cert-oidc-issuer', 'https://token.actions.githubusercontent.com', '--source-ref', 'refs/heads/main', '--deny-self-hosted-runners',
            '--predicate-type', 'https://slsa.dev/provenance/v1'], capture_output=True, timeout=60)
        require(result.returncode == 0, 'Fresh security assessment provenance verification failed.')
    return selection['builder'] + '@sha256:' + selection['builder_digest']


def verify_builder(selection, bundle):
    reference = selection['builder'] + '@sha256:' + selection['builder_digest']
    result = subprocess.run([
        'gh', 'attestation', 'verify', 'oci://' + reference, '--bundle', str(bundle),
        '--repo', REPOSITORY, '--signer-workflow', WORKFLOW,
        '--signer-digest', selection['signer_commit'], '--source-digest', selection['source_commit'],
        '--cert-oidc-issuer', 'https://token.actions.githubusercontent.com', '--source-ref', 'refs/heads/main', '--deny-self-hosted-runners',
    ], capture_output=True, timeout=60)
    require(result.returncode == 0, 'Builder provenance verification failed.')
    return reference
