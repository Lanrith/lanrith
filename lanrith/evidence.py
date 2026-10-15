"""Owner-signed private SLSA evidence without public transparency publication."""

import base64
import datetime
import hashlib
import json
from pathlib import Path
import re
import subprocess
import tempfile

from .release import canonical, file_record, public_key, read, require, unique


def pae(payload_type, payload):
    encoded = payload_type.encode('ascii')
    return b'DSSEv1 '+str(len(encoded)).encode()+b' '+encoded+b' '+str(len(payload)).encode()+b' '+payload


def predicate(root, *, repository, source_commit, workflow_commit, invocation, inputs):
    require(re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+', repository) and
            all(re.fullmatch(r'[0-9a-f]{40}', item) for item in (source_commit, workflow_commit)) and
            re.fullmatch(r'[1-9][0-9]*', invocation), 'Invalid provenance context.')
    # Identity is supplied by the isolated workflow, never copied from an uploaded predicate.
    subjects = [{'name': path.name, 'digest': {'sha256': file_record(path)['sha256']}}
                for path in sorted(root.iterdir()) if path.is_file()]
    return {'_type': 'https://in-toto.io/Statement/v1', 'subject': subjects,
            'predicateType': 'https://slsa.dev/provenance/v1', 'predicate': {
                'buildDefinition': {'buildType': 'https://github.com/Lanrith/lanrith/consumer/v1',
                                    'externalParameters': {'repository': repository, 'inputs': inputs},
                                    'internalParameters': {}, 'resolvedDependencies': [{
                                        'uri': 'git+https://github.com/'+repository,
                                        'digest': {'gitCommit': source_commit}}]},
                'runDetails': {'builder': {'id': 'https://github.com/Lanrith/lanrith/.github/workflows/consumer.yml@'+workflow_commit},
                               'metadata': {'invocationId': 'https://github.com/'+repository+'/actions/runs/'+invocation,
                                            'finishedOn': datetime.datetime.now(datetime.timezone.utc).isoformat()}}}}


def sign(statement, key, certificate, destination):
    require(not destination.exists(), 'Private evidence already exists.')
    require(key.is_file() and not key.is_symlink() and not key.stat().st_mode & 0o077,
            'Evidence key must be private.')
    payload = canonical(statement)
    kind = 'application/vnd.in-toto+json'
    result = subprocess.run(['openssl', 'dgst', '-sha256', '-sign', str(key)],
                            input=pae(kind, payload), capture_output=True, timeout=15)
    require(result.returncode == 0, 'Private evidence signing failed.')
    identity = hashlib.sha256(public_key(certificate)).hexdigest()
    value = {'payloadType': kind, 'payload': base64.b64encode(payload).decode(),
             'signatures': [{'keyid': identity, 'sig': base64.b64encode(result.stdout).decode()}]}
    destination.write_bytes(canonical(value))


def verify(path, root, certificate, *, repository, source_commit, workflow_commit):
    value = json.loads(read(path, 4*1024*1024), object_pairs_hook=unique)
    require(set(value) == {'payloadType', 'payload', 'signatures'} and
            value['payloadType'] == 'application/vnd.in-toto+json' and
            isinstance(value['signatures'], list) and len(value['signatures']) == 1,
            'Invalid private evidence envelope.')
    payload = base64.b64decode(value['payload'], validate=True)
    signature = value['signatures'][0]
    require(set(signature) == {'keyid', 'sig'}, 'Invalid evidence signature fields.')
    key = public_key(certificate)
    require(signature['keyid'] == hashlib.sha256(key).hexdigest(), 'Evidence signed by a different authority.')
    with tempfile.TemporaryDirectory(prefix='lanrith-evidence.') as temporary:
        directory = Path(temporary)
        (directory/'public.pem').write_bytes(key)
        (directory/'payload').write_bytes(pae(value['payloadType'], payload))
        (directory/'signature').write_bytes(base64.b64decode(signature['sig'], validate=True))
        result = subprocess.run(['openssl', 'pkeyutl', '-verify', '-pubin', '-inkey', str(directory/'public.pem'),
                                 '-rawin', '-digest', 'sha256', '-in', str(directory/'payload'),
                                 '-sigfile', str(directory/'signature')], capture_output=True, timeout=15)
        require(result.returncode == 0, 'Private evidence signature verification failed.')
    statement = json.loads(payload, object_pairs_hook=unique)
    require(statement.get('_type') == 'https://in-toto.io/Statement/v1' and
            statement.get('predicateType') == 'https://slsa.dev/provenance/v1', 'Unexpected evidence predicate.')
    predicate_value = statement['predicate']
    require(predicate_value['buildDefinition']['externalParameters']['repository'] == repository and
            predicate_value['buildDefinition']['resolvedDependencies'] == [{
                'uri': 'git+https://github.com/'+repository, 'digest': {'gitCommit': source_commit}}] and
            predicate_value['runDetails']['builder']['id'] ==
            'https://github.com/Lanrith/lanrith/.github/workflows/consumer.yml@'+workflow_commit,
            'Private evidence origin differs from the reviewed request.')
    # Every declared subject must match; the evidence envelope itself is not a subject.
    seen = set()
    for subject in statement['subject']:
        name = subject['name']
        require(isinstance(name, str) and re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._+-]{0,191}', name) and name not in seen,
                'Invalid or duplicate private evidence subject.')
        require(subject['digest'] == {'sha256': file_record(root/name)['sha256']}, 'Evidence subject differs.')
        seen.add(name)
    require(seen == {item.name for item in root.iterdir() if item.is_file() and item != path},
            'Private evidence subject set is incomplete.')
    return statement
