"""Validate signed Lanrith payloads without executing or extracting their contents."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess


SCHEMA = 'lanrith-release-v1'
FIELDS = {'schema', 'purpose', 'image_id', 'platform_version', 'deployment_sequence',
          'configuration_sha256', 'architecture', 'artifacts'}
ARTIFACT_FIELDS = {'role', 'name', 'size', 'sha256'}
ROLES = {'update': {'uki', 'root', 'verity', 'verity-sig'},
         'factory': {'uki', 'root', 'verity', 'verity-sig', 'disk', 'initrd'},
         'base': {'filesystem', 'initrd-filesystem', 'inventory', 'sbom', 'security', 'inputs', 'tools'}}
HEX = re.compile(r'[0-9a-f]{64}\Z')
VERSION = re.compile(r'(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)'
                     r'(?:-[0-9A-Za-z]+(?:[.-][0-9A-Za-z]+)*)?\Z')
NAME = re.compile(r'[A-Za-z0-9][A-Za-z0-9._+-]{0,191}\Z')


class ReleaseError(ValueError):
    """An artifact failed the release contract or signature policy."""


def require(condition, message):
    if not condition:
        raise ReleaseError(message)


def unique(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, 'Duplicate JSON field.')
        result[key] = value
    return result


def document(data):
    require(len(data) <= 65536, 'Release manifest exceeds its size limit.')
    try:
        value = json.loads(data, object_pairs_hook=unique,
                           parse_constant=lambda _: (_ for _ in ()).throw(ReleaseError('Invalid JSON number.')))
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as error:
        raise ReleaseError('Invalid release manifest.') from error
    require(isinstance(value, dict) and set(value) == FIELDS, 'Release manifest fields differ.')
    require(value['schema'] == SCHEMA, 'Unsupported release schema.')
    purpose = value['purpose']
    require(isinstance(purpose, str) and purpose in ROLES, 'Unsupported release purpose.')
    require(isinstance(value['image_id'], str) and
            re.fullmatch(r'[a-z][a-z0-9-]{0,47}', value['image_id']), 'Invalid image identity.')
    require(isinstance(value['platform_version'], str) and len(value['platform_version']) <= 64 and
            VERSION.fullmatch(value['platform_version']), 'Invalid semantic platform version.')
    sequence = value['deployment_sequence']
    require(type(sequence) is int and 0 <= sequence <= 999999999 and
            (sequence > 0 or purpose == 'base'), 'Invalid deployment sequence.')
    require(isinstance(value['configuration_sha256'], str) and HEX.fullmatch(value['configuration_sha256']),
            'Invalid configuration digest.')
    require(value['architecture'] in ('x86-64', 'arm64'), 'Unsupported architecture identity.')
    artifacts = value['artifacts']
    require(isinstance(artifacts, list) and len(artifacts) == len(ROLES[purpose]), 'Incomplete artifact set.')
    roles, names = set(), set()
    for artifact in artifacts:
        require(isinstance(artifact, dict) and set(artifact) == ARTIFACT_FIELDS, 'Artifact fields differ.')
        role, name = artifact['role'], artifact['name']
        require(isinstance(role, str) and role in ROLES[purpose] and role not in roles,
                'Unknown or duplicate artifact role.')
        require(isinstance(name, str) and NAME.fullmatch(name) and name not in names and
                name not in {'release.json', 'release.json.sig'}, 'Unsafe or duplicate artifact name.')
        require(type(artifact['size']) is int and 0 < artifact['size'] <= 2**40, 'Invalid artifact size.')
        require(isinstance(artifact['sha256'], str) and HEX.fullmatch(artifact['sha256']), 'Invalid artifact digest.')
        roles.add(role)
        names.add(name)
    require(roles == ROLES[purpose], 'Incomplete artifact set.')
    return value


def read(path, maximum):
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, 'rb') as stream:
        before = os.fstat(stream.fileno())
        require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and
                0 < before.st_size <= maximum, 'Unsafe release file metadata.')
        data = stream.read(maximum + 1)
        after = os.fstat(stream.fileno())
        require((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) ==
                (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns) and
                len(data) == before.st_size, 'Release file changed during inspection.')
        return data


def file_record(path):
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, 'rb') as stream:
        before = os.fstat(stream.fileno())
        require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and before.st_size > 0,
                'Artifact is not an exclusive regular file.')
        digest, size = hashlib.sha256(), 0
        while block := stream.read(1024 * 1024):
            digest.update(block)
            size += len(block)
        after = os.fstat(stream.fileno())
        require((before.st_size, before.st_mtime_ns, before.st_ctime_ns) ==
                (after.st_size, after.st_mtime_ns, after.st_ctime_ns) and size == before.st_size,
                'Artifact changed during inspection.')
        return {'name': path.name, 'size': size, 'sha256': digest.hexdigest()}


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode() + b'\n'


def unsigned_manifest(root, *, purpose, version, sequence, configuration_sha256,
                      files, image_id='lanrith', architecture='x86-64'):
    require(set(files) == ROLES.get(purpose), 'Incomplete artifact role selection.')
    artifacts = []
    for role, name in sorted(files.items()):
        require(isinstance(name, str) and NAME.fullmatch(name), 'Unsafe artifact name.')
        artifacts.append({'role': role, **file_record(root / name)})
    value = {'schema': SCHEMA, 'purpose': purpose, 'image_id': image_id,
             'platform_version': version, 'deployment_sequence': sequence,
             'configuration_sha256': configuration_sha256, 'architecture': architecture,
             'artifacts': artifacts}
    return document(canonical(value))


def public_key(certificate):
    encoded = read(certificate, 65536)
    encoding = 'PEM' if encoded.startswith(b'-----BEGIN CERTIFICATE-----') else 'DER'
    result = subprocess.run(['openssl', 'x509', '-inform', encoding, '-pubkey', '-noout'],
                            input=encoded, capture_output=True, timeout=15)
    require(result.returncode == 0 and result.stdout.startswith(b'-----BEGIN PUBLIC KEY-----'),
            'Trusted certificate is invalid.')
    return result.stdout


def verify(root, certificate, *, purpose, image_id, minimum_sequence=0,
           expected_configuration=None, expected_version=None):
    """Verify with a caller-owned certificate; payload metadata never chooses trust."""
    import tempfile

    require(root.is_dir() and not root.is_symlink() and root.resolve() == root.absolute(),
            'Release directory must be canonical.')
    data = read(root / 'release.json', 65536)
    signature = read(root / 'release.json.sig', 16384)
    with tempfile.TemporaryDirectory(prefix='lanrith-release-verify.') as temporary:
        directory = Path(temporary)
        (directory / 'public.pem').write_bytes(public_key(certificate))
        (directory / 'manifest').write_bytes(data)
        (directory / 'signature').write_bytes(signature)
        result = subprocess.run(['openssl', 'pkeyutl', '-verify', '-pubin',
                                 '-inkey', str(directory / 'public.pem'),
                                 '-sigfile', str(directory / 'signature'), '-rawin', '-digest', 'sha256',
                                 '-in', str(directory / 'manifest')],
                                capture_output=True, timeout=15)
        require(result.returncode == 0, 'Release signature does not match trusted certificate.')
    value = document(data)
    require(value['purpose'] == purpose and value['image_id'] == image_id,
            'Release purpose or image identity differs.')
    require(type(minimum_sequence) is int and value['deployment_sequence'] > minimum_sequence,
            'Release is not newer than the admitted deployment sequence.')
    if expected_configuration is not None:
        require(value['configuration_sha256'] == expected_configuration, 'Configuration digest differs.')
    if expected_version is not None:
        require(value['platform_version'] == expected_version, 'Platform version differs.')
    names = {item['name'] for item in value['artifacts']}
    require({entry.name for entry in root.iterdir()} == names | {'release.json', 'release.json.sig'},
            'Release contains unmanifested files.')
    for artifact in value['artifacts']:
        actual = file_record(root / artifact['name'])
        require(all(actual[key] == artifact[key] for key in actual), 'Artifact size or digest differs.')
    require(read(root / 'release.json', 65536) == data and
            read(root / 'release.json.sig', 16384) == signature,
            'Release metadata changed during inspection.')
    return value


def sign(root, private_key):
    """Sign a validated manifest with the owner-provided boot release authority."""
    data = read(root / 'release.json', 65536)
    document(data)
    require(private_key.is_file() and not private_key.is_symlink() and
            stat.S_IMODE(private_key.stat().st_mode) == 0o600, 'Signing key must be a private regular file.')
    result = subprocess.run(['openssl', 'dgst', '-sha256', '-sign', str(private_key)],
                            input=data, capture_output=True, timeout=15)
    require(result.returncode == 0 and result.stdout, 'Release signing failed.')
    descriptor = os.open(root / 'release.json.sig', os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o644)
    with os.fdopen(descriptor, 'wb') as stream:
        stream.write(result.stdout)
