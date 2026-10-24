"""Seal and verify candidate-bound security campaign evidence."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import tempfile

from .release import canonical, public_key, read, require, unique


HEX = re.compile(r'[0-9a-f]{64}\Z')
COMMIT = re.compile(r'[0-9a-f]{40}\Z')
IDENTIFIER = re.compile(r'[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}\Z')
OUTPUTS = {'manifest.json', 'manifest.sig'}
MAXIMUM_FILES = 20000
MAXIMUM_FILE = 16 * 1024**3
MAXIMUM_TOTAL = 128 * 1024**3


def digest(value, name):
    require(isinstance(value, str) and HEX.fullmatch(value), 'Invalid '+name+' digest.')
    return value


def campaign(value):
    """Validate the independently prepared candidate/facility binding."""
    require(isinstance(value, dict) and set(value) == {
        'schema', 'campaign_id', 'candidate', 'environment', 'updates', 'clones',
        'deviations', 'required_paths'}, 'Invalid campaign binding.')
    require(value['schema'] == 1 and isinstance(value['campaign_id'], str) and
            IDENTIFIER.fullmatch(value['campaign_id']), 'Invalid campaign identity.')
    candidate = value['candidate']
    require(isinstance(candidate, dict) and set(candidate) == {
        'source_commit', 'image_id', 'platform_version', 'deployment_sequence',
        'configuration_sha256', 'factory_release_sha256', 'owner_configuration_sha256',
        'local_patch_sha256', 'lab_certificate_sha256'}, 'Invalid candidate binding.')
    require(COMMIT.fullmatch(candidate['source_commit']) and
            isinstance(candidate['image_id'], str) and IDENTIFIER.fullmatch(candidate['image_id']) and
            isinstance(candidate['platform_version'], str) and 1 <= len(candidate['platform_version']) <= 64 and
            type(candidate['deployment_sequence']) is int and 1 <= candidate['deployment_sequence'] <= 999999999,
            'Invalid candidate identity.')
    for key in ('configuration_sha256', 'factory_release_sha256', 'owner_configuration_sha256',
                'local_patch_sha256', 'lab_certificate_sha256'):
        digest(candidate[key], key)
    environment = value['environment']
    require(isinstance(environment, dict) and set(environment) == {
        'hardware_profile', 'firmware_sha256', 'secure_boot_variables_sha256',
        'disk_baseline_sha256', 'tpm_baseline_sha256'}, 'Invalid campaign environment.')
    require(isinstance(environment['hardware_profile'], str) and
            IDENTIFIER.fullmatch(environment['hardware_profile']), 'Invalid hardware profile.')
    for key in set(environment)-{'hardware_profile'}:
        digest(environment[key], key)
    updates = value['updates']
    require(isinstance(updates, list) and len(updates) <= 64 and all(isinstance(item, dict) and
            set(item) == {'deployment_sequence', 'release_sha256'} and
            type(item['deployment_sequence']) is int and
            candidate['deployment_sequence'] < item['deployment_sequence'] <= 999999999 and
            isinstance(item['release_sha256'], str) and HEX.fullmatch(item['release_sha256'])
            for item in updates) and len({item['deployment_sequence'] for item in updates}) == len(updates),
            'Invalid update-candidate binding.')
    clones = value['clones']
    require(isinstance(clones, list) and 1 <= len(clones) <= 256 and all(isinstance(item, dict) and
            set(item) == {'id', 'disk_sha256', 'efi_variables_sha256', 'tpm_state_sha256'} and
            isinstance(item['id'], str) and IDENTIFIER.fullmatch(item['id']) and
            all(isinstance(item[key], str) and HEX.fullmatch(item[key]) for key in
                ('disk_sha256', 'efi_variables_sha256', 'tpm_state_sha256')) for item in clones) and
            len({item['id'] for item in clones}) == len(clones), 'Invalid test-clone binding.')
    require(isinstance(value['deviations'], list) and len(value['deviations']) <= 256 and
            all(isinstance(item, str) and 1 <= len(item) <= 1024 and '\n' not in item
                for item in value['deviations']), 'Invalid campaign deviation.')
    paths = value['required_paths']
    require(isinstance(paths, list) and len(paths) == len(set(paths)) and 3 <= len(paths) <= 1024 and
            'report.md' in paths and 'campaign.json' in paths and
            any(path.startswith('harness/') for path in paths) and
            any(path.startswith('evidence/') for path in paths), 'Campaign required paths are incomplete.')
    for name in paths:
        path = Path(name)
        require(not path.is_absolute() and path.as_posix() == name and '..' not in path.parts and
                all(IDENTIFIER.fullmatch(part) for part in path.parts), 'Unsafe required evidence path.')
    return value


def record(path, name):
    digest_value = hashlib.sha256()
    size = 0
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, 'rb') as stream:
        before = os.fstat(stream.fileno())
        require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and
                before.st_size <= MAXIMUM_FILE, 'Evidence member is not an exclusive bounded regular file.')
        while block := stream.read(1024*1024):
            size += len(block)
            require(size <= MAXIMUM_FILE, 'Evidence member grew beyond its bound.')
            digest_value.update(block)
        after = os.fstat(stream.fileno())
        require((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) ==
                (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns) and
                size == before.st_size, 'Evidence member changed during inspection.')
    return {'name': name, 'size': size, 'sha256': digest_value.hexdigest()}


def inventory(root):
    require(root.is_absolute() and root.is_dir() and not root.is_symlink() and root.resolve() == root,
            'Evidence bundle directory must be canonical.')
    files, total = [], 0
    for path in sorted(root.rglob('*')):
        relative = path.relative_to(root).as_posix()
        require(not path.is_symlink() and (path.is_dir() or path.is_file()),
                'Evidence bundle contains a link or special file.')
        if path.is_file() and relative not in OUTPUTS:
            item = record(path, relative)
            files.append(item)
            total += item['size']
            require(len(files) <= MAXIMUM_FILES and total <= MAXIMUM_TOTAL,
                    'Evidence bundle exceeds its inventory bound.')
    return files


def document(root):
    binding = campaign(json.loads(read(root/'campaign.json', 1024*1024), object_pairs_hook=unique))
    files = inventory(root)
    names = {item['name'] for item in files}
    require(set(binding['required_paths']) <= names, 'Campaign evidence is missing a required path.')
    return {'schema': 1, 'campaign_id': binding['campaign_id'], 'candidate': binding['candidate'],
            'campaign_sha256': next(item['sha256'] for item in files if item['name'] == 'campaign.json'),
            'files': files}


def seal(root, private_key):
    require(not any((root/name).exists() or (root/name).is_symlink() for name in OUTPUTS),
            'Evidence seal already exists.')
    data = canonical(document(root))
    key = private_key.stat(follow_symlinks=False)
    require(stat.S_ISREG(key.st_mode) and stat.S_IMODE(key.st_mode) == 0o600,
            'Evidence signing key must be a private regular file.')
    result = subprocess.run(['openssl', 'dgst', '-sha256', '-sign', str(private_key)],
                            input=data, capture_output=True, timeout=30)
    require(result.returncode == 0 and result.stdout, 'Evidence signing failed.')
    for name, content in (('manifest.json', data), ('manifest.sig', result.stdout)):
        descriptor = os.open(root/name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o644)
        with os.fdopen(descriptor, 'wb') as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
    return json.loads(data)


def verify(root, certificate):
    data = read(root/'manifest.json', 16*1024*1024)
    signature = read(root/'manifest.sig', 1024*1024)
    manifest = json.loads(data, object_pairs_hook=unique)
    require(isinstance(manifest, dict) and set(manifest) == {
        'schema', 'campaign_id', 'candidate', 'campaign_sha256', 'files'} and manifest['schema'] == 1 and
        canonical(manifest) == data, 'Evidence manifest is not canonical.')
    expected = document(root)
    require(manifest == expected, 'Evidence manifest differs from the complete bundle.')
    with tempfile.TemporaryDirectory(prefix='lanrith-evidence-verify.') as temporary:
        directory = Path(temporary)
        (directory/'public.pem').write_bytes(public_key(certificate))
        (directory/'manifest').write_bytes(data)
        (directory/'signature').write_bytes(signature)
        result = subprocess.run(['openssl', 'pkeyutl', '-verify', '-pubin', '-inkey', str(directory/'public.pem'),
                                 '-sigfile', str(directory/'signature'), '-rawin', '-digest', 'sha256',
                                 '-in', str(directory/'manifest')], capture_output=True, timeout=30)
        require(result.returncode == 0, 'Evidence signature does not match the trusted evaluation authority.')
    return manifest
