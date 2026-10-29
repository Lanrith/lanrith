"""Build-time inputs for the steady-state measured boot and state contract."""

import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import tarfile

from . import early_unlock, image_contract, release


def public_key(key, certificate):
    """Keep signing material outside the image and require a TPM RSA-2048 key."""
    for path in (key, certificate):
        release.require(isinstance(path, Path) and path.is_absolute() and path.resolve() == path and
                        path.is_file() and not path.is_symlink(), 'Invalid PCR signing input.')
    info = key.stat()
    release.require((info.st_uid == os.geteuid() or os.geteuid() == 0) and info.st_nlink == 1 and
                    stat.S_IMODE(info.st_mode) & 0o077 == 0,
                    'PCR private key must be protected by its owner.')
    def openssl(*args):
        result = subprocess.run(['openssl', *args], stdin=subprocess.DEVNULL, capture_output=True, timeout=15)
        release.require(result.returncode == 0 and 0 < len(result.stdout) <= 16384,
                        'Cannot validate PCR signing authority.')
        return result.stdout
    public = openssl('pkey', '-in', str(key), '-pubout')
    expected = openssl('x509', '-in', str(certificate), '-pubkey', '-noout')
    release.require(public == expected, 'PCR key and certificate differ.')
    details = openssl('pkey', '-in', str(key), '-text_pub', '-noout')
    release.require(re.search(rb'Public-Key: \(2048 bit\)', details) and b'Modulus:' in details and
                    b'Exponent: 65537 ' in details, 'PCR signing requires RSA-2048 with exponent 65537.')
    return public


def native_formats(base):
    """Use only an admitted base's unique, bounded root-owned declaration."""
    try:
        archive = tarfile.open(base, 'r|*')
    except tarfile.ReadError:
        return None
    result = None
    with archive:
        for item in archive:
            if item.name.removeprefix('./') != 'usr/share/lanrith/state-formats.json':
                continue
            release.require(result is None and item.isfile() and item.uid == item.gid == 0 and
                            not item.mode & 0o022 and 0 < item.size <= 32768,
                            'Unsafe or duplicate native state declaration.')
            data = archive.extractfile(item).read(item.size+1)
            release.require(len(data) == item.size, 'Native state declaration is truncated.')
            result = json.loads(data, object_pairs_hook=release.unique)
            release.require(isinstance(result, dict) and set(result) == {'schema', 'consumers'} and
                            type(result['schema']) is int and result['schema'] == 1 and
                            isinstance(result['consumers'], dict) and
                            all(not name.startswith('extension_') for name in result['consumers']),
                            'Invalid native state declaration.')
            image_contract.validate({'schema': 1, 'machine_id': '0'*32, 'state': result['consumers'],
                'trust': {'generation': 1, 'transition': 'steady', 'authorities': {
                    name: None for name in image_contract.AUTHORITIES}}})
    return result['consumers'] if result is not None else None


def contract(value, base, certificate, public, integrations):
    """Pin opaque native state formats to the admitted base until a bridge exists."""
    authority = release.file_record(certificate)['sha256']
    state = native_formats(base)
    if state is None:
        version = 'base:'+release.file_record(base)['sha256']
        state = {'platform': {'writes': version, 'reads': [version]}}
    for name, digest in integrations.items():
        release.require(re.fullmatch(r'[a-z][a-z0-9_-]{0,53}', name), 'Invalid state consumer identity.')
        version = 'extension:'+digest
        state['extension_'+name] = {'writes': version, 'reads': [version]}
    return image_contract.validate({'schema': 1, 'machine_id': value['hardware']['machine_id'], 'state': state,
        'trust': {'generation': 1, 'transition': 'steady', 'authorities': {
            'manifest': authority, 'secure_boot': authority, 'verity': authority,
            'pcr_policy': hashlib.sha256(public).hexdigest() if public else None}}})


def install(overlay, public):
    policy = early_unlock.policy(public)
    target = overlay/'usr/lib/systemd/tpm2-pcr-public-key.pem'
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(public)
    return policy
