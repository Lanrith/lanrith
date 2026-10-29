"""Authenticate a bounded encrypted-state stream; this does not authorize restore.

Device selection, an immutable or quiesced source, fresh cryptographic salt,
exclusive access, backup publication, replay policy and all disk writes require
separate implementation and qualification. This primitive does not open files
or devices and is not installed in a runtime image. The MAC permits offline
credential guessing; callers must require a high-entropy recovery key.
"""

import hashlib
import hmac
import re

from . import release, update


DOMAIN = b'lanrith-encrypted-state-backup-v1\0'


def descriptor(value):
    release.require(isinstance(value, dict) and set(value) ==
                    {'schema', 'image_id', 'volume_uuid', 'size', 'salt'} and
                    type(value['schema']) is int and value['schema'] == 1 and
                    isinstance(value['image_id'], str) and
                    re.fullmatch(r'[a-z][a-z0-9-]{0,47}', value['image_id']) and
                    isinstance(value['volume_uuid'], str) and re.fullmatch(update.UUID, value['volume_uuid']) and
                    type(value['size']) is int and 1 <= value['size'] <= 2**50 and
                    isinstance(value['salt'], str) and re.fullmatch(r'[0-9a-f]{64}', value['salt']),
                    'Invalid encrypted backup descriptor.')
    return value


def _mac(secret, value):
    value = descriptor(value)
    release.require(isinstance(secret, bytearray) and 1 <= len(secret) <= 512 and b'\0' not in secret,
                    'Invalid encrypted backup credential.')
    try:
        derived = hashlib.scrypt(secret, salt=bytes.fromhex(value['salt']), n=32768, r=8, p=1,
                                 dklen=32, maxmem=64*1024*1024)
    except (ValueError, MemoryError):
        raise release.ReleaseError('Encrypted backup key derivation failed.') from None
    return hmac.new(derived, DOMAIN+release.canonical(value), hashlib.sha256)


def _process(stream, secret, value, destination=None):
    value = dict(descriptor(value))
    release.require(destination is None or destination is not stream, 'Backup streams must be distinct.')
    mac = _mac(secret, value)
    remaining = value['size']
    while remaining:
        limit = min(1024*1024, remaining)
        chunk = stream.read(limit)
        release.require(isinstance(chunk, bytes) and 0 < len(chunk) <= limit,
                        'Encrypted backup stream is truncated or invalid.')
        if destination is not None:
            offset = 0
            view = memoryview(chunk)
            while offset < len(chunk):
                written = destination.write(view[offset:])
                release.require(type(written) is int and 0 < written <= len(chunk)-offset,
                                'Encrypted backup stream write failed.')
                offset += written
        mac.update(chunk)
        remaining -= len(chunk)
    release.require(stream.read(1) == b'', 'Encrypted backup stream exceeds its declared size.')
    return mac.hexdigest()


def authentication(stream, secret, value):
    """Return a MAC for exactly the described bytes from the current position."""
    return _process(stream, secret, value)


def copy_and_authenticate(source, destination, secret, value):
    """Copy and authenticate one stream; caller owns cleanup and publication."""
    return _process(source, secret, value, destination)


def verify(stream, secret, value, expected):
    """Report integrity only; a successful result is not permission to restore."""
    release.require(isinstance(expected, str) and re.fullmatch(r'[0-9a-f]{64}', expected),
                    'Invalid encrypted backup authenticator.')
    release.require(hmac.compare_digest(authentication(stream, secret, value), expected),
                    'Encrypted backup authentication failed.')
    return {'schema': 1, 'scope': 'encrypted-backup-authentication', 'authorized_to_restore': False}
