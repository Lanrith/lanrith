"""Inspect a narrowly supported LUKS2 layout; this does not authorize restore.

The caller must obtain metadata from cryptsetup after authenticating and pinning
an independent backup. This parser neither validates the binary header nor
checks the recovery key, media, target, freshness or write transaction. Layouts
using reencryption, integrity, detached metadata or multiple segments fail
closed until separately supported and qualified.
"""

import re

from . import release


METADATA_SIZES = {16*1024, 32*1024, 64*1024, 128*1024, 256*1024,
                  512*1024, 1024*1024, 2*1024*1024, 4*1024*1024}
MAX_KEYSLOTS_SIZE = 128*1024*1024
MAX_PREFIX_SIZE = 256*1024*1024


def decimal(value):
    release.require(isinstance(value, str) and re.fullmatch(r'(?:0|[1-9][0-9]{0,19})', value),
                    'Unsupported LUKS2 numeric metadata.')
    return int(value)


def observe(metadata, total_size):
    """Return a conservative data offset from one already validated LUKS2 JSON document."""
    release.require(type(total_size) is int and 0 < total_size <= 2**50 and
                    isinstance(metadata, dict) and set(metadata) ==
                    {'keyslots', 'tokens', 'segments', 'digests', 'config'} and
                    all(isinstance(metadata[key], dict) for key in metadata),
                    'Unsupported LUKS2 metadata layout.')
    config = metadata['config']
    release.require(set(config) == {'json_size', 'keyslots_size'},
                    'Unsupported LUKS2 configuration or transition.')
    metadata_size = decimal(config['json_size'])+4096
    keyslots_size = decimal(config['keyslots_size'])
    release.require(metadata_size in METADATA_SIZES and 0 < keyslots_size <= MAX_KEYSLOTS_SIZE and
                    keyslots_size % 4096 == 0, 'Unsupported LUKS2 metadata or keyslot area.')
    segments = metadata['segments']
    release.require(set(segments) == {'0'} and isinstance(segments['0'], dict),
                    'Unsupported LUKS2 segment layout.')
    segment = segments['0']
    release.require(set(segment) == {'type', 'offset', 'size', 'iv_tweak', 'encryption', 'sector_size'} and
                    segment['type'] == 'crypt' and segment['size'] == 'dynamic' and
                    isinstance(segment['encryption'], str) and
                    re.fullmatch(r'[a-z0-9][a-z0-9_.:-]{0,127}', segment['encryption']) and
                    type(segment['sector_size']) is int and segment['sector_size'] in (512, 1024, 2048, 4096),
                    'Unsupported LUKS2 encryption segment.')
    decimal(segment['iv_tweak'])
    offset = decimal(segment['offset'])
    release.require(2*metadata_size+keyslots_size <= offset <= MAX_PREFIX_SIZE and
                    offset % segment['sector_size'] == 0 and offset < total_size,
                    'Unsupported LUKS2 data offset.')
    return {'schema': 1, 'scope': 'luks2-layout-observation', 'metadata_size': metadata_size,
            'keyslots_size': keyslots_size, 'data_offset': offset, 'sector_size': segment['sector_size'],
            'header_authenticated': False, 'authorized_to_restore': False}


def inspect_pinned(payload_fd, *, expected_uuid, expected_measurement):
    """Inspect a sealed in-memory copy of LUKS2 metadata from a pinned backup.

    The caller must authenticate and hold the backup before invoking this
    observation. A sealed copy prevents cryptsetup's metadata auto-recovery
    from writing to the backup. No key or write authority is returned.
    """
    import fcntl
    import hmac
    import json
    import os
    import subprocess

    from . import recovery_backup_verity, update

    release.require(isinstance(expected_uuid, str) and re.fullmatch(update.UUID, expected_uuid) and
                    isinstance(expected_measurement, bytes) and len(expected_measurement) == 32,
                    'Invalid pinned backup identity.')
    before = recovery_backup_verity.regular(payload_fd)
    release.require(hmac.compare_digest(recovery_backup_verity.measure(payload_fd), expected_measurement),
                    'Pinned backup measurement differs.')
    # LUKS2 has two metadata areas, each at most 4 MiB. Copy both into a
    # private sealed memfd. Its sparse size also covers the supported data
    # offset so cryptsetup can validate attached-header geometry.
    metadata_bytes = min(before.st_size, 8*1024*1024)
    release.require(metadata_bytes == 8*1024*1024, 'Pinned backup is too small for LUKS2 metadata.')
    descriptor = os.memfd_create('lanrith-luks2-metadata', os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
    try:
        os.ftruncate(descriptor, min(before.st_size, MAX_PREFIX_SIZE+4096))
        position = 0
        while position < metadata_bytes:
            chunk = os.pread(payload_fd, min(1024*1024, metadata_bytes-position), position)
            release.require(chunk and len(chunk) <= metadata_bytes-position,
                            'Pinned backup metadata is truncated.')
            written = 0
            while written < len(chunk):
                count = os.pwrite(descriptor, chunk[written:], position+written)
                release.require(count > 0, 'LUKS2 metadata snapshot failed.')
                written += count
            position += len(chunk)
        seals = fcntl.F_SEAL_WRITE | fcntl.F_SEAL_GROW | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_SEAL
        fcntl.fcntl(descriptor, fcntl.F_ADD_SEALS, seals)
        release.require(fcntl.fcntl(descriptor, fcntl.F_GET_SEALS) & seals == seals,
                        'LUKS2 metadata snapshot is not sealed.')
        path = '/proc/self/fd/'+str(descriptor)
        def command(*arguments):
            try:
                result = subprocess.run(['cryptsetup', *arguments, path], stdin=subprocess.DEVNULL,
                                        capture_output=True, timeout=30, pass_fds=(descriptor,),
                                        env={'PATH': '/usr/sbin:/usr/bin', 'LC_ALL': 'C'})
            except (OSError, subprocess.TimeoutExpired):
                raise release.ReleaseError('LUKS2 metadata inspection failed.') from None
            release.require(result.returncode == 0 and len(result.stdout) <= 4*1024*1024,
                            'LUKS2 metadata inspection failed.')
            return result.stdout
        try:
            uuid = command('luksUUID').decode('ascii').strip().lower()
        except UnicodeError:
            raise release.ReleaseError('LUKS2 metadata inspection failed.') from None
        release.require(uuid == expected_uuid, 'Pinned backup LUKS2 identity differs.')
        try:
            metadata = json.loads(command('luksDump', '--dump-json-metadata'), object_pairs_hook=release.unique,
                                  parse_constant=lambda _: (_ for _ in ()).throw(ValueError('Invalid JSON number.')))
        except (ValueError, UnicodeError, RecursionError):
            raise release.ReleaseError('LUKS2 metadata inspection failed.') from None
        result = observe(metadata, before.st_size)
        after = recovery_backup_verity.regular(payload_fd)
        release.require((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) ==
                        (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns) and
                        hmac.compare_digest(recovery_backup_verity.measure(payload_fd), expected_measurement),
                        'Pinned backup changed during LUKS2 inspection.')
        return result
    finally:
        os.close(descriptor)


def verify_recovery_key_pinned(payload_fd, secret, *, expected_uuid, expected_measurement):
    """Verify an enrolled recovery key on a sealed snapshot; grant no restore authority."""
    import fcntl
    import hmac
    import json
    import os
    import subprocess

    from . import recovery_inputs, recovery_backup_verity

    release.require(isinstance(secret, bytearray) and recovery_inputs.RECOVERY_KEY.fullmatch(secret),
                    'A systemd recovery key is required.')
    observed = inspect_pinned(payload_fd, expected_uuid=expected_uuid, expected_measurement=expected_measurement)
    before = recovery_backup_verity.regular(payload_fd)
    prefix_size = observed['data_offset']
    descriptor = os.memfd_create('lanrith-luks2-keyslots', os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
    try:
        os.ftruncate(descriptor, min(before.st_size, MAX_PREFIX_SIZE+4096))
        position = 0
        while position < prefix_size:
            chunk = os.pread(payload_fd, min(1024*1024, prefix_size-position), position)
            release.require(chunk and len(chunk) <= prefix_size-position, 'Pinned backup keyslots are truncated.')
            written = 0
            while written < len(chunk):
                count = os.pwrite(descriptor, chunk[written:], position+written)
                release.require(count > 0, 'LUKS2 keyslot snapshot failed.')
                written += count
            position += len(chunk)
        seals = fcntl.F_SEAL_WRITE | fcntl.F_SEAL_GROW | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_SEAL
        fcntl.fcntl(descriptor, fcntl.F_ADD_SEALS, seals)
        release.require(fcntl.fcntl(descriptor, fcntl.F_GET_SEALS) & seals == seals,
                        'LUKS2 keyslot snapshot is not sealed.')
        path = '/proc/self/fd/'+str(descriptor)
        def command(arguments, input_data=None):
            try:
                return subprocess.run(['cryptsetup', *arguments, path], input=input_data,
                                      stdin=subprocess.DEVNULL if input_data is None else None,
                                      capture_output=True, timeout=120, pass_fds=(descriptor,),
                                      env={'PATH': '/usr/sbin:/usr/bin', 'LC_ALL': 'C'})
            except (OSError, subprocess.TimeoutExpired):
                raise release.ReleaseError('Recovery-key verification failed.') from None
        raw = command(['luksDump', '--dump-json-metadata'])
        release.require(raw.returncode == 0 and len(raw.stdout) <= 4*1024*1024,
                        'Recovery-key metadata is invalid.')
        try:
            metadata = json.loads(raw.stdout, object_pairs_hook=release.unique,
                                  parse_constant=lambda _: (_ for _ in ()).throw(ValueError('Invalid JSON number.')))
        except (ValueError, UnicodeError, RecursionError):
            raise release.ReleaseError('Recovery-key metadata is invalid.') from None
        release.require(observe(metadata, before.st_size) == observed, 'Pinned backup layout changed.')
        tokens, keyslots = metadata['tokens'], metadata['keyslots']
        release.require(len(tokens) <= 32 and len(keyslots) <= 32, 'Recovery-key metadata is invalid.')
        slots = []
        for token in tokens.values():
            release.require(isinstance(token, dict), 'Recovery-key metadata is invalid.')
            if token.get('type') != 'systemd-recovery':
                continue
            keys = token.get('keyslots')
            release.require(isinstance(keys, list) and len(keys) == 1 and isinstance(keys[0], str) and
                            re.fullmatch(r'(?:0|[1-9][0-9]?)', keys[0]) and keys[0] in keyslots and
                            int(keys[0]) < 32 and keys[0] not in slots, 'Recovery-key metadata is invalid.')
            slots.append(keys[0])
        release.require(1 <= len(slots) <= 4, 'Backup requires a systemd recovery keyslot.')
        valid = any(command(['open', '--test-passphrase', '--type', 'luks2', '--disable-external-tokens',
                             '--key-slot', slot, '--key-file=-'], secret).returncode == 0 for slot in slots)
        release.require(valid, 'Recovery-key verification failed.')
        after = recovery_backup_verity.regular(payload_fd)
        release.require((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) ==
                        (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns) and
                        hmac.compare_digest(recovery_backup_verity.measure(payload_fd), expected_measurement),
                        'Pinned backup changed during recovery-key verification.')
        return {'schema': 1, 'scope': 'recovery-key-observation', 'key_verified': True,
                'authorized_to_restore': False}
    finally:
        os.close(descriptor)
