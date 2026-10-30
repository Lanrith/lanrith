"""Experimental authenticated regular-file backup; not an operator workflow.

The public fixture entry point refuses block devices and cannot restore anything.
It does not establish that the input is an encrypted volume, a consistent
snapshot, or an independently held backup. Production media admission,
device binding, rollback policy and destructive restore remain separate gates.
"""

from contextlib import contextmanager
import json
import os
from pathlib import Path
import re
import secrets
import stat

from . import recovery_backup_auth as auth, release


def private_directory(path):
    release.require(isinstance(path, Path) and path.is_absolute() and path.resolve() == path,
                    'Backup directory is not canonical.')
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        info = os.fstat(fd)
        release.require(stat.S_ISDIR(info.st_mode) and info.st_uid == os.geteuid() and
                        stat.S_IMODE(info.st_mode) == 0o700, 'Backup directory is not private.')
        return fd
    except BaseException:
        os.close(fd)
        raise


def regular(fd, *, private=False):
    info = os.fstat(fd)
    release.require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_size > 0 and
                    (not private or info.st_uid == os.geteuid() and stat.S_IMODE(info.st_mode) == 0o600),
                    'Backup file is unsafe or is not a regular file.')
    return info


def fingerprint(info):
    return info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns


def _write_all(fd, data):
    offset = 0
    while offset < len(data):
        written = os.write(fd, data[offset:])
        release.require(written > 0, 'Backup metadata write failed.')
        offset += written


def _publish(directory, source_fd, secret, value, revalidate, *, protect=None):
    """Publish from an already bound source after the caller's precommit checks.

    This private helper establishes no device, mount or write authorization.
    A future device controller must hold and revalidate all relevant bindings.
    """
    value = dict(auth.descriptor(value))
    release.require(callable(revalidate) and (protect is None or callable(protect)),
                    'Backup source revalidation is required.')
    parent = private_directory(directory)
    backup_fd = None
    try:
        revalidate()
        space = os.fstatvfs(parent)
        # Allow for a SHA-256 Merkle tree even on 1 KiB filesystem blocks.
        reserve = 64*1024*1024 + ((value['size']+24)//25 if protect is not None else 0)
        release.require(space.f_bavail*space.f_frsize >= value['size']+reserve,
                        'Backup destination lacks space and reserve.')
        name = 'backup-'+secrets.token_hex(16)
        os.mkdir(name, 0o700, dir_fd=parent)
        backup_fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
        output_fd = os.open('payload', os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                            0o600, dir_fd=backup_fd)
        with os.fdopen(os.dup(source_fd), 'rb') as input_stream, os.fdopen(output_fd, 'wb') as output:
            mac = auth.copy_and_authenticate(input_stream, output, secret, value)
            output.flush()
            os.fsync(output.fileno())
        if protect is not None:
            protected_fd = os.open('payload', os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=backup_fd)
            try:
                protect(protected_fd)
                os.fsync(protected_fd)
            finally:
                os.close(protected_fd)
        revalidate()
        seal = release.canonical({'schema': 1, 'descriptor': value, 'authenticator': mac})
        temporary = os.open('.seal', os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                            0o600, dir_fd=backup_fd)
        try:
            _write_all(temporary, seal)
            os.fsync(temporary)
        finally:
            os.close(temporary)
        os.rename('.seal', 'seal', src_dir_fd=backup_fd, dst_dir_fd=backup_fd)
        os.fsync(backup_fd)
        os.fsync(parent)
        return name
    finally:
        if backup_fd is not None:
            os.close(backup_fd)
        os.close(parent)


def create(directory, source, secret, *, image_id, volume_uuid):
    """Publish one synthetic regular-file backup and return its generated name."""
    release.require(isinstance(source, Path) and source.is_absolute() and source.resolve() == source,
                    'Backup source is not canonical.')
    source_fd = os.open(source, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    try:
        before = regular(source_fd)
        value = {'schema': 1, 'image_id': image_id, 'volume_uuid': volume_uuid,
                 'size': before.st_size, 'salt': secrets.token_hex(32)}
        def revalidate():
            release.require(fingerprint(regular(source_fd)) == fingerprint(before) and source.resolve() == source and
                            fingerprint(source.stat()) == fingerprint(before), 'Backup source changed during copy.')
        return _publish(directory, source_fd, secret, value, revalidate)
    finally:
        os.close(source_fd)


@contextmanager
def open_authenticated(directory, name, secret, *, image_id, volume_uuid, require_verity=True):
    """Hold the authenticated file open without granting disk-write authority.

    A future restore must require verity and independently bind its offline
    media, destination, authorization, freshness and interruption protocol.
    """
    release.require(type(require_verity) is bool, 'Invalid immutable-backup requirement.')
    release.require(isinstance(name, str) and re.fullmatch(r'backup-[0-9a-f]{32}', name),
                    'Invalid backup identifier.')
    parent = private_directory(directory)
    backup = seal_fd = payload_fd = None
    try:
        backup = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
        info = os.fstat(backup)
        release.require(info.st_uid == os.geteuid() and stat.S_IMODE(info.st_mode) == 0o700 and
                        set(os.listdir(backup)) == {'payload', 'seal'}, 'Backup is incomplete or unsafe.')
        seal_fd = os.open('seal', os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK, dir_fd=backup)
        seal_info = regular(seal_fd, private=True)
        release.require(seal_info.st_size <= 4096, 'Backup metadata is oversized.')
        raw = os.read(seal_fd, 4097)
        release.require(len(raw) == seal_info.st_size and fingerprint(regular(seal_fd, private=True)) ==
                        fingerprint(seal_info), 'Backup metadata changed during inspection.')
        try:
            record = json.loads(raw, object_pairs_hook=release.unique,
                                parse_constant=lambda _: (_ for _ in ()).throw(ValueError('Invalid backup metadata.')))
        except (ValueError, UnicodeError, RecursionError):
            raise release.ReleaseError('Invalid backup metadata.') from None
        release.require(isinstance(record, dict) and set(record) == {'schema', 'descriptor', 'authenticator'} and
                        type(record['schema']) is int and record['schema'] == 1 and raw == release.canonical(record),
                        'Invalid backup metadata.')
        value = auth.descriptor(record['descriptor'])
        release.require(value['image_id'] == image_id and value['volume_uuid'] == volume_uuid,
                        'Backup identity differs from the expected volume.')
        payload_fd = os.open('payload', os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK, dir_fd=backup)
        before = regular(payload_fd, private=True)
        release.require(before.st_size == value['size'], 'Backup payload size differs.')
        if require_verity:
            from . import recovery_backup_verity
            observation = recovery_backup_verity.verify_pinned(payload_fd, secret, value, record['authenticator'])
        else:
            with os.fdopen(os.dup(payload_fd), 'rb') as stream:
                observation = auth.verify(stream, secret, value, record['authenticator'])
        def revalidate():
            if require_verity:
                release.require(recovery_backup_verity.measure(payload_fd).hex() == observation['measurement_sha256'],
                                'Immutable backup measurement changed.')
            current = os.stat(name, dir_fd=parent, follow_symlinks=False)
            release.require(fingerprint(os.fstat(backup)) == fingerprint(info) and
                            fingerprint(current) == fingerprint(info) and stat.S_ISDIR(current.st_mode) and
                            fingerprint(regular(payload_fd, private=True)) == fingerprint(before) and
                            fingerprint(regular(seal_fd, private=True)) == fingerprint(seal_info) and
                            fingerprint(os.stat('payload', dir_fd=backup, follow_symlinks=False)) == fingerprint(before) and
                            fingerprint(os.stat('seal', dir_fd=backup, follow_symlinks=False)) == fingerprint(seal_info) and
                            set(os.listdir(backup)) == {'payload', 'seal'}, 'Backup changed during inspection.')
        revalidate()
        os.lseek(payload_fd, 0, os.SEEK_SET)
        yield payload_fd, observation
        revalidate()
    finally:
        for fd in (payload_fd, seal_fd, backup, parent):
            if fd is not None:
                os.close(fd)


def inspect(directory, name, secret, *, image_id, volume_uuid, require_verity=False):
    """Authenticate a backup as an observation; no handle or restore authority escapes."""
    with open_authenticated(directory, name, secret, image_id=image_id, volume_uuid=volume_uuid,
                            require_verity=require_verity) as (_, observation):
        return observation
