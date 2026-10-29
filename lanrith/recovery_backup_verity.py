"""Experimental immutable-backup support; does not authorize restoration.

An fs-verity measurement protects subsequent reads from a pinned file but is
not itself an authentication or freshness guarantee. The backup MAC, trusted
binding, exclusive offline devices, replay policy and write transaction remain
separate requirements. This module is not installed in an image.
"""

import fcntl
import os
import stat
import struct

from . import recovery_backup_auth, release


# Linux fsverity.h ioctl ABI: _IOW('f', 133, 128) and _IOWR('f', 134, 4).
ENABLE_VERITY = 0x40806685
MEASURE_VERITY = 0xC0046686
SHA256 = 1


def regular(fd):
    info = os.fstat(fd)
    release.require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_size > 0 and
                    info.st_uid == os.geteuid() and stat.S_IMODE(info.st_mode) == 0o600 and
                    fcntl.fcntl(fd, fcntl.F_GETFL) & os.O_ACCMODE == os.O_RDONLY,
                    'Immutable backup payload is unsafe.')
    return info


def enable(fd):
    """Enable fs-verity on a private read-only file descriptor before publication."""
    regular(fd)
    # SHA-256 Merkle blocks must be a power of two no larger than either
    # the page or filesystem block size. Authentication is separate.
    page = os.sysconf('SC_PAGESIZE')
    filesystem = os.fstatvfs(fd).f_bsize
    release.require(type(page) is int and type(filesystem) is int and page >= 1024 and filesystem >= 1024,
                    'Immutable backup block size is invalid.')
    block = min(page, filesystem)
    release.require(block <= 65536 and block & (block-1) == 0, 'Immutable backup block size is invalid.')
    argument = struct.pack('=IIIIQIIQ11Q', 1, SHA256, block, 0, 0, 0, 0, 0, *([0]*11))
    release.require(len(argument) == 128, 'Unsupported fs-verity ABI.')
    try:
        fcntl.ioctl(fd, ENABLE_VERITY, argument)
    except OSError:
        raise release.ReleaseError('Immutable backup protection is unavailable.') from None
    return measure(fd)


def measure(fd):
    """Read the kernel's enforced SHA-256 fs-verity file measurement."""
    regular(fd)
    data = bytearray(struct.pack('=HH', 0, 32)+bytes(32))
    try:
        fcntl.ioctl(fd, MEASURE_VERITY, data, True)
    except OSError:
        raise release.ReleaseError('Immutable backup protection is unavailable.') from None
    algorithm, size = struct.unpack_from('=HH', data)
    release.require(algorithm == SHA256 and size == 32, 'Immutable backup measurement is invalid.')
    return bytes(data[4:])


def verify_pinned(fd, secret, descriptor, authenticator):
    """Authenticate exactly one pinned, verity-enforced file; never authorize writes."""
    before = regular(fd)
    first = measure(fd)
    os.lseek(fd, 0, os.SEEK_SET)
    with os.fdopen(os.dup(fd), 'rb') as source:
        result = recovery_backup_auth.verify(source, secret, descriptor, authenticator)
    after = regular(fd)
    release.require((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) ==
                    (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns) and
                    measure(fd) == first and result.get('authorized_to_restore') is False,
                    'Immutable backup changed during authentication.')
    os.lseek(fd, 0, os.SEEK_SET)
    return {'schema': 1, 'scope': 'immutable-backup-observation', 'measurement_sha256': first.hex(),
            'authorized_to_restore': False}
