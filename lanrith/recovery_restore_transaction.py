"""Copy an authenticated encrypted backup to a claimed target, metadata last.

The production controller supplies admission, independent receipt confirmation,
a verified recovery key and a pinned source and target. This primitive also
requires the signed recovery operation before writing."""
import fcntl
import hmac
import os
from . import recovery_authority
import stat
import struct

from . import recovery_backup_verity, recovery_restore_layout, release

RESTORE_WRITE_QUALIFIED = False
CHUNK = 1024*1024


def _target_size(fd):
    info = os.fstat(fd)
    release.require(stat.S_ISBLK(info.st_mode), 'Restore target is not a block device.')
    return struct.unpack('Q', fcntl.ioctl(fd, 0x80081272, bytes(8)))[0]  # BLKGETSIZE64


def _pwrite_all(fd, data, offset):
    done = 0
    while done < len(data):
        count = os.pwrite(fd, data[done:], offset+done)
        release.require(count > 0, 'Restore target write failed.')
        done += count


def _copy_and_verify(source, target, start, end):
    for verify in (False, True):
        position = start
        while position < end:
            size = min(CHUNK, end-position)
            block = os.pread(source, size, position)
            release.require(len(block) == size, 'Authenticated restore source is truncated.')
            if verify:
                release.require(hmac.compare_digest(os.pread(target, size, position), block),
                                'Restore target verification failed.')
            else:
                _pwrite_all(target, block, position)
            position += size
        if not verify:
            os.fsync(target)



def _headers_clear(source, target, metadata_size, volume_size):
    """Reject conflicting recognizable LUKS headers within supported LUKS2 offsets.

    This is a bounded observation, not a substitute for exclusive ownership or
    proving integrity of either header. The authenticated backup's two binary
    headers must describe the same supported metadata size.
    """
    primary, secondary = b'LUKS\xba\xbe', b'SKUL\xba\xbe'
    def header(fd, offset):
        raw = os.pread(fd, 16, offset)
        release.require(len(raw) == 16, 'Restore header observation is truncated.')
        return raw
    def expected(raw, magic):
        return raw[:6] == magic and raw[6:8] == b'\x00\x02' and \
               int.from_bytes(raw[8:16], 'big') == metadata_size
    release.require(expected(header(source, 0), primary) and
                    expected(header(source, metadata_size), secondary),
                    'Authenticated backup has inconsistent LUKS2 binary headers.')
    target_primary = header(target, 0)
    if target_primary[:6] in (primary, secondary):
        release.require(expected(target_primary, primary), 'Restore target has conflicting primary metadata.')
    for offset in sorted(recovery_restore_layout.METADATA_SIZES):
        if offset+16 > volume_size:
            continue
        source_header, target_header = header(source, offset), header(target, offset)
        if offset != metadata_size:
            release.require(source_header[:6] not in (primary, secondary) and
                            target_header[:6] not in (primary, secondary),
                            'Restore source or target has conflicting secondary metadata.')
        elif target_header[:6] in (primary, secondary):
            release.require(expected(target_header, secondary), 'Restore target has conflicting secondary metadata.')

def restore_pinned(source, target, *, expected_measurement, metadata_size, data_offset, revalidate):
    """Copy a pinned backup to an exclusively bound offline target, header last.

    This is an unqualified primitive: admission, freshness, target ownership,
    operator confirmation, recovery boot and transaction recovery are not
    supplied here. Never enable the gate until the whole workflow is qualified.
    A failure after header invalidation must leave the independent backup intact.
    """
    release.require(RESTORE_WRITE_QUALIFIED or recovery_authority.permits('restore'), 'Encrypted restore writes are not qualified.')
    release.require(callable(revalidate) and isinstance(expected_measurement, bytes) and
                    len(expected_measurement) == 32 and type(metadata_size) is int and
                    metadata_size in recovery_restore_layout.METADATA_SIZES and
                    type(data_offset) is int and 2*metadata_size <= data_offset <=
                    recovery_restore_layout.MAX_PREFIX_SIZE and data_offset % 512 == 0,
                    'Invalid restore transaction binding.')
    before = recovery_backup_verity.regular(source)
    release.require(before.st_size > data_offset and _target_size(target) == before.st_size and
                    fcntl.fcntl(target, fcntl.F_GETFL) & os.O_ACCMODE == os.O_RDWR and
                    hmac.compare_digest(recovery_backup_verity.measure(source), expected_measurement),
                    'Restore source or target differs from its binding.')
    target_identity = os.fstat(target).st_rdev
    revalidate()
    _headers_clear(source, target, metadata_size, before.st_size)
    revalidate()
    # The caller must also hold the target exclusively across the scan and copy.
    _pwrite_all(target, bytes(4096), 0)
    os.fsync(target)
    _pwrite_all(target, bytes(4096), metadata_size)
    os.fsync(target)
    revalidate()
    _copy_and_verify(source, target, 2*metadata_size, before.st_size)
    revalidate()
    # Publish a complete secondary header only after the rest of the encrypted
    # volume is durable and verified, then publish the primary header.
    _copy_and_verify(source, target, metadata_size, 2*metadata_size)
    _copy_and_verify(source, target, 0, metadata_size)
    after = recovery_backup_verity.regular(source)
    release.require((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) ==
                    (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns) and
                    os.fstat(target).st_rdev == target_identity and _target_size(target) == before.st_size and
                    hmac.compare_digest(recovery_backup_verity.measure(source), expected_measurement),
                    'Restore source or target changed.')
    revalidate()
    return {'schema': 1, 'scope': 'experimental-header-last-copy', 'authorized_to_boot': False}
