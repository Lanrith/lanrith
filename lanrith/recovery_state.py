"""Experimental read-only encrypted-state access for an offline recovery image.

Used only by the experimental recovery console, not an admitted image. The
caller must authenticate physical recovery access, bind the disk and LUKS UUID
from a trusted image, and wipe the supplied key. No state content is exposed
by this module's own API.
"""

from contextlib import contextmanager
import hmac
import json
import os
from pathlib import Path
import re
import secrets
import stat
import subprocess
import tempfile

from . import factory, release, repair, update


def cryptsetup_open(backing, mapping, secret):
    """Supply a bounded recovery key on stdin, never in arguments or logs."""
    release.require(isinstance(secret, bytearray) and 1 <= len(secret) <= 512 and b'\0' not in secret,
                    'Invalid recovery credential.')
    arguments = ['cryptsetup', 'open', '--readonly', '--type=luks2', '--disable-external-tokens',
                 '--key-file=-', '--tries=1', backing, mapping]
    try:
        result = subprocess.run(arguments, input=secret, capture_output=True, timeout=120,
                                env={'PATH': '/usr/sbin:/usr/bin', 'LC_ALL': 'C'})
    except (OSError, subprocess.TimeoutExpired):
        raise release.ReleaseError('Recovery key operation failed.') from None
    release.require(result.returncode == 0, 'Recovery key operation failed.')


def require_readonly(device):
    """Report only fixed device-check categories, never command diagnostics."""
    try:
        result = subprocess.run(['blockdev', '--getro', device], stdin=subprocess.DEVNULL,
                                capture_output=True, timeout=30,
                                env={'PATH': '/usr/sbin:/usr/bin', 'LC_ALL': 'C'})
    except (OSError, subprocess.TimeoutExpired):
        raise release.ReleaseError('Recovery read-only check unavailable.') from None
    if result.returncode:
        error = result.stderr.lower()
        if b'no such file' in error or b'not found' in error:
            raise release.ReleaseError('Recovery read-only device missing.')
        if b'permission denied' in error or b'operation not permitted' in error:
            raise release.ReleaseError('Recovery read-only device denied.')
        raise release.ReleaseError('Recovery read-only check failed.')
    release.require(result.stdout.strip() == b'1', 'Recovery device is not read-only.')


def verify_mount(path, mapping):
    result = json.loads(update.command(['findmnt', '--uniq', '--json', '--target', str(path),
                                        '--output', 'SOURCE,TARGET,FSTYPE,OPTIONS']))
    rows = result.get('filesystems', [])
    release.require(len(rows) == 1 and rows[0].get('target') == str(path) and
                    rows[0].get('fstype') == 'ext4' and
                    isinstance(rows[0].get('source'), str) and
                    Path(rows[0]['source']).resolve() == Path(mapping).resolve() and
                    {'ro', 'nodev', 'nosuid', 'noexec'} <= set((rows[0].get('options') or '').split(',')),
                    'Recovered state mount is not read-only and restricted.')


@contextmanager
def open_readonly(disk, expected_uuid, secret):
    """Temporarily mount one bound encrypted state partition without disk writes."""
    release.require(os.geteuid() == 0 and Path('/etc/initrd-release').is_file(),
                    'State recovery requires a verified recovery initrd.')
    release.require(isinstance(disk, str) and re.fullmatch(r'/dev/[A-Za-z0-9_.-]+', disk) and
                    Path(disk).resolve() == Path(disk) and isinstance(expected_uuid, str) and
                    re.fullmatch(update.UUID, expected_uuid), 'Invalid recovery state binding.')
    release.require(isinstance(secret, bytearray) and 1 <= len(secret) <= 512 and b'\0' not in secret,
                    'Invalid recovery credential.')
    boot_disk, _ = factory.verified_root('/sysroot')
    release.require(disk != boot_disk, 'Recovery state cannot be on the recovery boot disk.')
    layout = repair.disk_layout(disk)
    rows = update.geometry(disk)
    sizes = {node: (end-start)*layout['sector'] for start, end, node in layout['extents']}
    release.require(len(rows) == len(sizes) and all(row.get('device') in sizes and
                    row.get('size') == sizes[row['device']] for row in rows),
                    'Recovery state geometry differs from GPT.')
    matches = [row for row in rows if row.get('type') == factory.VAR_GUID and row.get('label') == 'var']
    release.require(len(matches) == 1 and matches[0].get('disk') == disk and not matches[0].get('mounted') and
                    type(matches[0].get('size')) is int and matches[0]['size'] > 0 and
                    matches[0]['size'] % 512 == 0, 'Encrypted recovery state is absent, ambiguous or in use.')
    device = matches[0]['device']
    release.require(isinstance(device, str) and re.fullmatch(r'/dev/[A-Za-z0-9_.-]+', device),
                    'Invalid recovery state device.')
    fd = os.open(device, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        info = os.fstat(fd)
        release.require(stat.S_ISBLK(info.st_mode), 'Recovery state is not a block device.')
        device_number = f'{os.major(info.st_rdev)}:{os.minor(info.st_rdev)}'
        suffix = secrets.token_hex(8)
        backing, mapping = 'lanrith-ro-backing-'+suffix, 'lanrith-ro-state-'+suffix
        backing_path, mapping_path = '/dev/mapper/'+backing, '/dev/mapper/'+mapping
        release.require(not Path(backing_path).exists() and not Path(mapping_path).exists(),
                        'Recovery device-mapper identity already exists.')
        point = Path(tempfile.mkdtemp(prefix='lanrith-recovery-state.', dir='/run'))
        backing_created = mapping_created = False
        try:
            update.command(['dmsetup', '--readonly', 'create', backing, '--table',
                            f'0 {matches[0]["size"]//512} linear {device_number} 0'])
            backing_created = True
            update.command(['udevadm', 'settle', '--timeout=30'])
            # The initrd may no longer have a running udev worker even when
            # the kernel mapping exists. Synchronize only our random name.
            update.command(['dmsetup', 'mknodes', backing])
            require_readonly(backing_path)
            actual_uuid = update.command(['cryptsetup', 'luksUUID', backing_path]).strip().lower()
            release.require(actual_uuid == expected_uuid, 'Recovery state belongs to another encrypted volume.')
            cryptsetup_open(backing_path, mapping, secret)
            mapping_created = True
            update.command(['udevadm', 'settle', '--timeout=30'])
            update.command(['dmsetup', 'mknodes', mapping])
            require_readonly(mapping_path)
            update.command(['mount', '-t', 'ext4', '-o', 'ro,noload,nodev,nosuid,noexec', '--', mapping_path, str(point)])
            verify_mount(point, mapping_path)
            yield point
        finally:
            # Never recursively delete a mountpoint or force-detach a device.
            # A failed unmount leaves the read-only mappings in place.
            if point.is_mount():
                update.command(['umount', str(point)])
                release.require(not point.is_mount(), 'Recovered state remains mounted.')
            if mapping_created:
                update.command(['cryptsetup', 'close', mapping])
            if backing_created:
                update.command(['dmsetup', 'remove', backing])
            point.rmdir()
    finally:
        os.close(fd)


def retained_contract(point):
    """Read the state inventory from a restricted recovery mount only.

    The inventory is mutable state, not authenticated evidence. Open each path
    component without following links and refuse nested devices, loose modes,
    oversized files and concurrent changes. The caller must still bind and
    authenticate the recovered state before authorizing a boot or restore.
    """
    from . import image_contract

    release.require(isinstance(point, Path) and point.is_absolute() and point.resolve() == point and
                    point.is_mount() and os.statvfs(point).f_flag & os.ST_RDONLY,
                    'Retained inventory requires a read-only recovery mount.')
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    descriptors = []
    try:
        descriptors.append(os.open(point, flags))
        mount = os.fstat(descriptors[-1])
        for name in ('lib', 'lanrith'):
            descriptors.append(os.open(name, flags, dir_fd=descriptors[-1]))
            info = os.fstat(descriptors[-1])
            release.require(stat.S_ISDIR(info.st_mode) and info.st_dev == mount.st_dev and info.st_uid == 0 and
                            not info.st_mode & 0o022, 'Retained inventory directory is unsafe.')
        fd = os.open('state-contract.json', os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
                     dir_fd=descriptors[-1])
        with os.fdopen(fd, 'rb') as stream:
            before = os.fstat(stream.fileno())
            release.require(stat.S_ISREG(before.st_mode) and before.st_dev == mount.st_dev and
                            before.st_uid == 0 and stat.S_IMODE(before.st_mode) == 0o600 and
                            before.st_nlink == 1 and 0 < before.st_size <= 32768,
                            'Retained inventory file is unsafe.')
            data = stream.read(32769)
            after = os.fstat(stream.fileno())
            release.require((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) ==
                            (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns) and
                            len(data) == before.st_size, 'Retained inventory changed during reading.')
        value = json.loads(data, object_pairs_hook=release.unique,
                           parse_constant=lambda _: (_ for _ in ()).throw(release.ReleaseError('Invalid JSON number.')))
        return image_contract.validate(value)
    finally:
        for descriptor in reversed(descriptors):
            os.close(descriptor)


def assess_fallback(current_root, fallback_root, certificate, *, image_id, disk, esp, state_mount):
    """Combine offline observations without granting authority to boot.

    The caller supplies independently authenticated release trust and an already
    opened read-only state mount. This observation does not establish retained
    inventory provenance, firmware trust, TPM unlock or anti-rollback policy.
    It must never be used on its own to select a boot entry.
    """
    retained = retained_contract(state_mount)
    contracts = repair.inspect_contracts(current_root, fallback_root, certificate,
                                  image_id=image_id, retained=retained)
    slot = repair.inspect_slot(fallback_root, certificate, image_id=image_id, disk=disk, esp=esp)
    release.require(slot['deployment_sequence'] == contracts['fallback_sequence'] and
                    hmac.compare_digest(slot['manifest_sha256'], contracts['fallback_manifest_sha256']) and
                    slot['authorized_to_boot'] is False and contracts['authorized_to_boot'] is False and
                    contracts['retained_state_authenticated'] is False,
                    'Recovery slot and contract observations differ.')
    return {'schema': 1, 'scope': 'offline-fallback-observation', 'image_id': image_id,
            'current_sequence': contracts['current_sequence'],
            'fallback_sequence': slot['deployment_sequence'], 'uki_name': slot['uki_name'],
            'retained_state_authenticated': False, 'authorized_to_boot': False}
