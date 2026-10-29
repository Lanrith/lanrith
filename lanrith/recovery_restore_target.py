"""Claim the exact offline state target exclusively after recovery admission."""
from contextlib import contextmanager
import os
from . import recovery_authority
from pathlib import Path
import stat

from . import (factory, recovery_backup_preflight, recovery_inputs,
               recovery_restore_transaction, release, update)


TARGET_CLAIM_QUALIFIED = False


@contextmanager
def claim(value, *, expected_size):
    """Claim one separately bound writable state partition with O_EXCL.

    The caller must first authenticate the independent backup and its freshness,
    validate the recovery key and require explicit operator approval. A target
    may only already be writable in a qualified, isolated recovery workflow.
    O_EXCL and mount/holder observations do not establish protection against a
    malicious privileged actor or faulty hardware.
    """
    release.require(TARGET_CLAIM_QUALIFIED or recovery_authority.permits('restore', value), 'Offline restore target claim is not qualified.')
    value = recovery_backup_preflight.policy(value)
    release.require(type(expected_size) is int and 0 < expected_size <= 2**50 and
                    os.geteuid() == 0 and Path('/etc/initrd-release').is_file(),
                    'Offline restore target claim requires a recovery initrd.')
    factory.secure_boot()
    recovery_disk, _ = factory.verified_root('/sysroot')
    disk = recovery_inputs.canonical_disk(value['target_disk_by_id'])
    backup = recovery_inputs.canonical_disk(value['backup_disk_by_id'])
    release.require(len({recovery_disk, disk, backup}) == 3, 'Offline restore disks overlap.')
    snapshot = recovery_inputs.disk_snapshot(disk)
    rows = snapshot[1]
    release.require(all(not row.get('mounted') for row in rows), 'Offline restore target is busy.')
    state = recovery_inputs.partition(rows, disk, value['state_partuuid'], factory.VAR_GUID, label='var')
    matches = [row for row in rows if row.get('device') == state]
    release.require(len(matches) == 1 and matches[0].get('size') == expected_size,
                    'Offline restore target capacity differs.')
    release.require(update.command(['blockdev', '--getro', state]).strip() == '0',
                    'Offline restore state partition is not writable.')
    release.require(update.command(['blockdev', '--getro', backup]).strip() == '1',
                    'Offline restore backup disk is not read-only.')
    descriptor = os.open(state, os.O_RDWR | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        opened = os.fstat(descriptor)
        release.require(stat.S_ISBLK(opened.st_mode) and os.stat(state).st_rdev == opened.st_rdev and
                        recovery_restore_transaction._target_size(descriptor) == expected_size,
                        'Exclusive restore target differs from its binding.')
        def revalidate():
            factory.secure_boot()
            current = os.fstat(descriptor)
            release.require(factory.verified_root('/sysroot')[0] == recovery_disk and
                            recovery_inputs.canonical_disk(value['target_disk_by_id']) == disk and
                            recovery_inputs.canonical_disk(value['backup_disk_by_id']) == backup and
                            recovery_inputs.disk_snapshot(disk) == snapshot and
                            stat.S_ISBLK(current.st_mode) and current.st_rdev == opened.st_rdev and
                            os.stat(state).st_rdev == opened.st_rdev and
                            recovery_restore_transaction._target_size(descriptor) == expected_size and
                            update.command(['blockdev', '--getro', state]).strip() == '0' and
                            update.command(['blockdev', '--getro', backup]).strip() == '1',
                            'Exclusive restore target changed.')
        revalidate()
        yield descriptor, revalidate
        revalidate()
    finally:
        os.close(descriptor)
