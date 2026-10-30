"""Inspect and protect the explicitly bound offline recovery devices."""

import os
from . import recovery_authority
from pathlib import Path
import re

from . import factory, recovery_inputs, release, update


READONLY_PREPARATION_QUALIFIED = False


def prepare_readonly(value, *, include_backup):
    """Protect verified offline devices; this grants no backup or restore authority."""
    release.require(READONLY_PREPARATION_QUALIFIED or recovery_authority.permits('restore' if include_backup else 'backup', value), 'Offline disk protection is not qualified.')
    release.require(type(include_backup) is bool, 'Invalid offline disk protection request.')
    value = policy(value)
    release.require(os.geteuid() == 0 and Path('/etc/initrd-release').is_file(),
                    'Offline disk protection requires its recovery initrd.')
    factory.secure_boot()
    recovery_disk, _ = factory.verified_root('/sysroot')
    target = recovery_inputs.canonical_disk(value['target_disk_by_id'])
    backup = recovery_inputs.canonical_disk(value['backup_disk_by_id'])
    release.require(len({target, backup, recovery_disk}) == 3, 'Offline disk protection bindings overlap.')
    target_snapshot = recovery_inputs.disk_snapshot(target)
    backup_snapshot = recovery_inputs.disk_snapshot(backup)
    target_rows, backup_rows = target_snapshot[1], backup_snapshot[1]
    release.require(all(not row.get('mounted') for row in target_rows+backup_rows),
                    'Offline disk protection requires unmounted disks.')
    state = recovery_inputs.partition(target_rows, target, value['state_partuuid'], factory.VAR_GUID, label='var')
    media = recovery_inputs.partition(backup_rows, backup, value['backup_partuuid'],
                                      recovery_inputs.LINUX_GUID, label='lanrith-backup')
    disks = (target, state, backup, media) if include_backup else (target, state)
    # Never enable writes here. A failed operation leaves any already-protected
    # devices read-only and does not authorize subsequent backup or restore.
    for disk in disks:
        update.command(['blockdev', '--setro', disk])
    factory.secure_boot()
    release.require(factory.verified_root('/sysroot')[0] == recovery_disk and
                    recovery_inputs.canonical_disk(value['target_disk_by_id']) == target and
                    recovery_inputs.canonical_disk(value['backup_disk_by_id']) == backup and
                    recovery_inputs.disk_snapshot(target) == target_snapshot and
                    recovery_inputs.disk_snapshot(backup) == backup_snapshot and
                    all(update.command(['blockdev', '--getro', disk]).strip() == '1' for disk in disks),
                    'Offline disk protection changed or did not take effect.')
    return {'schema': 1, 'scope': 'offline-readonly-preparation',
            'authorized_to_write': False, 'authorized_to_restore': False}


def policy(value):
    fields = {'schema', 'target_disk_by_id', 'state_partuuid', 'state_uuid',
              'backup_disk_by_id', 'backup_partuuid'}
    release.require(isinstance(value, dict) and set(value) == fields and
                    type(value['schema']) is int and value['schema'] == 1,
                    'Invalid offline backup binding.')
    for field in ('target_disk_by_id', 'backup_disk_by_id'):
        path = value[field]
        release.require(isinstance(path, str) and re.fullmatch(r'/dev/disk/by-id/[A-Za-z0-9_.:+-]{1,180}', path) and
                        path.rsplit('/', 1)[-1] not in ('.', '..') and not re.search(r'-part[0-9]+$', path),
                        'Invalid offline backup disk binding.')
    for field in ('state_partuuid', 'state_uuid', 'backup_partuuid'):
        release.require(isinstance(value[field], str) and re.fullmatch(update.UUID, value[field]),
                        'Invalid offline backup volume binding.')
    release.require(value['target_disk_by_id'] != value['backup_disk_by_id'] and
                    value['state_partuuid'] != value['backup_partuuid'], 'Offline backup bindings overlap.')
    return value


def inspect(value):
    """Inspect disks and volume identities without mounting or authorizing writes."""
    value = policy(value)
    release.require(os.geteuid() == 0 and Path('/etc/initrd-release').is_file(),
                    'Offline backup preflight requires its recovery initrd.')
    factory.secure_boot()
    recovery_disk, _ = factory.verified_root('/sysroot')
    target = recovery_inputs.canonical_disk(value['target_disk_by_id'])
    backup = recovery_inputs.canonical_disk(value['backup_disk_by_id'])
    release.require(len({target, backup, recovery_disk}) == 3,
                    'Recovery, target and backup disks must be independent.')
    target_before, target_rows = recovery_inputs.disk_snapshot(target)
    backup_before, backup_rows = recovery_inputs.disk_snapshot(backup)
    release.require(all(not row.get('mounted') for row in target_rows+backup_rows),
                    'Offline backup disk has mounted or held partitions.')
    state_device = recovery_inputs.partition(target_rows, target, value['state_partuuid'], factory.VAR_GUID,
                                             label='var')
    backup_device = recovery_inputs.partition(backup_rows, backup, value['backup_partuuid'],
                                              recovery_inputs.LINUX_GUID, label='lanrith-backup')
    state_rows = [row for row in target_rows if row.get('device') == state_device]
    destination_rows = [row for row in backup_rows if row.get('device') == backup_device]
    release.require(len(state_rows) == len(destination_rows) == 1 and
                    type(state_rows[0].get('size')) is int and state_rows[0]['size'] > 0 and
                    type(destination_rows[0].get('size')) is int and
                    destination_rows[0]['size'] >= state_rows[0]['size']+64*1024*1024,
                    'Offline backup partition lacks source capacity and reserve.')
    state_uuid = update.command(['cryptsetup', 'luksUUID', state_device]).strip().lower()
    filesystem = update.command(['blkid', '--probe', '--output', 'value', '--match-tag', 'TYPE', backup_device]).strip()
    release.require(state_uuid == value['state_uuid'] and filesystem == 'ext4',
                    'Offline backup volume identity or filesystem differs.')
    release.require(recovery_inputs.canonical_disk(value['target_disk_by_id']) == target and
                    recovery_inputs.canonical_disk(value['backup_disk_by_id']) == backup and
                    recovery_inputs.disk_snapshot(target) == (target_before, target_rows) and
                    recovery_inputs.disk_snapshot(backup) == (backup_before, backup_rows),
                    'Offline backup disks changed during preflight.')
    return {'schema': 1, 'scope': 'offline-backup-preflight', 'state_size': state_rows[0]['size'],
            'backup_size': destination_rows[0]['size'], 'authorized_to_write': False,
            'authorized_to_restore': False}


def inspect_restore(value):
    """Observe a damaged-state restore target without mounting or authorizing writes.

    The state partition is identified by the bound disk and GPT, not its LUKS
    header: the header can be damaged. This observation does not authenticate a
    backup, determine its freshness or grant authority to modify any disk.
    """
    value = policy(value)
    release.require(os.geteuid() == 0 and Path('/etc/initrd-release').is_file(),
                    'Offline restore preflight requires its recovery initrd.')
    factory.secure_boot()
    recovery_disk, _ = factory.verified_root('/sysroot')
    target = recovery_inputs.canonical_disk(value['target_disk_by_id'])
    backup = recovery_inputs.canonical_disk(value['backup_disk_by_id'])
    release.require(len({target, backup, recovery_disk}) == 3,
                    'Recovery, target and backup disks must be independent.')
    target_before, target_rows = recovery_inputs.disk_snapshot(target)
    backup_before, backup_rows = recovery_inputs.disk_snapshot(backup)
    release.require(all(not row.get('mounted') for row in target_rows+backup_rows),
                    'Offline restore disk has mounted or held partitions.')
    state = recovery_inputs.partition(target_rows, target, value['state_partuuid'], factory.VAR_GUID, label='var')
    media = recovery_inputs.partition(backup_rows, backup, value['backup_partuuid'],
                                      recovery_inputs.LINUX_GUID, label='lanrith-backup')
    state_rows = [row for row in target_rows if row.get('device') == state]
    media_rows = [row for row in backup_rows if row.get('device') == media]
    release.require(len(state_rows) == len(media_rows) == 1 and
                    type(state_rows[0].get('size')) is int and state_rows[0]['size'] > 0 and
                    type(media_rows[0].get('size')) is int and
                    media_rows[0]['size'] >= state_rows[0]['size']+64*1024*1024,
                    'Offline restore media lacks source capacity and reserve.')
    def readonly():
        release.require(all(update.command(['blockdev', '--getro', disk]).strip() == '1'
                            for disk in (target, state, backup, media)),
                        'Offline restore disks are not read-only.')
    readonly()
    filesystem = update.command(['blkid', '--probe', '--output', 'value', '--match-tag', 'TYPE', media]).strip()
    release.require(filesystem == 'ext4', 'Offline restore media filesystem differs.')
    factory.secure_boot()
    release.require(factory.verified_root('/sysroot')[0] == recovery_disk and
                    recovery_inputs.canonical_disk(value['target_disk_by_id']) == target and
                    recovery_inputs.canonical_disk(value['backup_disk_by_id']) == backup and
                    recovery_inputs.disk_snapshot(target) == (target_before, target_rows) and
                    recovery_inputs.disk_snapshot(backup) == (backup_before, backup_rows),
                    'Offline restore disk binding changed.')
    readonly()
    return {'schema': 1, 'scope': 'offline-restore-preflight', 'state_size': state_rows[0]['size'],
            'backup_size': media_rows[0]['size'], 'header_authenticated': False,
            'backup_authenticated': False, 'authorized_to_write': False, 'authorized_to_restore': False}
