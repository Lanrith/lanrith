"""Repair one signed OS slot offline while preserving GPT and encrypted state."""

from contextlib import contextmanager
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import stat
import struct
import tempfile

from . import (factory, image_contract, measured_boot, recovery_authority, recovery_inputs,
               recovery_state, release, update, early_unlock)


def plan(manifest, rows, disk, esp_uuid):
    """Select partitions by signed UUID, never by a free-form device or slot name."""
    release.require(manifest['purpose'] == 'update' and manifest['architecture'] == 'x86-64' and
                    'image_contract' in manifest, 'Slot repair requires a steady-state signed update.')
    artifacts = {item['role']: item for item in manifest['artifacts']}
    sequence, image = manifest['deployment_sequence'], manifest['image_id']
    release.require(set(artifacts) == set(update.GUIDS) | {'uki'} and
                    artifacts['uki']['name'] == f'{image}_{sequence}.efi', 'Invalid repair payload.')
    selected = {}
    uuids = {esp_uuid}
    for role, guid in update.GUIDS.items():
        artifact = artifacts[role]
        match = re.fullmatch(re.escape(f'{image}_{sequence}_')+r'('+update.UUID+r')\.'+re.escape(role)+r'\.raw', artifact['name'])
        release.require(match is not None and match[1] not in uuids and
                        sum(row.get('uuid') == match[1] for row in rows) == 1,
                        'Invalid or ambiguous repair partition identity.')
        uuids.add(match[1])
        matches = [row for row in rows if row.get('disk') == disk and row.get('type') == guid and
                   row.get('uuid') == match[1] and row.get('label') == f'l_{sequence}_{role.replace("-", "_")}' and
                   not row.get('mounted') and type(row.get('size')) is int and row['size'] >= artifact['size']]
        release.require(len(matches) == 1 and
                        sum(row.get('type') == guid and row.get('label') == matches[0]['label'] for row in rows) == 1,
                        'Bound repair partition is absent, busy or undersized.')
        selected[role] = matches[0]['device']
    esp = recovery_inputs.partition(rows, disk, esp_uuid, recovery_inputs.ESP_GUID)
    state = [row for row in rows if row.get('disk') == disk and row.get('type') == factory.VAR_GUID and
             row.get('label') == 'var' and not row.get('mounted')]
    release.require(len(state) == 1 and len(set(selected.values()) | {esp, state[0]['device']}) == 5,
                    'Repair and encrypted state partitions overlap or are ambiguous.')
    return selected, esp, state[0]['device']


def require_target(descriptor, target, size):
    identity = os.fstat(descriptor)
    release.require(stat.S_ISBLK(identity.st_mode) and identity.st_rdev == os.stat(target).st_rdev and
                    struct.unpack('Q', fcntl.ioctl(descriptor, 0x80081272, bytes(8)))[0] >= size,
                    'Repair target changed or lacks capacity.')


def copy_partition(source, target, record, *, check):
    """Bound every read and write and verify a pinned exclusive block target."""
    source_fd = os.open(source, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(source_fd)
        release.require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_size == record['size'],
                        'Repair source is unsafe or changed.')
        target_fd = os.open(target, os.O_RDWR | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            require_target(target_fd, target, record['size'])
            digest, offset = hashlib.sha256(), 0
            while offset < record['size']:
                if offset % (64*1024*1024) == 0:
                    check()
                chunk = os.read(source_fd, min(4*1024*1024, record['size']-offset))
                release.require(chunk, 'Repair source is truncated.')
                digest.update(chunk)
                written = 0
                while written < len(chunk):
                    count = os.pwrite(target_fd, chunk[written:], offset+written)
                    release.require(count > 0, 'Repair target write failed.')
                    written += count
                offset += len(chunk)
            release.require(not os.read(source_fd, 1) and digest.hexdigest() == record['sha256'],
                            'Repair source changed while writing.')
            os.fsync(target_fd)
            observed, offset = hashlib.sha256(), 0
            while offset < record['size']:
                chunk = os.pread(target_fd, min(4*1024*1024, record['size']-offset), offset)
                release.require(chunk, 'Repair read-back is truncated.')
                observed.update(chunk)
                offset += len(chunk)
            release.require(observed.hexdigest() == record['sha256'], 'Repair read-back differs from the signed payload.')
            check()
        finally:
            os.close(target_fd)
    finally:
        os.close(source_fd)


@contextmanager
def writable(disk, rows, selected):
    """Keep every other partition read-only, including state and the other slot."""
    for row in rows:
        update.command(['blockdev', '--setro', row['device']])
    try:
        update.command(['blockdev', '--setrw', disk])
        for device in selected:
            update.command(['blockdev', '--setrw', device])
        yield
    finally:
        try:
            for device in selected:
                update.command(['blockdev', '--setro', device])
        finally:
            update.command(['blockdev', '--setro', disk])


def repair_slot(value, secret, *, confirm):
    release.require(recovery_authority.permits('repair', value) and callable(confirm),
                    'OS slot repair is not admitted by this recovery image.')
    disk = recovery_inputs.canonical_disk(value['disk_by_id'])
    source_disk = recovery_inputs.canonical_disk(value['offline_inputs']['release_disk_by_id'])
    recovery_disk, _ = factory.verified_root('/sysroot')
    release.require(disk not in (source_disk, recovery_disk), 'Repair target overlaps its recovery or source disk.')
    before = recovery_inputs.disk_snapshot(disk)
    rows = before[1]
    release.require(all(not row.get('mounted') for row in rows), 'Repair target is mounted or held.')
    source_before = recovery_inputs.disk_snapshot(source_disk)
    source_device = recovery_inputs.partition(source_before[1], source_disk,
        value['offline_inputs']['release_partition_uuid'], recovery_inputs.LINUX_GUID, label='lanrith-recovery-input')
    for row in rows:
        update.command(['blockdev', '--setro', row['device']])
    update.command(['blockdev', '--setro', disk])
    update.command(['blockdev', '--setro', source_disk])
    update.command(['blockdev', '--setro', source_device])
    installed = json.loads(release.read(Path('/sysroot/usr/share/lanrith/installed.json'), 65536), object_pairs_hook=release.unique)
    with recovery_inputs.mounted(source_device, 'ext4') as point:
        source = point/'release'
        certificate = Path('/sysroot/usr/share/lanrith/owner.crt')
        manifest = release.verify(source, certificate, purpose='update', image_id=value['image_id'])
        image_contract.compatible(installed['image_contract'], manifest['image_contract'])
        selected, esp, state = plan(manifest, rows, disk, value['offline_inputs']['target_esp_uuid'])
        artifacts = {item['role']: item for item in manifest['artifacts']}
        if installed.get('tpm_policy'):
            measured_boot.verify(source/artifacts['uki']['name'], installed['tpm_policy'])
        luks = json.loads(update.command(['cryptsetup', 'luksDump', '--dump-json-metadata', state]))
        factory.enrollment_tokens(luks, tpm_required=installed['boot'].get('tpm', 'required') == 'required',
                                  policy=installed.get('tpm_policy'))
        if installed.get('tpm_policy'):
            early_unlock.in_initrd()
            release.require(all(early_unlock.token_test(state, identifier) for identifier, token in luks['tokens'].items()
                                if token.get('type') == 'systemd-tpm2'),
                            'Repaired image TPM policy cannot unlock this state on the current firmware.')
        with recovery_state.open_readonly(disk, value['state_uuid'], secret) as state_mount:
            retained = recovery_state.retained_contract(state_mount)
            release.require(retained['machine_id'] == manifest['image_contract']['machine_id'], 'Repair state belongs to another machine.')
            for name in retained['state'].keys() & manifest['image_contract']['state'].keys():
                release.require(retained['state'][name]['writes'] in manifest['image_contract']['state'][name]['reads'],
                                'Repair image cannot read retained state.')
        digest = hashlib.sha256(release.canonical(manifest)).hexdigest()
        release.require(confirm(manifest['deployment_sequence'], digest) == str(manifest['deployment_sequence']),
                        'OS slot repair was not confirmed.')
        esp_mounted = False
        non_targets = {row['device'] for row in rows} - set(selected.values()) - {esp}
        def check():
            factory.secure_boot()
            release.require(recovery_inputs.canonical_disk(value['disk_by_id']) == disk and
                            recovery_inputs.canonical_disk(value['offline_inputs']['release_disk_by_id']) == source_disk and
                            all(update.command(['blockdev', '--getro', device]).strip() == '1' for device in non_targets),
                            'Repair disk identity or state protection changed.')
            recovery_inputs.stable_snapshot(disk, before, esp if esp_mounted else None)
            recovery_inputs.stable_snapshot(source_disk, source_before, source_device)
            recovery_inputs.verify_mount(point, source_device, 'ext4')
        check()
        with writable(disk, rows, set(selected.values()) | {esp}):
            for role in ('root', 'verity', 'verity-sig'):
                copy_partition(source/artifacts[role]['name'], selected[role], artifacts[role], check=check)
            mount = Path(tempfile.mkdtemp(prefix='lanrith-repair-esp.', dir='/run'))
            temporary = None
            try:
                update.command(['mount', '-t', 'vfat', '-o', 'ro,nodev,nosuid,noexec,umask=0077', '--', esp, str(mount)])
                esp_mounted = True
                release.require(mount.is_mount() and update.boot_esp({'esp': str(mount)}, disk=disk) == mount,
                                'Repair ESP did not mount on the bound disk.')
                folder = mount/'EFI/Linux'
                release.require(folder.is_dir() and not folder.is_symlink(), 'Repair EFI directory is unavailable.')
                name = artifacts['uki']['name']
                release.require(artifacts['uki']['size'] <= 512*1024*1024, 'Repair UKI exceeds its memory bound.')
                matches = [p for p in folder.iterdir() if re.fullmatch(re.escape(name[:-4])+r'(?:\+[0-9]+(?:-[0-9]+)?)?\.efi', p.name)]
                release.require(len(matches) <= 1 and all(p.is_file() and not p.is_symlink() for p in matches),
                                'Repair UKI identity is ambiguous.')
                temporary = mount/'EFI'/('lanrith-repair-'+secrets.token_hex(16)+'.tmp')
                data = release.read(source/name, artifacts['uki']['size'])
                release.require(len(data) == artifacts['uki']['size'] and hashlib.sha256(data).hexdigest() == artifacts['uki']['sha256'],
                                'Repair UKI changed.')
                with update.writable_esp({'esp': str(mount)}, esp=mount):
                    try:
                        with temporary.open('xb') as output:
                            output.write(data); output.flush(); os.fsync(output.fileno())
                        check()
                        os.replace(temporary, folder/name)
                        update.command(['sync', '-f', str(mount)])
                        for old in matches:
                            if old.name != name:
                                old.unlink()
                        update.command(['sync', '-f', str(mount)])
                        release.require(release.file_record(folder/name)['sha256'] == artifacts['uki']['sha256'], 'Repair UKI read-back differs.')
                    finally:
                        temporary.unlink(missing_ok=True)
                recovery_inputs.verify_mount(mount, esp, 'vfat')
            finally:
                if mount.is_mount():
                    update.command(['umount', '--', str(mount)])
                    release.require(not mount.is_mount(), 'Repair ESP remains mounted.')
                    esp_mounted = False
                mount.rmdir()
            check()
        check()
        release.require(json.loads(update.command(['cryptsetup', 'luksDump', '--dump-json-metadata', state])) == luks,
                        'Encrypted state metadata changed during OS repair.')
    return {'schema': 1, 'scope': 'offline-slot-repair', 'deployment_sequence': manifest['deployment_sequence'],
            'state_preserved': True, 'authorized_to_boot': False}
