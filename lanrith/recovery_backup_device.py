"""Back up encrypted state only from an explicitly admitted recovery initrd.

The signed policy binds independent disks and the offline key authenticates
state before backup writes. Legacy experimental gate hooks remain isolated.
"""

from contextlib import contextmanager
import json
from . import recovery_authority
import os
from pathlib import Path
import re
import secrets
import stat
import subprocess
import tempfile

from . import (factory, recovery_backup_auth, recovery_backup_files, recovery_backup_preflight, recovery_backup_verity,
               recovery_inputs, release, update)


BACKUP_WRITE_QUALIFIED = False


def check_key(device, secret):
    release.require(isinstance(secret, bytearray) and recovery_inputs.RECOVERY_KEY.fullmatch(secret) is not None,
                    'A systemd recovery key is required for encrypted backup.')
    try:
        raw = update.command(['cryptsetup', 'luksDump', '--dump-json-metadata', device])
        release.require(isinstance(raw, str) and len(raw) <= 1024*1024, 'Backup recovery-key metadata is invalid.')
        luks = json.loads(raw, object_pairs_hook=release.unique)
    except (ValueError, UnicodeError, RecursionError):
        raise release.ReleaseError('Backup recovery-key metadata is invalid.') from None
    release.require(isinstance(luks, dict) and isinstance(luks.get('tokens'), dict) and
                    isinstance(luks.get('keyslots'), dict) and len(luks['tokens']) <= 32 and
                    len(luks['keyslots']) <= 32, 'Backup recovery-key metadata is invalid.')
    slots = []
    for token in luks['tokens'].values():
        release.require(isinstance(token, dict), 'Backup recovery-key metadata is invalid.')
        if token.get('type') != 'systemd-recovery':
            continue
        keys = token.get('keyslots')
        release.require(isinstance(keys, list) and len(keys) == 1 and isinstance(keys[0], str) and
                        re.fullmatch(r'(?:0|[1-9][0-9]?)', keys[0]) and keys[0] in luks['keyslots'] and
                        int(keys[0]) < 32 and keys[0] not in slots, 'Backup recovery-key metadata is invalid.')
        slots.append(keys[0])
    release.require(1 <= len(slots) <= 4, 'Backup requires a systemd recovery keyslot.')
    try:
        valid = any(subprocess.run(['cryptsetup', 'open', '--test-passphrase', '--type', 'luks2',
                                    '--disable-external-tokens', '--key-slot', slot, '--key-file=-', device],
                                   input=secret, capture_output=True, timeout=120,
                                   env={'PATH': '/usr/sbin:/usr/bin', 'LC_ALL': 'C'}).returncode == 0
                    for slot in slots)
    except (OSError, subprocess.TimeoutExpired):
        raise release.ReleaseError('Backup recovery-key verification failed.') from None
    release.require(valid, 'Backup recovery-key verification failed.')


def verify_mount(point, device):
    observed = json.loads(update.command(['findmnt', '--uniq', '--json', '--target', str(point),
                                          '--output', 'SOURCE,FSTYPE,TARGET,OPTIONS']))
    rows = observed.get('filesystems') if isinstance(observed, dict) else None
    release.require(isinstance(rows, list) and len(rows) == 1 and isinstance(rows[0], dict) and
                    rows[0].get('target') == str(point) and rows[0].get('fstype') == 'ext4' and
                    isinstance(rows[0].get('source'), str) and rows[0]['source'].startswith('/dev/') and
                    Path(rows[0]['source']).resolve() == Path(device) and isinstance(rows[0].get('options'), str),
                    'Backup media mount differs from its binding.')
    options = set(rows[0]['options'].split(','))
    release.require({'rw', 'nodev', 'nosuid', 'noexec'} <= options and 'ro' not in options,
                    'Backup media mount is not restricted and writable.')


@contextmanager
def mounted_backup(device):
    """Mount only the already bound backup partition; never recursively clean up."""
    point = Path(tempfile.mkdtemp(prefix='lanrith-backup-media.', dir='/run'))
    try:
        update.command(['mount', '-t', 'ext4', '-o', 'rw,nodev,nosuid,noexec', '--', device, str(point)])
        release.require(point.is_mount(), 'Backup media did not mount.')
        verify_mount(point, device)
        yield point
        verify_mount(point, device)
    finally:
        if point.is_mount():
            update.command(['umount', '--', str(point)])
            release.require(not point.is_mount(), 'Backup media remains mounted.')
        point.rmdir()


def create(value, secret, *, image_id):
    """Create a backup after the gates; the caller must erase its secret buffer."""
    release.require(BACKUP_WRITE_QUALIFIED or recovery_authority.permits('backup', value), 'Offline backup writes are not qualified.')
    release.require(isinstance(image_id, str) and re.fullmatch(r'[a-z][a-z0-9-]{0,47}', image_id),
                    'Invalid offline backup image identity.')
    value = recovery_backup_preflight.policy(value)
    observation = recovery_backup_preflight.inspect(value)
    release.require(observation.get('authorized_to_write') is False and
                    observation.get('authorized_to_restore') is False,
                    'Unexpected backup preflight authority.')
    installed = json.loads(release.read(Path('/sysroot/usr/share/lanrith/installed.json'), 65536),
                           object_pairs_hook=release.unique)
    release.require(isinstance(installed, dict) and installed.get('image_id') == image_id,
                    'Offline backup image identity differs from the verified recovery root.')
    recovery_disk, _ = factory.verified_root('/sysroot')
    target = recovery_inputs.canonical_disk(value['target_disk_by_id'])
    backup = recovery_inputs.canonical_disk(value['backup_disk_by_id'])
    release.require(len({recovery_disk, target, backup}) == 3, 'Offline backup disks overlap.')
    target_layout, target_rows = recovery_inputs.disk_snapshot(target)
    backup_layout, backup_rows = recovery_inputs.disk_snapshot(backup)
    release.require(all(not row.get('mounted') for row in target_rows+backup_rows),
                    'Offline backup disks became busy.')
    state = recovery_inputs.partition(target_rows, target, value['state_partuuid'], factory.VAR_GUID, label='var')
    media = recovery_inputs.partition(backup_rows, backup, value['backup_partuuid'],
                                      recovery_inputs.LINUX_GUID, label='lanrith-backup')
    state_rows = [row for row in target_rows if row.get('device') == state]
    media_rows = [row for row in backup_rows if row.get('device') == media]
    release.require(len(state_rows) == len(media_rows) == 1 and
                    state_rows[0].get('size') == observation['state_size'] and
                    media_rows[0].get('size') == observation['backup_size'],
                    'Offline encrypted state capacity changed.')
    release.require(update.command(['blockdev', '--getro', target]).strip() == '1' and
                    update.command(['blockdev', '--getro', state]).strip() == '1',
                    'Offline encrypted state is not read-only.')
    check_key(state, secret)
    source = os.open(state, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    try:
        initial = os.fstat(source)
        release.require(stat.S_ISBLK(initial.st_mode) and os.stat(state).st_rdev == initial.st_rdev,
                        'Offline encrypted state device changed.')
        with mounted_backup(media) as point:
            directory = point/'lanrith-backups'
            value_for_mac = recovery_backup_auth.descriptor({'schema': 1, 'image_id': image_id,
                'volume_uuid': value['state_uuid'], 'size': observation['state_size'], 'salt': secrets.token_hex(32)})
            def revalidate():
                factory.secure_boot()
                release.require(factory.verified_root('/sysroot')[0] == recovery_disk and
                                recovery_inputs.canonical_disk(value['target_disk_by_id']) == target and
                                recovery_inputs.canonical_disk(value['backup_disk_by_id']) == backup and
                                recovery_inputs.disk_snapshot(target) == (target_layout, target_rows),
                                'Offline backup source binding changed.')
                recovery_inputs.stable_snapshot(backup, (backup_layout, backup_rows), media)
                verify_mount(point, media)
                current = os.fstat(source)
                release.require(stat.S_ISBLK(current.st_mode) and current.st_rdev == initial.st_rdev and
                                os.stat(state).st_rdev == initial.st_rdev and
                                update.command(['blockdev', '--getro', target]).strip() == '1' and
                                update.command(['blockdev', '--getro', state]).strip() == '1' and
                                update.command(['cryptsetup', 'luksUUID', state]).strip().lower() == value['state_uuid'],
                                'Offline encrypted state is not stable and read-only.')
            name = recovery_backup_files._publish(directory, source, secret, value_for_mac, revalidate,
                                                   protect=recovery_backup_verity.enable)
            verified = recovery_backup_files.inspect(directory, name, secret, image_id=image_id,
                                                      volume_uuid=value['state_uuid'], require_verity=True)
            release.require(verified.get('authorized_to_restore') is False,
                            'Backup inspection unexpectedly authorized restoration.')
            revalidate()
        return {'schema': 1, 'scope': 'offline-encrypted-backup', 'backup_id': name,
                'measurement_sha256': verified['measurement_sha256'], 'authorized_to_restore': False}
    finally:
        os.close(source)
