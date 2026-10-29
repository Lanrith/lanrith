"""Authenticated offline recovery console with explicitly bound operations."""

import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import termios

from . import factory, release, repair, update


POLICY = Path('/usr/share/lanrith/recovery-console.json')
CREDENTIAL = Path('/usr/share/lanrith/recovery-console.hash')
RELEASE = Path('/run/lanrith/recovery/release')
ESP = Path('/run/lanrith/recovery/esp')
CERTIFICATE = Path('/sysroot/usr/share/lanrith/owner.crt')
HASH = re.compile(r'scrypt:32768:8:1:([0-9a-f]{32}):([0-9a-f]{64})\n?\Z')


def policy(value):
    required = {'schema', 'tty', 'image_id', 'disk_by_id'}
    release.require(isinstance(value, dict) and required <= set(value) and
                    set(value) <= required | {'state_uuid', 'offline_inputs', 'offline_backup', 'operations'} and
                    type(value['schema']) is int and value['schema'] == 1 and
                    isinstance(value['tty'], str) and
                    re.fullmatch(r'(?:tty(?:S|AMA|USB|ACM)|hvc)[0-9]{1,3}', value['tty']) and
                    isinstance(value['image_id'], str) and re.fullmatch(r'[a-z][a-z0-9-]{0,47}', value['image_id']) and
                    isinstance(value['disk_by_id'], str) and re.fullmatch(
                        r'/dev/disk/by-id/[A-Za-z0-9_.:+-]{1,180}', value['disk_by_id']) and
                    value['disk_by_id'].rsplit('/', 1)[-1] not in ('.', '..') and
                    not re.search(r'-part[0-9]+$', value['disk_by_id']),
                    'Invalid recovery console policy.')
    if 'state_uuid' in value:
        release.require(isinstance(value['state_uuid'], str) and re.fullmatch(update.UUID, value['state_uuid']),
                        'Invalid recovery state binding.')
    if 'offline_inputs' in value:
        inputs = value['offline_inputs']
        release.require(isinstance(inputs, dict) and set(inputs) ==
                        {'release_disk_by_id', 'release_partition_uuid', 'target_esp_uuid'} and
                        isinstance(inputs['release_disk_by_id'], str) and re.fullmatch(
                            r'/dev/disk/by-id/[A-Za-z0-9_.:+-]{1,180}', inputs['release_disk_by_id']) and
                        inputs['release_disk_by_id'].rsplit('/', 1)[-1] not in ('.', '..') and
                        not re.search(r'-part[0-9]+$', inputs['release_disk_by_id']) and
                        inputs['release_disk_by_id'] != value['disk_by_id'] and
                        all(isinstance(inputs[name], str) and re.fullmatch(update.UUID, inputs[name])
                            for name in ('release_partition_uuid', 'target_esp_uuid')) and
                        inputs['release_partition_uuid'] != inputs['target_esp_uuid'],
                        'Invalid offline recovery input binding.')
    if 'offline_backup' in value:
        from . import recovery_backup_preflight
        binding = recovery_backup_preflight.policy(value['offline_backup'])
        release.require('state_uuid' in value and binding['state_uuid'] == value['state_uuid'] and
                        binding['target_disk_by_id'] == value['disk_by_id'],
                        'Offline backup differs from the recovery target.')
    if 'operations' in value:
        operations = value['operations']
        release.require(isinstance(operations, list) and operations and
                        operations == [name for name in ('repair', 'backup', 'restore') if name in operations] and
                        (not ({'backup', 'restore'} & set(operations)) or 'offline_backup' in value) and
                        ('repair' not in operations or 'state_uuid' in value and 'offline_inputs' in value),
                        'Invalid recovery write operations.')
    return value


def protected_file(path, maximum, *, private):
    info = path.lstat()
    release.require(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and info.st_nlink == 1 and
                    not info.st_mode & (0o077 if private else 0o022), 'Unsafe recovery console input.')
    return release.read(path, maximum)


def verify_secret(secret, stored):
    match = HASH.fullmatch(stored)
    if match is None or not isinstance(secret, bytearray) or not 1 <= len(secret) <= 512 or b'\0' in secret:
        return False
    try:
        actual = hashlib.scrypt(secret, salt=bytes.fromhex(match[1]), n=32768, r=8, p=1,
                                dklen=32, maxmem=64*1024*1024)
    except (ValueError, MemoryError):
        return False
    return hmac.compare_digest(actual, bytes.fromhex(match[2]))


def secret_from_tty(stream, output, *, prompt='Recovery passphrase: '):
    """Read a bounded secret with echo disabled; never log or pass it as an argument."""
    descriptor = stream.fileno()
    saved = termios.tcgetattr(descriptor)
    changed = list(saved)
    changed[3] &= ~termios.ECHO
    try:
        termios.tcsetattr(descriptor, termios.TCSAFLUSH, changed)
        release.require(prompt in ('Recovery passphrase: ', 'Offline recovery key: '), 'Invalid recovery prompt.')
        output.write(prompt)
        output.flush()
        data = stream.readline(514)
    finally:
        termios.tcsetattr(descriptor, termios.TCSAFLUSH, saved)
        output.write('\n')
        output.flush()
    if not isinstance(data, bytes) or not data.endswith(b'\n') or len(data) > 513:
        return bytearray()
    return bytearray(data.rstrip(b'\r\n'))


def fixed_menu(value, *, read_command, write, inspect, read_state_key=None, inspect_state=None,
               read_restore_key=None, restore=None, read_backup_key=None, backup=None,
               read_repair_key=None, repair_slot=None):
    """Accept fixed commands only after the entry point has authenticated."""
    commands = 'status, inspect, inspect-state, exit' if 'state_uuid' in value else 'status, inspect, exit'
    restore_available = 'offline_backup' in value and callable(read_restore_key) and callable(restore)
    backup_available = 'offline_backup' in value and callable(read_backup_key) and callable(backup)
    repair_available = 'repair' in value.get('operations', []) and callable(read_repair_key) and callable(repair_slot)
    if repair_available:
        commands += ', repair'
    if backup_available:
        commands += ', backup'
    if restore_available:
        commands += ', restore'
    if repair_available:
        write('Recovery console: '+commands+'. Repair replaces one OS slot and preserves encrypted state.\n')
    elif restore_available or backup_available:
        write('Recovery console: '+commands+'. '+('Restore replaces encrypted state.' if restore_available else
                                                  'Backup writes to the bound backup media.')+'\n')
    else:
        write('Recovery console: '+commands+'. No boot or disk writes are available.\n')
    for _ in range(32):
        command = read_command()
        if not isinstance(command, str) or len(command) > 82:
            write('Invalid command.\n')
            return
        if command == 'exit':
            return
        if command == 'status':
            write('Recovery environment active. Slot selection is not available.'+
                  (' Confirmed OS slot repair is available.\n' if repair_available else
                  (' Restore is gated and destructive.\n' if restore_available else
                   ' Backup is gated.\n' if backup_available else ' Repair is not available.\n')))
        elif command == 'repair' and repair_available:
            secret = read_repair_key()
            try:
                def confirm(sequence, digest):
                    release.require(type(sequence) is int and 1 <= sequence <= 999999999 and
                                    isinstance(digest, str) and re.fullmatch(r'[0-9a-f]{64}', digest),
                                    'Invalid OS repair confirmation.')
                    write('Repair deployment '+str(sequence)+'. Manifest SHA-256: '+digest+'\n')
                    write('Encrypted state and the other OS slot are preserved. Type the deployment number: ')
                    return read_command()
                result = repair_slot(value, secret, confirm=confirm)
                release.require(result.get('state_preserved') is True and result.get('authorized_to_boot') is False and
                                type(result.get('deployment_sequence')) is int, 'Invalid OS repair result.')
                write('OS slot repaired. Remove recovery media and select deployment '+str(result['deployment_sequence'])+' in the boot menu.\n')
            except (release.ReleaseError, OSError, ValueError, KeyError, subprocess.SubprocessError):
                write('OS slot repair failed. Encrypted state was preserved; retain the signed release for retry.\n')
            finally:
                if isinstance(secret, bytearray):
                    for index in range(len(secret)):
                        secret[index] = 0
        elif command == 'inspect':
            try:
                result = inspect(value)
                release.require(isinstance(result, dict) and result.get('authorized_to_boot') is False and
                                type(result.get('deployment_sequence')) is int and
                                1 <= result['deployment_sequence'] <= 999999999,
                                'Invalid recovery inspection result.')
                write('Signed slot inspection passed for deployment '+str(result['deployment_sequence'])+
                      '. Boot compatibility is not established.\n')
            except (release.ReleaseError, OSError, ValueError, KeyError, subprocess.SubprocessError):
                write('Slot inspection failed. Check the offline release, disk, and read-only ESP.\n')
        elif command == 'backup' and backup_available:
            binding = value['offline_backup']
            write('Back up encrypted state from '+binding['target_disk_by_id']+' to '+
                  binding['backup_disk_by_id']+'. Type BACKUP to confirm: ')
            if read_command() != 'BACKUP':
                write('Backup cancelled.\n')
                continue
            secret = read_backup_key()
            try:
                result = backup(value, secret)
                release.require(isinstance(result, dict) and result.get('authorized_to_restore') is False and
                                isinstance(result.get('backup_id'), str) and
                                re.fullmatch(r'backup-[0-9a-f]{32}', result['backup_id']),
                                'Invalid backup result.')
                write('Backup created: '+result['backup_id']+'.\n')
                if 'operations' in value:
                    measurement = result.get('measurement_sha256')
                    release.require(isinstance(measurement, str) and re.fullmatch(r'[0-9a-f]{64}', measurement),
                                    'Backup receipt is missing.')
                    write('Keep this receipt separately from the backup media. SHA-256: '+measurement+'\n')
            except (release.ReleaseError, OSError, ValueError, KeyError, subprocess.SubprocessError):
                write('Backup failed. Check the source and backup media before retrying.\n')
            finally:
                if isinstance(secret, bytearray):
                    for index in range(len(secret)):
                        secret[index] = 0
        elif command == 'restore' and restore_available:
            write('Enter backup ID: ')
            name = read_command()
            if not isinstance(name, str) or re.fullmatch(r'backup-[0-9a-f]{32}', name) is None:
                write('Invalid backup ID.\n')
                continue
            secret = read_restore_key()
            try:
                def confirm(backup_id, measurement):
                    release.require(backup_id == name and isinstance(measurement, str) and
                                    re.fullmatch(r'[0-9a-f]{64}', measurement),
                                    'Invalid recovery confirmation.')
                    write('Restoring '+backup_id+' replaces encrypted state. Backup measurement: '+measurement+'\n')
                    if 'operations' in value:
                        write('Enter the SHA-256 from your separately stored backup receipt: ')
                        expected = read_command()
                        release.require(expected == measurement, 'Backup receipt differs.')
                    write('Type the backup ID to confirm: ')
                    selected = read_command()
                    return {'backup_id': selected, 'measurement_sha256': expected} if 'operations' in value else selected
                result = restore(value, name, secret, confirm)
                release.require(isinstance(result, dict) and result.get('authorized_to_boot') is False,
                                'Invalid restore result.')
                write('Restore completed. Boot compatibility is not established.\n')
            except (release.ReleaseError, OSError, ValueError, KeyError, subprocess.SubprocessError):
                write('Restore failed. The backup was retained; check the target before retrying.\n')
            finally:
                if isinstance(secret, bytearray):
                    for index in range(len(secret)):
                        secret[index] = 0
        elif command == 'inspect-state' and 'state_uuid' in value and read_state_key and inspect_state:
            secret = read_state_key()
            try:
                inventory = inspect_state(value, secret)
                release.require(inventory in ('available', 'missing'), 'Invalid retained inventory observation.')
                write('Encrypted state opened read-only. Retained inventory '+inventory+'.\n')
            except release.ReleaseError as error:
                # These are fixed internal messages, never command output or
                # credential data. All other failures remain generic.
                details = {'Recovery key operation failed.': 'key or volume',
                           'Update command failed: mount': 'read-only filesystem mount',
                           'Recovery state cannot be on the recovery boot disk.': 'target disk',
                           'Encrypted recovery state is absent, ambiguous or in use.': 'target state',
                           'Recovery state belongs to another encrypted volume.': 'state identity',
                           'Recovery state geometry differs from GPT.': 'target geometry',
                           'Recovery GPT geometry is invalid.': 'target geometry',
                           'Recovery GPT extents overlap or repeat.': 'target geometry',
                           'Recovery GPT exceeds the selected disk.': 'target geometry',
                           'Recovery backing device is not read-only.': 'read-only backing',
                           'Recovered state device is not read-only.': 'read-only mapping',
                           'Recovery read-only device missing.': 'read-only device missing',
                           'Recovery read-only device denied.': 'read-only device denied',
                           'Recovery read-only check unavailable.': 'read-only device unavailable',
                           'Recovery read-only check failed.': 'read-only device check',
                           'Recovery device is not read-only.': 'read-only device check',
                           'Update command failed: dmsetup': 'read-only mapping',
                           'Update command failed: blockdev': 'read-only device check',
                           'Update command failed: cryptsetup': 'encrypted metadata',
                           'Update command failed: udevadm': 'device discovery',
                           'Factory and boot checks require a read-only root.': 'recovery boot root',
                           'Root is not a block-device mapping.': 'recovery boot root',
                           'Root is not a device-mapper verified filesystem.': 'recovery boot root',
                           'dm-verity root status is not valid.': 'recovery boot root',
                           'Verified root does not identify one physical/virtual disk.': 'recovery boot root'}
                detail = details.get(str(error))
                write('State inspection failed'+(' ('+detail+')' if detail else '')+'.\n')
            except (OSError, ValueError, KeyError, subprocess.SubprocessError):
                write('State inspection failed.\n')
            finally:
                if isinstance(secret, bytearray):
                    for index in range(len(secret)):
                        secret[index] = 0
        else:
            write('Unknown command.\n')
    write('Session limit reached.\n')


def inspect_configured(value):
    disk = Path(value['disk_by_id']).resolve(strict=True)
    release.require(disk.parent == Path('/dev') and re.fullmatch(r'[A-Za-z0-9_.-]+', disk.name),
                    'Recovery disk is not a canonical block device.')
    # The release authority is embedded in the verified recovery root. Never
    # treat a writable or target-installed root as an independent authority.
    factory.secure_boot()
    boot_disk, _ = factory.verified_root('/sysroot')
    release.require(str(disk) != boot_disk, 'Recovery slot cannot be on the recovery boot disk.')
    if 'offline_inputs' in value:
        from . import recovery_inputs
        return recovery_inputs.inspect(value, target_disk=str(disk), recovery_disk=boot_disk, certificate=CERTIFICATE)
    return repair.inspect_slot(RELEASE, CERTIFICATE, image_id=value['image_id'], disk=str(disk), esp=ESP)


def inspect_state_configured(value, secret):
    from . import recovery_state
    disk = Path(value['disk_by_id']).resolve(strict=True)
    release.require(disk.parent == Path('/dev') and re.fullmatch(r'[A-Za-z0-9_.-]+', disk.name),
                    'Recovery disk is not a canonical block device.')
    # Opening and verifying the restricted mount is the entire operation. No
    # path or file contents from persistent state are exposed through the UI.
    factory.secure_boot()
    with recovery_state.open_readonly(str(disk), value['state_uuid'], secret) as point:
        try:
            recovery_state.retained_contract(point)
        except FileNotFoundError:
            return 'missing'
        return 'available'


def qualified_operations(backup_device, preflight, restore, target, transaction):
    """Require every independent qualification gate for each operation."""
    protection = preflight.READONLY_PREPARATION_QUALIFIED is True
    return (protection and backup_device.BACKUP_WRITE_QUALIFIED is True,
            protection and restore.RESTORE_WORKFLOW_QUALIFIED is True and
            restore.BACKUP_FRESHNESS_QUALIFIED is True and
            target.TARGET_CLAIM_QUALIFIED is True and transaction.RESTORE_WRITE_QUALIFIED is True)


def main():
    release.require(os.geteuid() == 0 and Path('/etc/initrd-release').is_file(),
                    'Recovery console requires its verified initrd.')
    # Do not prompt for either credential until the recovery boot and root
    # have passed their basic integrity checks.
    factory.secure_boot()
    factory.verified_root('/sysroot')
    value = policy(json.loads(protected_file(POLICY, 4096, private=False), object_pairs_hook=release.unique,
                              parse_constant=lambda _: (_ for _ in ()).throw(ValueError('Invalid JSON number.'))))
    tty = Path('/dev')/value['tty']
    identity = tty.stat()
    release.require(stat.S_ISCHR(identity.st_mode) and sys.stdin.isatty() and sys.stdout.isatty() and
                    os.fstat(sys.stdin.fileno()).st_rdev == identity.st_rdev and
                    os.fstat(sys.stdout.fileno()).st_rdev == identity.st_rdev,
                    'Recovery console requires the configured physical terminal.')
    stored = protected_file(CREDENTIAL, 512, private=True).decode('ascii')
    release.require(HASH.fullmatch(stored) is not None, 'Recovery credential is invalid.')
    for _ in range(3):
        secret = secret_from_tty(sys.stdin.buffer, sys.stdout)
        try:
            admitted = verify_secret(secret, stored)
        finally:
            for index in range(len(secret)):
                secret[index] = 0
        if admitted:
            def read_command():
                sys.stdout.write('recovery> ')
                sys.stdout.flush()
                line = sys.stdin.readline(84)
                if not line.endswith('\n'):
                    return None
                return line.rstrip('\r\n')
            restore_fn = None
            backup_fn = None
            repair_fn = None
            if 'repair' in value.get('operations', []):
                from . import recovery_slot
                repair_fn = recovery_slot.repair_slot
            if 'offline_backup' in value:
                from . import (recovery_backup_device, recovery_backup_preflight, recovery_restore,
                               recovery_restore_target, recovery_restore_transaction)
                backup_qualified, restore_qualified = qualified_operations(
                    recovery_backup_device, recovery_backup_preflight, recovery_restore,
                    recovery_restore_target, recovery_restore_transaction)
                if {'backup', 'restore'} & set(value.get('operations', [])):
                    from . import recovery_authority
                    backup_qualified = recovery_authority.permits('backup', value['offline_backup'])
                    restore_qualified = recovery_authority.permits('restore', value['offline_backup'])
                if backup_qualified:
                    def backup_fn(policy, key):
                        recovery_backup_preflight.prepare_readonly(policy['offline_backup'], include_backup=False)
                        return recovery_backup_device.create(policy['offline_backup'], key, image_id=policy['image_id'])
                if restore_qualified:
                    def restore_fn(policy, name, key, confirm):
                        recovery_backup_preflight.prepare_readonly(policy['offline_backup'], include_backup=True)
                        return recovery_restore.restore(policy['offline_backup'], name, key,
                                                        image_id=policy['image_id'], confirm=confirm)
            fixed_menu(value, read_command=read_command, write=sys.stdout.write, inspect=inspect_configured,
                       read_state_key=lambda: secret_from_tty(sys.stdin.buffer, sys.stdout,
                                                            prompt='Offline recovery key: '),
                       inspect_state=inspect_state_configured,
                       read_restore_key=(lambda: secret_from_tty(sys.stdin.buffer, sys.stdout,
                                                                 prompt='Offline recovery key: ')) if restore_fn else None,
                       restore=restore_fn,
                       read_backup_key=(lambda: secret_from_tty(sys.stdin.buffer, sys.stdout,
                                                                prompt='Offline recovery key: ')) if backup_fn else None,
                       backup=backup_fn,
                       read_repair_key=(lambda: secret_from_tty(sys.stdin.buffer, sys.stdout,
                                                                prompt='Offline recovery key: ')) if repair_fn else None,
                       repair_slot=repair_fn)
            return 0
        sys.stdout.write('Authentication failed.\n')
        sys.stdout.flush()
    sys.stdout.write('Recovery session closed.\n')
    return 1
