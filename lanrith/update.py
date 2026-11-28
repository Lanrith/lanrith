"""Plan an A/B update from authenticated artifacts and observed partition geometry."""

from __future__ import annotations

import errno
import fcntl
import hashlib
from contextlib import contextmanager
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import stat
import tempfile
import time

from .release import ReleaseError, authenticated_manifest, document, require, read, verify


IMAGE_LOCK_DIR = Path('/run/lanrith-image-locks')
OPERATION_LOCK_NAME = 'lanrith-image-operation.lock'
PARTITION_ROLES = ('verity-sig', 'verity', 'root')
GUIDS = {'root': '4f68bce3-e8cd-4db1-96e7-fbcaf984b709',
         'verity': '2c7357ed-ebd2-46d9-aec1-23d437ec2bf5',
         'verity-sig': '41092b05-9fc8-4523-994f-2def0408b176'}
UUID = r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}'


def command(arguments, timeout=30):
    try:
        result = subprocess.run(arguments, stdin=subprocess.DEVNULL, capture_output=True,
                                text=True, timeout=timeout, env={'PATH': '/usr/sbin:/usr/bin', 'LC_ALL': 'C'})
    except subprocess.TimeoutExpired as error:
        from .release import ReleaseError
        raise ReleaseError('Update command timed out: '+Path(arguments[0]).name) from error
    except OSError as error:
        from .release import ReleaseError
        raise ReleaseError('Update command could not start: '+Path(arguments[0]).name) from error
    require(result.returncode == 0, 'Update command failed: ' + Path(arguments[0]).name)
    return result.stdout


def layout_limits(storage):
    return {'root': storage['root_mib'] * 1024**2, 'verity': max(64, storage['root_mib']//16) * 1024**2,
            'verity-sig': 16384, 'uki': (storage['esp_mib']-32) * 1024**2}


def plan(manifest, installed, partitions, *, disk, active_partitions, esp_available):
    """Select only inactive partitions; never infer a storage device from its name."""
    require(manifest['purpose'] == 'update' and manifest['architecture'] == 'x86-64',
            'Unsupported update purpose or hardware architecture.')
    sequence = manifest['deployment_sequence']
    require(type(installed.get('deployment_sequence')) is int and
            sequence > installed['deployment_sequence'], 'Update deployment sequence is not newer.')
    require(installed.get('layout') == 'ab-verity-v1', 'Unsupported installed layout.')
    require(isinstance(disk, str) and re.fullmatch(r'/dev/[A-Za-z0-9_.-]+', disk), 'Unsafe target disk.')
    require(isinstance(active_partitions, set) and len(active_partitions) >= 2 and
            all(type(number) is int and 1 <= number <= 128 for number in active_partitions),
            'Verified root dependencies are missing.')
    image = manifest['image_id']
    artifacts = {artifact['role']: artifact for artifact in manifest['artifacts']}
    require(set(artifacts) == {'uki', *PARTITION_ROLES}, 'Update artifact set is incomplete.')
    uki = artifacts['uki']
    require(uki['name'] == f'{image}_{sequence}.efi', 'UKI filename differs from the signed deployment identity.')
    require(type(esp_available) is int and esp_available >= uki['size'] + 32 * 1024 * 1024,
            'EFI filesystem lacks candidate and recovery reserves.')
    policy = installed.get('payload_limits')
    if policy is None and 'storage' in installed:
        policy = layout_limits(installed['storage'])
    selected = {}
    used_numbers = set()
    used_uuids = set()
    active_labels = installed.get('active_labels')
    require(isinstance(active_labels, dict) and set(active_labels) == set(PARTITION_ROLES),
            'Installed image does not declare its active slot labels.')
    for role in PARTITION_ROLES:
        candidates = [partition for partition in partitions if partition.get('type', '').lower() == GUIDS[role]]
        require(len(candidates) == 2, 'Expected exactly two slots for each verified-root partition type.')
        require(all(isinstance(p.get('uuid'), str) and re.fullmatch(UUID, p['uuid'].lower()) for p in candidates),
                'Verified-root slot UUIDs are missing or invalid.')
        active = [partition for partition in candidates if partition.get('label') == active_labels[role]]
        require(len(active) == 1, 'Cannot identify exactly one active partition for each role.')
        if role in ('root', 'verity'):
            require(active[0].get('number') in active_partitions,
                    'Installed labels do not match the mounted verified root dependencies.')
        inactive = [partition for partition in candidates if partition is not active[0]]
        require(len(inactive) == 1 and not inactive[0].get('mounted'), 'Inactive slot is ambiguous or mounted.')
        target = inactive[0]
        number = target.get('number')
        require(type(number) is int and 1 <= number <= 128 and number not in used_numbers,
                'Invalid or reused target partition number.')
        require(number not in active_partitions, 'A target is part of the mounted verified root.')
        require(target.get('disk') == disk and active[0].get('disk') == disk,
                'Slots do not belong to the observed root disk.')
        require(type(target.get('size')) is int and target['size'] >= artifacts[role]['size'],
                'Update exceeds an inactive partition capacity.')
        if policy is not None:
            require(isinstance(policy, dict) and type(policy.get(role)) is int and policy[role] > 0 and
                    artifacts[role]['size'] <= policy[role] <= target['size'],
                    'Inactive partition or payload differs from the signed capacity budget.')
        match = re.fullmatch(rf'{re.escape(image)}_{sequence}_({UUID})\.{re.escape(role)}\.raw',
                             artifacts[role]['name'])
        require(match is not None, 'Partition artifact filename differs from the signed deployment identity.')
        require(match[1] != '00000000-0000-0000-0000-000000000000' and match[1] not in used_uuids and
                not any(str(partition.get('uuid') or '').lower() == match[1] and partition.get('number') != number
                        for partition in partitions), 'Candidate UUID collides with another disk partition.')
        used_numbers.add(number)
        used_uuids.add(match[1])
        selected[role] = {'number': number, 'uuid': match[1],
                          'label': f'l_{sequence}_{role.replace("-", "_")}', 'type': GUIDS[role]}
    return {'schema': 1, 'disk': disk, 'sequence': sequence, 'image_id': image,
            'partitions': selected, 'uki': f'{image}_{sequence}.efi',
            'protected_sequence': installed['deployment_sequence']}


def transfers(value, root, esp):
    require(root.is_absolute() and esp.is_absolute() and
            re.fullmatch(r'/[A-Za-z0-9_./-]+', str(root)) and
            re.fullmatch(r'/[A-Za-z0-9_./-]+', str(esp)), 'Unsafe update transfer directory.')
    image, result = value['image_id'], {}
    for index, role in enumerate(PARTITION_ROLES, 51):
        target = value['partitions'][role]
        result[f'{index}-{role}.transfer'] = (
            f'[Transfer]\nProtectVersion={value["protected_sequence"]}\n\n'
            f'[Source]\nType=regular-file\nPath={root}\nPathRelativeTo=root\nMatchPattern={image}_@v_@u.{role}.raw\n'
            f'\n[Target]\nType=partition\nPath={value["disk"]}\n'
            f'MatchPattern=l_@v_{role.replace("-", "_")}\n'
            f'MatchPartitionType={target["type"]}\nReadOnly=yes\n')
    result['59-uki.transfer'] = (
        f'[Transfer]\nProtectVersion={value["protected_sequence"]}\n\n'
        f'[Source]\nType=regular-file\nPath={root}\nPathRelativeTo=root\nMatchPattern={image}_@v.efi\n'
        f'\n[Target]\nType=regular-file\nPath={esp}/EFI/Linux\nPathRelativeTo=root\n'
        f'MatchPattern={image}_@v+@l-@d.efi {image}_@v+@l.efi {image}_@v.efi\n'
        'TriesLeft=3\nTriesDone=0\nInstancesMax=2\n')
    return result


def mounted_root_device(mountpoint):
    require(mountpoint in ('/', '/sysroot'), 'Unsupported verified-root mountpoint.')
    source = command(['findmnt', '--noheadings', '--output', 'SOURCE', mountpoint]).strip()
    require(source.startswith('/dev/'), 'Root is not backed by a known block device.')
    info = os.stat(source)
    require(stat.S_ISBLK(info.st_mode) and info.st_rdev == os.stat(mountpoint).st_dev,
            'Block source differs from the mounted root filesystem.')
    # A /dev/mapper alias can itself be a block node when udev is unavailable.
    # Bind its device number to sysfs rather than interpreting the alias basename.
    sysdev = Path('/sys/dev/block')/f'{os.major(info.st_rdev)}:{os.minor(info.st_rdev)}'
    return source, sysdev.resolve(strict=True).name


def root_disk(mountpoint='/'):
    _, name = mounted_root_device(mountpoint)
    pending, seen, disks, numbers = [name], set(), set(), set()
    while pending:
        name = pending.pop()
        require(re.fullmatch(r'[A-Za-z0-9_.-]+', name) and len(seen) <= 128,
                'Invalid root device dependency graph.')
        if name in seen:
            continue
        seen.add(name)
        device = Path('/sys/class/block') / name
        if (device / 'partition').is_file():
            disks.add('/dev/' + device.resolve().parent.name)
            number = (device / 'partition').read_text().strip()
            require(number.isdecimal(), 'Invalid root partition number.')
            numbers.add(int(number))
        slaves = device / 'slaves'
        if slaves.is_dir():
            pending.extend(path.name for path in slaves.iterdir())
    require(len(disks) == 1, 'Verified root does not identify one physical/virtual disk.')
    return disks.pop(), numbers


def claimed(device):
    # A filesystem mounted in another mount namespace can be absent from lsblk.
    # Linux rejects an exclusive read-only open while the block device is claimed.
    try:
        descriptor = os.open(device, os.O_RDONLY | os.O_EXCL | os.O_NOFOLLOW | os.O_NONBLOCK)
    except OSError as error:
        if error.errno == errno.EBUSY:
            return True
        raise
    os.close(descriptor)
    return False


class StaleExtent(ReleaseError):
    pass


def geometry(disk, *, sysfs=Path('/sys/class/block')):
    for attempt in range(3):
        try:
            return _geometry(disk, sysfs=sysfs)
        except StaleExtent:
            if attempt == 2:
                raise
            time.sleep(0.25)


def _geometry(disk, *, sysfs=Path('/sys/class/block')):
    # Partition GUIDs and labels in udev can still describe the pre-repartition
    # disk after its kernel devices are ready. Read identity from the GPT itself;
    # use the kernel view for device numbers, capacity and in-use detection.
    table = json.loads(command(['sfdisk', '--json', disk]))['partitiontable']
    require(table.get('label') == 'gpt' and table.get('device') == disk and
            isinstance(table.get('id'), str) and re.fullmatch(UUID, table['id'].lower()) and
            table.get('unit') == 'sectors' and table.get('sectorsize') in (512, 4096),
            'Cannot bind GPT geometry to the observed disk.')
    entries = table.get('partitions', [])
    require(isinstance(entries, list) and 1 <= len(entries) <= 128 and
            all(isinstance(part, dict) and isinstance(part.get('node'), str) for part in entries),
            'GPT partition geometry is malformed.')
    partitions = {part['node']: part for part in entries}
    require(len(partitions) == len(entries), 'GPT contains duplicate partition devices.')
    data = json.loads(command(['lsblk', '--json', '--bytes', '--paths', '--output',
                              'NAME,TYPE,PKNAME,SIZE,MOUNTPOINTS', disk]))
    result, pending = [], list(data.get('blockdevices', []))
    seen = set()
    numbers = set()
    while pending:
        device = pending.pop()
        pending.extend(device.get('children', []))
        if device.get('type') != 'part':
            continue
        name = device.get('name')
        require(name in partitions and name not in seen and device.get('pkname') == disk,
                'Kernel partition devices differ from the selected GPT.')
        seen.add(name)
        part = partitions[name]
        kernel_device = sysfs/Path(name).name
        number = (kernel_device/'partition').read_text().strip()
        require(number.isdecimal() and 1 <= int(number) <= 128 and int(number) not in numbers,
                'Kernel partition numbers are invalid or duplicated.')
        number = int(number)
        numbers.add(number)
        start = (kernel_device/'start').read_text().strip()
        require(type(part.get('start')) is int and part['start'] > 0 and start.isdecimal() and
                type(part.get('size')) is int and part['size'] > 0 and type(device.get('size')) is int,
                'Partition extent is malformed.')
        offset = part['start'] * table['sectorsize']
        if (name != disk + ('p' if disk[-1].isdigit() else '') + str(number) or
                int(start)*512 != offset or device['size'] != part['size']*table['sectorsize']):
            raise StaleExtent('Kernel partition extent differs from the selected GPT.')
        require(all(isinstance(part.get(key), str) and re.fullmatch(UUID, part[key].lower())
                    for key in ('type', 'uuid')), 'GPT partition identities are malformed.')
        descendants, busy = [device], False
        while descendants:
            child = descendants.pop()
            busy = busy or any(child.get('mountpoints') or [])
            descendants.extend(child.get('children', []))
        holders = kernel_device/'holders'
        busy = busy or any(holders.iterdir()) or claimed(name)
        result.append({'disk': device.get('pkname'), 'device': name, 'number': number,
                       'type': part['type'].lower(), 'label': part.get('name'),
                       'uuid': part['uuid'].lower(), 'disk_uuid': table['id'].lower(), 'start_bytes': offset,
                       'size': device.get('size'), 'mounted': bool(busy)})
    require(seen == set(partitions), 'A GPT partition has no matching kernel device.')
    extents = sorted((row['start_bytes'], row['start_bytes'] + row['size']) for row in result)
    require(all(end <= following for (_, end), (following, _) in zip(extents, extents[1:])),
            'GPT partition extents overlap.')
    return result


def accepted_boot(current, expected, esp):
    require(current.is_absolute() and current.parent == esp / 'EFI/Linux' and
            re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.+-]{0,191}\.efi', expected), 'Invalid current boot identity.')
    stable = current.with_name(expected)
    require(stable.is_file() and not stable.is_symlink(), 'Accepted boot entry is absent.')
    if current.name == expected:
        return stable
    require(re.fullmatch(re.escape(expected[:-4]) + r'\+[0-9]+(?:-[0-9]+)?\.efi', current.name) and
            not current.exists() and not current.is_symlink(), 'Current boot is pending or differs from installed policy.')
    return stable


def _mounted_esp(installed, *, disk, allow_writable):
    """Resolve the mounted ESP and bind it to the observed verified-root disk."""
    selected = installed.get('esp', 'auto')
    esp = Path(command(['bootctl', '--print-esp-path']).strip() if selected == 'auto' else selected)
    require(esp.is_absolute() and esp.resolve() == esp and esp.is_dir() and
            esp.stat().st_uid == 0 and not esp.stat().st_mode & 0o022,
            'EFI mount path is unsafe.')
    # Crossing the automount first ensures findmnt observes vfat, not autofs.
    require((esp/'EFI').is_dir() and esp.is_mount(), 'EFI filesystem must be mounted.')
    # util-linux 2.41 can report both the autofs trigger and its mounted
    # filesystem for --target. --uniq selects the visible filesystem.
    mount = json.loads(command(['findmnt', '--uniq', '--json', '--target', str(esp/'EFI'),
                                '--output', 'SOURCE,FSTYPE,TARGET,OPTIONS']))
    rows = mount.get('filesystems', [])
    require(len(rows) == 1 and rows[0].get('target') == str(esp) and rows[0].get('fstype') == 'vfat' and
            isinstance(rows[0].get('source'), str) and rows[0]['source'].startswith('/dev/'),
            'EFI filesystem is not a mounted FAT block partition.')
    options = set((rows[0].get('options') or '').split(','))
    mode = options & {'ro', 'rw'}
    require({'nodev', 'nosuid', 'noexec'} <= options and
            (mode == {'ro'} or allow_writable and mode == {'rw'}),
            'EFI filesystem is not protected read-only at rest.')
    device = str(Path(rows[0]['source']).resolve())
    if disk is None:
        disk, _ = root_disk()
    # The initrd failure path may run after udev's database is cleaned up.
    # Bind the mounted device to the disk's GPT and kernel geometry directly;
    # lsblk PARTTYPE is udev metadata and may be absent at that point.
    esp_type = 'c12a7328-f81f-11d2-ba4b-00a0c93ec93b'
    devices = geometry(disk)
    if allow_writable:
        require(sum(row['type'] == esp_type for row in devices) == 1, 'Interrupted EFI partition is ambiguous.')
    partitions = [row for row in devices if row.get('device') == device]
    require(len(partitions) == 1 and partitions[0].get('disk') == disk and partitions[0].get('type') == esp_type,
            'EFI partition differs from the verified root disk.')
    return esp, partitions[0], mode == {'rw'}


def boot_esp(installed, *, disk=None):
    esp, _, _ = _mounted_esp(installed, disk=disk, allow_writable=False)
    return esp


def restore_esp(installed):
    """Close a stopped worker's verified write window and read back the mount."""
    disk, _ = root_disk()
    esp, partition, writable = _mounted_esp(installed, disk=disk, allow_writable=True)
    if writable:
        command(['mount', '--options', 'remount,ro,nodev,nosuid,noexec', '--', str(esp)])
        observed, current, _ = _mounted_esp(installed, disk=disk, allow_writable=False)
        require(observed == esp and current == partition, 'EFI partition changed during restoration.')
    return esp


@contextmanager
def writable_esp(installed, *, esp=None):
    """Open the verified ESP for one bounded mutation and restore it read-only."""
    esp = boot_esp(installed) if esp is None else esp
    require(esp.is_absolute() and esp.is_mount(), 'EFI filesystem must be mounted.')
    command(['mount', '--options', 'remount,rw,nodev,nosuid,noexec', '--', str(esp)])
    try:
        yield esp
        descriptor = os.open(esp, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    finally:
        # A failed close is an update failure: never report success while the
        # normal read-only-at-rest boundary has not been restored.
        command(['mount', '--options', 'remount,ro,nodev,nosuid,noexec', '--', str(esp)])


DEFAULT_VARIABLE = Path('/sys/firmware/efi/efivars/LoaderEntryDefault-4a67b082-0a4c-41cf-b6c7-440b29bb8c4f')


def default_entry(variable=DEFAULT_VARIABLE):
    """Read the persistent EFI selection. Only a missing variable means unset."""
    data = read(variable, 4096)
    require(len(data) >= 6 and (len(data)-4) % 2 == 0, 'Boot-default EFI variable is malformed.')
    try:
        entry = data[4:].decode('utf-16-le').rstrip('\x00')
    except UnicodeError as error:
        from .release import ReleaseError
        raise ReleaseError('Boot-default EFI variable is malformed.') from error
    require(entry and '\x00' not in entry, 'Boot-default EFI variable is malformed.')
    return entry


def require_default(accepted, variable=DEFAULT_VARIABLE):
    """Do not overwrite the last accepted fallback from an unaccepted running slot."""
    require(default_entry(variable) == accepted.name,
            'Accept the running boot as default before staging another update.')


def select_boot_once(entry, *, variable=Path('/sys/firmware/efi/efivars/LoaderEntryOneShot-4a67b082-0a4c-41cf-b6c7-440b29bb8c4f')):
    """Make the admitted pending UKI durable before publishing its boot choice."""
    descriptor = os.open(entry, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    descriptor = os.open(entry.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    # Resolve the installed bootloader's ID for this exact admitted file.
    # Debian's loader normalizes boot counters out of the entry ID.
    entries = json.loads(command(['bootctl', '--json=short', 'list']))
    require(isinstance(entries, list), 'Boot loader entry inventory is malformed.')
    matches = [item for item in entries if isinstance(item, dict) and
               item.get('type') == 'type2' and item.get('source') == 'esp' and
               item.get('path') == str(entry)]
    stable = re.sub(r'[+][0-9]+(?:-[0-9]+)?(?=[.]efi$)', '', entry.name)
    require(len(matches) == 1 and matches[0].get('id') in (entry.name, stable),
            'Boot loader does not identify exactly the admitted pending image.')
    identifier = matches[0]['id']
    command(['bootctl', 'set-oneshot', identifier])
    data = read(variable, 4096)
    require(6 <= len(data) and data[4:].decode('utf-16-le').rstrip('\x00') == identifier,
            'Boot loader did not retain the requested one-shot entry.')



def contract_admission(installed, manifest):
    """Never accept a new state contract without a compatible installed one."""
    if 'image_contract' not in installed and 'image_contract' not in manifest:
        return
    require('image_contract' in installed and 'image_contract' in manifest,
            'State contract transitions require a separately qualified bridge.')
    from .image_contract import admission
    admission(installed, manifest['image_contract'])


def recovery_admission(installed, manifest, *, disk, active, esp, accepted):
    """Reject an update whose authenticated recovery target is not this running slot."""
    if 'image_contract' not in installed:
        return
    from . import early_failure, release, tpm_migration
    contract = manifest.get('image_contract', {})
    recovery = contract.get('recovery')
    require(isinstance(recovery, dict) and recovery.get('image_id') == installed['image_id'] and
            recovery.get('sequence') == manifest['deployment_sequence'],
            'Update lacks a bound recovery path to the accepted image.')
    binding = recovery['binding']
    early_failure.validate_fallback_binding(binding, image=installed['image_id'],
                                            current_sequence=manifest['deployment_sequence'])
    require(str(Path(binding['disk_by_id']).resolve(strict=True)) == disk,
            'Update recovery binding selects another disk.')
    bound = binding['release']
    require(bound['sequence'] == installed['deployment_sequence'] and bound['uki_name'] == installed['uki_name'] and
            release.file_record(accepted)['sha256'] == bound['uki_sha256'],
            'Update recovery image is not the accepted running image.')
    if installed.get('tpm_policy'):
        from .measured_boot import check_measurement_budget
        check_measurement_budget(accepted)
    before = geometry(disk)
    esps = [row for row in before if row.get('uuid') == binding['esp_uuid'] and row.get('disk') == disk and
            row.get('type') == 'c12a7328-f81f-11d2-ba4b-00a0c93ec93b']
    require(len(esps) == 1 and boot_esp(installed, disk=disk) == esp, 'Update recovery ESP differs.')
    for role, item in bound['partitions'].items():
        rows = [row for row in before if row.get('disk') == disk and row.get('type') == GUIDS[role] and
                row.get('uuid') == item['uuid'] and row.get('label') == installed['active_labels'][role] and
                row.get('label') == item['label'] and row.get('size', 0) >= item['size']]
        require(len(rows) == 1 and (role == 'verity-sig' or rows[0].get('number') in active),
                'Update recovery partition is not in the running slot.')
        require(tpm_migration.partition_digest(rows[0]['device'], item['size']) == item['sha256'],
                'Update recovery partition differs from its signed payload.')
    require(before == geometry(disk) and release.file_record(accepted)['sha256'] == bound['uki_sha256'],
            'Update recovery target changed during admission.')


@contextmanager
def image_lock(name, *, wait=False):
    """Keep all admission and transfer locks in a boot-lifetime, root-only directory."""
    directory = os.open(IMAGE_LOCK_DIR, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        info = os.fstat(directory)
        require(info.st_uid == info.st_gid == 0 and stat.S_IMODE(info.st_mode) == 0o700,
                'Image lock directory is unsafe.')
        descriptor = os.open(name, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK,
                             0o600, dir_fd=directory)
        try:
            info = os.fstat(descriptor)
            require(stat.S_ISREG(info.st_mode) and info.st_uid == info.st_gid == 0 and info.st_nlink == 1
                    and stat.S_IMODE(info.st_mode) == 0o600, 'Image lock file is unsafe.')
            try:
                flags = fcntl.LOCK_EX if wait else fcntl.LOCK_EX | fcntl.LOCK_NB
                fcntl.flock(descriptor, flags)
            except BlockingIOError as error:
                raise ReleaseError('An image operation is already running.') from error
            yield
        finally:
            os.close(descriptor)
    finally:
        os.close(directory)


def stage(directory, installed_path=Path('/usr/share/lanrith/installed.json')):
    from .image_operation import admission_lock
    with admission_lock(installed_path):
        return stage_locked(directory, installed_path)


def stage_locked(directory, installed_path):
    """Stage an admitted root-owned inbox through the ordinary A/B mechanism."""
    require(os.geteuid() == 0, 'Update staging requires the root-owned admission helper.')
    installed = json.loads(read(installed_path, 65536))
    require(installed_path.stat().st_uid == 0 and not installed_path.stat().st_mode & 0o022,
            'Installed update policy must be root-owned and immutable to users.')
    inbox = Path(installed['state_directory']) / 'update-inbox'
    require(directory.resolve() == directory.absolute() and directory.parent == inbox and
            directory.stat().st_uid == 0 and not directory.stat().st_mode & 0o077,
            'Update must be an exclusive root-owned inbox directory.')
    esp = boot_esp(installed)
    current = Path(command(['bootctl', '--print-stub-path']).strip())
    accepted = accepted_boot(current, installed['uki_name'], esp)
    lock_path = Path(installed.get('lock_path', IMAGE_LOCK_DIR/'lanrith-update.lock'))
    # Older installed policies could name a lock under /run/lock. Preserve the
    # name inside the protected directory shared by all entry points.
    require(lock_path.parent in (IMAGE_LOCK_DIR, Path('/run/lock')) and
            re.fullmatch(r'[A-Za-z0-9_-]+\.lock', lock_path.name) and lock_path.name != OPERATION_LOCK_NAME,
            'Unsafe update lock path.')
    with image_lock(lock_path.name):
        # A completed target can outlive a required listener or route. This oneshot
        # has no RemainAfterExit, so PID 1 runs fresh probes outside the socket
        # executor's network sandbox and returns the result of this boot's job.
        command(['systemctl', 'start', 'lanrith-health.service'], timeout=70)
        require_default(accepted)
        manifest = verify(directory, Path(installed['certificate']), purpose='update',
                          image_id=installed['update_image_id'],
                          minimum_sequence=installed['deployment_sequence'])
        contract_admission(installed, manifest)
        require(esp.is_mount(), 'EFI filesystem must be mounted.')
        disk, active_partitions = root_disk()
        recovery_admission(installed, manifest, disk=disk, active=active_partitions, esp=esp, accepted=accepted)
        admitted_rows = geometry(disk)
        value = plan(manifest, installed, admitted_rows, disk=disk,
                     active_partitions=active_partitions,
                     esp_available=shutil.disk_usage(esp).free)
        if 'tpm_policy' in installed:
            from .measured_boot import verify as verify_measurement
            candidate = next(item for item in manifest['artifacts'] if item['role'] == 'uki')
            verify_measurement(directory/candidate['name'], installed['tpm_policy'])
        require(root_disk() == (disk, active_partitions) and boot_esp(installed, disk=disk) == esp and
                geometry(disk) == admitted_rows, 'Slot geometry or use changed before staging.')
        with writable_esp(installed, esp=esp):
            with tempfile.TemporaryDirectory(prefix='lanrith-update.', dir='/run') as temporary:
                definitions = Path(temporary)
                for name, contents in transfers(value, directory, esp).items():
                    (definitions / name).write_text(contents)
                # Relabel only the already-selected inactive slots. Active data is never a target.
                for target in value['partitions'].values():
                    command(['sfdisk', '--part-label', disk, str(target['number']), '_empty'])
                sysupdate = shutil.which('systemd-sysupdate') or '/usr/lib/systemd/systemd-sysupdate'
                command([sysupdate, '--definitions=' + str(definitions), '--verify=no',
                         'update', str(value['sequence'])], timeout=900)
        deadline = time.monotonic() + 15
        while True:
            observed = geometry(disk)
            complete = all(any(partition['number'] == target['number'] and partition['label'] == target['label'] and
                               partition['uuid'] == target['uuid'] for partition in observed)
                           for target in value['partitions'].values())
            if complete or time.monotonic() >= deadline:
                break
            time.sleep(0.25)
        require(complete, 'Staged partition identity differs from the admitted plan.')
        candidates = list((esp / 'EFI/Linux').glob(f'{value["image_id"]}_{value["sequence"]}+*.efi'))
        require(len(candidates) == 1 and candidates[0].is_file() and not candidates[0].is_symlink(),
                'Staging did not produce exactly one pending UKI.')
        expected = next(item for item in manifest['artifacts'] if item['role'] == 'uki')
        from .release import file_record
        observed_uki = file_record(candidates[0])
        require(observed_uki['sha256'] == expected['sha256'] and observed_uki['size'] == expected['size'],
                'Staged UKI differs from the admitted bytes.')
        require_default(accepted)
        # Boot selection changes only the root-only EFI variable. The ESP has
        # already returned to read-only before its bytes are authenticated.
        select_boot_once(candidates[0])
        return value


def promote(source, installed_path=Path('/usr/share/lanrith/installed.json'), *, expected_digest=None,
            stage_payload=True):
    from .image_operation import admission_lock
    with admission_lock(installed_path):
        destination = promote_locked(source, installed_path, expected_digest=expected_digest)
        return stage_locked(destination, installed_path) if stage_payload else destination


def promote_locked(source, installed_path, *, expected_digest=None):
    """Pin the untrusted directory before inspecting or copying any of its members."""
    installed = json.loads(read(installed_path, 65536))
    upload = Path(installed.get('upload_directory', '/var/tmp/lanrith-update'))
    require(source.is_absolute() and source.parent == upload and
            re.fullmatch(r'[A-Za-z0-9_-]{1,64}', source.name), 'Unsafe upload identifier.')
    parent = os.open(upload, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        descriptor = os.open(source.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
        try:
            return _promote(source, descriptor, installed_path, expected_digest=expected_digest)
        finally:
            os.close(descriptor)
    finally:
        os.close(parent)


def copy_member(source_fd, root, name, limit):
    descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=source_fd)
    with os.fdopen(descriptor, 'rb') as input_stream, (root/name).open('xb') as output:
        before = os.fstat(input_stream.fileno())
        require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and
                0 < before.st_size <= limit, 'Unsafe upload file.')
        size = 0
        while block := input_stream.read(1024*1024):
            size += len(block)
            require(size <= limit, 'Upload grew while being copied.')
            output.write(block)
        after = os.fstat(input_stream.fileno())
        require((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) ==
                (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns) and
                size == before.st_size, 'Upload changed during promotion.')
        output.flush()
        os.fchmod(output.fileno(), 0o600)
        os.fsync(output.fileno())


def sync_directory(directory):
    descriptor = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _promote(source, source_fd, installed_path, *, expected_digest):
    require(os.geteuid() == 0, 'Update promotion requires root.')
    installed = json.loads(read(installed_path, 65536))
    require(installed_path.stat().st_uid == 0 and not installed_path.stat().st_mode & 0o022,
            'Installed update policy is not protected.')
    upload = Path(installed.get('upload_directory', '/var/tmp/lanrith-update'))
    require(source.is_absolute() and source.resolve() == source and source.parent == upload and
            source.is_dir() and not source.is_symlink(), 'Upload is outside the declared staging directory.')
    inbox = Path(installed['state_directory'])/'update-inbox'
    inbox.mkdir(mode=0o700, parents=True, exist_ok=True)
    require(inbox.resolve() == inbox and inbox.stat().st_uid == 0 and
            stat.S_IMODE(inbox.stat().st_mode) == 0o700, 'Unsafe root update inbox.')
    certificate = Path(installed['certificate'])
    policy = {'purpose': 'update', 'image_id': installed['update_image_id'],
              'minimum_sequence': installed['deployment_sequence']}
    with tempfile.TemporaryDirectory(prefix='.upload-', dir=inbox) as temporary:
        root = Path(temporary)
        metadata = {'release.json': 65536, 'release.json.sig': 16384}
        for name, limit in metadata.items():
            copy_member(source_fd, root, name, limit)
        data = read(root/'release.json', 65536)
        signature = read(root/'release.json.sig', 16384)
        if expected_digest is not None:
            require(isinstance(expected_digest, str) and hashlib.sha256(data).hexdigest() == expected_digest,
                    'Uploaded manifest identity differs.')
        manifest = authenticated_manifest(data, signature, certificate, **policy)
        contract_admission(installed, manifest)
        members = {artifact['name']: artifact['size'] for artifact in manifest['artifacts']}
        names = set(metadata) | set(members)
        require(set(os.listdir(source_fd)) == names, 'Upload has unexpected members.')
        esp = boot_esp(installed)
        require(esp.is_mount(), 'EFI filesystem must be mounted before upload admission.')
        disk, active = root_disk()
        upload_limits(manifest, installed, geometry(disk), disk=disk, active_partitions=active,
                      esp_available=shutil.disk_usage(esp).free)
        require(shutil.disk_usage(inbox).free >= sum(members.values()) + 64*1024*1024,
                'Persistent state lacks space for authenticated promotion and reserves.')
        for name, limit in members.items():
            copy_member(source_fd, root, name, limit)
        require(verify(root, certificate, **policy) == manifest and set(os.listdir(source_fd)) == names and
                read('release.json', 65536, dir_fd=source_fd) == data and
                read('release.json.sig', 16384, dir_fd=source_fd) == signature, 'Upload changed during promotion.')
        destination = inbox/str(manifest['deployment_sequence'])
        if destination.exists():
            require(not destination.is_symlink() and read(destination/'release.json', 65536) == data,
                    'Inbox already contains a different deployment.')
            require(verify(destination, certificate, **policy) == manifest, 'Existing inbox release differs.')
        else:
            sync_directory(root)
            os.rename(root, destination)
            root.mkdir(mode=0o700)  # Preserve TemporaryDirectory's cleanup ownership.
    sync_directory(inbox)
    return destination


def upload_limits(manifest, installed, partitions, *, disk, active_partitions, esp_available):
    """Bound upload copies to actual inactive slots and explicit owner policy."""
    value = plan(manifest, installed, partitions, disk=disk, active_partitions=active_partitions,
                 esp_available=esp_available)
    limits = {role: next(part['size'] for part in partitions if part['number'] == target['number'])
              for role, target in value['partitions'].items()}
    limits['uki'] = esp_available-32*1024*1024
    policy = installed.get('payload_limits')
    if policy is not None:
        require(isinstance(policy, dict) and set(policy) == set(limits) and
                all(type(size) is int and size > 0 for size in policy.values()),
                'Installed upload capacity policy is malformed.')
        limits = {role: min(limit, policy[role]) for role, limit in limits.items()}
    require(all(artifact['size'] <= limits[artifact['role']] for artifact in manifest['artifacts']),
            'Upload exceeds installed payload capacity.')
    return limits

def prune_inbox(installed):
    """Discard only closed-operation copies; fallback data lives in its A/B slot."""
    require(os.geteuid() == 0, 'Inbox retention requires system service authority.')
    inbox = Path(installed['state_directory'])/'update-inbox'
    if not inbox.exists():
        require(not inbox.is_symlink(), 'Update inbox is unsafe.')
        return
    require(inbox.resolve() == inbox and inbox.stat().st_uid == 0 and
            stat.S_IMODE(inbox.stat().st_mode) == 0o700, 'Update inbox is unsafe.')
    entries = list(inbox.iterdir())
    require(len(entries) <= 128, 'Update inbox requires recovery inspection.')
    names = {path.name for path in entries}
    cleanup = []
    for path in entries:
        unpublished = re.fullmatch(r'\.upload-[a-z0-9_]{8}', path.name)
        numbered = re.fullmatch(r'[1-9][0-9]{0,8}', path.name)
        retired = re.fullmatch(r'\.retiring-([1-9][0-9]{0,8})', path.name)
        info = path.lstat()
        require((unpublished or numbered or retired) and stat.S_ISDIR(info.st_mode) and
                info.st_uid == 0 and stat.S_IMODE(info.st_mode) == 0o700,
                'Unexpected update inbox directory.')
        members = {member.name for member in path.iterdir()}
        require(len(members) <= 6, 'Unexpected update inbox contents.')
        for name in members:
            info = (path/name).lstat()
            require(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and info.st_nlink == 1,
                    'Unsafe update inbox member.')
        if unpublished:
            cleanup.append((path, None, members))
            continue
        sequence = path.name if numbered else retired[1]
        target = inbox/('.retiring-' + sequence)
        require(not numbered or target.name not in names, 'Ambiguous update retirement.')
        if numbered or members:
            require('release.json' in members, 'Missing update retirement manifest.')
            manifest = document(read(path/'release.json', 65536))
            expected = {'release.json', 'release.json.sig'} | {a['name'] for a in manifest['artifacts']}
            require(manifest['purpose'] == 'update' and manifest['image_id'] == installed['update_image_id'] and
                    manifest['deployment_sequence'] == int(sequence) and
                    (members == expected if numbered else members <= expected), 'Unexpected update inbox contents.')
        cleanup.append((path, target, members))

    for path, target, members in cleanup:
        if target is not None:
            if path != target:
                path.rename(target)
                path = target
            # A prior invocation can stop immediately after rename.
            sync_directory(inbox)
        for name in sorted(members - {'release.json'}):
            (path/name).unlink()
        if 'release.json' in members:
            # The protected manifest identifies every resumable deletion. Once
            # it is gone the only admissible retirement state is an empty directory.
            sync_directory(path)
            (path/'release.json').unlink()
        path.rmdir()
    sync_directory(inbox)
