"""Plan an A/B update from authenticated artifacts and observed partition geometry."""

from __future__ import annotations

import fcntl
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import stat
import tempfile
import time

from .release import canonical, require, read, verify


PARTITION_ROLES = ('verity-sig', 'verity', 'root')
GUIDS = {'root': '4f68bce3-e8cd-4db1-96e7-fbcaf984b709',
         'verity': '2c7357ed-ebd2-46d9-aec1-23d437ec2bf5',
         'verity-sig': '41092b05-9fc8-4523-994f-2def0408b176'}
UUID = r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}'


def command(arguments, timeout=30):
    try:
        result = subprocess.run(arguments, stdin=subprocess.DEVNULL, capture_output=True,
                                text=True, timeout=timeout, env={'PATH': '/usr/sbin:/usr/bin', 'LC_ALL': 'C'})
    except OSError as error:
        from .release import ReleaseError
        raise ReleaseError('Update command could not start: '+Path(arguments[0]).name) from error
    require(result.returncode == 0, 'Update command failed: ' + Path(arguments[0]).name)
    return result.stdout


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


def root_disk(mountpoint='/'):
    require(mountpoint in ('/', '/sysroot'), 'Unsupported verified-root mountpoint.')
    source = command(['findmnt', '--noheadings', '--output', 'SOURCE', mountpoint]).strip()
    require(source.startswith('/dev/'), 'Root is not backed by a known block device.')
    pending, seen, disks, numbers = [Path(source).resolve().name], set(), set(), set()
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


def geometry(disk, *, sysfs=Path('/sys/class/block')):
    # Partition GUIDs and labels in udev can still describe the pre-repartition
    # disk after its kernel devices are ready. Read identity from the GPT itself;
    # use the kernel view for device numbers, capacity and in-use detection.
    table = json.loads(command(['sfdisk', '--json', disk]))['partitiontable']
    require(table.get('label') == 'gpt' and table.get('device') == disk and
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
        require(type(part.get('size')) is int and part['size'] > 0 and
                type(device.get('size')) is int and device['size'] == part['size']*table['sectorsize'],
                'Kernel partition capacity differs from the selected GPT.')
        require(all(isinstance(part.get(key), str) and re.fullmatch(UUID, part[key].lower())
                    for key in ('type', 'uuid')), 'GPT partition identities are malformed.')
        descendants, busy = [device], False
        while descendants:
            child = descendants.pop()
            busy = busy or any(child.get('mountpoints') or [])
            descendants.extend(child.get('children', []))
        holders = kernel_device/'holders'
        busy = busy or holders.is_dir() and any(holders.iterdir())
        result.append({'disk': device.get('pkname'), 'device': name, 'number': number,
                       'type': part['type'].lower(), 'label': part.get('name'),
                       'uuid': part['uuid'].lower(),
                       'size': device.get('size'), 'mounted': bool(busy)})
    require(seen == set(partitions), 'A GPT partition has no matching kernel device.')
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


def boot_esp(installed, *, disk=None):
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
                                '--output', 'SOURCE,FSTYPE,TARGET']))
    rows = mount.get('filesystems', [])
    require(len(rows) == 1 and rows[0].get('target') == str(esp) and rows[0].get('fstype') == 'vfat' and
            isinstance(rows[0].get('source'), str) and rows[0]['source'].startswith('/dev/'),
            'EFI filesystem is not a mounted FAT block partition.')
    device = str(Path(rows[0]['source']).resolve())
    partition = json.loads(command(['lsblk', '--json', '--nodeps', '--paths', '--output',
                                   'NAME,TYPE,PKNAME,PARTTYPE', device])).get('blockdevices', [])
    if disk is None:
        disk, _ = root_disk()
    require(len(partition) == 1 and partition[0].get('name') == device and
            partition[0].get('type') == 'part' and partition[0].get('pkname') == disk and
            (partition[0].get('parttype') or '').lower() == 'c12a7328-f81f-11d2-ba4b-00a0c93ec93b',
            'EFI partition differs from the verified root disk.')
    return esp


def require_default(accepted, variable=Path('/sys/firmware/efi/efivars/LoaderEntryDefault-4a67b082-0a4c-41cf-b6c7-440b29bb8c4f')):
    """Do not overwrite the last accepted fallback from an unaccepted running slot."""
    data = read(variable, 4096)
    require(len(data) >= 6 and (len(data)-4) % 2 == 0, 'Boot-default EFI variable is malformed.')
    try:
        entry = data[4:].decode('utf-16-le').rstrip('\x00')
    except UnicodeError as error:
        from .release import ReleaseError
        raise ReleaseError('Boot-default EFI variable is malformed.') from error
    require(entry == accepted.name, 'Accept the running boot as default before staging another update.')


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


def stage(directory, installed_path=Path('/usr/share/lanrith/installed.json')):
    """Stage an admitted root-owned inbox through the ordinary A/B mechanism."""
    require(os.geteuid() == 0, 'Update staging requires the root-owned admission helper.')
    installed = json.loads(read(installed_path, 65536))
    require(installed_path.stat().st_uid == 0 and not installed_path.stat().st_mode & 0o022,
            'Installed update policy must be root-owned and immutable to users.')
    inbox = Path(installed['state_directory']) / 'update-inbox'
    require(directory.resolve() == directory.absolute() and directory.parent == inbox and
            directory.stat().st_uid == 0 and not directory.stat().st_mode & 0o077,
            'Update must be an exclusive root-owned inbox directory.')
    require(command(['systemctl', 'is-active', 'boot-complete.target']).strip() == 'active',
            'Running boot has not completed acceptance.')
    esp = boot_esp(installed)
    current = Path(command(['bootctl', '--print-stub-path']).strip())
    accepted = accepted_boot(current, installed['uki_name'], esp)
    lock_path = Path(installed.get('lock_path', '/run/lock/lanrith-update.lock'))
    require(lock_path.parent == Path('/run/lock') and re.fullmatch(r'[A-Za-z0-9_-]+\.lock', lock_path.name),
            'Unsafe update lock path.')
    descriptor = os.open(lock_path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        info = os.fstat(descriptor)
        require(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and info.st_nlink == 1 and
                stat.S_IMODE(info.st_mode) == 0o600, 'Unsafe update lock file.')
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        require_default(accepted)
        manifest = verify(directory, Path(installed['certificate']), purpose='update',
                          image_id=installed['update_image_id'],
                          minimum_sequence=installed['deployment_sequence'])
        require(esp.is_mount(), 'EFI filesystem must be mounted.')
        disk, active_partitions = root_disk()
        value = plan(manifest, installed, geometry(disk), disk=disk,
                     active_partitions=active_partitions,
                     esp_available=shutil.disk_usage(esp).free)
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
        select_boot_once(candidates[0])
        return value
    finally:
        os.close(descriptor)


def promote(source, installed_path=Path('/usr/share/lanrith/installed.json')):
    """Copy an upload into exclusively root-owned files before authentication and staging."""
    require(os.geteuid() == 0, 'Update promotion requires root.')
    installed = json.loads(read(installed_path, 65536))
    require(installed_path.stat().st_uid == 0 and not installed_path.stat().st_mode & 0o022,
            'Installed update policy is not protected.')
    upload = Path(installed.get('upload_directory', '/var/tmp/lanrith-update'))
    require(source.is_absolute() and source.resolve() == source and source.parent == upload and
            source.is_dir() and not source.is_symlink(), 'Upload is outside the declared staging directory.')
    manifest = json.loads(read(source/'release.json', 65536))
    from .release import document, canonical
    manifest = document(canonical(manifest))
    require(manifest['purpose'] == 'update', 'Only update payloads can be promoted.')
    esp = boot_esp(installed)
    require(esp.is_mount(), 'EFI filesystem must be mounted before upload admission.')
    disk, active = root_disk()
    limits = upload_limits(manifest, installed, geometry(disk), disk=disk,
                           active_partitions=active, esp_available=shutil.disk_usage(esp).free)
    members = {'release.json': 65536, 'release.json.sig': 16384}
    for artifact in manifest['artifacts']:
        require(artifact['size'] <= limits[artifact['role']], 'Upload exceeds installed payload capacity.')
        members[artifact['name']] = artifact['size']
    require({path.name for path in source.iterdir()} == set(members), 'Upload has unexpected members.')
    inbox = Path(installed['state_directory'])/'update-inbox'
    inbox.mkdir(mode=0o700, parents=True, exist_ok=True)
    require(inbox.resolve() == inbox and inbox.stat().st_uid == 0 and
            stat.S_IMODE(inbox.stat().st_mode) == 0o700, 'Unsafe root update inbox.')
    destination = inbox/str(manifest['deployment_sequence'])
    with tempfile.TemporaryDirectory(prefix='.upload-', dir=inbox) as temporary:
        root = Path(temporary)
        for name, limit in members.items():
            descriptor = os.open(source/name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
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
                os.fsync(output.fileno())
            (root/name).chmod(0o600)
        verified = verify(root, Path(installed['certificate']), purpose='update',
                          image_id=installed['update_image_id'], minimum_sequence=installed['deployment_sequence'])
        require(verified == manifest, 'Manifest changed during promotion.')
        if destination.exists():
            require(not destination.is_symlink() and read(destination/'release.json', 65536) ==
                    read(root/'release.json', 65536), 'Inbox already contains a different deployment.')
        else:
            os.rename(root, destination)
            root.mkdir(mode=0o700)  # Preserve TemporaryDirectory's cleanup ownership.
    return stage(destination, installed_path)


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
