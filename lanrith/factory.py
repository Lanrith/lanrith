"""Explicit factory installation and checks for the verified A/B state layout."""

import argparse
import getpass
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import tempfile

from .release import canonical, file_record, read, require, verify, ReleaseError
from .update import GUIDS, command, geometry, root_disk


VAR_GUID = '4d21b016-b534-45c2-a9fb-5c16e091fd2d'


def verified_root(mountpoint='/'):
    options = command(['findmnt', '--noheadings', '--output', 'OPTIONS', mountpoint]).strip().split(',')
    require('ro' in options, 'Factory and boot checks require a read-only root.')
    source = command(['findmnt', '--noheadings', '--output', 'SOURCE', mountpoint]).strip()
    require(source.startswith('/dev/'), 'Root is not a block-device mapping.')
    name = Path(source).resolve().name
    require(re.fullmatch(r'dm-[0-9]+', name), 'Root is not a device-mapper verified filesystem.')
    status = command(['dmsetup', 'status', '/dev/'+name]).strip().splitlines()
    require(len(status) == 1 and len(status[0].split()) == 4 and
            status[0].split()[2:] == ['verity', 'V'], 'dm-verity root status is not valid.')
    return root_disk(mountpoint)


def secure_boot(required=True):
    if required:
        path = Path('/sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c')
        data = path.read_bytes()
        require(len(data) == 5 and data[4] == 1, 'UEFI Secure Boot is not enabled.')
        setup = path.with_name('SetupMode-8be4df61-93ca-11d2-aa0d-00e098032b8c').read_bytes()
        require(len(setup) == 5 and setup[4] == 0, 'UEFI remains in setup mode.')


def minimum_size(installed):
    storage = installed['storage']
    return (storage['esp_mib'] + 2*storage['root_mib'] +
            2*max(64, storage['root_mib']//16) + storage['state_mib'] + 32)*1024*1024


def eligible(value, boot_disk, minimum):
    """Reject mounted, in-use, read-only, non-disk and incompatible devices."""
    if value.get('type') != 'disk' or value.get('name') == boot_disk or value.get('ro') is not False:
        return False
    if value.get('log-sec') != 512 or type(value.get('size')) is not int or value['size'] < minimum:
        return False
    pending = [value]
    while pending:
        device = pending.pop()
        if any(device.get('mountpoints') or []) or device.get('type') not in ('disk', 'part'):
            return False
        name = Path(device['name']).name
        holders = Path('/sys/class/block')/name/'holders'
        if holders.is_dir() and any(holders.iterdir()):
            return False
        pending.extend(device.get('children', []))
    return True


def target(installed, boot_disk):
    devices = json.loads(command(['lsblk', '--json', '--bytes', '--paths', '--output',
                                 'NAME,TYPE,SIZE,RO,LOG-SEC,MOUNTPOINTS,MODEL,SERIAL']))['blockdevices']
    allowed = {device['name']: device for device in devices if eligible(device, boot_disk, minimum_size(installed))}
    identities = {}
    for path in sorted(Path('/dev/disk/by-id').glob('*')):
        resolved = str(path.resolve())
        if path.is_symlink() and resolved in allowed and '-part' not in path.name:
            identities[str(path)] = resolved
    selected = installed['storage'].get('target')
    if not selected:
        require(identities, 'No eligible stable disk identity is available.')
        print('Eligible disk identities (all contents on the selected disk will be erased):')
        for identity in identities:
            device = allowed[identities[identity]]
            print(identity, device.get('model') or '', device['size'])
        selected = input('Enter the complete /dev/disk/by-id identity: ').strip()
    require(selected in identities, 'The selected disk is not eligible for factory installation.')
    device = identities[selected]
    confirmation = 'ERASE-AND-INSTALL '+selected
    require(input('Type '+confirmation+' to continue: ').strip() == confirmation,
            'Destructive installation was not explicitly confirmed.')
    # Resolve and inspect again after operator input; never trust a stale selection.
    require(str(Path(selected).resolve()) == device, 'Selected disk identity changed.')
    current = json.loads(command(['lsblk', '--json', '--bytes', '--paths', '--output',
                                 'NAME,TYPE,SIZE,RO,LOG-SEC,MOUNTPOINTS', device]))['blockdevices']
    require(len(current) == 1 and eligible(current[0], boot_disk, minimum_size(installed)),
            'Selected disk became ineligible before writing.')
    return device


def initialize(installed):
    disk, active = verified_root()
    rows = geometry(disk)
    for role, guid in GUIDS.items():
        candidates = [row for row in rows if row['type'].lower() == guid]
        require(len(candidates) == 2, 'The installed disk does not contain both verified-root slots.')
        current = [row for row in candidates if row['label'] == installed['active_labels'][role]]
        require(len(current) == 1 and (role == 'verity-sig' or current[0]['number'] in active),
                'The active slot does not match the mounted verified root.')
    var = [row for row in rows if row['type'].lower() == VAR_GUID]
    require(len(var) == 1 and var[0]['label'] == 'var', 'The state volume is absent or ambiguous.')
    # Use the verified disk's partition number; global label symlinks are not authority.
    listing = json.loads(command(['lsblk', '--json', '--paths', '--output', 'NAME,TYPE,PARTN', disk]))
    parts = listing['blockdevices'][0].get('children', [])
    devices = [item['name'] for item in parts if item.get('partn') == var[0]['number']]
    require(len(devices) == 1, 'Cannot resolve the selected encrypted state partition.')
    command(['cryptsetup', 'isLuks', devices[0]])
    source = command(['findmnt', '--noheadings', '--output', 'SOURCE', '/var']).strip()
    require(source.startswith(('/dev/mapper/', '/dev/dm-')), 'Persistent state is not mounted through encryption.')
    status = command(['cryptsetup', 'status', source])
    backing = re.findall(r'^\s*device:\s+(\S+)\s*$', status, re.MULTILINE)
    require(len(backing) == 1 and Path(backing[0]).resolve() == Path(devices[0]).resolve(),
            'Mounted state is not backed by the selected encrypted partition.')
    luks = json.loads(command(['cryptsetup', 'luksDump', '--dump-json-metadata', devices[0]]))
    tokens = [item.get('type') for item in luks.get('tokens', {}).values()]
    if installed['boot'].get('tpm', 'required') == 'required':
        require('systemd-tpm2' in tokens, 'State lacks its required TPM enrollment.')
    directory = Path(installed['state_directory'])
    directory.mkdir(mode=0o700, exist_ok=True)
    require(not directory.is_symlink() and directory.stat().st_uid == 0 and
            not directory.stat().st_mode & 0o077, 'Unsafe state-administration directory.')
    marker = directory/'slots-initialized'
    if not marker.exists():
        with marker.open('xb') as stream:
            stream.write(canonical({'schema': 1, 'disk': disk}))
        marker.chmod(0o600)
    return devices[0], tokens


def recovery(installed):
    require(os.geteuid() == 0 and os.ttyname(sys.stdin.fileno()) ==
            '/dev/'+installed['boot']['recovery_console'], 'Recovery requires the selected physical console.')
    device, tokens = initialize(installed)
    marker = Path(installed['state_directory'])/'recovery-key-enrolled'
    require(not marker.exists(), 'Recovery enrollment is already complete.')
    if 'systemd-recovery' not in tokens:
        print('Record the following recovery key outside the router. It is shown only on this console.')
        argv = ['systemd-cryptenroll', '--recovery-key']
        if installed['boot'].get('tpm', 'required') == 'required':
            argv.append('--unlock-tpm2-device=auto')
        # This command intentionally inherits only the selected TTY, never a log capture.
        subprocess.run([*argv, device], check=True, env={'PATH': '/usr/sbin:/usr/bin', 'LC_ALL': 'C'})
    else:
        print('A recovery key already exists. No additional key will be generated.')
    require(input('Type RECOVERY-KEY-STORED after recording the key offline: ').strip() == 'RECOVERY-KEY-STORED',
            'Recovery-key storage was not acknowledged.')
    descriptor = os.open(marker, os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW, 0o600)
    os.close(descriptor)


def provision():
    require(os.geteuid() == 0, 'Installation requires root in the verified initrd.')
    installed = json.loads(read(Path('/sysroot/usr/share/lanrith/installed.json'), 65536))
    secure_boot(installed['boot'].get('secure_boot', True))
    disk, active = verified_root('/sysroot')
    table = json.loads(command(['lsblk', '--json', '--paths', '--output', 'NAME,TYPE,PKNAME,PARTLABEL']))
    pending, media = list(table['blockdevices']), []
    while pending:
        item = pending.pop()
        pending.extend(item.get('children', []))
        if item.get('partlabel') == 'lanrith-factory-media':
            media.append(item)
    if not media:
        selected = installed['storage'].get('target')
        if selected:
            require(str(Path(selected).resolve()) == disk, 'Installed boot disk differs from the selected hardware profile.')
        require(command(['lsblk', '--nodeps', '--noheadings', '--output', 'TRAN', disk]).strip() != 'usb',
                'Removable boot media lacks its authenticated factory payload.')
        return
    require(len(media) == 1 and media[0].get('pkname') == disk,
            'Factory payload must be on the single verified boot disk.')
    with tempfile.TemporaryDirectory(prefix='lanrith-media.', dir='/run') as temporary:
        mount = Path(temporary)
        command(['mount', '-o', 'ro,noload,nodev,nosuid,noexec', media[0]['name'], str(mount)])
        try:
            payload = mount/'release'
            manifest = verify(payload, Path('/sysroot'+installed['certificate']), purpose='factory',
                              image_id=installed['image_id'], configuration_sha256=installed['configuration_sha256'])
            require(manifest['deployment_sequence'] == installed['deployment_sequence'] and
                    manifest['platform_version'] == installed['platform_version'], 'Media does not match the booted root.')
            rows = geometry(disk)
            for role in ('root', 'verity'):
                artifact = next(item for item in manifest['artifacts'] if item['role'] == role)
                partuuid = artifact['name'].removeprefix(f'{manifest["image_id"]}_{manifest["deployment_sequence"]}_').split('.')[0]
                require(any(row['number'] in active and row['type'].lower() == GUIDS[role] and row['uuid'] == partuuid
                            for row in rows), 'Media verified-root identity differs from the booted root.')
            raw = payload/next(item['name'] for item in manifest['artifacts'] if item['role'] == 'disk')
            chosen = target(installed, disk)
            command(['dd', 'if='+str(raw), 'of='+chosen, 'bs=4M', 'conv=fsync', 'status=progress'], timeout=1800)
            command(['cmp', '--bytes='+str(raw.stat().st_size), str(raw), chosen], timeout=1800)
            command(['sfdisk', '--relocate', 'gpt-bak-std', chosen])
            if installed['boot'].get('tpm', 'required') == 'disabled':
                # Encrypt with an operator passphrase supplied directly on the selected console.
                first = getpass.getpass('State encryption passphrase (at least 24 characters): ')
                require(len(first) >= 24 and first == getpass.getpass('Repeat state encryption passphrase: '),
                        'State encryption passphrases differ or are too short.')
                with tempfile.TemporaryDirectory(prefix='lanrith-state.', dir='/run') as secret:
                    key = Path(secret)/'key'
                    key.write_text(first)
                    key.chmod(0o600)
                    del first
                    definitions = Path(secret)/'repart'
                    shutil.copytree('/sysroot/usr/lib/repart.d', definitions)
                    command(['systemd-repart', '--definitions='+str(definitions), '--empty=allow',
                             '--key-file='+str(key), chosen], timeout=600)
            print('Installation read-back passed. Remove the factory medium after power-off.')
            command(['systemctl', '--no-block', 'poweroff'])
            # Never return into initrd-switch-root on the removable installation medium.
            while True:
                import time
                time.sleep(60)
        finally:
            command(['umount', str(mount)])


def main(arguments=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=('provision',))
    parser.parse_args(arguments)
    try:
        provision()
    except (ReleaseError, OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
        print(str(error) if isinstance(error, ReleaseError) else 'Factory installation failed closed.', file=sys.stderr)
        return 1
    return 0
