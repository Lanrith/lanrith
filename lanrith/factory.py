"""Explicit factory installation and checks for the verified A/B state layout."""

import argparse
import base64
import hashlib
import getpass
import json
import os
from pathlib import Path
import re
import signal
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


def enrollment_tokens(luks, *, tpm_required, policy=None):
    entries = luks.get('tokens', {})
    require(isinstance(entries, dict) and all(isinstance(item, dict) for item in entries.values()),
            'State encryption token metadata is malformed.')
    tokens = [item.get('type') for item in entries.values()]
    if tpm_required:
        if policy is not None:
            from .early_unlock import validate
            validate(policy)
        require('systemd-tpm2' in tokens, 'State lacks its required TPM enrollment.')
        require(all(item.get('tpm2-pcrs') == (policy['direct_pcrs'] if policy else [7]) for item in entries.values()
                    if item.get('type') == 'systemd-tpm2'),
                'State TPM enrollment differs from the selected Secure Boot policy.')
        if policy is not None:
            require(isinstance(luks.get('keyslots'), dict) and 1 <= len(luks['keyslots']) <= 32,
                    'State keyslot inventory is malformed.')
            covered = set()
            for item in entries.values():
                require(item.get('type') in ('systemd-tpm2', 'systemd-recovery') and
                        isinstance(item.get('keyslots'), list) and len(item['keyslots']) == 1 and
                        isinstance(item['keyslots'][0], str) and item['keyslots'][0].isdecimal() and
                        item['keyslots'][0] in luks.get('keyslots', {}), 'Unexpected state unlock method.')
                slot = item['keyslots'][0]
                require(slot not in covered, 'State unlock tokens share a keyslot.')
                covered.add(slot)
                if item['type'] == 'systemd-recovery':
                    continue
                try:
                    public = base64.b64decode(item.get('tpm2_pubkey', ''), validate=True)
                except (ValueError, TypeError):
                    raise ReleaseError('Invalid enrolled TPM policy key.') from None
                require(item.get('tpm2-pcr-bank') == policy['bank'] and
                        item.get('tpm2_pubkey_pcrs') == policy['signed_pcrs'] and
                        item.get('tpm2_pcrlock', False) is False and
                        item.get('tpm2-pin', False) is False and
                        hashlib.sha256(public).hexdigest() == policy['public_key_sha256'],
                        'State TPM token lacks the complete authorized measured policy.')
            require(covered == set(luks.get('keyslots', {})), 'State contains an unapproved unlock keyslot.')
    return tokens


def state_metadata(installed, *, root='/'):
    disk, active = verified_root(root)
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
    device = var[0]['device']
    command(['cryptsetup', 'isLuks', device])
    source = command(['findmnt', '--noheadings', '--output', 'SOURCE', str(Path(root)/'var')]).strip()
    require(source.startswith(('/dev/mapper/', '/dev/dm-')), 'Persistent state is not mounted through encryption.')
    status = command(['cryptsetup', 'status', source])
    backing = re.findall(r'^\s*device:\s+(\S+)\s*$', status, re.MULTILINE)
    require(len(backing) == 1 and Path(backing[0]).resolve() == Path(device).resolve(),
            'Mounted state is not backed by the selected encrypted partition.')
    luks = json.loads(command(['cryptsetup', 'luksDump', '--dump-json-metadata', device]))
    return disk, device, luks


def state_tokens(installed, luks):
    if 'tpm_transition' in installed:
        from .tpm_migration import classify
        classify(installed, luks)
        return [item['type'] for item in luks['tokens'].values()]
    return enrollment_tokens(luks, tpm_required=installed['boot'].get('tpm', 'required') == 'required',
                             policy=installed.get('tpm_policy'))


def initialize(installed, *, root='/'):
    disk, device, luks = state_metadata(installed, root=root)
    tokens = state_tokens(installed, luks)
    if 'tpm_policy' in installed and root == '/':
        from .early_unlock import observation
        observation(installed)
    if installed.get('tpm_transition', {}).get('phase') == 'enforce':
        enrollment_tokens(luks, tpm_required=True, policy=installed['tpm_policy'])
    directory = Path(root)/installed['state_directory'].lstrip('/')
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    require(not directory.is_symlink() and directory.stat().st_uid == 0 and
            not directory.stat().st_mode & 0o077, 'Unsafe state-administration directory.')
    marker = directory/'slots-initialized'
    if not marker.exists():
        with marker.open('xb') as stream:
            stream.write(canonical({'schema': 1, 'disk': disk}))
        marker.chmod(0o600)
    if root == '/' and 'image_contract' in installed:
        from .image_contract import remember
        remember(installed)
    return device, tokens


def recovery(installed, *, root='/'):
    if 'tpm_policy' in installed:
        from .early_unlock import in_initrd
        in_initrd()
        require(root == '/sysroot', 'Measured recovery enrollment requires the verified initrd root.')
    require(os.geteuid() == 0 and os.ttyname(sys.stdin.fileno()) ==
            '/dev/'+installed['boot']['recovery_console'], 'Recovery requires the selected physical console.')
    device, tokens = initialize(installed, root=root)
    marker = Path(root)/installed['state_directory'].lstrip('/')/'recovery-key-enrolled'
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
    os.fsync(descriptor)
    os.close(descriptor)
    descriptor = os.open(marker.parent, os.O_RDONLY|os.O_DIRECTORY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def repartition(installed, disk, *, installed_root):
    """Create bounded slots/state only on the explicitly observed or selected disk."""
    definitions = '/sysroot/usr/lib/repart.d'
    arguments = ['systemd-repart', '--definitions='+definitions, '--empty=refuse', '--dry-run=no', '--offline=no',
                 '--seed='+installed['machine_id']]
    if installed_root:
        arguments.append('--root=/sysroot')
    if installed['boot'].get('tpm', 'required') == 'disabled':
        require(os.ttyname(sys.stdin.fileno()) == '/dev/'+installed['boot']['recovery_console'],
                'Manual state encryption requires the selected physical console.')
        first = getpass.getpass('State encryption passphrase (at least 24 characters): ')
        require(len(first) >= 24 and first == getpass.getpass('Repeat state encryption passphrase: '),
                'State encryption passphrases differ or are too short.')
        with tempfile.TemporaryDirectory(prefix='lanrith-state.', dir='/run') as secret:
            key = Path(secret)/'key'
            key.write_text(first)
            key.chmod(0o600)
            del first
            command([*arguments, '--key-file='+str(key), disk], timeout=600)
    else:
        policy = installed.get('tpm_policy')
        if policy is None:
            command([*arguments, '--tpm2-pcrs=7', '--tpm2-pcrlock=', disk], timeout=600)
        else:
            public = Path('/sysroot/usr/lib/systemd/tpm2-pcr-public-key.pem')
            require(hashlib.sha256(read(public, 16384)).hexdigest() == policy['public_key_sha256'],
                    'Factory measured-policy authority differs.')
            from .early_unlock import in_initrd, validate
            validate(policy)
            in_initrd()
            command([*arguments, '--tpm2-pcrs=7:sha256+15:sha256='+('0'*64), '--tpm2-pcrlock=',
                     '--tpm2-public-key='+str(public), '--tpm2-public-key-pcrs=11', disk], timeout=600)
    command(['udevadm', 'settle', '--timeout=30'])


def prepare_state(installed, disk, active):
    rows = geometry(disk)
    state = [row for row in rows if row['type'].lower() == VAR_GUID]
    require(len(state) <= 1, 'Persistent state partition is ambiguous.')
    if not state:
        # A pristine installed factory image has only ESP and one verified-root
        # triplet. Never repartition a populated or otherwise foreign disk.
        require(len(rows) == 4 and sum(row['type'].lower() ==
            'c12a7328-f81f-11d2-ba4b-00a0c93ec93b' for row in rows) == 1,
            'Initial state provisioning requires the pristine factory layout.')
        for role, guid in GUIDS.items():
            parts = [row for row in rows if row['type'].lower() == guid]
            require(len(parts) == 1 and parts[0]['label'] == installed['active_labels'][role] and
                    (role == 'verity-sig' or parts[0]['number'] in active),
                    'Factory slot identity differs from the verified boot.')
        observed = json.loads(command(['lsblk', '--json', '--bytes', '--nodeps', '--output', 'SIZE,RO,LOG-SEC', disk]))
        devices = observed['blockdevices']
        require(len(devices) == 1 and devices[0].get('ro') is False and devices[0].get('log-sec') == 512 and
                type(devices[0].get('size')) is int and devices[0]['size'] >= minimum_size(installed),
                'Installed disk cannot accommodate the selected state and A/B budgets.')
        repartition(installed, disk, installed_root=True)
        state = [row for row in geometry(disk) if row['type'].lower() == VAR_GUID]
    require(len(state) == 1 and state[0]['label'] == 'var' and
            state[0]['size'] >= installed['storage']['state_mib']*1024*1024,
            'Selected persistent state partition is absent or undersized.')
    command(['cryptsetup', 'isLuks', state[0]['device']])
    return state[0]['device']


def provision():
    require(os.geteuid() == 0, 'Installation requires root in the verified initrd.')
    installed = json.loads(read(Path('/sysroot/usr/share/lanrith/installed.json'), 65536))
    secure_boot(installed['boot'].get('secure_boot', True))
    disk, active = verified_root('/sysroot')
    command(['udevadm', 'settle', '--timeout=30'])
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
        require(selected or command(['lsblk', '--nodeps', '--noheadings', '--output', 'TRAN', disk]).strip() != 'usb',
                'Removable boot media lacks its authenticated factory payload.')
        device = prepare_state(installed, disk, active)
        if 'tpm_policy' in installed:
            from .early_unlock import unlock
            unlock(installed, device)
        return
    require(len(media) == 1 and media[0].get('pkname') == disk,
            'Factory payload must be on the single verified boot disk.')
    with tempfile.TemporaryDirectory(prefix='lanrith-media.', dir='/run') as temporary:
        mount = Path(temporary)
        command(['mount', '-o', 'ro,noload,nodev,nosuid,noexec', media[0]['name'], str(mount)])
        try:
            payload = mount/'release'
            manifest = verify(payload, Path('/sysroot'+installed['certificate']), purpose='factory',
                              image_id=installed['image_id'], expected_configuration=installed['configuration_sha256'])
            require(manifest['deployment_sequence'] == installed['deployment_sequence'] and
                    manifest['platform_version'] == installed['platform_version'], 'Media does not match the booted root.')
            if 'image_contract' in installed:
                require(manifest.get('image_contract') == installed['image_contract'],
                        'Factory image operation contract differs from its verified root.')
            if 'tpm_policy' in installed:
                from .measured_boot import verify as verify_measured_boot
                uki = next(item for item in manifest['artifacts'] if item['role'] == 'uki')
                verify_measured_boot(payload/uki['name'], installed['tpm_policy'])
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
                repartition(installed, chosen, installed_root=False)
        finally:
            command(['umount', str(mount)])
    command(['sync'])
    print('Installation read-back passed. Remove the factory medium after power-off.', flush=True)
    # The installer holds initrd-switch-root while awaiting confirmation. Ask
    # the manager to terminate processes and unmount filesystems directly,
    # without waiting for that unfinished initrd boot transaction to complete.
    # All target writes are synced and the read-only payload is unmounted first.
    command(['systemctl', '--force', 'poweroff'])
    # Never return into initrd-switch-root on the removable installation medium.
    while True:
        import time
        time.sleep(60)


FALLBACK_DEADLINE_SECONDS = 900


def bounded_fallback(identity):
    """Limit emergency verification; a timed-out attempt must hold for recovery.

    This bounds interruptible userspace work. An uninterruptible kernel I/O
    stall still needs an independently qualified hardware watchdog.
    """
    from .early_failure import failed_boot

    require(signal.getitimer(signal.ITIMER_REAL) == (0.0, 0.0),
            'Fallback cannot replace an existing process timer.')
    previous = signal.getsignal(signal.SIGALRM)
    def expired(_signum, _frame):
        raise TimeoutError('Fallback verification deadline exceeded.')
    signal.signal(signal.SIGALRM, expired)
    try:
        signal.setitimer(signal.ITIMER_REAL, FALLBACK_DEADLINE_SECONDS)
        failed_boot(identity)
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous)


def fallback_diagnostic(error):
    """Return a bounded failure location without exception text or runtime values."""
    categories = ((ReleaseError, 'verification'), (OSError, 'os'), (ValueError, 'value'),
                  (KeyError, 'key'), (subprocess.SubprocessError, 'subprocess'))
    category = next((name for kind, name in categories if isinstance(error, kind)), 'other')
    trusted = {'early_failure.py', 'repair.py', 'update.py', 'release.py', 'factory.py',
               'tpm_migration.py', 'measured_boot.py'}
    location = 'unknown'
    trace = error.__traceback__
    while trace is not None:
        code = trace.tb_frame.f_code
        module = Path(code.co_filename).name
        if (module in trusted and not (module == 'release.py' and code.co_name == 'require') and
                re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]{0,63}', code.co_name)):
            location = f'{module}:{code.co_name}:{trace.tb_lineno}'
        trace = trace.tb_next
    return f'Automatic fallback diagnostic: {category} {location}'


def main(arguments=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=('provision', 'failed', 'hold', 'emergency'))
    args = parser.parse_args(arguments)
    try:
        if args.command == 'provision':
            provision()
        elif args.command == 'failed':
            from .early_failure import failed_boot, failure_identity
            installed = failure_identity(json.loads(read(Path('/usr/share/lanrith/initrd-failure.json'), 65536)))
            failed_boot(installed)
        else:
            require(os.geteuid() == 0 and Path('/etc/initrd-release').is_file(),
                    'Initrd recovery hold is unavailable in normal userspace.')
            if args.command == 'emergency':
                try:
                    from .early_failure import failure_identity
                    identity = failure_identity(json.loads(read(Path('/usr/share/lanrith/initrd-failure.json'), 65536)))
                    bounded_fallback(identity)
                except (ReleaseError, OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
                    print(fallback_diagnostic(error), flush=True)
                    print('Automatic fallback unavailable; holding for recovery.', flush=True)
            print('Entering emergency mode. Boot verified signed recovery media.', flush=True)
            import time
            while True:
                time.sleep(60)
    except (ReleaseError, OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
        if isinstance(error, ReleaseError):
            print(str(error), file=sys.stderr)
        else:
            detail = 'operation='+args.command+',exception='+type(error).__name__
            if isinstance(error, OSError):
                detail += ',errno='+str(error.errno)
            print('Factory installation failed closed ('+detail+').', file=sys.stderr)
        return 1
    return 0
