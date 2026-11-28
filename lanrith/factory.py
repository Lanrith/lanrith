"""Explicit factory installation and checks for the verified A/B state layout."""

import argparse
import base64
from contextlib import contextmanager, nullcontext
import ctypes
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
import time

from .release import canonical, file_record, read, require, verify, ReleaseError
from .update import GUIDS, command, geometry, layout_limits, mounted_root_device, root_disk
from .factory_console import Consoles, require_physical_input


VAR_GUID = '4d21b016-b534-45c2-a9fb-5c16e091fd2d'


# Factory I/O budgets count logical bytes across both endpoints. Keep some
# headroom for device flushes and startup even on a small factory image.
IO_BYTES_PER_SECOND = 1024 * 1024
OPERATOR_SECONDS = 15 * 60
PARTITION_SECONDS = 600
BOOT_SECONDS = 300


def notify_manager(message):
    if os.environ.get('NOTIFY_SOCKET'):
        result = ctypes.CDLL('libsystemd.so.0').sd_notify(0, message.encode('ascii'))
        require(result > 0, 'Cannot notify the initrd service manager.')


def extend_startup(seconds):
    # The command/input deadline expires first, with time left for cleanup.
    notify_manager(f'EXTEND_TIMEOUT_USEC={(seconds + 60) * 1_000_000}')


def io_seconds(size):
    return 120 + (size + IO_BYTES_PER_SECOND - 1) // IO_BYTES_PER_SECOND


@contextmanager
def input_deadline():
    require(signal.getitimer(signal.ITIMER_REAL) == (0.0, 0.0),
            'Cannot replace an active provisioning timer.')
    previous = signal.getsignal(signal.SIGALRM)

    def expired(_signum, _frame):
        raise ReleaseError('Provisioning input expired. Reboot to retry.')

    signal.signal(signal.SIGALRM, expired)
    try:
        signal.setitimer(signal.ITIMER_REAL, OPERATOR_SECONDS)
        yield
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous)


def verified_root(mountpoint='/'):
    options = command(['findmnt', '--noheadings', '--output', 'OPTIONS', mountpoint]).strip().split(',')
    require('ro' in options, 'Factory and boot checks require a read-only root.')
    source, name = mounted_root_device(mountpoint)
    require(re.fullmatch(r'dm-[0-9]+', name), 'Root is not a device-mapper verified filesystem.')
    status = command(['dmsetup', 'status', source]).strip().splitlines()
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


def profile_allows(installed, device):
    pinned = installed['storage'].get('target')
    if pinned:
        return str(Path(pinned).resolve()) == device['name']
    # lsblk reports null for disks without transport metadata (e.g. virtio).
    return 'tran' in device and device['tran'] != 'usb'


def target(installed, boot_disk, console):
    devices = json.loads(command(['lsblk', '--json', '--bytes', '--paths', '--output',
                                 'NAME,TYPE,SIZE,RO,LOG-SEC,MOUNTPOINTS,MODEL,SERIAL,TRAN']))['blockdevices']
    allowed = {device['name']: device for device in devices
               if profile_allows(installed, device) and eligible(device, boot_disk, minimum_size(installed))}
    identities = {}
    for path in sorted(Path('/dev/disk/by-id').glob('*')):
        resolved = str(path.resolve())
        if path.is_symlink() and resolved in allowed and '-part' not in path.name:
            identities[str(path)] = resolved
    selected = installed['storage'].get('target')
    if not selected:
        require(identities, 'No eligible stable disk identity is available.')
        console.write('Eligible disk identities (all contents on the selected disk will be erased):\n')
        for identity in identities:
            device = allowed[identities[identity]]
            console.write(f'{identity} {device.get("model") or ""} {device["size"]} bytes\n')
        selected = console.input('Enter the complete /dev/disk/by-id identity: ')
    require(selected in identities, 'The selected disk is not eligible for factory installation.')
    device = identities[selected]
    confirmation = 'ERASE-AND-INSTALL '+selected
    console.write('Selected disk: '+selected+'. All its contents will be erased.\n')
    console.write('Enter the full line exactly as shown, including the disk path. Type CANCEL to stop.\n')
    for attempt in range(3):
        answer = console.input('Type '+confirmation+' to continue: ')
        if answer == confirmation:
            break
        require(answer != 'CANCEL', 'Installation cancelled; nothing was written.')
        if attempt < 2:
            console.write('Confirmation did not match. Nothing was written. Try again or type CANCEL.\n')
    else:
        raise ReleaseError('Destructive installation was not explicitly confirmed.')
    # Resolve and inspect again after operator input; never trust a stale selection.
    require(str(Path(selected).resolve()) == device, 'Selected disk identity changed.')
    current = json.loads(command(['lsblk', '--json', '--bytes', '--paths', '--output',
                                 'NAME,TYPE,SIZE,RO,LOG-SEC,MOUNTPOINTS,TRAN', device]))['blockdevices']
    require(len(current) == 1 and current[0]['name'] == device and profile_allows(installed, current[0]) and
            eligible(current[0], boot_disk, minimum_size(installed)),
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


def slot_report(installed, rows, active):
    limits = installed.get('payload_limits') or layout_limits(installed['storage'])
    standby = {'short': [], 'busy': [], 'ambiguous': []}
    active_short = []
    for role, guid in GUIDS.items():
        candidates = [row for row in rows if row['type'].lower() == guid]
        current = [row for row in candidates if row['label'] == installed['active_labels'][role]]
        require(len(current) == 1 and (role == 'verity-sig' or current[0]['number'] in active),
                'The active slot does not match the mounted verified root.')
        if current[0]['size'] < limits[role]:
            active_short.append(role)
        other = [row for row in candidates if row is not current[0]]
        if len(other) != 1:
            standby['ambiguous'].append(role)
            continue
        if other[0]['size'] < limits[role]:
            standby['short'].append(role)
        if other[0]['mounted'] or other[0]['number'] in active:
            standby['busy'].append(role)
    standby['available'] = not any(standby.values())
    return {'active_verified': True, 'active_short': active_short, 'standby': standby}


def inspect_state(installed, root):
    disk, active = verified_root(root)
    rows = geometry(disk)
    report = slot_report(installed, rows, active)
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
    return disk, var[0], luks, report


def state_metadata(installed, *, root='/'):
    disk, state, luks, _ = inspect_state(installed, root)
    return disk, state['device'], luks


def state_tokens(installed, luks):
    if 'tpm_transition' in installed:
        from .tpm_migration import classify
        classify(installed, luks)
        return [item['type'] for item in luks['tokens'].values()]
    return enrollment_tokens(luks, tpm_required=installed['boot'].get('tpm', 'required') == 'required',
                             policy=installed.get('tpm_policy'))


def initialize(installed, *, root='/'):
    from . import slot_state
    started = time.monotonic_ns()
    _, state, luks, report = inspect_state(installed, root)
    tokens = state_tokens(installed, luks)
    if 'tpm_policy' in installed and root == '/':
        from .early_unlock import observation
        observation(installed)
    if installed.get('tpm_transition', {}).get('phase') == 'enforce':
        enrollment_tokens(luks, tpm_required=True, policy=installed['tpm_policy'])
    directory = Path(root)/installed['state_directory'].lstrip('/')
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    if root == '/' and 'image_contract' in installed:
        from .image_contract import remember
        remember(installed)
    slot_state.remember_marker(directory, state)
    if root == '/':
        try:
            slot_state.write_health(installed, report, started)
        except (OSError, ValueError):
            # The active root and state were verified. Operators still get the
            # observed roles in the journal if runtime status is unavailable.
            print('Could not publish verified slot health: '+json.dumps(report, sort_keys=True), file=sys.stderr)
        else:
            if not report['standby']['available'] or report['active_short']:
                print('Verified slot capacity and use: '+json.dumps(report, sort_keys=True), file=sys.stderr)
    return state['device'], tokens


def recovery(installed, *, root='/', verification_only=False):
    require(os.geteuid() == 0, 'Recovery enrollment requires root.')
    with Consoles(installed) as console:
        console.write('An offline state recovery key must be recorded before startup can finish.\n')
        in_factory = root == '/sysroot'
        if in_factory:
            extend_startup(OPERATOR_SECONDS)
            console.write('You have 15 minutes to finish enrollment. Reboot from the installed disk to retry.\n')
        with input_deadline() if in_factory else nullcontext():
            console.private(lambda: enroll_recovery(installed, root=root, verification_only=verification_only))
        if in_factory:
            extend_startup(BOOT_SECONDS)


def enroll_recovery(installed, *, root='/', verification_only=False):
    from . import recovery_enrollment
    if 'tpm_policy' in installed:
        from .early_unlock import in_initrd
        in_initrd()
        require(root == '/sysroot', 'Measured recovery enrollment requires the verified initrd root.')
    require_physical_input(installed)
    if verification_only and 'tpm_transition' in installed:
        # This runs before migration can change the header or initialize the new image.
        _, device, _ = state_metadata(installed, root=root)
    else:
        device, _ = initialize(installed, root=root)
    directory = Path(root)/installed['state_directory'].lstrip('/')
    recovery_enrollment.enroll(installed, device, directory, verification_only=verification_only)


def manual_repartition(installed, disk, arguments):
    require_physical_input(installed)
    with input_deadline():
        first = getpass.getpass('State encryption passphrase (at least 24 characters): ')
        require(len(first) >= 24 and first == getpass.getpass('Repeat state encryption passphrase: '),
                'State encryption passphrases differ or are too short.')
    with tempfile.TemporaryDirectory(prefix='lanrith-state.', dir='/run') as secret:
        key = Path(secret)/'key'
        key.write_text(first)
        key.chmod(0o600)
        del first
        command([*arguments, '--key-file='+str(key), disk], timeout=PARTITION_SECONDS)


def repartition(installed, disk, *, installed_root, console=None):
    """Create bounded slots/state only on the explicitly observed or selected disk."""
    definitions = '/sysroot/usr/lib/repart.d'
    arguments = ['systemd-repart', '--definitions='+definitions, '--empty=refuse', '--dry-run=no', '--offline=no',
                 '--seed='+installed['machine_id']]
    if installed_root:
        arguments.append('--root=/sysroot')
    if installed['boot'].get('tpm', 'required') == 'disabled':
        with Consoles(installed) if console is None else nullcontext(console) as selected:
            selected.write('Enter and repeat the passphrase within 15 minutes. Reboot to retry.\n')
            if selected.owner is None:
                extend_startup(OPERATOR_SECONDS)
                selected.write('Console selection expires in 15 minutes.\n')
                with input_deadline():
                    require(selected.input('Press Enter on this console to set the state encryption passphrase: ') == '',
                            'Private console selection was not confirmed.')
            extend_startup(OPERATOR_SECONDS + PARTITION_SECONDS)
            selected.private(lambda: manual_repartition(installed, disk, arguments))
    else:
        extend_startup(PARTITION_SECONDS)
        policy = installed.get('tpm_policy')
        if policy is None:
            command([*arguments, '--tpm2-pcrs=7', '--tpm2-pcrlock=', disk], timeout=PARTITION_SECONDS)
        else:
            public = Path('/sysroot/usr/lib/systemd/tpm2-pcr-public-key.pem')
            require(hashlib.sha256(read(public, 16384)).hexdigest() == policy['public_key_sha256'],
                    'Factory measured-policy authority differs.')
            from .early_unlock import in_initrd, validate
            validate(policy)
            in_initrd()
            command([*arguments, '--tpm2-pcrs=7:sha256+15:sha256='+('0'*64), '--tpm2-pcrlock=',
                     '--tpm2-public-key='+str(public), '--tpm2-public-key-pcrs=11', disk], timeout=PARTITION_SECONDS)
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
        extend_startup(BOOT_SECONDS)
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
    table = json.loads(command(['lsblk', '--json', '--paths', '--output', 'NAME,TYPE,PKNAME,PARTLABEL,TRAN', disk]))
    devices = table['blockdevices']
    require(len(devices) == 1 and devices[0].get('name') == disk and devices[0].get('type') == 'disk',
            'Cannot identify partitions on the verified boot disk.')
    media = [item for item in devices[0].get('children', [])
             if item.get('type') == 'part' and item.get('partlabel') == 'lanrith-factory-media']
    if not media:
        require(profile_allows(installed, devices[0]), 'Boot disk lacks a factory payload and is not an installed target.')
        device = prepare_state(installed, disk, active)
        if 'tpm_policy' in installed:
            from .early_unlock import unlock
            unlock(installed, device)
        return
    with Consoles(installed) as console:
        install_media(installed, disk, active, media, console)


def check_tpm_capability(policy):
    from .early_unlock import validate
    validate(policy)
    pcrs = sorted(set(policy['direct_pcrs'] + policy['signed_pcrs']))
    selection = policy['bank'] + ':' + ','.join(str(pcr) for pcr in pcrs)
    with tempfile.TemporaryDirectory(prefix='lanrith-pcr.') as temporary:
        values = Path(temporary)/'pcrs'
        # Force the kernel resource-manager device, with no software TPM fallback.
        command(['tpm2_pcrread', '-T', 'device:/dev/tpmrm0', '-o', str(values), selection])
        size = len(pcrs) * hashlib.new(policy['bank']).digest_size
        require(len(read(values, size)) == size, 'TPM lacks the PCRs required by the signed state policy.')


def install_media(installed, disk, active, media, console):
    require(len(media) == 1 and media[0].get('pkname') == disk,
            'Factory payload must be on the single verified boot disk.')
    console.write('Lanrith factory installer. Verifying the signed USB payload; no target disk has been changed.\n')
    with tempfile.TemporaryDirectory(prefix='lanrith-media.', dir='/run') as temporary:
        mount = Path(temporary)
        command(['mount', '-o', 'ro,noload,nodev,nosuid,noexec', media[0]['name'], str(mount)])
        try:
            payload = mount/'release'
            manifest = verify(payload, Path('/sysroot'+installed['certificate']), purpose='factory',
                              image_id=installed['image_id'], expected_configuration=installed['configuration_sha256'],
                              before_hashing=lambda size: extend_startup(io_seconds(size)))
            require(manifest['deployment_sequence'] == installed['deployment_sequence'] and
                    manifest['platform_version'] == installed['platform_version'], 'Media does not match the booted root.')
            if 'image_contract' in installed:
                require(manifest.get('image_contract') == installed['image_contract'],
                        'Factory image operation contract differs from its verified root.')
            if 'tpm_policy' in installed:
                from .measured_boot import verify as verify_measured_boot
                uki = next(item for item in manifest['artifacts'] if item['role'] == 'uki')
                extend_startup(io_seconds(2 * uki['size']) + 120)
                verify_measured_boot(payload/uki['name'], installed['tpm_policy'])
            rows = geometry(disk)
            for role in ('root', 'verity'):
                artifact = next(item for item in manifest['artifacts'] if item['role'] == role)
                partuuid = artifact['name'].removeprefix(f'{manifest["image_id"]}_{manifest["deployment_sequence"]}_').split('.')[0]
                require(any(row['number'] in active and row['type'].lower() == GUIDS[role] and row['uuid'] == partuuid
                            for row in rows), 'Media verified-root identity differs from the booted root.')
            if 'tpm_policy' in installed:
                check_tpm_capability(installed['tpm_policy'])
            artifact = next(item for item in manifest['artifacts'] if item['role'] == 'disk')
            raw = payload/artifact['name']
            budget = io_seconds(2 * artifact['size'])
            extend_startup(OPERATOR_SECONDS)
            console.write('You have 15 minutes to select and confirm. Reboot from the factory medium to retry.\n')
            with input_deadline():
                chosen = target(installed, disk, console)
            extend_startup(budget)
            console.write('Writing the verified image to '+chosen+'. Do not remove power.\n')
            command(['dd', 'if='+str(raw), 'of='+chosen, 'bs=4M', 'conv=fsync', 'status=progress'], timeout=budget)
            console.write('Image written. Reading back the target disk...\n')
            extend_startup(budget)
            command(['cmp', '--bytes='+str(artifact['size']), str(raw), chosen], timeout=budget)
            extend_startup(BOOT_SECONDS)
            command(['sfdisk', '--relocate', 'gpt-bak-std', chosen])
            if installed['boot'].get('tpm', 'required') == 'disabled':
                repartition(installed, chosen, installed_root=False, console=console)
        finally:
            command(['umount', str(mount)])
    command(['sync'])
    console.write('Installation read-back passed. Remove the factory medium after power-off.\n')
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
ATTEMPT_DIRECTORY = Path('/run')
FAILURE_IDENTITY = Path('/usr/share/lanrith/initrd-failure.json')
MEDIA_ACTION = ('Use the firmware boot menu to start independently signed recovery media '
                'on its prepared serial or hypervisor terminal.')


def read_failure_identity():
    from . import early_failure, release
    return early_failure.failure_identity(json.loads(read(FAILURE_IDENTITY, 65536), object_pairs_hook=release.unique))


def reserve_fallback_attempt(identity):
    from .early_failure import FallbackUnavailable
    require(os.geteuid() == 0 and Path('/etc/initrd-release').is_file(),
            'Automatic fallback requires the initrd.')
    info = ATTEMPT_DIRECTORY.lstat()
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o022,
            'Unsafe initrd runtime directory.')
    boot = Path('/proc/sys/kernel/random/boot_id').read_text().strip()
    require(re.fullmatch(r'[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}', boot),
            'Invalid kernel boot identity.')
    digest = hashlib.sha256(canonical(identity)).hexdigest()
    mark = ATTEMPT_DIRECTORY/f'lanrith-fallback-{boot}-{digest}'
    # An interrupted, overlapping or completed attempt has spent the budget.
    # The marker is never read as evidence that a boot is safe.
    try:
        descriptor = os.open(mark, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
    except FileExistsError:
        raise FallbackUnavailable('Automatic fallback was already attempted during this boot.') from None
    with os.fdopen(descriptor, 'w') as stream:
        stream.write(str(time.monotonic_ns())+'\n')


def bounded_fallback(identity):
    """Limit emergency verification; a timed-out attempt must hold for recovery.

    This bounds interruptible userspace work. An uninterruptible kernel I/O
    stall still needs an independently qualified hardware watchdog.
    """
    from .early_failure import failed_boot, require_fallback_policy

    require_fallback_policy(identity)

    require(signal.getitimer(signal.ITIMER_REAL) == (0.0, 0.0),
            'Fallback cannot replace an existing process timer.')
    previous = signal.getsignal(signal.SIGALRM)
    def expired(_signum, _frame):
        raise TimeoutError('Fallback verification deadline exceeded.')
    signal.signal(signal.SIGALRM, expired)
    try:
        signal.setitimer(signal.ITIMER_REAL, identity.get('fallback_timeout_seconds', FALLBACK_DEADLINE_SECONDS))
        reserve_fallback_attempt(identity)
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


def automatic_fallback():
    from .early_failure import FallbackUnavailable
    try:
        bounded_fallback(read_failure_identity())
    except (ReleaseError, OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
        try:
            if isinstance(error, FallbackUnavailable):
                print(str(error), flush=True)
            else:
                print('Automatic fallback verification failed.\n'+fallback_diagnostic(error), flush=True)
        except OSError:
            pass
        return False
    return True


def main(arguments=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=('provision', 'failed', 'hold', 'emergency'))
    args = parser.parse_args(arguments)
    try:
        if args.command == 'provision':
            provision()
            # Installation media never returns. An installed boot reaches this
            # point only after all required state checks and enrollment succeed.
            notify_manager('READY=1')
        elif args.command == 'failed':
            if not automatic_fallback():
                action = ('Continue on the configured recovery terminal.'
                          if Path('/usr/share/lanrith/failure-console.json').is_file() else MEDIA_ACTION)
                print(action, flush=True)
                return 1
        else:
            require(os.geteuid() == 0 and Path('/etc/initrd-release').is_file(),
                    'Initrd recovery hold is unavailable in normal userspace.')
            if args.command == 'emergency' and automatic_fallback():
                print('Reboot requested for the verified fallback.', flush=True)
            else:
                if args.command == 'emergency':
                    print('Automatic fallback unavailable; holding for recovery.', flush=True)
                print('Entering emergency mode. '+MEDIA_ACTION, flush=True)
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
