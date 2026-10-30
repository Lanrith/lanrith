"""Image-owned, resumable migration of explicitly bound legacy TPM tokens."""

import copy
from contextlib import ExitStack
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import struct
import tempfile

from .release import ReleaseError, canonical, file_record, read, require, unique
from .update import command, geometry, GUIDS, require_default


HEX = r'[0-9a-f]{64}'
IDENTIFIER = r'[0-9]|[12][0-9]|3[01]'
UUID = r'[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}'

# Static PCR calculation has not yet been reconciled with the observed PCR
# in the private initrd VM. It must not authorize TPM enrollment or retirement.
FALLBACK_MEASUREMENT_RUNTIME_QUALIFIED = False
# Image and PCR measurements do not prove that the fallback accepts this
# machine's current LUKS and legacy-token bindings. Keep that proof separate.
FALLBACK_STATE_COMPATIBILITY_RUNTIME_QUALIFIED = False
# A legacy image has no migration-aware state contract. Its boot authority,
# PCR behavior and retained-state compatibility require separate qualification.
LEGACY_FALLBACK_RUNTIME_QUALIFIED = False


def validate(value):
    require(isinstance(value, dict) and set(value) ==
            {'schema', 'phase', 'luks_uuid', 'legacy_tokens', 'fallback'} and
            type(value['schema']) is int and value['schema'] == 1 and
            value['phase'] in ('prepare', 'enroll', 'enforce') and isinstance(value['luks_uuid'], str) and
            re.fullmatch(UUID, value['luks_uuid']), 'Invalid TPM migration contract.')
    tokens = value['legacy_tokens']
    require(isinstance(tokens, dict) and 1 <= len(tokens) <= 4, 'Invalid legacy TPM inventory.')
    slots = set()
    for identifier, item in tokens.items():
        require(isinstance(identifier, str) and re.fullmatch(IDENTIFIER, identifier) and
                isinstance(item, dict) and set(item) == {'sha256', 'keyslot'} and
                isinstance(item['sha256'], str) and re.fullmatch(HEX, item['sha256']) and
                isinstance(item['keyslot'], str) and re.fullmatch(IDENTIFIER, item['keyslot']) and
                item['keyslot'] not in slots, 'Invalid bound legacy TPM token.')
        slots.add(item['keyslot'])
    fallback = value['fallback']
    if value['phase'] == 'prepare':
        require(fallback is None, 'Prepare image cannot authorize token retirement.')
        return value
    require(isinstance(fallback, dict) and set(fallback) ==
            {'sequence', 'uki_name', 'uki_sha256', 'partitions'} and
            type(fallback['sequence']) is int and 1 <= fallback['sequence'] <= 999999999 and
            isinstance(fallback['uki_name'], str) and
            re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._+-]{0,183}\.efi', fallback['uki_name']) and
            isinstance(fallback['uki_sha256'], str) and re.fullmatch(HEX, fallback['uki_sha256']) and
            isinstance(fallback['partitions'], dict) and set(fallback['partitions']) == set(GUIDS),
            'TPM enforcement requires a bound compatible fallback.')
    for item in fallback['partitions'].values():
        require(isinstance(item, dict) and set(item) == {'label', 'uuid', 'size', 'sha256'} and
                isinstance(item['label'], str) and re.fullmatch(r'[A-Za-z0-9_.-]{1,36}', item['label']) and
                isinstance(item['uuid'], str) and re.fullmatch(UUID, item['uuid']) and
                type(item['size']) is int and 0 < item['size'] <= 2**40 and
                isinstance(item['sha256'], str) and re.fullmatch(HEX, item['sha256']),
                'Invalid fallback partition binding.')
    return value


def classify(installed, luks):
    """Accept only the exact legacy tokens and the complete new policy."""
    from .factory import enrollment_tokens
    transition = validate(installed['tpm_transition'])
    require(isinstance(luks, dict) and isinstance(luks.get('tokens'), dict) and
            isinstance(luks.get('keyslots'), dict),
            'Malformed migration enrollment inventory.')
    projected = copy.deepcopy(luks)
    legacy, covered = [], set()
    for identifier, item in luks['tokens'].items():
        require(isinstance(item, dict), 'Malformed migration unlock token.')
        bound = transition['legacy_tokens'].get(identifier)
        if bound is None:
            continue
        restored = {**item, 'keyslots': [bound['keyslot']]}
        require(item.get('type') == 'systemd-tpm2' and item.get('tpm2-pcrs') == [7] and
                item.get('tpm2-pcr-bank', 'sha256') == 'sha256' and
                not item.get('tpm2_pubkey_pcrs') and not item.get('tpm2-pin') and
                not item.get('tpm2_pcrlock') and
                hashlib.sha256(canonical(restored)).hexdigest() == bound['sha256'] and
                (item.get('keyslots') == [bound['keyslot']] or
                 transition['phase'] == 'enforce' and item.get('keyslots') == [] and
                 bound['keyslot'] not in luks['keyslots']), 'Legacy TPM token differs from its image binding.')
        legacy.append(identifier)
        covered.add(bound['keyslot'])
        projected['tokens'].pop(identifier)
        projected['keyslots'].pop(bound['keyslot'], None)
    # Recovery methods are never invented from a marker or a missing TPM token.
    recovery = [item for item in projected['tokens'].values() if item.get('type') == 'systemd-recovery']
    require(recovery, 'TPM migration requires an existing recovery enrollment.')
    strong = [identifier for identifier, item in projected['tokens'].items() if item.get('type') == 'systemd-tpm2']
    if strong:
        enrollment_tokens(projected, tpm_required=True, policy=installed['tpm_policy'])
    else:
        for item in projected['tokens'].values():
            require(item.get('type') == 'systemd-recovery' and isinstance(item.get('keyslots'), list) and
                    len(item['keyslots']) == 1 and item['keyslots'][0] in projected['keyslots'],
                    'Unexpected pre-migration state unlock method.')
        expected = [item['keyslots'][0] for item in projected['tokens'].values()]
        require(len(set(expected)) == len(expected) and set(expected) == set(projected['keyslots']),
                'Pre-migration state contains unapproved keyslots.')
    require(legacy or strong, 'No approved TPM enrollment remains.')
    return {'legacy': sorted(legacy), 'strong': sorted(strong)}


def snapshot(device):
    return json.loads(command(['cryptsetup', 'luksDump', '--dump-json-metadata', device]))


def compare_fallback_state(installed, fallback_installed, luks):
    """Compare contracts only; the caller must authenticate fallback bytes.

    This does not authenticate the supplied fallback metadata, establish the
    historical runtime's behavior, or authorize enrollment or rollback.
    """
    from .early_unlock import validate as validate_policy
    require(isinstance(installed, dict) and isinstance(fallback_installed, dict) and
            isinstance(luks, dict), 'Malformed fallback state comparison.')
    transition = validate(installed.get('tpm_transition'))
    previous = validate(fallback_installed.get('tpm_transition'))
    require(transition['phase'] == 'enroll' and previous['phase'] == 'prepare' and
            transition['fallback'] is not None and
            fallback_installed.get('deployment_sequence') == transition['fallback']['sequence'] and
            isinstance(installed.get('image_id'), str) and
            fallback_installed.get('image_id') == installed['image_id'] and
            isinstance(installed.get('state_directory'), str) and
            fallback_installed.get('state_directory') == installed['state_directory'],
            'Fallback image identity or migration phase differs.')
    current_policy = validate_policy(installed.get('tpm_policy'))
    fallback_policy = validate_policy(fallback_installed.get('tpm_policy'))
    require(current_policy == fallback_policy and previous['luks_uuid'] == transition['luks_uuid'] and
            previous['legacy_tokens'] == transition['legacy_tokens'],
            'Fallback state or token bindings differ.')
    current = classify(installed, luks)
    accepted = classify(fallback_installed, luks)
    require(current == accepted and current['legacy'],
            'Fallback state token inventory differs.')
    return {'scope': 'contract-comparison', 'authorized_to_enroll': False,
            'authorized_to_rollback': False}


def bound_uki_roothash(path, expected_sha256):
    """Read a single root hash from the exact bound UKI, without executing it."""
    require(isinstance(expected_sha256, str) and re.fullmatch(HEX, expected_sha256),
            'Invalid fallback UKI digest.')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    with os.fdopen(fd, 'rb') as stream:
        before = os.fstat(stream.fileno())
        require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and 64 <= before.st_size <= 1024**3,
                'Unsafe fallback UKI.')
        digest = hashlib.sha256()
        for block in iter(lambda: stream.read(1024*1024), b''):
            digest.update(block)
        require(digest.hexdigest() == expected_sha256, 'Fallback UKI differs from its binding.')
        stream.seek(0)
        dos = stream.read(64)
        require(len(dos) == 64 and dos[:2] == b'MZ', 'Fallback UKI PE header is invalid.')
        offset = struct.unpack_from('<I', dos, 60)[0]
        require(64 <= offset <= min(before.st_size-24, 1024*1024), 'Fallback UKI PE offset is invalid.')
        stream.seek(offset)
        header = stream.read(24)
        require(len(header) == 24 and header[:4] == b'PE\0\0', 'Fallback UKI PE header is invalid.')
        machine, count = struct.unpack_from('<HH', header, 4)
        optional = struct.unpack_from('<H', header, 20)[0]
        table_end = offset+24+optional+count*40
        require(machine == 0x8664 and 1 <= count <= 96 and 112 <= optional <= 4096 and
                table_end <= before.st_size, 'Unsupported fallback UKI PE layout.')
        stream.seek(offset+24+optional)
        table = stream.read(count*40)
        entries = []
        for index in range(count):
            entry = table[index*40:(index+1)*40]
            if entry[:8].rstrip(b'\0') == b'.cmdline':
                size, _, raw_size, start = struct.unpack_from('<IIII', entry, 8)
                require(0 < size <= min(raw_size, 16384) and start >= table_end and
                        start+raw_size <= before.st_size, 'Fallback UKI command line is out of bounds.')
                entries.append((start, size))
        require(len(entries) == 1, 'Fallback UKI command line is missing or ambiguous.')
        stream.seek(entries[0][0])
        raw = stream.read(entries[0][1])
        require(len(raw) == entries[0][1] and b'\0' not in raw.rstrip(b'\0'),
                'Fallback UKI command line is malformed.')
        try:
            text = raw.rstrip(b'\0').decode('ascii')
        except UnicodeDecodeError:
            raise ReleaseError('Fallback UKI command line is malformed.') from None
        require(all(c in '\t\n\r ' or 33 <= ord(c) <= 126 for c in text) and
                not any(c in text for c in "\"'\\"), 'Unsupported fallback UKI command line.')
        matches = [item for item in text.split() if item.startswith('roothash=')]
        require(len(matches) == 1 and re.fullmatch(r'roothash=[0-9a-f]{64}', matches[0]),
                'Fallback UKI root hash is missing or ambiguous.')
        after = os.fstat(stream.fileno())
        require((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) ==
                (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns),
                'Fallback UKI changed during root-hash inspection.')
        return matches[0].split('=', 1)[1]


def read_fallback_contract(root):
    """Read installed metadata beneath a pinned root without following links."""
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    with ExitStack() as stack:
        descriptor = os.open(root, flags)
        stack.callback(os.close, descriptor)
        root_stat = os.fstat(descriptor)
        require(stat.S_ISDIR(root_stat.st_mode), 'Fallback root is not a directory.')
        for component in ('usr', 'share', 'lanrith'):
            descriptor = os.open(component, flags, dir_fd=descriptor)
            stack.callback(os.close, descriptor)
            info = os.fstat(descriptor)
            require(stat.S_ISDIR(info.st_mode) and info.st_dev == root_stat.st_dev,
                    'Fallback metadata crosses a filesystem boundary.')
        data = read('installed.json', 65536, dir_fd=descriptor)
    try:
        value = json.loads(data, object_pairs_hook=unique,
                           parse_constant=lambda _: (_ for _ in ()).throw(ReleaseError('Invalid fallback JSON.')))
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as error:
        raise ReleaseError('Invalid fallback metadata.') from error
    require(isinstance(value, dict), 'Invalid fallback metadata.')
    return value


def verify_fallback_root_mount(mount, mapping):
    """Require a restricted EROFS mount backed by the selected mapping."""
    observed = json.loads(command(['findmnt', '--uniq', '--json', '--target', str(mount),
                                   '--output', 'TARGET,SOURCE,FSTYPE,OPTIONS']))
    rows = observed.get('filesystems', []) if isinstance(observed, dict) else []
    require(isinstance(rows, list) and len(rows) == 1 and isinstance(rows[0], dict) and
            rows[0].get('target') == str(mount) and rows[0].get('fstype') == 'erofs' and
            isinstance(rows[0].get('source'), str) and rows[0]['source'].startswith('/dev/') and
            isinstance(rows[0].get('options'), str) and
            {'ro', 'nodev', 'nosuid', 'noexec'} <= set(rows[0]['options'].split(',')),
            'Fallback root mount is not restricted.')
    actual, expected = os.stat(rows[0]['source']), os.stat(mapping)
    require(stat.S_ISBLK(actual.st_mode) and stat.S_ISBLK(expected.st_mode) and
            actual.st_rdev == expected.st_rdev, 'Fallback root mount uses another device.')


def inspect_fallback_state(installed, luks, root_device, hash_device, root_hash):
    """Compare metadata read from a restricted dm-verity fallback root.

    The caller must authenticate the UKI and partitions and supply its bound
    root hash. This experimental reader does not authorize enrollment or boot.
    """
    require(all(isinstance(item, str) and re.fullmatch(r'/dev/[A-Za-z0-9_.-]+', item)
                for item in (root_device, hash_device)) and root_device != hash_device and
            isinstance(root_hash, str) and re.fullmatch(HEX, root_hash),
            'Invalid verified fallback root inputs.')
    mount = Path(tempfile.mkdtemp(prefix='lanrith-fallback-root.', dir='/run'))
    name = mount.name.replace('.', '-')
    mapping = Path('/dev/mapper')/name
    opened = False
    try:
        require(re.fullmatch(r'lanrith-fallback-root-[A-Za-z0-9_-]+', name) and not mapping.exists(),
                'Fallback mapping name is unsafe or in use.')
        command(['veritysetup', 'open', root_device, name, hash_device, root_hash], timeout=120)
        opened = True
        command(['mount', '-t', 'erofs', '-o', 'ro,nodev,nosuid,noexec', '--', str(mapping), str(mount)])
        require(mount.is_mount(), 'Fallback root did not mount.')
        verify_fallback_root_mount(mount, mapping)
        previous = read_fallback_contract(mount)
        if 'steady_state' in installed:
            from . import steady_recovery
            result = steady_recovery.compare(installed, previous, luks)
        else:
            result = compare_fallback_state(installed, previous, luks)
        verify_fallback_root_mount(mount, mapping)
        return result
    finally:
        if mount.is_mount():
            command(['umount', '--', str(mount)])
            require(not mount.is_mount(), 'Fallback root remains mounted.')
        if opened:
            command(['veritysetup', 'close', name], timeout=120)
            require(not mapping.exists(), 'Fallback verity mapping remains active.')
        mount.rmdir()


def partition_digest(device, size):
    descriptor = os.open(device, os.O_RDONLY|os.O_NOFOLLOW)
    digest = hashlib.sha256()
    with os.fdopen(descriptor, 'rb') as stream:
        remaining = size
        while remaining:
            block = stream.read(min(remaining, 4*1024*1024))
            require(block, 'Compatible fallback partition is truncated.')
            digest.update(block)
            remaining -= len(block)
    return digest.hexdigest()


def verify_fallback_esp(mount, disk):
    """Verify the mounted fallback ESP is on the intended disk and restricted."""
    from . import update
    require(update.boot_esp({'esp': str(mount)}, disk=disk) == mount,
            'Compatible fallback ESP differs from the selected disk.')
    observed = json.loads(command(['findmnt', '--uniq', '--json', '--target', str(mount/'EFI'),
                                   '--output', 'TARGET,OPTIONS']))
    require(isinstance(observed, dict), 'Compatible fallback ESP observation is malformed.')
    rows = observed.get('filesystems', [])
    require(isinstance(rows, list) and len(rows) == 1 and isinstance(rows[0], dict) and rows[0].get('target') == str(mount) and
            isinstance(rows[0].get('options'), str) and
            {'ro', 'nodev', 'nosuid', 'noexec'} <= set(rows[0]['options'].split(',')),
            'Compatible fallback ESP is not read-only and restricted.')


def legacy_fallback(installed, binding, disk, active, state_device):
    """Inspect a signed Prepare-to-legacy binding without granting authority.

    The caller must authenticate the running initrd and its binding. A current
    PCR-7 token probe does not prove the token will unseal after another boot,
    nor does matching image bytes prove all retained application state is
    rollback compatible. Those conditions need separate qualification.
    """
    require(LEGACY_FALLBACK_RUNTIME_QUALIFIED,
            'Legacy fallback behavior and state compatibility are not qualified.')
    from . import early_failure, early_unlock
    require(isinstance(installed, dict) and isinstance(binding, dict) and
            isinstance(disk, str) and re.fullmatch(r'/dev/[A-Za-z0-9_.-]+', disk) and
            isinstance(active, set) and all(type(item) is int and item > 0 for item in active) and
            isinstance(state_device, str) and re.fullmatch(r'/dev/[A-Za-z0-9_.-]+', state_device),
            'Invalid legacy fallback inputs.')
    transition = validate(installed.get('tpm_transition'))
    require(transition['phase'] == 'prepare' and transition['fallback'] is None,
            'Legacy fallback requires a Prepare transition.')
    require(command(['cryptsetup', 'luksUUID', state_device]).strip() == transition['luks_uuid'],
            'Legacy fallback state volume differs from its binding.')
    early_unlock.validate(installed.get('tpm_policy'))
    image, sequence = installed.get('image_id'), installed.get('deployment_sequence')
    require(isinstance(image, str) and re.fullmatch(r'[a-z][a-z0-9-]{0,47}', image) and
            type(sequence) is int and 1 <= sequence <= 999999999,
            'Invalid legacy fallback image identity.')
    early_failure.validate_fallback_binding(binding, image=image, current_sequence=sequence)
    require(str(Path(binding['disk_by_id']).resolve(strict=True)) == disk,
            'Legacy fallback disk differs from its signed binding.')
    identity = {'image_id': image, 'deployment_sequence': sequence,
                'uki_name': installed.get('uki_name'), 'fallback_binding': binding}
    early_failure.failure_identity(identity)
    bound = binding['release']
    require_default(Path(bound['uki_name']))
    rows = geometry(disk)
    for role, item in bound['partitions'].items():
        matches = [row for row in rows if row.get('disk') == disk and row.get('type') == GUIDS[role] and
                   row.get('label') == item['label'] and row.get('uuid') == item['uuid']]
        require(len(matches) == 1 and matches[0].get('number') not in active and
                not matches[0].get('mounted'), 'Legacy fallback slot is missing or in use.')
    observed = early_failure.inspect_bound_fallback(identity)
    require(isinstance(observed, dict) and observed.get('sequence') == bound['sequence'] and
            observed.get('authorized_to_boot') is False,
            'Legacy fallback observation differs from its binding.')
    before = snapshot(state_device)
    inventory = classify(installed, before)
    require(inventory['legacy'] and all(early_unlock.token_test(state_device, item) for item in inventory['legacy']),
            'Bound legacy token did not unseal in the current boot.')
    require(command(['cryptsetup', 'luksUUID', state_device]).strip() == transition['luks_uuid'] and
            snapshot(state_device) == before and geometry(disk) == rows and
            str(Path(binding['disk_by_id']).resolve(strict=True)) == disk,
            'Legacy fallback state or geometry changed during inspection.')
    observed = early_failure.inspect_bound_fallback(identity)
    require(isinstance(observed, dict) and observed.get('sequence') == bound['sequence'] and
            observed.get('authorized_to_boot') is False,
            'Legacy fallback changed during inspection.')
    require(command(['cryptsetup', 'luksUUID', state_device]).strip() == transition['luks_uuid'] and
            snapshot(state_device) == before and geometry(disk) == rows and
            str(Path(binding['disk_by_id']).resolve(strict=True)) == disk,
            'Legacy fallback state or geometry changed during final inspection.')
    require_default(Path(bound['uki_name']))
    return {'schema': 1, 'scope': 'legacy-fallback-observation', 'authorized_to_boot': False}


def fallback(installed, disk, active, state_device=None):
    """Authenticate the retained bridge before touching an unlock method."""
    steady = installed.get('steady_state')
    require(FALLBACK_MEASUREMENT_RUNTIME_QUALIFIED or steady is not None,
            'Fallback PCR measurement is not qualified against a real boot.')
    require(FALLBACK_STATE_COMPATIBILITY_RUNTIME_QUALIFIED or steady is not None,
            'Fallback state and token compatibility is not qualified.')
    require(isinstance(state_device, str) and re.fullmatch(r'/dev/[A-Za-z0-9_.-]+', state_device),
            'Fallback state device is invalid.')
    from .measured_boot import verify
    bound = installed['fallback_binding']['release'] if steady is not None else validate(installed['tpm_transition'])['fallback']
    require(bound is not None and bound['sequence'] < installed['deployment_sequence'],
            'TPM migration fallback is not an earlier accepted image.')
    require_default(Path(bound['uki_name']))
    rows = geometry(disk)
    devices = {}
    for role, item in bound['partitions'].items():
        matches = [row for row in rows if row['type'] == GUIDS[role] and
                   row['label'] == item['label'] and row['uuid'] == item['uuid']]
        require(len(matches) == 1 and matches[0]['number'] not in active and not matches[0]['mounted'] and
                matches[0]['size'] >= item['size'], 'Compatible fallback slot is missing or in use.')
        require(partition_digest(matches[0]['device'], item['size']) == item['sha256'],
                'Compatible fallback partition differs from its signed binding.')
        devices[role] = matches[0]['device']
    esp = [row for row in rows if row['type'] == 'c12a7328-f81f-11d2-ba4b-00a0c93ec93b']
    require(len(esp) == 1 and esp[0].get('disk') == disk and not esp[0].get('mounted') and
            isinstance(esp[0].get('device'), str) and re.fullmatch(r'/dev/[A-Za-z0-9_.-]+', esp[0]['device']),
            'Migration ESP is absent, ambiguous or in use.')
    mount = Path(tempfile.mkdtemp(prefix='lanrith-tpm-fallback.', dir='/run'))
    try:
        command(['mount', '-t', 'vfat', '-o', 'ro,nodev,nosuid,noexec', '--', esp[0]['device'], str(mount)])
        require(mount.is_mount(), 'Compatible fallback ESP did not mount.')
        verify_fallback_esp(mount, disk)
        uki = mount/'EFI/Linux'/bound['uki_name']
        require(file_record(uki)['sha256'] == bound['uki_sha256'], 'Compatible fallback UKI differs.')
        policy = steady['tpm_policy'] if steady is not None else installed['tpm_policy']
        if policy is not None:
            verify(uki, policy)
        root_hash = bound_uki_roothash(uki, bound['uki_sha256'])
        verify_fallback_esp(mount, disk)
    finally:
        # Never recursively remove a mountpoint. If unmount fails, leave the
        # restricted mount and its directory intact and fail the transaction.
        if mount.is_mount():
            command(['umount', '--', str(mount)])
            require(not mount.is_mount(), 'Compatible fallback ESP remains mounted.')
        mount.rmdir()
    before = snapshot(state_device)
    inspect_fallback_state(installed, before, devices['root'], devices['verity'], root_hash)
    require(snapshot(state_device) == before, 'State token inventory changed during fallback inspection.')


def preflight_pcr_key(public):
    """Reject unsupported RSA parameters before adding a new state keyslot."""
    text = command(['openssl', 'pkey', '-pubin', '-in', str(public), '-text', '-noout'])
    sizes = re.findall(r'^Public-Key: \(([0-9]{4}) bit\)$', text, re.MULTILINE)
    require(len(sizes) == 1 and sizes[0] in ('2048', '3072', '4096'),
            'TPM migration requires a supported RSA PCR policy key.')
    try:
        command(['tpm2_testparms', '-T', 'device:/dev/tpmrm0', 'rsa'+sizes[0]])
    except ReleaseError as error:
        raise ReleaseError('TPM cannot validate the PCR policy key parameters.') from error


def migrate(installed, device, disk, active):
    """Prepare is read-only; enrollment retains all legacy and recovery methods."""
    from .early_unlock import in_initrd, token_test, validate as validate_policy
    in_initrd()
    validate_policy(installed['tpm_policy'])
    transition = validate(installed['tpm_transition'])
    require(transition['phase'] != 'enforce',
            'TPM retirement is blocked pending staged recovery qualification.')
    require(command(['cryptsetup', 'luksUUID', device]).strip() == transition['luks_uuid'],
            'TPM migration belongs to another encrypted state volume.')
    state = classify(installed, snapshot(device))
    if transition['phase'] == 'prepare':
        return state
    if transition['phase'] == 'enroll':
        require(state['legacy'], 'Enrollment requires the bound legacy TPM method to remain present.')
    fallback(installed, disk, active, device)
    if not state['strong']:
        public = Path('/sysroot/usr/lib/systemd/tpm2-pcr-public-key.pem')
        require(hashlib.sha256(read(public, 16384)).hexdigest() == installed['tpm_policy']['public_key_sha256'],
                'Migration policy key differs from the verified image.')
        preflight_pcr_key(public)
        command(['systemd-cryptenroll', '--unlock-tpm2-device=/dev/tpmrm0', '--tpm2-device=/dev/tpmrm0',
                 '--tpm2-pcrs=7:sha256+15:sha256='+('0'*64), '--tpm2-pcrlock=',
                 '--tpm2-public-key='+str(public), '--tpm2-public-key-pcrs=11',
                 '--tpm2-signature=/run/systemd/tpm2-pcr-signature.json', device], timeout=90)
        state = classify(installed, snapshot(device))
    require(state['strong'] and all(token_test(device, item) for item in state['strong']),
            'Strong TPM enrollment did not pass native unseal.')
    command(['sync'])
    return state
