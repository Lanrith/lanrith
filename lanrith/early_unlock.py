"""Fixed initrd transaction for measured state unlock and its PCR 15 barrier."""

import ctypes
import errno
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys

from .release import canonical, read, require, ReleaseError
from .update import command


ZERO = '0'*64
BARRIER = 'lanrith-state-unlock-closed-v1'
BARRIER_DIGEST = hashlib.sha256(BARRIER.encode()).hexdigest()
CLOSED = hashlib.sha256(bytes(32)+bytes.fromhex(BARRIER_DIGEST)).hexdigest()
PCR = Path('/sys/class/tpm/tpm0/pcr-sha256/15')
OBSERVATION = Path('/run/lanrith/unlock/early-unlock.json')
SYSROOT = Path('/sysroot')


def kernel_text(path, maximum):
    # procfs/sysfs files report synthetic sizes; artifact-file validation is
    # intentionally unsuitable here. The path is fixed by the signed code.
    with path.open('rb') as stream:
        data = stream.read(maximum+1)
    require(0 < len(data) <= maximum, 'Kernel observation exceeds its bound.')
    return data.decode('ascii').strip()


def policy(public):
    return {'bank': 'sha256', 'direct_pcrs': [7, 15], 'signed_pcrs': [11],
            'public_key_sha256': hashlib.sha256(public).hexdigest(), 'early_boot_only': True}


def validate(value):
    require(isinstance(value, dict) and set(value) ==
            {'bank', 'direct_pcrs', 'signed_pcrs', 'public_key_sha256', 'early_boot_only'} and
            value['bank'] == 'sha256' and value['direct_pcrs'] == [7, 15] and
            value['signed_pcrs'] == [11] and value['early_boot_only'] is True and
            isinstance(value['public_key_sha256'], str) and
            re.fullmatch(r'[0-9a-f]{64}', value['public_key_sha256']),
            'Invalid early measured-unlock contract.')
    return value


def pcr15():
    value = kernel_text(PCR, 256).lower()
    require(re.fullmatch(r'[0-9a-f]{64}', value), 'Cannot observe SHA-256 PCR 15.')
    return value


def in_initrd():
    require(os.geteuid() == 0 and Path('/etc/initrd-release').is_file(),
            'Measured state enrollment is restricted to the verified initrd.')
    require(pcr15() == ZERO, 'The early TPM unlock window is already closed.')


def failure_identity(value):
    """Validate the minimal identity embedded in the signed failure initrd."""
    fields = {'image_id', 'deployment_sequence', 'uki_name'}
    require(isinstance(value, dict) and set(value) in (fields, fields | {'tpm_transition'}),
            'Invalid initrd failure identity.')
    image = value['image_id']
    sequence = value['deployment_sequence']
    require(isinstance(image, str) and re.fullmatch(r'[a-z][a-z0-9-]{0,47}', image) and
            type(sequence) is int and 1 <= sequence <= 999999999 and
            isinstance(value['uki_name'], str), 'Invalid initrd failure image.')
    safe = re.fullmatch(re.escape(image)+r'_[A-Za-z0-9._-]{1,160}\.efi', value['uki_name'])
    current = re.search(r'([1-9][0-9]{0,8})\.efi$', value['uki_name'])
    require(safe is not None and current is not None and int(current[1]) == sequence,
            'Invalid initrd failure image.')
    if 'tpm_transition' in value:
        transition = value['tpm_transition']
        require(isinstance(transition, dict) and set(transition) == {'fallback'} and
                isinstance(transition['fallback'], dict) and set(transition['fallback']) == {'uki_name'} and
                isinstance(transition['fallback']['uki_name'], str), 'Invalid initrd fallback binding.')
        fallback = transition['fallback']['uki_name']
        safe = re.fullmatch(re.escape(image)+r'_[A-Za-z0-9._-]{1,160}\.efi', fallback)
        previous = re.search(r'([1-9][0-9]{0,8})\.efi$', fallback) if safe else None
        require(previous is not None and int(previous[1]) < sequence, 'Invalid initrd fallback image.')
    return value


def failed_boot(installed):
    """A failed candidate returns to the existing older default, without a shell."""
    require(os.geteuid() == 0 and Path('/etc/initrd-release').is_file(),
            'Initrd failure handling is unavailable in normal userspace.')
    root = Path('/sys/firmware/efi/efivars')
    vendor = '-4a67b082-0a4c-41cf-b6c7-440b29bb8c4f'
    def entry(name):
        data = read(root/(name+vendor), 4096)
        require(len(data) >= 6 and (len(data)-4) % 2 == 0, 'Malformed boot selection observation.')
        return data[4:].decode('utf-16-le').rstrip('\0')
    selected, default = entry('LoaderEntrySelected'), entry('LoaderEntryDefault')
    stable = re.sub(r'\+[0-9]+(?:-[0-9]+)?(?=\.efi$)', '', selected)
    require(stable == installed['uki_name'] and default != stable and
            re.fullmatch(re.escape(installed['image_id'])+r'_[A-Za-z0-9._-]{1,160}\.efi', default),
            'Failed boot has no distinct accepted default.')
    previous = re.search(r'([1-9][0-9]{0,8})\.efi$', default)
    require(previous is not None and int(previous[1]) < installed['deployment_sequence'],
            'Failed boot default is not an earlier image.')
    bound = installed.get('tpm_transition', {}).get('fallback')
    require(bound is None or default == bound['uki_name'], 'Failed migration default differs from its bound bridge.')
    # The updater leaves the old default in place and selects a candidate for
    # one boot. Reboot consumes no new authority and never changes EFI entries.
    command(['systemctl', '--force', 'reboot'])


def native_probe(device, identifier, *, _parameters=None):
    """Use the stable libcryptsetup API with a NULL mapping name; export no key."""
    require(isinstance(identifier, str) and re.fullmatch(r'[0-9]|[12][0-9]|3[01]', identifier),
            'Unexpected state token identifier.')
    require(isinstance(device, str) and device.startswith('/') and '\0' not in device and len(device) <= 4096,
            'Unexpected state device path.')
    library = ctypes.CDLL('libcryptsetup.so.12')
    pointer = ctypes.c_void_p
    library.crypt_init.argtypes = [ctypes.POINTER(pointer), ctypes.c_char_p]
    library.crypt_init.restype = ctypes.c_int
    library.crypt_load.argtypes = [pointer, ctypes.c_char_p, pointer]
    library.crypt_load.restype = ctypes.c_int
    library.crypt_token_external_path.argtypes = []
    library.crypt_token_external_path.restype = ctypes.c_char_p
    library.crypt_token_json_get.argtypes = [pointer, ctypes.c_int, ctypes.POINTER(ctypes.c_char_p)]
    library.crypt_token_json_get.restype = ctypes.c_int
    library.crypt_activate_by_passphrase.argtypes = [pointer, ctypes.c_char_p, ctypes.c_int, pointer,
                                                    ctypes.c_size_t, ctypes.c_uint32]
    library.crypt_activate_by_passphrase.restype = ctypes.c_int
    library.crypt_free.argtypes = [pointer]
    library.crypt_free.restype = None
    callback_type = ctypes.CFUNCTYPE(None, ctypes.c_int, ctypes.c_char_p, pointer)
    library.crypt_set_log_callback.argtypes = [pointer, callback_type, pointer]
    library.crypt_set_log_callback.restype = None
    context = pointer()
    # Keep the callback alive until crypt_free; never forward native metadata
    # or diagnostic buffers to a journal or an evidence consumer.
    discard = callback_type(lambda *_: None)
    require(library.crypt_init(ctypes.byref(context), device.encode()) == 0 and context.value,
            'Cannot initialize the native state token probe.')
    try:
        library.crypt_set_log_callback(context, discard, None)
        require(library.crypt_load(context, b'LUKS2', None) == 0, 'Cannot load the native state token probe.')
        encoded = ctypes.c_char_p()
        require(library.crypt_token_json_get(context, int(identifier), ctypes.byref(encoded)) == int(identifier),
                'Native state token is missing.')
        require(encoded.value is not None and len(encoded.value) <= 65536, 'Native state token exceeds its bound.')
        token = json.loads(encoded.value)
        slots = token.get('keyslots')
        require(token.get('type') == 'systemd-tpm2' and isinstance(slots, list) and len(slots) == 1 and
                isinstance(slots[0], str) and re.fullmatch(r'[0-9]|[12][0-9]|3[01]', slots[0]),
                'Native state token is not bound to one TPM keyslot.')
        directory = library.crypt_token_external_path()
        require(directory is not None and directory.startswith(b'/'), 'Native token plugin path is unavailable.')
        plugin = ctypes.CDLL(str(Path(os.fsdecode(directory))/'libcryptsetup-token-systemd-tpm2.so'))
        plugin.cryptsetup_token_open.argtypes = [pointer, ctypes.c_int, ctypes.POINTER(pointer),
                                                ctypes.POINTER(ctypes.c_size_t), pointer]
        plugin.cryptsetup_token_open.restype = ctypes.c_int
        plugin.cryptsetup_token_buffer_free.argtypes = [pointer, ctypes.c_size_t]
        plugin.cryptsetup_token_buffer_free.restype = None
        password, length = pointer(), ctypes.c_size_t()
        try:
            # The token framework collapses provider errors into ENOENT. Use
            # its standard external-token ABI to retain the provider's errno.
            # Secret bytes stay in the native allocation: never dereference,
            # decode, print or copy them into a Python object or evidence file.
            code = plugin.cryptsetup_token_open(context, int(identifier), ctypes.byref(password),
                                                ctypes.byref(length), _parameters)
            if code < 0:
                return code
            require(password.value and 0 < length.value <= 4096, 'Native TPM credential has an invalid size.')
            slot = library.crypt_activate_by_passphrase(context, None, int(slots[0]), password, length.value, 0)
            require(slot == int(slots[0]), 'Native TPM credential does not unlock its declared state keyslot.')
            return slot
        finally:
            if password.value:
                plugin.cryptsetup_token_buffer_free(password, length.value)
    finally:
        library.crypt_free(context)


def token_test(device, identifier):
    """Bound native calls in a child; a missing resource is not a policy rejection."""
    program = ('import sys;sys.path.insert(0,sys.argv[1]);'
               'from lanrith.early_unlock import native_probe;'
               'print(native_probe(sys.argv[2],sys.argv[3]))')
    result = subprocess.run([sys.executable, '-I', '-c', program, str(Path(__file__).resolve().parents[1]),
                             device, identifier], stdin=subprocess.DEVNULL, capture_output=True, timeout=30,
                            env={'PATH': '/usr/sbin:/usr/bin', 'LC_ALL': 'C'})
    require(result.returncode == 0 and len(result.stdout) <= 16 and
            re.fullmatch(rb'-?[0-9]{1,4}\n', result.stdout), 'Native state token probe process failed.')
    code = int(result.stdout)
    if 0 <= code <= 31:
        return True
    # The external provider preserves errno; the general token framework and
    # CLI collapse policy denial and missing-device errors into shared codes.
    require(code == -errno.EPERM, 'State token probe failed unexpectedly (native errno '+str(code)+').')
    return False


def tpm_tokens(luks):
    # An interrupted, image-bound retirement may leave its exact legacy token
    # with no keyslot. Classification validates that exceptional header first;
    # only live credentials can be probed or selected for opening the volume.
    return sorted(identifier for identifier, item in luks['tokens'].items()
                  if item['type'] == 'systemd-tpm2' and item['keyslots'])


def record(installed, identifiers, *, legacy=()):
    directory = OBSERVATION.parent
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    info = directory.lstat()
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o077,
            'Unsafe early-unlock observation directory.')
    value = {'schema': 1, 'scope': 'local-observation',
             'boot_id': kernel_text(Path('/proc/sys/kernel/random/boot_id'), 64),
             'image_id': installed['image_id'], 'deployment_sequence': installed['deployment_sequence'],
             'policy': installed['tpm_policy'], 'pcr15_before': ZERO, 'pcr15_barrier': CLOSED,
             'tested_tokens': identifiers, 'legacy_tokens': list(legacy), 'late_unseal_denied': not legacy}
    fd = os.open(OBSERVATION, os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(canonical(value))
        stream.flush()
        os.fsync(stream.fileno())


def observation(installed):
    """Check current-boot evidence; it is not a hardware attestation."""
    validate(installed['tpm_policy'])
    info = OBSERVATION.lstat()
    require(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o077,
            'Unsafe early-unlock observation.')
    value = json.loads(read(OBSERVATION, 16384))
    require(isinstance(value, dict), 'Malformed early-unlock observation.')
    legacy = value.get('legacy_tokens')
    prepare = installed.get('tpm_transition', {}).get('phase') in ('prepare', 'enroll')
    require(isinstance(legacy, list) and len(legacy) <= 4 and
            all(isinstance(item, str) and item in installed.get('tpm_transition', {}).get('legacy_tokens', {})
                for item in legacy) and len(set(legacy)) == len(legacy) and (prepare or not legacy),
            'Unexpected legacy unlock observation.')
    require(set(value) == {'schema', 'scope', 'boot_id', 'image_id', 'deployment_sequence',
                           'policy', 'pcr15_before', 'pcr15_barrier', 'tested_tokens', 'legacy_tokens', 'late_unseal_denied'} and
            value['schema'] == 1 and value['scope'] == 'local-observation' and
            value['boot_id'] == kernel_text(Path('/proc/sys/kernel/random/boot_id'), 64) and
            value['image_id'] == installed['image_id'] and
            value['deployment_sequence'] == installed['deployment_sequence'] and
            value['policy'] == installed['tpm_policy'] and value['pcr15_before'] == ZERO and
            value['pcr15_barrier'] == CLOSED and value['late_unseal_denied'] is (not legacy) and
            isinstance(value['tested_tokens'], list) and (legacy or value['tested_tokens']) and
            len(value['tested_tokens']) <= 32 and
            all(isinstance(item, str) and re.fullmatch(r'[0-9]|[12][0-9]|3[01]', item)
                for item in value['tested_tokens']) and pcr15() != ZERO,
            'The current boot lacks its measured-unlock boundary evidence.')
    return value


def ensure_recovery_marker(installed, root, *, allow_enrollment):
    """Never replace a missing recovery method during a bound migration."""
    from .factory import recovery
    require(type(allow_enrollment) is bool, 'Invalid recovery enrollment policy.')
    marker = root/installed['state_directory'].lstrip('/')/'recovery-key-enrolled'
    if not marker.exists():
        require(allow_enrollment, 'Existing recovery enrollment is required for migration.')
        recovery(installed, root=str(root))
    return marker


def validate_existing_recovery_marker(marker):
    """Check ownership and type before a migration can alter token slots."""
    directory = marker.parent.lstat()
    record = marker.lstat()
    require(stat.S_ISDIR(directory.st_mode) and directory.st_uid == 0 and not directory.st_mode & 0o077 and
            stat.S_ISREG(record.st_mode) and record.st_uid == 0 and not record.st_mode & 0o077 and
            record.st_nlink == 1, 'Existing recovery enrollment is unsafe.')


def unlock(installed, device, *, allow_recovery_enrollment=True, reporter=None):
    """Mount only the verified disk's state, before switching to the signed root."""
    from .factory import initialize, state_tokens, verified_root
    require(reporter is None or callable(reporter), 'Invalid unlock progress reporter.')
    def stage(name):
        if reporter is not None:
            reporter(name)
    stage('policy')
    validate(installed['tpm_policy'])
    in_initrd()
    require(not OBSERVATION.exists() and not OBSERVATION.is_symlink(),
            'Measured state unlock cannot be repeated in the same boot.')
    stage('state-metadata')
    luks = json.loads(command(['cryptsetup', 'luksDump', '--dump-json-metadata', device]))
    if 'tpm_transition' in installed:
        from .tpm_migration import validate as validate_transition
        transition = validate_transition(installed['tpm_transition'])
        require(command(['cryptsetup', 'luksUUID', device]).strip() == transition['luks_uuid'],
                'TPM migration belongs to another encrypted state volume.')
    state_tokens(installed, luks)
    stage('token-preflight')
    identifiers = tpm_tokens(luks)
    require(identifiers and all(token_test(device, item) for item in identifiers),
            'An enrolled TPM token cannot unlock at the approved early phase.')
    # Never adopt an existing initrd mapping or a state mount from another disk.
    require(not Path('/dev/mapper/var').exists(), 'An unexpected state mapping already exists.')
    stage('state-open')
    command(['cryptsetup', 'open', '--type=luks2', '--token-only', '--token-type=systemd-tpm2',
             '--token-id='+identifiers[0], device, 'var'])
    command(['mount', '-t', 'ext4', '-o', 'nodev,nosuid,noexec', '/dev/mapper/var', str(SYSROOT/'var')])
    if 'tpm_transition' in installed:
        # A migration must never create a new recovery key or alter a TPM
        # token before proving the existing recovery ceremony was recorded.
        stage('recovery-preflight')
        marker = ensure_recovery_marker(installed, SYSROOT, allow_enrollment=False)
        validate_existing_recovery_marker(marker)
        from .tpm_migration import migrate
        disk, active = verified_root('/sysroot')
        stage('migration')
        migrate(installed, device, disk, active)
    stage('state-initialize')
    initialize(installed, root=str(SYSROOT))
    marker = ensure_recovery_marker(installed, SYSROOT,
        allow_enrollment=allow_recovery_enrollment and 'tpm_transition' not in installed)
    # Recovery enrollment may have changed the header. Validate every remaining
    # method before closing the window; no spare weak token may survive.
    stage('recovery-verify')
    luks = json.loads(command(['cryptsetup', 'luksDump', '--dump-json-metadata', device]))
    tokens = state_tokens(installed, luks)
    require('systemd-recovery' in tokens and marker.is_file() and not marker.is_symlink(),
            'Measured state requires completed offline recovery enrollment.')
    identifiers = tpm_tokens(luks)
    require(all(token_test(device, item) for item in identifiers) and pcr15() == ZERO,
            'The early TPM unlock window changed during enrollment.')
    stage('pcr15-barrier')
    command(['sync', '-f', str(SYSROOT/'var')])
    command(['/usr/lib/systemd/systemd-pcrextend', '--bank=sha256', '--pcr=15', BARRIER])
    require(pcr15() == CLOSED, 'The TPM unlock barrier did not reach its expected PCR value.')
    legacy = []
    if 'tpm_transition' in installed:
        from .tpm_migration import classify
        state = classify(installed, luks)
        identifiers, legacy = state['strong'], state['legacy']
    stage('late-unseal-check')
    require(all(not token_test(device, item) for item in identifiers),
            'An enrolled TPM token still unlocks after the PCR 15 barrier.')
    # Prepare and enrollment retain these PCR 7-only tokens for rollback.
    # Confirm they remain usable rather than merely recording their metadata.
    active_legacy = [item for item in legacy if item in tpm_tokens(luks)]
    require(all(token_test(device, item) for item in active_legacy),
            'A retained legacy TPM token no longer unlocks after the barrier.')
    stage('record-observation')
    if legacy:
        record(installed, identifiers, legacy=legacy)
    else:
        record(installed, identifiers)
