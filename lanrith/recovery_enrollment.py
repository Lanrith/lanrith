"""Offline-copy verification and crash recovery for the factory LUKS2 volume."""

import fcntl
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import secrets
import stat
import subprocess
import sys
import tempfile
import termios

from .release import canonical, read, require, unique
from .update import command, UUID


MARKER = 'recovery-key-verified'
LEGACY = 'recovery-key-enrolled'
INTENT = 'recovery-key-pending.json'
AUTHORITY = 'recovery-enrollment-auth.json'
MODHEX = b'cbdefghijklnrtuv'
KEY = re.compile(rb'(?:[cbdefghijklnrtuv]{8}-){7}[cbdefghijklnrtuv]{8}')
IDS = tuple(str(i) for i in range(32))
ENV = {'PATH': '/usr/sbin:/usr/bin', 'LC_ALL': 'C'}


def header(device):
    return json.loads(command(['cryptsetup', 'luksDump', '--dump-json-metadata', device]), object_pairs_hook=unique)


def volume_id(device):
    value = command(['cryptsetup', 'luksUUID', device]).strip()
    require(re.fullmatch(UUID, value), 'Encrypted state has an invalid UUID.')
    return value


def inventory(luks):
    return {field: {i: hashlib.sha256(canonical(obj)).hexdigest() for i, obj in luks[field].items()}
            for field in ('keyslots', 'tokens')}


def recovery_slots(luks):
    result = {}
    for identifier, token in luks['tokens'].items():
        if token['type'] == 'systemd-recovery':
            slots = token.get('keyslots')
            require(isinstance(slots, list) and len(slots) == 1 and slots[0] in IDS and
                    slots[0] in luks['keyslots'] and slots[0] not in result.values() and identifier in IDS,
                    'Invalid recovery slot assignment.')
            result[identifier] = slots[0]
    return result


def protect(directory):
    info = directory.lstat()
    require(directory.resolve() == directory and stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and
            not info.st_mode & 0o077, 'Unsafe recovery enrollment directory.')


def load(path):
    protect(path.parent)
    try:
        info = path.lstat()
    except FileNotFoundError:
        return None
    require(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o077 and info.st_nlink == 1,
            'Unsafe recovery enrollment record.')
    return json.loads(read(path, 16384), object_pairs_hook=unique)


def save(path, value):
    fd, temp = tempfile.mkstemp(dir=path.parent, prefix='.recovery-')
    try:
        with os.fdopen(fd, 'wb') as stream:
            stream.write(canonical(value))
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temp, path)
        sync_directory(path.parent)
    finally:
        Path(temp).unlink(missing_ok=True)


def begin(directory, uuid, luks, secret, retire, authority):
    intent = create_intent(uuid, luks, secret, retire, authority)
    save(directory/INTENT, intent)
    # First install may have just created ancestors of the administration directory.
    command(['sync', '-f', str(directory)])
    return intent


def sync_directory(directory):
    fd = os.open(directory, os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def private_input(prompt):
    # No fallback to echoed input or non-TTY streams. Discard typeahead.
    stream = sys.stdin.buffer
    saved = termios.tcgetattr(stream.fileno())
    hidden = list(saved)
    hidden[3] &= ~(termios.ECHO | termios.ECHONL)
    try:
        termios.tcsetattr(stream.fileno(), termios.TCSAFLUSH, hidden)
        print(prompt, end='', flush=True)
        line = stream.readline(514)
    finally:
        termios.tcsetattr(stream.fileno(), termios.TCSAFLUSH, saved)
        print(flush=True)
    require(line.endswith(b'\n') and 1 < len(line) <= 513, 'A recorded secret is required.')
    return bytearray(line.rstrip(b'\r\n'))


def recorded_key(*, allow_replace=False):
    if allow_replace:
        print('Enter the recorded copy, or type REPLACE to verify a new copy before retiring the lost one.')
    secret = private_input('Offline recovery key: ')
    if allow_replace and secret == b'REPLACE':
        return None
    require(KEY.fullmatch(secret), 'Enter the recorded recovery key exactly as displayed.')
    return secret


def fresh_key():
    raw = secrets.token_hex(32).encode().translate(bytes.maketrans(b'0123456789abcdef', MODHEX))
    generated = b'-'.join(raw[i:i+8] for i in range(0, len(raw), 8))
    print('Record this recovery key outside the router, then enter the recorded copy.', flush=True)
    print(generated.decode('ascii'), flush=True)
    secret = recorded_key()
    require(hmac.compare_digest(secret, generated), 'The recorded copy did not match. Reboot to retry.')
    return secret


def run_private(args, secret):
    return subprocess.run(['cryptsetup', *args], input=secret, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                          env=ENV, timeout=120).returncode == 0


def matches(device, slot, secret):
    return run_private(['open', '--type=luks2', '--test-passphrase', '--disable-external-tokens',
                        '--key-slot', slot, '--key-file=-', device], secret)


def add_slot(device, luks, slot, secret, tpm):
    args = ['luksAddKey', '--batch-mode', '--type=luks2', '--new-key-slot', slot,
            '--pbkdf=pbkdf2', '--pbkdf-force-iterations=1000']
    if tpm:
        ids = [i for i, token in luks['tokens'].items() if token['type'] == 'systemd-tpm2']
        require(ids, 'The enrolled TPM method is missing.')
        success = run_private([*args, '--token-only', '--token-type=systemd-tpm2', '--token-id', ids[0],
                               '--new-keyfile=-', device], secret)
    else:
        # Both passphrases must reach cryptsetup without arguments, disk files or echoed prompts.
        current = private_input('Current state passphrase: ')
        fd = os.memfd_create('lanrith-offline-enrollment')
        try:
            os.write(fd, secret)
            os.lseek(fd, 0, os.SEEK_SET)
            success = subprocess.run(['cryptsetup', *args, '--key-file=-', '--new-keyfile=/proc/self/fd/'+str(fd),
                                      device], input=current, pass_fds=(fd,), stdout=subprocess.DEVNULL,
                                     stderr=subprocess.DEVNULL, env=ENV, timeout=120).returncode == 0
        finally:
            current[:] = bytes(len(current))
            os.close(fd)
    require(success, 'Could not add the authorized recovery slot.')


def recovery_token(slot):
    return {'type': 'systemd-recovery', 'keyslots': [slot]}


def journal_key(directory, *, create=False):
    stored = load(directory/AUTHORITY)
    if stored is None and create:
        stored = secrets.token_hex(32)
        save(directory/AUTHORITY, stored)
    require(isinstance(stored, str) and re.fullmatch('[0-9a-f]{64}', stored), 'Enrollment authority is missing.')
    return bytes.fromhex(stored)


def create_intent(uuid, luks, secret, retire, authority):
    inv = inventory(luks)
    free = {}
    for field, items in inv.items():
        require(set(items) <= set(IDS) and len(items) < len(IDS), 'No free recovery enrollment slot.')
        free[field] = next(i for i in IDS if i not in items)
    body = {'schema': 1, 'uuid': uuid, 'prior': inv, 'slot': free['keyslots'], 'token': free['tokens'],
            'retire': retire, 'key_mac': hmac.digest(secret, b'lanrith-recovery:'+uuid.encode(), 'sha256').hex()}
    return {'body': body, 'mac': hmac.digest(authority, canonical(body), 'sha256').hex()}


def classify(intent, uuid, luks, authority):
    """Match the entire original inventory and only the explicitly permitted deltas."""
    body = intent['body']
    require(hmac.compare_digest(intent['mac'], hmac.digest(authority, canonical(body), 'sha256').hex()) and
            body['uuid'] == uuid and body['schema'] == 1, 'Recovery intent authentication failed.')
    slot, token, old = body['slot'], body['token'], body['retire']
    prior = body['prior']
    require(slot in IDS and token in IDS and slot not in prior['keyslots'] and token not in prior['tokens'],
            'Recovery intent has invalid identifiers.')
    observed = inventory(luks)
    slots, tokens = observed['keyslots'], observed['tokens']
    candidate = slots.pop(slot, None)
    has_slot = candidate is not None
    require('candidate' not in body or candidate == body['candidate'], 'The recorded candidate slot changed.')
    has_token = tokens.pop(token, None) is not None
    require(not has_token or (has_slot and luks['tokens'][token] == recovery_token(slot)),
            'Unexpected token at the selected recovery slot.')
    expected_slots, expected_tokens = dict(prior['keyslots']), dict(prior['tokens'])
    phase = 'prior' if not has_slot else 'added' if not has_token else 'tagged'
    live_old = False
    for old_token, old_slot in old:
        require(old_token in expected_tokens and old_slot in expected_slots and
                expected_tokens[old_token] == hashlib.sha256(canonical(recovery_token(old_slot))).hexdigest(),
                'Retirement is not bound to a previous recovery token.')
        if old_token in tokens:
            live_old = True
        else:
            require(has_token and not live_old, 'Original recovery methods changed out of order.')
            del expected_tokens[old_token]
            if old_slot in slots:
                live_old = True
                phase = 'untagged'
            else:
                del expected_slots[old_slot]
    if has_token and old and not live_old:
        phase = 'retired'
    require(slots == expected_slots and tokens == expected_tokens, 'Encrypted state differs from its recovery intent.')
    return phase


def step(device, intent, uuid, luks, secret, authority, *, tpm, directory=None, repair_only=False):
    phase = classify(intent, uuid, luks, authority)
    body = intent['body']
    require(hmac.compare_digest(body['key_mac'], hmac.digest(secret, b'lanrith-recovery:'+uuid.encode(), 'sha256').hex()),
            'The recorded copy does not authenticate this enrollment.')
    slot, token = body['slot'], body['token']
    old = next((pair for pair in body['retire'] if pair[1] in luks['keyslots']), None)
    if repair_only:
        require(phase in ('added', 'untagged'), 'No matching interrupted enrollment command.')
    if phase == 'prior':
        add_slot(device, luks, slot, secret, tpm)
    else:
        require(matches(device, slot, secret), 'The recorded copy cannot unlock the intended slot.')
        if 'candidate' not in body and directory is not None:
            # An immutable fingerprint also permits explicit replacement if a committed copy is later lost.
            body['candidate'] = inventory(luks)['keyslots'][slot]
            intent['mac'] = hmac.digest(authority, canonical(body), 'sha256').hex()
            save(directory/INTENT, intent)
        if phase == 'added':
            require(run_private(['token', 'import', '--token-id', token, '--json-file=-', device],
                                canonical(recovery_token(slot))), 'Could not bind the verified recovery token.')
        elif phase == 'tagged' and old:
            command(['cryptsetup', 'token', 'remove', '--token-id', old[0], device])
        elif phase == 'untagged':
            # Authenticate the deletion with the NEW copy as well as checking its exact slot above.
            require(run_private(['luksKillSlot', '--key-file=-', device, old[1]], secret),
                    'Could not retire the superseded recovery slot.')
        else:
            return True
    return False


def finish(directory, device, uuid, luks, slot):
    require(volume_id(device) == uuid and inventory(header(device)) == inventory(luks),
            'Encrypted state changed before verification could be recorded.')
    value = {'schema': 1, 'uuid': uuid, 'slot': slot,
             'fingerprint': inventory(luks)['keyslots'][slot]}
    # Keep the old path usable by a signed fallback image.
    if not (directory/LEGACY).exists():
        save(directory/LEGACY, {'schema': 1})
    save(directory/MARKER, value)
    (directory/INTENT).unlink(missing_ok=True)
    sync_directory(directory)


def verified(directory, device, luks):
    value = load(directory/MARKER)
    if value is None:
        return False
    slots = recovery_slots(luks).values()
    require(isinstance(value, dict) and value.get('schema') == 1 and value.get('uuid') == volume_id(device) and
            value.get('slot') in slots and value.get('fingerprint') == inventory(luks)['keyslots'][value['slot']],
            'Verified offline recovery record differs from the current volume.')
    return True


def enroll(installed, device, directory, *, verification_only=False):
    protect(directory)
    fd = os.open(directory, os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        enroll_locked(installed, device, directory, verification_only=verification_only)
    finally:
        os.close(fd)


def enroll_locked(installed, device, directory, *, verification_only):
    from .factory import state_tokens
    luks = header(device)
    require(not verified(directory, device, luks), 'Recovery enrollment is already complete.')
    uuid = volume_id(device)
    intent = load(directory/INTENT)
    if intent is None:
        state_tokens(installed, luks)
        slots = recovery_slots(luks)
        retire = []
        if slots:
            secret = recorded_key(allow_replace=not verification_only and len(slots) == 1)
            if secret is not None:
                try:
                    valid = [slot for slot in slots.values() if matches(device, slot, secret)]
                    require(len(valid) == 1, 'The recorded copy does not unlock an enrolled recovery slot.')
                    finish(directory, device, uuid, luks, valid[0])
                    return
                finally:
                    secret[:] = bytes(len(secret))
            retire = [list(next(iter(slots.items())))]
        require(not verification_only, 'An existing recovery copy is required.')
        secret = fresh_key()
        authority = journal_key(directory, create=True)
        intent = begin(directory, uuid, luks, secret, retire, authority)
    else:
        require(not verification_only, 'Pending enrollment must finish before TPM migration.')
        authority = journal_key(directory)
        phase = classify(intent, uuid, luks, authority)
        # Only reset from a complete, independently admitted header. The previous methods
        # remain live until we have verified the newly recorded copy against its own slot.
        allow_replace = phase == 'prior' or phase in ('tagged', 'retired') and 'candidate' in intent['body']
        if allow_replace:
            state_tokens(installed, luks)
        print('Resume the pending enrollment using its recorded copy.')
        secret = recorded_key(allow_replace=allow_replace)
        if secret is None:
            # Only retire methods already named by this authenticated transaction.
            body = intent['body']
            retire = [pair for pair in body['retire'] if pair[0] in luks['tokens']]
            if phase != 'prior':
                retire.append([body['token'], body['slot']])
            secret = fresh_key()
            intent = begin(directory, uuid, luks, secret, retire, authority)
    try:
        for _ in range(4 + 2*len(intent['body']['retire'])):
            luks = header(device)
            if step(device, intent, volume_id(device), luks, secret, authority,
                    tpm=installed['boot'].get('tpm') != 'disabled', directory=directory):
                state_tokens(installed, luks)
                finish(directory, device, uuid, luks, intent['body']['slot'])
                return
        require(False, 'Recovery enrollment did not converge.')
    finally:
        secret[:] = bytes(len(secret))


def repair_partial(installed, device, luks):
    """Read the pending transaction through the approved TPM before normal state admission."""
    from . import early_unlock, factory
    covered = {s for t in luks['tokens'].values() for s in t['keyslots']}
    orphan = set(luks['keyslots']) - covered
    require(len(orphan) == 1, 'No unambiguous recovery enrollment to resume.')
    prior_slots = {i: spec for i, spec in luks['keyslots'].items() if i not in orphan}
    factory.state_tokens(installed, {**luks, 'keyslots': prior_slots})
    ids = early_unlock.tpm_tokens(luks)
    require(ids and all(early_unlock.token_test(device, i) for i in ids),
            'Recovery inspection requires the approved TPM method.')
    name = 'lanrith-recovery-inspect'
    mapper = '/dev/mapper/'+name
    require(not os.path.lexists(mapper) and not os.path.lexists('/dev/mapper/var'),
            'An unexpected mapping already exists.')
    tmp = tempfile.mkdtemp(prefix='recovery-inspect-', dir='/run')
    try:
        command(['cryptsetup', 'open', '--type=luks2', '--token-only', '--token-type=systemd-tpm2',
                 '--token-id='+ids[0], device, name])
        try:
            # ext4 may replay its journal to expose the last fsynced transaction. No service sees this mount.
            command(['mount', '-t', 'ext4', '-o', 'ro,nodev,nosuid,noexec', mapper, tmp])
            try:
                directory = Path(tmp)/Path(installed['state_directory']).relative_to('/var')
                intent = load(directory/INTENT)
                authority = journal_key(directory)
                require(intent is not None and load(directory/MARKER) is None and
                        classify(intent, volume_id(device), luks, authority) in ('added', 'untagged'),
                        'An interrupted slot requires its protected pending enrollment.')
            finally:
                command(['umount', tmp])
        finally:
            command(['cryptsetup', 'close', name])
    finally:
        # Never recursively remove a mount if unmounting failed.
        os.rmdir(tmp)

    def confirm():
        factory.require_physical_input(installed)
        print('A recovery header write was interrupted. Enter its recorded copy to finish that write.')
        secret = recorded_key()
        try:
            step(device, intent, volume_id(device), header(device), secret, authority, tpm=True, repair_only=True)
        finally:
            secret[:] = bytes(len(secret))
    with factory.Consoles(installed) as console:
        factory.extend_startup(factory.OPERATOR_SECONDS)
        console.write('Interrupted recovery enrollment requires its recorded copy within 15 minutes. Reboot to retry.\n')
        with factory.input_deadline():
            console.private(confirm)
        factory.extend_startup(factory.BOOT_SECONDS)
