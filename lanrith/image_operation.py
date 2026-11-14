"""Fixed image operations for an authenticated, unprivileged operator.

SSH supplies authentication and the existing upload transport. The socket grants
only status and one digest-selected image operation, never a command or path.
"""

import argparse
from contextlib import contextmanager
import fcntl
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import socket
import stat
import struct
import subprocess
import sys
import tempfile
import time

from .release import ReleaseError, canonical, document, read, require, unique
from . import update
from .update import boot_esp, command, promote, prune_inbox, require_default, select_boot_once, stage


SOCKET = '/run/lanrith-image-operation.sock'
INSTALLED = Path('/usr/share/lanrith/installed.json')
LOCK = Path('/run/lock/lanrith-image-operation.lock')
PHASES = {'staging', 'rebooting', 'accepted', 'failed', 'fallback'}
IDENTITY = {'image_id', 'deployment_sequence', 'configuration_sha256', 'uki_name'}


def identity(value):
    require(isinstance(value.get('image_id'), str) and re.fullmatch(r'[a-z][a-z0-9-]{0,47}', value['image_id']) and
            type(value.get('deployment_sequence')) is int and 1 <= value['deployment_sequence'] <= 999999999 and
            isinstance(value.get('configuration_sha256'), str) and
            re.fullmatch(r'[0-9a-f]{64}', value['configuration_sha256']) and
            value.get('uki_name') == f'{value["image_id"]}_{value["deployment_sequence"]}.efi',
            'Invalid image operation identity.')
    return {key: value[key] for key in IDENTITY}


def policy(path=INSTALLED):
    info = path.stat()
    require(info.st_uid == 0 and not info.st_mode & 0o022, 'Installed image policy is not protected.')
    value = json.loads(read(path, 65536), object_pairs_hook=unique)
    require(isinstance(value.get('operator'), str) and
            re.fullmatch(r'[a-z][a-z0-9_-]{0,30}', value['operator']), 'Operator policy is absent.')
    return value


def state_path(value):
    directory = Path(value['state_directory'])
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    info = directory.stat()
    require(directory.resolve() == directory and info.st_uid == 0 and
            stat.S_IMODE(info.st_mode) == 0o700, 'Image operation state directory is unsafe.')
    return directory/'image-operation.json'


def load(value):
    path = state_path(value)
    if not path.exists():
        require(not path.is_symlink(), 'Image operation record is unsafe.')
        return None
    info = path.stat()
    require(info.st_uid == 0 and stat.S_IMODE(info.st_mode) == 0o600,
            'Image operation record is not protected.')
    result = json.loads(read(path, 16384), object_pairs_hook=unique)
    require(isinstance(result, dict) and set(result) ==
            {'schema', 'digest', 'phase', 'candidate', 'fallback', 'error', 'executor_id'} and
            type(result['schema']) is int and result['schema'] == 1 and
            isinstance(result['executor_id'], str) and re.fullmatch(r'[0-9a-f]{32}', result['executor_id']) and
            isinstance(result['digest'], str) and re.fullmatch(r'[0-9a-f]{64}', result['digest']) and
            isinstance(result['phase'], str) and result['phase'] in PHASES and result['error'] in
            (None, 'admission-or-staging-failed', 'readiness-failed', 'reboot-failed') and
            all(isinstance(result[key], dict) and set(result[key]) == IDENTITY
                for key in ('candidate', 'fallback')), 'Image operation record is malformed.')
    identity(result['candidate'])
    identity(result['fallback'])
    return result


def save(value, record):
    path = state_path(value)
    atomic(path, record)


def atomic(path, record):
    descriptor, temporary = tempfile.mkstemp(prefix='.image-operation-', dir=path.parent)
    try:
        with os.fdopen(descriptor, 'wb') as stream:
            stream.write(canonical(record))
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        descriptor = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    finally:
        Path(temporary).unlink(missing_ok=True)


def accepted_identity(value):
    path = state_path(value).with_name('accepted-image.json')
    if not path.exists():
        require(not path.is_symlink(), 'Accepted image record is unsafe.')
        return None
    info = path.stat()
    require(info.st_uid == 0 and stat.S_IMODE(info.st_mode) == 0o600, 'Accepted image record is not protected.')
    result = json.loads(read(path, 4096), object_pairs_hook=unique)
    require(isinstance(result, dict) and set(result) == IDENTITY, 'Accepted image record is malformed.')
    identity(result)
    return result


def save_accepted(value):
    atomic(state_path(value).with_name('accepted-image.json'), identity(value))


def recovery_information(value):
    """Expose only non-secret disk bindings needed to build recovery media."""
    from . import factory
    try:
        disk, state, _ = factory.state_metadata(value)
        rows = update.geometry(disk)
        state_rows = [row for row in rows if row.get('device') == state]
        esps = [row for row in rows if row.get('type') == 'c12a7328-f81f-11d2-ba4b-00a0c93ec93b']
        require(len(state_rows) == len(esps) == 1, 'Recovery disk inventory is ambiguous.')
        state_uuid = update.command(['cryptsetup', 'luksUUID', state]).strip().lower()
        require(re.fullmatch(update.UUID, state_uuid), 'Recovery state identity is invalid.')
        aliases = sorted(str(path) for path in Path('/dev/disk/by-id').glob('*')
            if re.fullmatch(r'[A-Za-z0-9_.:+-]{1,180}', path.name) and
            not re.search(r'-part[0-9]+$', path.name) and str(path.resolve()) == disk)
        require(len(aliases) <= 64 and rows == update.geometry(disk), 'Recovery disk inventory changed.')
        return {'schema': 1, 'scope': 'local-observation', 'machine_id': value['machine_id'],
                'disk_by_ids': aliases, 'esp_partuuid': esps[0]['uuid'],
                'state_partuuid': state_rows[0]['uuid'], 'state_uuid': state_uuid}
    except (OSError, ValueError, KeyError, subprocess.SubprocessError):
        return None


@contextmanager
def operation_lock():
    descriptor = os.open(LOCK, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
    try:
        info = os.fstat(descriptor)
        require(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and info.st_nlink == 1 and
                stat.S_IMODE(info.st_mode) == 0o600, 'Image operation lock is unsafe.')
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise ReleaseError('An image operation is already running.') from error
        yield
    finally:
        os.close(descriptor)


def uploaded(value, digest):
    """Inspect a bounded manifest using pinned directory descriptors."""
    require(isinstance(digest, str) and re.fullmatch(r'[0-9a-f]{64}', digest), 'Invalid bundle digest.')
    upload = Path(value.get('upload_directory', '/var/tmp/lanrith-update'))
    parent = os.open(upload, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        directory = os.open(digest, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
        try:
            data = read('release.json', 65536, dir_fd=directory)
        finally:
            os.close(directory)
    finally:
        os.close(parent)
    require(hashlib.sha256(data).hexdigest() == digest, 'Uploaded manifest identity differs.')
    manifest = document(data)
    require(manifest['purpose'] == 'update' and manifest['image_id'] == value['update_image_id'] and
            manifest['deployment_sequence'] > value['deployment_sequence'], 'Bundle is not a newer target image.')
    return manifest, upload/digest


def trigger(digest, installed_path=INSTALLED):
    value = policy(installed_path)
    with operation_lock():
        previous = load(value)
        require(previous is None or previous['phase'] in ('accepted', 'failed', 'fallback'),
                'The pending image operation must finish before another trigger.')
        prune_inbox(value)
        manifest, source = uploaded(value, digest)
        admitted = promote(source, installed_path, expected_digest=digest, stage_payload=False)
        # Only an independently verified root-owned copy may become durable
        # authority for this operation, including after a power interruption.
        manifest = document(read(admitted/'release.json', 65536))
        candidate = identity({**manifest, 'uki_name': f'{manifest["image_id"]}_{manifest["deployment_sequence"]}.efi'})
        executor = os.environ.get('INVOCATION_ID')
        require(isinstance(executor, str) and re.fullmatch(r'[0-9a-f]{32}', executor), 'Executor identity is unavailable.')
        record = {'schema': 1, 'digest': digest, 'phase': 'staging', 'candidate': candidate,
                  'fallback': identity(value), 'error': None, 'executor_id': executor}
        # Publish intent durably before stage can select the candidate for boot.
        save(value, record)
        try:
            stage(admitted, installed_path)
        except (OSError, ValueError, KeyError):
            # A failure can occur after setting OneShot but before its readback.
            # Do not permit another transfer until that ambiguity is removed.
            failed = {**record, 'phase': 'rebooting', 'error': 'admission-or-staging-failed'}
            save(value, failed)
            select_boot_once(boot_esp(value)/'EFI/Linux'/value['uki_name'])
            save(value, {**failed, 'phase': 'failed'})
            raise ReleaseError('Image admission or staging failed; no success was recorded.') from None
        save(value, {**record, 'phase': 'rebooting'})
        try:
            command(['systemctl', '--no-block', 'reboot'])
        except (OSError, ValueError):
            # Keep the pending record: a selected candidate must remain tracked.
            save(value, {**record, 'phase': 'rebooting', 'error': 'reboot-failed'})
            raise
        return {'schema': 1, 'digest': digest, 'phase': 'rebooting', 'candidate': candidate}


def complete(installed_path=INSTALLED, *, deadline_seconds=180):
    """Accept a healthy boot, or reboot a failed candidate to its old default."""
    from . import runtime
    from .credential_operation import wait_ready

    value = policy(installed_path)
    require(type(deadline_seconds) is int and 30 <= deadline_seconds <= 600, 'Invalid readiness deadline.')
    with operation_lock():
        record = load(value)
        pending = record is not None and record['phase'] in ('staging', 'rebooting')
        candidate = record is not None and record['candidate'] == identity(value)
        fallback = pending and record['fallback'] == identity(value)
        require(not pending or candidate or fallback, 'Running image is outside the authorized operation.')
        if not pending and accepted_identity(value) not in (None, identity(value)):
            # Preserve the old root-only manual staging interface. Only an
            # operator trigger authorizes automatic completion of later images.
            return
        # The provisioning socket uses a separate lock and remains usable
        # while this observer waits. Its failure never suppresses fallback.
        provisioned = (False if candidate and record['error'] == 'admission-or-staging-failed'
                       else wait_ready(value))
        deadline = time.monotonic()+deadline_seconds
        while provisioned:
            try:
                # accept() rechecks health and blessings and verifies the durable
                # boot default. Merely reaching multi-user is never acceptance.
                runtime.accept(value['deployment_sequence'])
                save_accepted(value)
                if candidate:
                    save(value, {**record, 'phase': 'accepted', 'error': None})
                elif fallback:
                    save(value, {**record, 'phase': 'fallback', 'error': 'readiness-failed'})
                return
            except (OSError, ValueError, KeyError):
                if time.monotonic() >= deadline:
                    break
                time.sleep(2)
        if candidate:
            # Do not change default on failure. Read it back before rebooting;
            # the accepted image was protected throughout the transfer.
            fallback_boot(installed_path)
        raise ReleaseError('Image readiness deadline expired.')


def fallback_boot(installed_path=INSTALLED):
    """Also runs after a completion-service crash or its hard runtime deadline."""
    value = policy(installed_path)
    record = load(value)
    if (record is None or record['phase'] not in ('staging', 'rebooting') or
            record['candidate'] != identity(value)):
        return
    require('image_contract' in value and 'recovery_state' in value,
            'Automatic fallback is blocked pending recovery qualification.')
    from .steady_recovery import runtime_fallback
    runtime_fallback(value)


def cancel_request(installed_path=INSTALLED):
    """Undo an ambiguous OneShot after this executor crashes in the old image."""
    value = policy(installed_path)
    with operation_lock():
        record = load(value)
        if (record is None or record['phase'] not in ('staging', 'rebooting') or
                record.get('executor_id') != os.environ.get('INVOCATION_ID') or
                record['fallback'] != identity(value)):
            return
        entry = boot_esp(value)/'EFI/Linux'/value['uki_name']
        select_boot_once(entry)
        require_default(entry)
        save(value, {**record, 'phase': 'failed', 'error': 'admission-or-staging-failed'})


def request(data):
    require(isinstance(data, bytes) and 0 < len(data) <= 512 and data.endswith(b'\n'), 'Invalid image request.')
    try:
        value = json.loads(data, object_pairs_hook=unique)
    except (ValueError, UnicodeError, RecursionError):
        raise ReleaseError('Invalid image request.') from None
    require(isinstance(value, dict) and type(value.get('schema')) is int and value['schema'] == 1 and
            (set(value) == {'schema', 'action'} and value['action'] == 'status' or
             set(value) == {'schema', 'action', 'digest'} and value['action'] == 'trigger' and
             isinstance(value['digest'], str) and re.fullmatch(r'[0-9a-f]{64}', value['digest'])),
            'Unsupported image request.')
    return value


def serve(connection, installed_path=INSTALLED):
    value = policy(installed_path)
    _, uid, _ = struct.unpack('3i', connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
    require(uid == pwd.getpwnam(value['operator']).pw_uid, 'Caller is not the installed image operator.')
    connection.settimeout(10)
    data = bytearray()
    while not data.endswith(b'\n'):
        block = connection.recv(513-len(data))
        require(block and len(data)+len(block) <= 512, 'Invalid image request.')
        data.extend(block)
    selected = request(bytes(data))
    if selected['action'] == 'trigger':
        result = trigger(selected['digest'], installed_path)
    else:
        result = {'schema': 1, 'operation': load(value), 'accepted': accepted_identity(value),
                  'recovery': recovery_information(value)}
    try:
        connection.sendall(canonical({'ok': True, 'result': result}))
    except (OSError, TimeoutError):
        # Disconnecting after an authorized trigger does not cancel the update.
        pass


def main(arguments=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='action', required=True)
    commands.add_parser('status')
    commands.add_parser('trigger').add_argument('digest')
    commands.add_parser('serve', help=argparse.SUPPRESS)
    commands.add_parser('complete', help=argparse.SUPPRESS)
    commands.add_parser('fallback', help=argparse.SUPPRESS)
    commands.add_parser('cancel-request', help=argparse.SUPPRESS)
    args = parser.parse_args(arguments)
    try:
        if args.action == 'serve':
            require(os.geteuid() == 0, 'Image executor requires system service authority.')
            with socket.socket(fileno=0) as connection:
                try:
                    serve(connection)
                except ReleaseError as error:
                    connection.sendall(canonical({'ok': False, 'error': str(error)}))
                    return 1
                except (OSError, ValueError, KeyError):
                    connection.sendall(canonical({'ok': False, 'error': 'image-operation-rejected'}))
                    return 1
        elif args.action in ('complete', 'fallback', 'cancel-request'):
            require(os.geteuid() == 0, 'Image completion requires system service authority.')
            if args.action == 'complete':
                complete()
            elif args.action == 'fallback' and os.environ.get('SERVICE_RESULT') != 'success':
                fallback_boot()
            elif args.action == 'cancel-request' and os.environ.get('SERVICE_RESULT') != 'success':
                cancel_request()
        else:
            selected = {'schema': 1, 'action': args.action}
            if args.action == 'trigger':
                selected['digest'] = args.digest
            encoded = canonical(selected)
            request(encoded)
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
                connection.settimeout(1200)
                connection.connect(SOCKET)
                connection.sendall(encoded)
                with connection.makefile('rb') as stream:
                    response = stream.readline(32769)
                require(0 < len(response) <= 32768, 'Invalid image executor response.')
                result = json.loads(response, object_pairs_hook=unique)
                if result.get('ok') is not True:
                    message = result.get('error')
                    require(isinstance(message, str) and 0 < len(message) <= 256 and
                            all(32 <= ord(c) < 127 for c in message), 'Invalid image executor response.')
                    print(message, file=sys.stderr)
                    return 1
                print(json.dumps(result['result'], sort_keys=True))
    except (OSError, ValueError, KeyError):
        print('Image operation failed; inspect operator status and system diagnostics.', file=sys.stderr)
        return 1
    return 0
