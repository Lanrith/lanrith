"""Fixed image operations for an authenticated, unprivileged operator.

SSH supplies authentication and the existing upload transport. The socket grants
only status and one digest-selected image operation, never a command or path.
"""

import argparse
from contextlib import contextmanager
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
from .update import command, promote_locked, prune_inbox, require_default, select_boot_once, stage_locked


SOCKET = '/run/lanrith-image-operation.sock'
INSTALLED = Path('/usr/share/lanrith/installed.json')
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


def promotion_path(value):
    return state_path(value).with_name('image-promotion.json')


def load_promotion(value):
    path = promotion_path(value)
    try:
        info = path.lstat()
    except FileNotFoundError:
        return None
    require(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and stat.S_IMODE(info.st_mode) == 0o600,
            'Image promotion record is not protected.')
    intent = json.loads(read(path, 4096), object_pairs_hook=unique)
    require(isinstance(intent, dict) and set(intent) == {'schema', 'target', 'previous', 'operation', 'manual'} and
            type(intent['manual']) is bool and
            type(intent['schema']) is int and intent['schema'] == 1 and
            isinstance(intent['target'], dict) and set(intent['target']) == IDENTITY and
            (intent['previous'] is None or isinstance(intent['previous'], dict) and
             set(intent['previous']) == IDENTITY) and (intent['operation'] is None or
             isinstance(intent['operation'], str) and re.fullmatch(r'[0-9a-f]{64}/[0-9a-f]{32}', intent['operation'])),
            'Image promotion record is malformed.')
    identity(intent['target'])
    if intent['previous'] is not None:
        identity(intent['previous'])
    return intent


def visible_accepted(value):
    # The file may already contain the target while its operation is committing.
    result = accepted_identity(value)
    return result if load_promotion(value) is None else None


def finish_promotion(value):
    path = promotion_path(value)
    path.unlink()
    descriptor = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def save_accepted(value):
    from .runtime import invalidate_boot_receipt
    invalidate_boot_receipt()
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


def operation_lock(*, wait=False):
    return update.image_lock(update.OPERATION_LOCK_NAME, wait=wait)


@contextmanager
def admission_lock(installed_path):
    from .runtime import require_accepted_boot
    with operation_lock():
        value = policy(installed_path)
        require(not is_pending(load(value)), 'The pending image operation must finish before another trigger.')
        require(load_promotion(value) is None, 'Image promotion must finish before another trigger.')
        require_accepted_boot(value)
        yield value


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
    with admission_lock(installed_path) as value:
        prune_inbox(value)
        manifest, source = uploaded(value, digest)
        admitted = promote_locked(source, installed_path, expected_digest=digest)
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
            stage_locked(admitted, installed_path)
        except (OSError, ValueError, KeyError):
            # A failure can occur after setting OneShot but before its readback.
            # Do not permit another transfer until that ambiguity is removed.
            failed = {**record, 'phase': 'rebooting', 'error': 'admission-or-staging-failed'}
            save(value, failed)
            close_failed_stage(value, failed)
            raise ReleaseError('Image admission or staging failed; no success was recorded.') from None
        save(value, {**record, 'phase': 'rebooting'})
        try:
            command(['systemctl', '--no-block', 'reboot'])
        except (OSError, ValueError):
            # Keep the pending record: a selected candidate must remain tracked.
            save(value, {**record, 'phase': 'rebooting', 'error': 'reboot-failed'})
            raise
        return {'schema': 1, 'digest': digest, 'phase': 'rebooting', 'candidate': candidate}


def operation_id(record):
    return record['digest'] + '/' + record['executor_id'] if record else None


def is_pending(record):
    return record is not None and record['phase'] in ('staging', 'rebooting')


def current_promotion(value, record):
    intent = load_promotion(value)
    if intent is None or intent['operation'] == operation_id(record):
        return intent
    # An older predecessor ignores the sidecar. It can finish fallback and admit a
    # later update. Discard the obsolete intent only with independently agreeing
    # new authorization, recorded acceptance and persistent predecessor selection.
    require(is_pending(record) and identity(value) in (record['candidate'], record['fallback'])
            and record['fallback'] in (intent['target'], intent['previous'])
            and record['candidate']['deployment_sequence'] > intent['target']['deployment_sequence']
            and accepted_identity(value) == record['fallback'],
            'Promotion intent differs from the current image operation.')
    require_default(Path(record['fallback']['uki_name']))
    finish_promotion(value)
    return None


def promote_running(value, *, manual=False):
    """Commit or resume one promotion under the caller's image-operation lock."""
    from . import runtime
    running = identity(value)
    record = load(value)
    accepted = accepted_identity(value)
    intent = current_promotion(value, record)
    pending = is_pending(record)
    if pending:
        require(running in (record['candidate'], record['fallback']), 'Running image is outside the authorized operation.')
        require(running != record['candidate'] or record['error'] not in
                ('admission-or-staging-failed', 'readiness-failed'), 'Candidate has already failed.')
    if intent:
        require(running in (intent['target'], intent['previous'])
                and accepted in (intent['previous'], intent['target'], None),
                'Promotion intent differs from the current image operation.')
        if (not intent['manual'] and record and record['phase'] in ('fallback', 'failed')
                and intent['target'] == record['candidate']):
            require(running == record['fallback'], 'Candidate promotion was superseded by fallback.')
        if pending:
            require(not intent['manual'] and intent['target'] in (record['candidate'], record['fallback']) and
                    intent['previous'] == record['fallback'],
                    'Promotion intent differs from the authorized update.')
    elif not pending and not manual and accepted != running:
        if accepted is not None:
            # Root-only manual staging requires explicit acceptance of the new slot.
            return None
        require(record is None and not value.get('image_contract', {}).get('recovery'),
                'Initial promotion requires an unbound installation.')
    if pending and intent is None:
        require(accepted in (None, record['fallback']), 'Recorded predecessor differs from the authorized update.')

    # Revalidate even if a prior invocation already changed the persistent selector.
    require(identity(runtime.health()) == running, 'Readiness result differs from the running image.')
    runtime.complete_target()
    stable = runtime.bless(value)
    require(stable.name == running['uki_name'], 'Blessed image differs from the authorized promotion.')
    try:
        selected = update.default_entry()
    except FileNotFoundError:
        selected = None
    if intent:
        previous = intent['previous']
        if running == intent['target']:
            allowed = (previous['uki_name'] if previous else None, stable.name)
        else:
            # Power returned to the original default before promotion completed.
            allowed = (stable.name,)
    else:
        previous = record['fallback'] if pending else accepted
        allowed = (previous['uki_name'],) if previous else (None, stable.name)
    require(selected in allowed, 'Persistent boot selector differs from the authorized promotion.')

    if intent is None and (selected != stable.name or accepted != running or pending and running == record['candidate']):
        intent = {'schema': 1, 'operation': operation_id(record), 'target': running, 'previous': previous,
                  'manual': manual and not pending}
        runtime.invalidate_boot_receipt()
        atomic(promotion_path(value), intent)
    if selected != stable.name:
        command(['bootctl', 'set-default', stable.name])
    require_default(stable)
    if accepted != running:
        save_accepted(value)
    if pending:
        candidate = running == record['candidate']
        save(value, {**record, 'phase': 'accepted' if candidate else 'fallback',
                     'error': None if candidate else 'readiness-failed'})
    if intent:
        finish_promotion(value)
    return runtime.publish_boot(value, stable, accepted=True)


def complete(installed_path=INSTALLED, *, deadline_seconds=180):
    """Accept a healthy boot, or reboot a failed candidate to its verified predecessor."""
    from .boot_health import LocalRequirementFailed
    from .credential_operation import wait_ready

    value = policy(installed_path)
    require(type(deadline_seconds) is int and 30 <= deadline_seconds <= 600, 'Invalid readiness deadline.')
    with operation_lock():
        record = load(value)
        pending = is_pending(record)
        running = identity(value)
        require(not pending or running in (record['candidate'], record['fallback']),
                'Running image is outside the authorized operation.')
        candidate = record is not None and running == record['candidate'] and (
            pending or record['phase'] == 'accepted' and load_promotion(value) is not None)
        provisioned = (False if candidate and record['error'] in ('admission-or-staging-failed', 'readiness-failed')
                       else wait_ready(value))
        deadline = time.monotonic()+deadline_seconds
        reported_requirements = set()
        while provisioned:
            try:
                return promote_running(value)
            except (OSError, ValueError, KeyError) as error:
                # Only the boot verifier can supply a journal-safe requirement.
                # Other errors can carry paths, command output or credential details.
                if isinstance(error, LocalRequirementFailed) and len(reported_requirements) < 16:
                    reason = str(error)
                    if len(reason) <= 512 and reason.isprintable() and reason not in reported_requirements:
                        reported_requirements.add(reason)
                        print(reason, file=sys.stderr)
                if time.monotonic() >= deadline:
                    break
                time.sleep(2)
        if candidate:
            rollback_running(value)
        raise ReleaseError('Image readiness deadline expired.')


def rollback_running(value):
    """Verify a pending candidate's predecessor while holding the operation lock."""
    record = load(value)
    intent = current_promotion(value, record)
    running = identity(value)
    if record is None or running != record['candidate'] or not (
            is_pending(record) or record['phase'] == 'accepted' and intent is not None):
        return
    require('image_contract' in value and 'recovery_state' in value,
            'Automatic fallback is blocked pending recovery qualification.')
    binding = value['image_contract']['recovery']['binding']['release']
    previous = record['fallback']
    accepted = accepted_identity(value)
    require(accepted is None or accepted == previous or intent and accepted == running,
            'Recorded acceptance differs from the authorized rollback.')
    require(previous['image_id'] == running['image_id'] and previous['deployment_sequence'] == binding['sequence']
            and previous['uki_name'] == binding['uki_name'], 'Rollback target differs from the authorized predecessor.')
    if intent:
        require(intent == {'schema': 1, 'operation': operation_id(record), 'target': running, 'previous': previous,
                           'manual': False},
                'Rollback promotion intent differs from the authorized operation.')
    from .steady_recovery import runtime_fallback
    # A later retry may continue rollback, even if a reboot request fails.
    save(value, {**record, 'phase': 'rebooting', 'error': 'readiness-failed'})

    def restored():
        # Older slots understand these two schema-1 records and ignore the journal.
        save_accepted({**value, **previous})
        if intent:
            finish_promotion(value)

    runtime_fallback(value, restore_promoted=bool(intent), restored=restored)


def fallback_boot(installed_path=INSTALLED):
    """Reconcile a crash between intent, EFI selection, commit and publication."""
    value = policy(installed_path)
    with operation_lock():
        intent = load_promotion(value)
        record = load(value)
        if intent or not is_pending(record) and accepted_identity(value) == identity(value):
            try:
                promote_running(value)
                return
            except (OSError, ValueError, KeyError):
                if not is_pending(record) and not (intent and record and record['phase'] == 'accepted'):
                    raise
        rollback_running(value)


def close_failed_stage(value, record):
    from .runtime import require_accepted_boot
    require_accepted_boot(value)
    esp = update.restore_esp(value)
    current = Path(command(['bootctl', '--print-stub-path']).strip())
    entry = update.accepted_boot(current, value['uki_name'], esp)
    require_default(entry)
    select_boot_once(entry)
    save(value, {**record, 'phase': 'failed', 'error': 'admission-or-staging-failed'})


def cancel_request(installed_path=INSTALLED):
    """Undo an ambiguous OneShot after this executor crashes in the old image."""
    value = policy(installed_path)
    executor = os.environ.get('INVOCATION_ID')
    successful_stop = os.environ.get('SERVICE_RESULT') == 'success'
    running = identity(value)

    def owned(record):
        # systemd can report success for SIGTERM in the write window. A clean
        # stop after the committed reboot checkpoint preserves the selected image.
        return (is_pending(record) and record['executor_id'] == executor and record['fallback'] == running and
                (not successful_stop or record['phase'] == 'staging' or record['error'] is not None))

    if owned(load(value)):
        # A rejecting competitor may hold the lock briefly after the staging
        # worker exits. Recheck the record under lock before restoring anything.
        with operation_lock(wait=True):
            record = load(value)
            if owned(record):
                close_failed_stage(value, record)


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
        result = {'schema': 1, 'operation': load(value), 'accepted': visible_accepted(value),
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
            elif args.action == 'cancel-request':
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
