"""Fixed credential transactions for one image-admitted extension namespace."""

import argparse
import json
import os
from pathlib import Path
import pwd
import socket
import struct
import subprocess
import sys
import time

from . import credential_operation as core, credential_store, image_operation
from . import extension_credential_values as values
from .policy_runtime import read
from .release import canonical, require, unique


CATALOGS = Path('/usr/share/lanrith/extension-credentials')


def index(value):
    selected = value.get('extension_credential_catalogs', {})
    require(isinstance(selected, dict) and len(selected) <= 64, 'Extension credential index differs.')
    for extension, row in selected.items():
        values.namespace(extension)
        require(isinstance(row, dict) and set(row) == {'sha256', 'core_required'} and
                isinstance(row['sha256'], str) and credential_store.HEX.fullmatch(row['sha256']) and
                type(row['core_required']) is bool, 'Extension credential index binding differs.')
    return selected


def catalog(value, extension):
    values.namespace(extension)
    selected = index(value)
    require(extension in selected, 'Extension has no admitted credential namespace.')
    raw = read(CATALOGS/(extension+'.json'), 256*1024)
    require(credential_store.digest(raw) == selected[extension]['sha256'],
            'Extension credential catalog identity differs.')
    result = values.validate_catalog(extension, json.loads(raw, object_pairs_hook=unique))
    require(result['credentials'], 'Admitted extension credential catalog is empty.')
    return result


def socket_path(extension):
    return '/run/lanrith-extension-credentials.'+values.namespace(extension)+'.sock'


def ready_unit(extension):
    return 'lanrith-extension-credential-'+values.namespace(extension)+'-ready.service'


def core_accepted(value):
    """A prior boot's persisted acceptance alone cannot enable optional setup."""
    try:
        if image_operation.accepted_identity(value) != image_operation.identity(value):
            return False
        observation = json.loads(read(Path('/run/lanrith/boot.json'), 4096), object_pairs_hook=unique)
        return isinstance(observation, dict) and type(observation.get('schema')) is int and \
            observation['schema'] == 1 and observation.get('accepted') is True and \
            observation.get('boot_complete') is True and observation.get('image_id') == value['image_id'] and \
            type(observation.get('deployment_sequence')) is int and \
            observation['deployment_sequence'] == value['deployment_sequence'] and \
            observation.get('boot_id') == Path('/proc/sys/kernel/random/boot_id').read_text().strip()
    except (OSError, ValueError, KeyError, TypeError, RecursionError):
        return False


def eligible(value, extension):
    return index(value)[extension]['core_required'] or core_accepted(value)


def store_for(value, extension):
    return credential_store.Store(value, catalog(value, extension), extension=extension)


def activate(store, *, core_required, committed=False):
    units = [ready_unit(store.extension), *store.catalog['units']]
    checks = [*core.OBSERVERS, 'boot-complete.target'] if core_required and committed else []
    core.control('reset-failed', [*units, *core.OBSERVERS] if checks else units)
    core.control('start', [*units, *checks])


def execute(value, extension, selected):
    store = store_for(value, extension)
    require(store.items, 'This extension has no credential provisioning requirement.')
    if not eligible(value, extension):
        require(selected['action'] == 'status', 'Optional extension provisioning requires current core acceptance.')
        return {'schema': 1, 'required': True, 'configuration_sha256': store.identity['configuration_sha256'],
                'phase': 'needs-core-acceptance', 'references': sorted(store.items), 'transaction_id': None}
    if selected['action'] == 'stage':
        require(selected['configuration_sha256'] == store.identity['configuration_sha256'],
                'Extension credential request targets a different configuration.')
    # Parents are image-generated tmpfiles. This operation can write only the
    # selected namespace; it never needs broad /var or core provisioning access.
    store.setup()
    required = index(value)[extension]['core_required']
    with store.lock():
        if selected['action'] == 'status':
            return store.status()
        if selected['action'] == 'stage':
            # Repair unadmitted optional setup even on an accepted core image.
            # The store always preserves every admitted fallback path and byte.
            store.preflight(selected['credentials'], allow_replace=True)
            if store.admitted():
                return store.status()
            core.control('stop', [ready_unit(extension), *store.catalog['units']])
            result = store.stage(selected['credentials'], allow_replace=True)
            activate(store, core_required=required)
            return result
        result = store.commit(selected['transaction_id'])
        activate(store, core_required=required, committed=True)
        return result


def request(raw):
    require(isinstance(raw, bytes) and 0 < len(raw) <= credential_store.LIMIT and raw.endswith(b'\n'),
            'Extension credential request framing differs.')
    try:
        value = json.loads(raw, object_pairs_hook=unique)
    except (ValueError, UnicodeError, RecursionError):
        raise ValueError('Extension credential request encoding differs.') from None
    require(isinstance(value, dict) and type(value.get('schema')) is int and value['schema'] == 1,
            'Extension credential request schema differs.')
    action = value.get('action')
    if action == 'status':
        require(set(value) == {'schema', 'action'}, 'Extension credential status scope differs.')
    elif action == 'stage':
        require(set(value) == {'schema', 'action', 'configuration_sha256', 'credentials'} and
                isinstance(value['configuration_sha256'], str) and
                credential_store.HEX.fullmatch(value['configuration_sha256']) and
                isinstance(value['credentials'], dict) and 1 <= len(value['credentials']) <= values.SLOT_LIMIT,
                'Extension credential staging scope differs.')
        for name, body in value['credentials'].items():
            values.reference(name)
            values.decoded(body)
    elif action == 'commit':
        require(set(value) == {'schema', 'action', 'transaction_id'} and
                isinstance(value['transaction_id'], str) and credential_store.TRANSACTION.fullmatch(value['transaction_id']),
                'Extension credential confirmation scope differs.')
    else:
        require(False, 'Unsupported extension credential operation.')
    return value


def serve(connection, extension):
    value = image_operation.policy()
    _, uid, _ = struct.unpack('3i', connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
    require(uid == pwd.getpwnam(value['operator']).pw_uid, 'Caller is not the installed credential operator.')
    result = execute(value, extension, request(core.receive(connection)))
    try:
        connection.sendall(canonical({'ok': True, 'result': result}))
    except OSError:
        pass  # durable state survives a disconnected operator transport


def ready(value, extension, *, committed=True):
    store = store_for(value, extension)
    if not eligible(value, extension):
        return False
    with store.lock():
        return store.admitted() or not committed and store.prepared()


def required_ready(value):
    return all(ready(value, extension) for extension, row in index(value).items() if row['core_required'])


def wait_ready(value, extension, *, setup=False):
    catalog(value, extension)
    deadline = time.monotonic()+core.PROVISION_SECONDS
    while True:
        try:
            if eligible(value, extension):
                if setup:
                    store = store_for(value, extension)
                    store.setup()
                    with store.lock():
                        store.resume()
                    return True
                if ready(value, extension, committed=False):
                    return True
        except (OSError, ValueError, KeyError, TypeError, RecursionError):
            pass
        if time.monotonic() >= deadline:
            return False
        time.sleep(1)


def client(extension, selected):
    encoded = canonical(selected)
    request(encoded)
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
        connection.settimeout(285)
        connection.connect(socket_path(extension))
        connection.sendall(encoded)
        with connection.makefile('rb') as stream:
            raw = stream.readline(core.RESPONSE_LIMIT+1)
        require(0 < len(raw) <= core.RESPONSE_LIMIT, 'Extension credential response exceeds its bound.')
        value = json.loads(raw, object_pairs_hook=unique)
        require(isinstance(value, dict) and set(value) == {'ok', 'result'} and value['ok'] is True and
                isinstance(value['result'], dict), 'Extension credential operation rejected.')
        return value['result']


def main(arguments=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('extension')
    commands = parser.add_subparsers(dest='action', required=True)
    commands.add_parser('status')
    commands.add_parser('stage').add_argument('configuration_sha256')
    commands.add_parser('commit').add_argument('transaction_id')
    for action in ('serve', 'setup', 'gate'):
        commands.add_parser(action, help=argparse.SUPPRESS)
    args = parser.parse_args(arguments)
    try:
        values.namespace(args.extension)
        if args.action == 'serve':
            require(os.geteuid() == 0, 'Extension credential executor requires service authority.')
            with socket.socket(fileno=0) as connection:
                try:
                    serve(connection, args.extension)
                except (OSError, ValueError, KeyError, TypeError, RecursionError, subprocess.SubprocessError):
                    try:
                        connection.sendall(canonical({'ok': False, 'error': 'extension-credential-operation-rejected'}))
                    except OSError:
                        pass
                    print('Extension credential operation rejected.', file=sys.stderr)
                    return 1
        elif args.action in ('setup', 'gate'):
            require(os.geteuid() == 0, 'Extension credential boot preparation requires service authority.')
            require(wait_ready(image_operation.policy(), args.extension, setup=args.action == 'setup'),
                    'Extension credential provisioning deadline expired.')
        else:
            selected = {'schema': 1, 'action': args.action}
            if args.action == 'stage':
                raw = sys.stdin.buffer.read(credential_store.LIMIT+1)
                require(0 < len(raw) <= credential_store.LIMIT, 'Extension credential input exceeds its bound.')
                selected.update(configuration_sha256=args.configuration_sha256,
                                credentials=json.loads(raw, object_pairs_hook=unique))
            elif args.action == 'commit':
                selected['transaction_id'] = args.transaction_id
            print(json.dumps(client(args.extension, selected), sort_keys=True))
    except (OSError, ValueError, KeyError, TypeError, RecursionError, subprocess.SubprocessError):
        print('Extension credential operation failed; inspect operator status and system diagnostics.', file=sys.stderr)
        return 1
    return 0
