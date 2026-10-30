"""Fixed operator credential transactions; values enter through stdin only."""

import argparse
import json
import os
import pwd
import socket
import struct
import subprocess
import sys
import time

from . import credential_store, image_operation
from .credential_values import validate_catalog
from .release import canonical, require, unique


SOCKET = '/run/lanrith-credentials.sock'
READY = 'lanrith-credential-ready.service'
OBSERVERS = ('lanrith-health.service', 'lanrith-observation.service', 'lanrith-image-completion.service')
PROVISION_SECONDS = 600
RESPONSE_LIMIT = 65536


def catalog(value):
    expected = value.get('credential_catalog_sha256')
    if expected is None:
        require(not credential_store.MANIFEST.exists() and not credential_store.MANIFEST.is_symlink(),
                'Unexpected credential catalog.')
        return {'schema': 1, 'credentials': [], 'units': []}
    require(isinstance(expected, str) and credential_store.HEX.fullmatch(expected), 'Credential catalog binding differs.')
    from .policy_runtime import read
    raw = read(credential_store.MANIFEST, 256*1024)
    require(credential_store.digest(raw) == expected, 'Credential catalog identity differs.')
    return validate_catalog(json.loads(raw, object_pairs_hook=unique))


def store_for(value):
    return credential_store.Store(value, catalog(value))


def control(action, units):
    """All unit names come from the validated image catalog or fixed constants."""
    require(action in ('stop', 'start', 'reset-failed') and units, 'Credential service operation differs.')
    if action == 'reset-failed':
        # Inactive units may have been garbage-collected after stop. Resetting
        # such a unit reports "not loaded"; only failed states need a reset.
        result = subprocess.run(['/usr/bin/systemctl', 'show', '--property=Id', '--property=ActiveState',
                                 '--', *units], capture_output=True, timeout=15, check=False)
        require(result.returncode == 0 and len(result.stdout) <= 65536, 'Credential service inspection failed.')
        observed = {}
        for group in result.stdout.decode('ascii').strip().split('\n\n'):
            fields = [line.split('=', 1) for line in group.splitlines()]
            require(len(fields) == 2 and all(len(pair) == 2 for pair in fields), 'Credential service state differs.')
            row = dict(fields)
            require(set(row) == {'Id', 'ActiveState'} and row['Id'] in units and row['Id'] not in observed,
                    'Credential service identity differs.')
            observed[row['Id']] = row['ActiveState']
        require(set(observed) == set(units), 'Credential service inventory differs.')
        units = [unit for unit in units if observed[unit] == 'failed']
        if not units:
            return
    args = ['/usr/bin/systemctl', action]+(['--no-block'] if action == 'start' else [])+['--', *units]
    result = subprocess.run(args, capture_output=True, timeout=120 if action == 'stop' else 15, check=False)
    require(result.returncode == 0, 'Credential service operation failed.')


def activate(store, *, committed=False):
    units = [READY, *store.catalog['units']]
    checks = [*OBSERVERS, 'boot-complete.target'] if committed else []
    control('reset-failed', [*units, *OBSERVERS] if committed else units)
    # Starting an already active completion observer is a no-op. Never stop,
    # restart or try-restart it: its stop hook can select the accepted fallback.
    control('start', [*units, *checks])


def execute(value, selected):
    store = store_for(value)
    require(store.items, 'This image has no credential provisioning requirement.')
    with store.lock():
        if selected['action'] == 'status':
            return store.status()
        if selected['action'] == 'stage':
            require(selected['configuration_sha256'] == store.identity['configuration_sha256'],
                    'Credential request targets a different configuration.')
            # Neither an invalid set nor an attempted fallback rotation may
            # stop a working service. Derive replacement policy locally.
            accepted = image_operation.accepted_identity(value)
            replace = accepted is None
            store.preflight(selected['credentials'], allow_replace=replace)
            if store.admitted():
                return store.status()
            require(accepted != store.identity, 'An accepted image cannot replace credential bindings.')
            control('stop', [READY, *store.catalog['units']])
            status = store.stage(selected['credentials'], allow_replace=replace)
            activate(store)
            return status
        status = store.commit(selected['transaction_id'])
        activate(store, committed=True)
        return status


def request(raw):
    require(isinstance(raw, bytes) and 0 < len(raw) <= credential_store.LIMIT and raw.endswith(b'\n'),
            'Credential request framing differs.')
    try:
        value = json.loads(raw, object_pairs_hook=unique)
    except (ValueError, UnicodeError, RecursionError):
        raise ValueError('Credential request encoding differs.') from None
    require(isinstance(value, dict) and type(value.get('schema')) is int and value['schema'] == 1,
            'Credential request schema differs.')
    action = value.get('action')
    if action == 'status':
        require(set(value) == {'schema', 'action'}, 'Credential status scope differs.')
    elif action == 'stage':
        require(set(value) == {'schema', 'action', 'configuration_sha256', 'credentials'} and
                isinstance(value['configuration_sha256'], str) and
                credential_store.HEX.fullmatch(value['configuration_sha256']) and
                isinstance(value['credentials'], dict) and 1 <= len(value['credentials']) <= 256 and
                all(isinstance(name, str) and len(name) <= 64 and isinstance(body, str) and
                    1 <= len(body) <= 8192 for name, body in value['credentials'].items()),
                'Credential staging scope differs.')
    elif action == 'commit':
        require(set(value) == {'schema', 'action', 'transaction_id'} and
                isinstance(value['transaction_id'], str) and
                credential_store.TRANSACTION.fullmatch(value['transaction_id']),
                'Credential confirmation scope differs.')
    else:
        require(False, 'Unsupported credential operation.')
    return value


def receive(connection):
    data = bytearray()
    deadline = time.monotonic()+10
    while not data.endswith(b'\n'):
        remaining = deadline-time.monotonic()
        require(remaining > 0, 'Credential request deadline expired.')
        connection.settimeout(remaining)
        block = connection.recv(min(65536, credential_store.LIMIT+1-len(data)))
        require(block and len(data)+len(block) <= credential_store.LIMIT, 'Credential request exceeds its bound.')
        data.extend(block)
    return bytes(data)


def serve(connection):
    value = image_operation.policy()
    _, uid, _ = struct.unpack('3i', connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
    require(uid == pwd.getpwnam(value['operator']).pw_uid, 'Caller is not the installed credential operator.')
    selected = request(receive(connection))
    result = execute(value, selected)
    try:
        connection.sendall(canonical({'ok': True, 'result': result}))
    except OSError:
        # Durable staging/confirmation survives a disconnected SSH transport.
        pass


def ready(value, *, committed=True):
    selected = catalog(value)
    if not selected['credentials']:
        return True
    store = credential_store.Store(value, selected)
    with store.lock():
        return store.admitted() or not committed and store.prepared()


def wait_ready(value, *, committed=True, deadline_seconds=PROVISION_SECONDS):
    require(type(deadline_seconds) is int and 1 <= deadline_seconds <= PROVISION_SECONDS,
            'Credential provisioning deadline differs.')
    if not catalog(value)['credentials']:
        return True
    deadline = time.monotonic()+deadline_seconds
    while True:
        try:
            if ready(value, committed=committed):
                return True
        except (OSError, ValueError, KeyError, RecursionError):
            pass
        if time.monotonic() >= deadline:
            return False
        time.sleep(1)


def setup(value):
    store = store_for(value)
    require(store.items, 'No credential setup scope.')
    store.setup()
    with store.lock():
        store.resume()


def client(selected):
    encoded = canonical(selected)
    request(encoded)
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
        connection.settimeout(285)
        connection.connect(SOCKET)
        connection.sendall(encoded)
        with connection.makefile('rb') as stream:
            raw = stream.readline(RESPONSE_LIMIT+1)
        require(0 < len(raw) <= RESPONSE_LIMIT, 'Credential response exceeds its bound.')
        value = json.loads(raw, object_pairs_hook=unique)
        require(isinstance(value, dict) and value.get('ok') is True and
                set(value) == {'ok', 'result'} and isinstance(value['result'], dict), 'Credential operation rejected.')
        return value['result']


def main(arguments=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='action', required=True)
    commands.add_parser('status')
    commands.add_parser('stage').add_argument('configuration_sha256')
    commands.add_parser('commit').add_argument('transaction_id')
    for action in ('serve', 'setup', 'gate'):
        commands.add_parser(action, help=argparse.SUPPRESS)
    args = parser.parse_args(arguments)
    try:
        if args.action == 'serve':
            require(os.geteuid() == 0, 'Credential executor requires service authority.')
            with socket.socket(fileno=0) as connection:
                try:
                    serve(connection)
                except (OSError, ValueError, KeyError, TypeError, RecursionError, subprocess.SubprocessError):
                    try:
                        connection.sendall(canonical({'ok': False, 'error': 'credential-operation-rejected'}))
                    except OSError:
                        pass
                    print('Credential operation rejected.', file=sys.stderr)
                    return 1
        elif args.action in ('setup', 'gate'):
            require(os.geteuid() == 0, 'Credential boot preparation requires service authority.')
            value = image_operation.policy()
            if args.action == 'setup':
                setup(value)
            else:
                require(wait_ready(value, committed=False), 'Credential provisioning deadline expired.')
        else:
            selected = {'schema': 1, 'action': args.action}
            if args.action == 'stage':
                raw = sys.stdin.buffer.read(credential_store.LIMIT+1)
                require(0 < len(raw) <= credential_store.LIMIT, 'Credential input exceeds its bound.')
                selected.update(configuration_sha256=args.configuration_sha256,
                                credentials=json.loads(raw, object_pairs_hook=unique))
            elif args.action == 'commit':
                selected['transaction_id'] = args.transaction_id
            print(json.dumps(client(selected), sort_keys=True))
    except (OSError, ValueError, KeyError, TypeError, RecursionError, subprocess.SubprocessError):
        # Never print parser errors, subprocess output, paths or supplied bytes.
        print('Credential operation failed; inspect operator status and system diagnostics.', file=sys.stderr)
        return 1
    return 0
