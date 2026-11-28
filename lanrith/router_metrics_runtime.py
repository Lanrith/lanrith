"""Collect bounded public host health from an immutable component contract."""

import csv
import ipaddress as ip
import json
import math
import os
from pathlib import Path
import pwd
import re
import selectors
import signal
import socket
import struct
import stat
import subprocess
import sys
import tempfile
import time

from .release import read, require, unique


MANIFEST = Path('/usr/share/lanrith/router-metrics.json')
OUTPUT = Path('/var/lib/node_exporter/textfile_collector/lanrith_router.prom')
INTERFACE = re.compile(r'[A-Za-z0-9][A-Za-z0-9_.:-]{0,14}\Z')
UNIT = re.compile(r'[A-Za-z0-9][A-Za-z0-9_.@:-]{0,127}\.(?:service|timer)\Z')
BASE_LIMIT = 1024*1024
DHCP_LIMIT = 1024*1024
USABLE = {'REACHABLE', 'STALE', 'DELAY', 'PROBE', 'PERMANENT', 'NOARP'}


class QueryError(ValueError):
    """An observation is unavailable, not an observed healthy or empty state."""


def load(path=MANIFEST):
    value = json.loads(read(path, 192*1024), object_pairs_hook=unique)
    require(isinstance(value, dict) and set(value) in ({'schema', 'units', 'interfaces', 'clients', 'ntp', 'logs', 'directory'},
            {'schema', 'units', 'interfaces', 'clients', 'ntp', 'logs', 'directory', 'hooks', 'dhcp4', 'startup_set'}) and
            value['schema'] == 1 and type(value['ntp']) is bool and type(value['logs']) is bool and
            type(value['directory']) is bool and
            isinstance(value['units'], list) and 1 <= len(value['units']) <= 256 and
            all(isinstance(name, str) and UNIT.fullmatch(name) for name in value['units']) and
            len(set(value['units'])) == len(value['units']) and
            isinstance(value['interfaces'], list) and 1 <= len(value['interfaces']) <= 256 and
            all(isinstance(name, str) and INTERFACE.fullmatch(name) for name in value['interfaces']) and
            len(set(value['interfaces'])) == len(value['interfaces']) and
            isinstance(value['clients'], list) and len(value['clients']) <= 64,
            'Invalid router metrics contract.')
    names = set()
    for item in value['clients']:
        require(isinstance(item, dict) and set(item) == {'network', 'interface'} and
                isinstance(item['network'], str) and re.fullmatch(r'[a-z][a-z0-9-]{0,11}', item['network']) and
                item['interface'] in value['interfaces'] and item['interface'] not in names,
                'Invalid client observation attachment.')
        names.add(item['interface'])
    if 'hooks' in value:
        require(type(value['startup_set']) is bool and isinstance(value['dhcp4'], dict) and len(value['dhcp4']) <= 64 and
                all(re.fullmatch(r'[1-9][0-9]{0,9}', k) and int(k) < 2**32 and
                    isinstance(v, list) and len(v) <= 64 and all(integer(p, 2**32-1) and p for p in v) and
                    len(v) == len(set(v)) for k, v in value['dhcp4'].items()), 'Invalid DHCP metrics contract.')
        require(isinstance(value['hooks'], dict) and set(value['hooks']) == {'host', 'services'}, 'Invalid hook inventory.')
        for hooks in value['hooks'].values():
            require(isinstance(hooks, list) and 1 <= len(hooks) <= 256, 'Invalid hook count.')
            names = set()
            for hook in hooks:
                fields = {'family', 'table', 'name', 'type', 'hook', 'prio', 'policy'}
                require(isinstance(hook, dict) and set(hook) in (fields, fields | {'dev'}) and
                        all(isinstance(hook[k], str) and re.fullmatch(r'[a-zA-Z_][a-zA-Z0-9_]{0,63}', hook[k])
                            for k in fields-{'prio'}) and type(hook['prio']) is int and
                        ('dev' not in hook or isinstance(hook['dev'], str) and INTERFACE.fullmatch(hook['dev'])),
                        'Invalid firewall hook.')
                name = hook['family'], hook['table'], hook['name']
                require(name not in names, 'Duplicate firewall hook.')
                names.add(name)
    return value


def command(argv, deadline, limit=1024*1024):
    end = min(deadline, time.monotonic()+2)
    if end <= time.monotonic():
        raise QueryError
    with subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                          stdin=subprocess.DEVNULL, start_new_session=True,
                          env={'PATH': '/usr/sbin:/usr/bin', 'LC_ALL': 'C'}) as child:
        try:
            chunks, size = [], 0
            with selectors.DefaultSelector() as selector:
                selector.register(child.stdout, selectors.EVENT_READ)
                while True:
                    remaining = end-time.monotonic()
                    if remaining <= 0 or not selector.select(remaining):
                        raise QueryError
                    block = os.read(child.stdout.fileno(), min(65536, limit+1-size))
                    if not block:
                        break
                    size += len(block)
                    if size > limit:
                        raise QueryError
                    chunks.append(block)
            while (result := os.waitid(os.P_PID, child.pid, os.WEXITED|os.WNOHANG|os.WNOWAIT)) is None:
                if time.monotonic() >= end:
                    raise QueryError
                time.sleep(.01)
            if result.si_code != os.CLD_EXITED or result.si_status != 0:
                raise QueryError
            return b''.join(chunks).decode('utf-8')
        finally:
            # Keep the leader unreaped until its process group is stopped.
            try:
                os.killpg(child.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass


def tracking_measurements(text):
    rows = list(csv.reader(text.splitlines()))
    if len(rows) != 1 or len(rows[0]) != 14:
        raise QueryError
    fields = rows[0]
    if (not re.fullmatch(r'[0-9A-Fa-f]{8}', fields[0]) or not fields[2].isdecimal() or
            not 0 <= int(fields[2]) <= 16 or any(not math.isfinite(float(v)) for v in fields[3:13]) or
            fields[13] not in {'Normal', 'Insert second', 'Delete second', 'Not synchronised'}):
        raise QueryError
    synchronised = (fields[13] != 'Not synchronised' and 1 <= int(fields[2]) <= 15 and
                    fields[0].upper() not in {'00000000', '7F7F0101'})
    reference, correction = float(fields[3]), float(fields[4])
    delay, dispersion = float(fields[10]), float(fields[11])
    error = abs(correction) + dispersion + delay / 2
    # An external synchronisation report alone does not supply a usable bound.
    measured = synchronised and reference > 0 and dispersion >= 0 and 0 <= error < math.inf
    return {'synchronised': synchronised, 'reference_timestamp_seconds': reference if measured else None,
            'clock_error_bound_seconds': error if measured else None}


def tracking(text):
    return int(tracking_measurements(text)['synchronised'])


def neighbors(text):
    rows = json.loads(text)
    if not isinstance(rows, list) or len(rows) > 8192:
        raise QueryError
    result = set()
    for item in rows:
        if not isinstance(item, dict) or not isinstance(item.get('state'), list):
            raise QueryError
        if not all(isinstance(state, str) for state in item['state']):
            raise QueryError
        if not USABLE.intersection(item['state']):
            continue
        address = ip.ip_address(item['dst'])
        mac = item['lladdr'].lower()
        if (not re.fullmatch(r'(?:[0-9a-f]{2}:){5}[0-9a-f]{2}', mac) or int(mac[:2], 16) & 1 or
                mac == '00:00:00:00:00:00' or address.is_multicast or address.is_unspecified or
                getattr(address, 'scope_id', None) is not None):
            raise QueryError
        result.add((str(address), mac, 'ipv'+str(address.version)))
    return sorted(result)


def netdev(text, selected):
    rows = text.splitlines()
    if len(rows) < 2 or not rows[0].lstrip().startswith('Inter-|') or not rows[1].lstrip().startswith('face |'):
        raise QueryError
    result = {}
    for line in rows[2:]:
        name, separator, counters = line.partition(':')
        fields = counters.split()
        if not separator or len(fields) != 16 or not all(v.isdecimal() and len(v) <= 20 for v in fields):
            raise QueryError
        if name.strip() in selected:
            if name.strip() in result:
                raise QueryError
            result[name.strip()] = [int(fields[n]) for n in (0, 1, 2, 3, 8, 9, 10, 11)]
    return result


class Metrics:
    def __init__(self, *, limit=BASE_LIMIT):
        self.limit = limit
        self.lines, self.names, self.queries = [], set(), {}
        self.started = time.monotonic()
        self.deadline = self.started+20

    def emit(self, name, value, *, counter=False, **labels):
        name = 'lanrith_router_'+name
        if name not in self.names:
            self.lines += ['# TYPE '+name+(' counter' if counter else ' gauge')]
            self.names.add(name)
        suffix = '{'+','.join(key+'='+json.dumps(str(value)) for key, value in sorted(labels.items()))+'}' if labels else ''
        self.lines.append(name+suffix+' '+str(value))

    def query(self, name, operation):
        try:
            result = operation()
        except (OSError, ValueError, KeyError, TypeError, AttributeError, RecursionError):
            self.queries[name] = 0
            return None
        self.queries[name] = 1
        return result

    def finish(self):
        for name, success in self.queries.items():
            self.emit('metrics_query_success', success, collector=name)
        self.emit('metrics_collection_success', int(bool(self.queries) and all(self.queries.values())))
        self.emit('metrics_collection_timestamp_seconds', time.time())
        self.emit('metrics_collection_duration_seconds', time.monotonic()-self.started)
        result = '\n'.join(self.lines)+'\n'
        if len(result.encode()) > self.limit:
            raise QueryError
        return result


def last_inventory(path=OUTPUT):
    try:
        info = path.lstat()
        if info.st_uid != 0 or info.st_mode & 0o022:
            raise QueryError
        text = read(path, BASE_LIMIT+DHCP_LIMIT).decode('ascii')
        lines = [line.split()[-1] for line in text.splitlines()
                 if line.startswith('lanrith_router_client_inventory_collection_timestamp_seconds ')]
        if len(lines) == 1:
            value = float(lines[0])
            if math.isfinite(value) and 0 <= value <= time.time()+5:
                return value
    except (OSError, ValueError):
        pass
    return 0


def mount_modes():
    if (os.environ.get('LISTEN_PID'), os.environ.get('LISTEN_FDS'), os.environ.get('LISTEN_FDNAMES')) != (
            str(os.getpid()), '1', 'host-mountinfo'):
        raise QueryError
    with os.fdopen(os.dup(3), 'rb') as stream:
        data = stream.read(1024*1024+1)
    if len(data) > 1024*1024:
        raise QueryError
    return data.splitlines()


def mount_writable(lines, target):
    matches = []
    for line in lines:
        left, separator, right = line.partition(b' - ')
        fields = left.split()
        if len(fields) < 6 or not separator or len(right.split()) != 3:
            raise QueryError
        if fields[4] == target:
            flags = [set(v.split(b',')) & {b'ro', b'rw'} for v in (fields[5], right.split()[2])]
            if any(len(v) != 1 for v in flags):
                raise QueryError
            matches.append(all(b'rw' in v for v in flags))
    if len(matches) != 1:
        raise QueryError
    return matches[0]


def socket_observation(name, end, limit):
    path = Path('/run')/(name+'.sock')
    info = path.lstat()
    if (not stat.S_ISSOCK(info.st_mode) or info.st_uid or info.st_gid or
            stat.S_IMODE(info.st_mode) != 0o600):
        raise QueryError
    deadline = min(end, time.monotonic()+4)
    remaining = deadline-time.monotonic()
    if remaining <= 0:
        raise QueryError
    data = bytearray()
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as stream:
        stream.settimeout(remaining)
        stream.connect(str(path))
        _, uid, gid = struct.unpack('3i', stream.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
        if uid or gid:  # PID 1 owns the socket-activation listener.
            raise QueryError
        while len(data) <= limit:
            remaining = deadline-time.monotonic()
            if remaining <= 0:
                raise QueryError
            stream.settimeout(remaining)
            part = stream.recv(min(65536, limit+1-len(data)))
            if not part:
                return json.loads(data, object_pairs_hook=unique)
            data.extend(part)
    raise QueryError


def integer(value, maximum=2**63-1):
    return type(value) is int and 0 <= value <= maximum


def dhcp_capacity(expected, response):
    if not isinstance(response, dict) or set(response) != {'pools', 'subnets'}:
        raise QueryError
    wanted_subnets = {int(s) for s in expected}
    wanted_pools = {(int(s), p) for s, pools in expected.items() for p in pools}
    for key, fields, wanted in (('subnets', {'subnet_id', 'allocation_failures', 'declined'}, wanted_subnets),
                                ('pools', {'subnet_id', 'pool', 'total', 'assigned'}, wanted_pools)):
        rows = response[key]
        if not isinstance(rows, list) or len(rows) != len(wanted):
            raise QueryError
        for row in rows:
            if not isinstance(row, dict) or set(row) != fields or not all(integer(v) for v in row.values()):
                raise QueryError
            index = row['subnet_id'] if key == 'subnets' else (row['subnet_id'], row['pool'])
            if index not in wanted or key == 'pools' and (not 1 <= row['total'] < 2**32 or row['assigned'] > row['total']):
                raise QueryError
            wanted.remove(index)
    return response


def nft_objects(kind, deadline):
    rows = json.loads(command(['nft', '-j', '-n', 'list', kind+'s'], deadline), object_pairs_hook=unique)['nftables']
    if not isinstance(rows, list) or any(not isinstance(r, dict) for r in rows):
        raise QueryError
    return [row[kind] for row in rows if kind in row]


def table_states(deadline):
    tables = {}
    for row in nft_objects('table', deadline):
        key = (row['family'], row['name'])
        if key in tables or not isinstance(row.get('flags', []), list):
            raise QueryError
        tables[key] = 'dormant' not in row.get('flags', [])
    return tables


def hook_states(expected, tables, deadline):
    chains = {}
    for row in nft_objects('chain', deadline):
        key = (row['family'], row['table'], row['name'])
        if key in chains:
            raise QueryError
        chains[key] = row
    result = []
    for hook in expected:
        table = (hook['family'], hook['table'])
        row = chains.get((*table, hook['name']), {})
        result.append(bool(tables.get(table) and all(row.get(k) == v for k, v in hook.items())))
    return result


def startup_barrier(text):
    rows = [item['set'] for item in json.loads(text, object_pairs_hook=unique)['nftables'] if 'set' in item]
    if len(rows) != 1:
        raise QueryError
    row = rows[0]
    if (row['family'], row['table'], row['name'], row['type']) != ('inet', 'lanrith', 'tp_started', 'mark'):
        raise QueryError
    elements = row.get('elem', [])
    if elements == []:
        return 1
    if len(elements) == 1 and (type(elements[0]) is int and elements[0] == 0 or elements[0] == '0x00000000'):
        return 0
    raise QueryError


READER_UNIT = 'lanrith-policy-reader.service'
READER_OUTCOMES = {'collection_failed', 'submission_failed', 'rejected', 'shadow', 'applied'}


def reader_attempt(deadline):
    uid = pwd.getpwnam('router-policy-reader').pw_uid
    boot = Path('/proc/sys/kernel/random/boot_id').read_text().strip().replace('-', '')
    if uid == 0 or not re.fullmatch(r'[0-9a-f]{32}', boot):
        raise QueryError
    # Read one service stderr record. The unit, user, transport and timestamps
    # come from journald. Application-supplied journal fields cannot select it.
    fields = 'MESSAGE,_UID,_SYSTEMD_UNIT,_TRANSPORT'
    text = command(['journalctl', '--boot=0', '--no-pager', '--lines=1',
                    '--output=json', '--output-fields='+fields, '_SYSTEMD_UNIT='+READER_UNIT,
                    '_UID='+str(uid), '_TRANSPORT=stdout'], deadline, 4096)
    row = json.loads(text, object_pairs_hook=unique)
    if (row['_BOOT_ID'] != boot or row['_SYSTEMD_UNIT'] != READER_UNIT or
            row['_UID'] != str(uid) or row['_TRANSPORT'] != 'stdout'):
        raise QueryError
    monotonic, realtime = row['__MONOTONIC_TIMESTAMP'], row['__REALTIME_TIMESTAMP']
    if not all(isinstance(v, str) and re.fullmatch(r'[0-9]{1,19}', v) for v in (monotonic, realtime)):
        raise QueryError
    age = time.monotonic_ns()//1000 - int(monotonic)
    if not 0 <= age <= 90_000_000 or abs(time.time_ns()//1000 - int(realtime) - age) > 5_000_000:
        raise QueryError
    event = json.loads(row['MESSAGE'], object_pairs_hook=unique)
    if (set(event) != {'schema_version', 'outcome', 'grant_count', 'denial_count'} or
            type(event['schema_version']) is not int or event['schema_version'] != 1 or
            event['outcome'] not in READER_OUTCOMES or
            not all(integer(event[key]) for key in ('grant_count', 'denial_count'))):
        raise QueryError
    return event['outcome'], int(realtime)/1_000_000


def policy_summary(text):
    # router-policy-status validates the full report and authenticates the peer.
    report = json.loads(text, object_pairs_hook=unique)
    return {'ready': report['helper_state'] == 'ready', 'applied': report['permit_state'] == 'last_application'
            and report['mode'] == 'enforce' and report['clock_state'] == 'usable',
            'directory_age_ms': report['directory_age_ms'], 'apply_age_ms': report['apply_age_ms']}


def firewall_health(metrics, policy):
    end = metrics.deadline
    tables = metrics.query('nftables', lambda: table_states(end))
    metrics.emit('nftables_loaded', int(('inet', 'lanrith') in (tables or {})))
    if tables is not None:
        metrics.emit('firewall_recovery_floor_active', int(tables.get(('inet', 'lanrith_recovery'), False)))
    for namespace, expected in policy.get('hooks', {}).items():
        def states():
            if namespace == 'host':
                if tables is None:
                    raise QueryError
                return hook_states(expected, tables, end)
            values = socket_observation('lanrith-router-service-hooks', end, 8192)
            if not isinstance(values, list) or len(values) != len(expected) or not all(type(v) is bool for v in values):
                raise QueryError
            return values
        values = metrics.query('firewall_hooks_'+namespace, states)
        if values is not None:
            for hook, present in zip(expected, values):
                metrics.emit('firewall_hook_present', int(present), namespace=namespace, family=hook['family'],
                             table=hook['table'], chain=hook['name'], interface=hook.get('dev', ''))
    if policy.get('startup_set'):
        barrier = metrics.query('firewall_startup_barrier', lambda: startup_barrier(
            command(['nft', '-j', '-n', 'list', 'set', 'inet', 'lanrith', 'tp_started'], end, 8192)))
        if barrier is not None:
            metrics.emit('firewall_startup_barrier_closed', barrier)
    if policy.get('hooks') and policy['directory']:
        queried_at = time.time()
        def status():
            row = socket_observation('lanrith-router-policy-status', end, 4096)
            if (set(row) != {'ready', 'applied', 'directory_age_ms', 'apply_age_ms'} or
                    any(type(row[key]) is not bool for key in ('ready', 'applied')) or
                    any(row[key] is not None and not integer(row[key]) for key in ('directory_age_ms', 'apply_age_ms'))):
                raise QueryError
            return row
        row = metrics.query('policy_status', status)
        if row is not None:
            metrics.emit('policy_status_query_timestamp_seconds', queried_at)
            metrics.emit('policy_helper_ready', int(row['ready']))
            metrics.emit('policy_last_application', int(row['applied']))
            for name in ('directory', 'apply'):
                age = row[name+'_age_ms']
                if age is not None:
                    metrics.emit('policy_'+name+'_age_seconds', age/1000)


def collect(policy, *, previous_inventory=0):
    metrics = Metrics(limit=BASE_LIMIT+(DHCP_LIMIT if policy.get('dhcp4') else 0))

    def query(name, argv, parser):
        return metrics.query(name, lambda: parser(command(argv, metrics.deadline)))

    installed = metrics.query('image_identity', lambda: json.loads(
        read(Path('/usr/share/lanrith/installed.json'), 65536), object_pairs_hook=unique)) or {}
    metrics.emit('image_info', 1, version=installed.get('platform_version', 'unknown'),
                 sequence=installed.get('deployment_sequence', 'unknown'), image=installed.get('image_id', 'unknown'))
    def unit_states(text):
        result = {}
        for block in text.strip().split('\n\n'):
            fields = {}
            for line in block.splitlines():
                key, separator, value = line.partition('=')
                if not separator or key in fields:
                    raise QueryError
                fields[key] = value
            if set(fields) != {'Id', 'LoadState', 'ActiveState'}:
                raise QueryError
            name = fields['Id']
            if name in result or name not in policy['units']:
                raise QueryError
            result[name] = int(fields['LoadState'] == 'loaded' and fields['ActiveState'] in ('active', 'reloading'))
        if set(result) != set(policy['units']):
            raise QueryError
        return result
    states = query('units', ['systemctl', 'show', '--no-pager', '--property=Id,LoadState,ActiveState',
                             *policy['units']], unit_states) or {}
    for unit in policy['units']:
        metrics.emit('unit_active', states.get(unit, 0), unit=unit)
    try:
        mounts = mount_modes()
    except (OSError, ValueError):
        mounts = []
    for target, name, writable in ((b'/', 'mount_read_only', False), (b'/var', 'var_mounted_rw', True)):
        state = metrics.query('mount_'+name, lambda: mount_writable(mounts, target))
        if state is not None:
            metrics.emit(name, int(state == writable))
    capacity = metrics.query('var_capacity', lambda: os.statvfs('/var'))
    if capacity:
        metrics.emit('var_free_bytes', capacity.f_bavail*capacity.f_frsize)
    def secure_boot():
        with Path('/sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c').open('rb') as stream:
            raw = stream.read(6)
        if len(raw) != 5 or raw[4] not in (0, 1):
            raise QueryError
        return raw[4]
    metrics.emit('secure_boot_enabled', metrics.query('secure_boot', secure_boot) or 0)
    directory = installed.get('state_directory')
    for name, marker in (('ab_slots_initialized', 'slots-initialized'), ('recovery_key_enrolled', 'recovery-key-verified')):
        def observed():
            if not isinstance(directory, str) or not directory.startswith('/var/lib/'):
                raise QueryError
            path = Path(directory)/marker
            if marker == 'slots-initialized':
                from .slot_state import marker as slot_marker
                return int(slot_marker(path) is not None)
            return int(path.is_file() and not path.is_symlink())
        metrics.emit(name, metrics.query(name, observed) or 0)
    def links(text):
        rows = json.loads(text)
        if not isinstance(rows, list) or len(rows) > 1024:
            raise QueryError
        result = {}
        for row in rows:
            if row.get('ifname') not in policy['interfaces']:
                continue
            if row['ifname'] in result or not isinstance(row.get('flags'), list):
                raise QueryError
            flags = set(row['flags'])
            admin, carrier, operational = 'UP' in flags, 'LOWER_UP' in flags, row.get('operstate') == 'UP'
            result[row['ifname']] = [1, int(admin), int(carrier), int(operational),
                                    int(admin and carrier and operational and not flags & {'DORMANT', 'NO-CARRIER'})]
        return result
    states = query('links', ['ip', '-j', 'link', 'show'], links) or {}
    for interface in policy['interfaces']:
        for name, state in zip(('present', 'admin_up', 'carrier_up', 'operational_up', 'up'),
                               states.get(interface, [0]*5)):
            metrics.emit('interface_'+name, state, interface=interface)
    counters = query('host_netdev', ['cat', '/proc/net/dev'], lambda text: netdev(text, policy['interfaces'])) or {}
    for interface, row in counters.items():
        for name, count in zip(('receive_bytes', 'receive_packets', 'receive_errors', 'receive_drops',
                                'transmit_bytes', 'transmit_packets', 'transmit_errors', 'transmit_drops'), row):
            metrics.emit('interface_'+name+'_total', count, counter=True, interface=interface)
    firewall_health(metrics, policy)
    if policy.get('dhcp4'):
        state = metrics.query('dhcp4', lambda: dhcp_capacity(policy['dhcp4'],
            socket_observation('lanrith-kea-statistics', metrics.deadline, 512*1024)))
        if state is not None:
            for pool in state['pools']:
                labels = {'subnet_id': pool['subnet_id'], 'pool': pool['pool']}
                metrics.emit('dhcp4_pool_assigned_addresses', pool['assigned'], **labels)
                metrics.emit('dhcp4_pool_capacity_addresses', pool['total'], **labels)
            for subnet in state['subnets']:
                metrics.emit('dhcp4_allocation_failures_total', subnet['allocation_failures'],
                             counter=True, subnet_id=subnet['subnet_id'])
                metrics.emit('dhcp4_declined_addresses', subnet['declined'], subnet_id=subnet['subnet_id'])
    if policy['ntp']:
        from .ntp_health_runtime import read_observation
        state = metrics.query('chrony', read_observation)
        if state is not None:
            metrics.queries['chrony'] = int(state['query_success'])
            metrics.emit('chrony_synchronised', int(state['synchronised']))
            metrics.emit('chrony_observation_timestamp_seconds', state['observed_timestamp_seconds'])
            for name in ('reference_timestamp_seconds', 'clock_error_bound_seconds'):
                if state.get(name) is not None:
                    metrics.emit('chrony_'+name, state[name])
    if 'lanrith-ids.service' in policy['units']:
        from .ids_observer import read_observation
        state = metrics.query('ids_capture', read_observation)
        metrics.emit('ids_stats_fresh', int(state is not None))
        if state is not None:
            metrics.emit('ids_stats_timestamp_seconds', state['timestamp'])
            for name, total in state['totals'].items():
                metrics.emit('ids_'+name+'_total', total, counter=True)
            metrics.emit('ids_interval_valid', int(state['delta'] is not None))
            for name, change in (state['delta'] or {}).items():
                metrics.emit('ids_'+name+'_delta', change)
    if policy['logs']:
        from .logs_runtime import read_observation
        state = metrics.query('alloy', read_observation)
        if state is not None:
            metrics.emit('alloy_queue_capacity_bytes', state['queue_capacity_bytes'])
            metrics.emit('alloy_queue_size_bytes', state['queue_size_bytes'])
            metrics.emit('alloy_enqueue_failed_records_total', state['enqueue_failed_records'], counter=True)
            metrics.emit('alloy_send_failed_records_total', state['send_failed_records'], counter=True)
    if policy['directory']:
        from .directory_runtime import read_observation, trust_expiries
        attempt = metrics.query('policy_reader', lambda: reader_attempt(metrics.deadline))
        if attempt is not None:
            metrics.emit('policy_reader_latest_attempt', 1, outcome=attempt[0])
            metrics.emit('policy_reader_attempt_timestamp_seconds', attempt[1])
        anchors = metrics.query('directory_trust', lambda: trust_expiries(metrics.deadline))
        if anchors is not None:
            for fingerprint, expiry in anchors.items():
                metrics.emit('directory_trust_certificate_not_after_seconds', expiry, sha256=fingerprint)
        state = metrics.query('directory', read_observation)
        if state is not None:
            metrics.emit('directory_tls_verified', int(state['tls_verified']))
            metrics.emit('directory_tls_observation_timestamp_seconds', state['observed_timestamp_seconds'])
            metrics.emit('directory_tls_endpoints_total', state['endpoints_total'])
            metrics.emit('directory_tls_endpoints_verified', state['endpoints_verified'])
            metrics.emit('directory_tls_certificate_not_after_seconds', state['certificate_not_after_seconds'])
    complete, budget = True, 1024
    for client in policy['clients']:
        entries = query('neighbors_'+client['interface'], ['ip', '-j', 'neigh', 'show', 'dev', client['interface']], neighbors)
        if entries is None:
            complete = False
            continue
        metrics.emit('client_neighbor_count', len(entries), **client)
        selected = entries[:min(256, budget)]
        complete &= len(selected) == len(entries)
        budget -= len(selected)
        for address, mac, family in selected:
            metrics.emit('client_neighbor_info', 1, **client, address=address, mac=mac, family=family)
    metrics.emit('client_inventory_complete', int(complete))
    metrics.emit('client_inventory_collection_timestamp_seconds', time.time() if complete else previous_inventory)
    return metrics.finish()


def publish(text, path=OUTPUT):
    directory = path.parent
    info = directory.lstat()
    require(directory.resolve() == directory and stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and
            not info.st_mode & 0o022, 'Metrics output directory is not protected.')
    descriptor, temporary = tempfile.mkstemp(prefix='.lanrith-router.', dir=directory)
    try:
        with os.fdopen(descriptor, 'w') as stream:
            stream.write(text)
            stream.flush()
            os.fchmod(stream.fileno(), 0o644)
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        Path(temporary).unlink(missing_ok=True)


def main(arguments=None):
    arguments = sys.argv[1:] if arguments is None else arguments
    if arguments in (['--service-hooks'], ['--policy-status']):
        try:
            deadline = time.monotonic()+2
            if arguments == ['--service-hooks']:
                result = hook_states(load()['hooks']['services'], table_states(deadline), deadline)
            else:
                result = policy_summary(command(['router-policy-status', '-socket', '/run/router-policy-ipc/status.sock',
                                                 '-server-uid', '0', '-timeout', '1500ms'], deadline, 64*1024))
            print(json.dumps(result, separators=(',', ':')))
            return 0
        except (OSError, ValueError, KeyError, TypeError):
            return 1
    if arguments not in ([], ['--on-stop']):
        return 64
    try:
        require(os.geteuid() == 0, 'Host health collection requires its root service.')
        if arguments == ['--on-stop']:
            if os.environ.get('SERVICE_RESULT') != 'success':
                failed = Metrics()
                failed.emit('client_inventory_collection_timestamp_seconds', last_inventory())
                publish(failed.finish())
            return 0
        publish(collect(load(), previous_inventory=last_inventory()))
        return 0
    except Exception:
        try:
            failed = Metrics()
            failed.emit('client_inventory_collection_timestamp_seconds', last_inventory())
            publish(failed.finish())
        except Exception:
            pass
        print('Router health collection failed.', file=sys.stderr)
        return 1
