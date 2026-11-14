"""Collect bounded public host health from an immutable component contract."""

import csv
import ipaddress as ip
import json
import math
import os
from pathlib import Path
import re
import selectors
import signal
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
USABLE = {'REACHABLE', 'STALE', 'DELAY', 'PROBE', 'PERMANENT', 'NOARP'}


class QueryError(ValueError):
    """An observation is unavailable, not an observed healthy or empty state."""


def load(path=MANIFEST):
    value = json.loads(read(path, 64*1024), object_pairs_hook=unique)
    require(isinstance(value, dict) and set(value) == {'schema', 'units', 'interfaces', 'clients', 'ntp', 'logs', 'directory'} and
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


def tracking(text):
    rows = list(csv.reader(text.splitlines()))
    if len(rows) != 1 or len(rows[0]) != 14:
        raise QueryError
    fields = rows[0]
    if (not re.fullmatch(r'[0-9A-Fa-f]{8}', fields[0]) or not fields[2].isdecimal() or
            not 0 <= int(fields[2]) <= 16 or any(not math.isfinite(float(v)) for v in fields[3:13]) or
            fields[13] not in {'Normal', 'Insert second', 'Delete second', 'Not synchronised'}):
        raise QueryError
    return int(fields[13] != 'Not synchronised' and 1 <= int(fields[2]) <= 15 and
               fields[0].upper() not in {'00000000', '7F7F0101'})


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
    def __init__(self):
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
        except (OSError, ValueError, KeyError, TypeError, AttributeError):
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
        if len(result.encode()) > 1024*1024:
            raise QueryError
        return result


def last_inventory(path=OUTPUT):
    try:
        info = path.lstat()
        if info.st_uid != 0 or info.st_mode & 0o022:
            raise QueryError
        text = read(path, 1024*1024).decode('ascii')
        lines = [line.split()[-1] for line in text.splitlines()
                 if line.startswith('lanrith_router_client_inventory_collection_timestamp_seconds ')]
        if len(lines) == 1:
            value = float(lines[0])
            if math.isfinite(value) and 0 <= value <= time.time()+5:
                return value
    except (OSError, ValueError):
        pass
    return 0


def collect(policy, *, previous_inventory=0):
    metrics = Metrics()

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
    for target, name, expected in (('/', 'mount_read_only', 'ro'), ('/var', 'var_mounted_rw', 'rw')):
        def mount(text):
            rows = json.loads(text)['filesystems']
            if len(rows) != 1 or rows[0]['target'] != target or not isinstance(rows[0]['options'], str):
                raise QueryError
            options = set(rows[0]['options'].split(','))
            if len(options & {'ro', 'rw'}) != 1:
                raise QueryError
            return int(expected in options)
        metrics.emit(name, query('mount_'+name, ['findmnt', '--json', '--output=TARGET,OPTIONS',
                                               '--mountpoint', target], mount) or 0)
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
    for name, marker in (('ab_slots_initialized', 'slots-initialized'), ('recovery_key_enrolled', 'recovery-key-enrolled')):
        def observed():
            if not isinstance(directory, str) or not directory.startswith('/var/lib/'):
                raise QueryError
            path = Path(directory)/marker
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
    def nftables(text):
        return int(any(row.get('table', {}).get('family') == 'inet' and row['table'].get('name') == 'lanrith'
                       for row in json.loads(text)['nftables']))
    metrics.emit('nftables_loaded', query('nftables', ['nft', '-j', 'list', 'tables'], nftables) or 0)
    if policy['ntp']:
        from .ntp_health_runtime import read_observation
        state = metrics.query('chrony', read_observation)
        if state is not None:
            metrics.queries['chrony'] = int(state['query_success'])
            metrics.emit('chrony_synchronised', int(state['synchronised']))
            metrics.emit('chrony_observation_timestamp_seconds', state['observed_timestamp_seconds'])
    if policy['logs']:
        from .logs_runtime import read_observation
        state = metrics.query('alloy', read_observation)
        if state is not None:
            metrics.emit('alloy_queue_capacity_bytes', state['queue_capacity_bytes'])
            metrics.emit('alloy_queue_size_bytes', state['queue_size_bytes'])
            metrics.emit('alloy_enqueue_failed_records_total', state['enqueue_failed_records'], counter=True)
            metrics.emit('alloy_send_failed_records_total', state['send_failed_records'], counter=True)
    if policy['directory']:
        from .directory_runtime import read_observation
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
