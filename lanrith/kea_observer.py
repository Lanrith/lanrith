"""Expose bounded observations without forwarding client commands to Kea."""

import ipaddress
import json
import os
from pathlib import Path
import pwd
import re
import socket
import struct
import sys
import time

ADMIN = '/run/kea/kea4-ctrl-socket'
READER = Path('/run/lanrith-kea-leases/leases.sock')
CONFIG = Path('/etc/kea/kea-dhcp4.conf')
FIELDS = ('ip-address', 'hw-address', 'subnet-id', 'state', 'cltt', 'valid-lft')
MAC = re.compile(r'(?:[0-9a-f]{2}:){5}[0-9a-f]{2}')
ERROR = {'result': 1}


def unique(pairs):
    obj = dict(pairs)
    if len(obj) != len(pairs):
        raise ValueError('Duplicate keys.')
    return obj


def receive(stream, maximum, deadline, *, request=False):
    data = bytearray()
    while len(data) <= maximum:
        remaining = deadline-time.monotonic()
        if remaining <= 0:
            raise TimeoutError
        stream.settimeout(remaining)
        chunk = stream.recv(min(65536, maximum+1-len(data)))
        if not chunk:
            return json.loads(data, object_pairs_hook=unique)
        data.extend(chunk)
        if request and len(data) <= maximum:
            # The pinned client waits for a reply without closing its write side.
            try:
                return json.loads(data, object_pairs_hook=unique)
            except json.JSONDecodeError:
                pass
    raise ValueError('Oversized response.')


def backend(message, deadline, maximum):
    with socket.socket(socket.AF_UNIX) as stream:
        stream.settimeout(max(0.001, deadline-time.monotonic()))
        stream.connect(ADMIN)
        _, uid, _ = struct.unpack('3i', stream.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
        if uid != pwd.getpwnam('_kea').pw_uid:
            raise ValueError('Unexpected Kea peer.')
        stream.sendall(json.dumps(message).encode())
        stream.shutdown(socket.SHUT_WR)
        return receive(stream, maximum, deadline)


def lease(request, subnet_id, prefix, deadline):
    if (not isinstance(request, dict) or set(request) != {'command', 'arguments'} or
            request['command'] != 'lease4-get-by-hw-address' or not isinstance(request['arguments'], dict) or
            set(request['arguments']) != {'hw-address'}):
        raise ValueError('Unsupported lease request.')
    mac = request['arguments']['hw-address']
    if not isinstance(mac, str) or not MAC.fullmatch(mac) or int(mac[:2], 16) & 1 or mac == '00:00:00:00:00:00':
        raise ValueError('Invalid client address.')
    response = backend({'command': 'lease4-get-by-hw-address', 'arguments': {'hw-address': mac}},
                       deadline, 256*1024)
    code = response['result']
    rows = response.get('arguments', {}).get('leases', [])
    if type(code) is not int or not isinstance(rows, list) or len(rows) > 16:
        raise ValueError('Invalid lease response.')
    if code == 3 and not rows:
        return {'result': 3}
    if code != 0 or not rows:
        raise ValueError('Unavailable lease response.')
    result = []
    for row in rows:
        if type(row['subnet-id']) is not int or row['hw-address'] != mac:
            raise ValueError('Invalid lease identity.')
        if row['subnet-id'] != subnet_id:
            continue
        if ipaddress.IPv4Address(row['ip-address']) not in prefix:
            raise ValueError('Invalid lease subnet.')
        if (not isinstance(row['ip-address'], str) or
                any(type(row[field]) is not int or not 0 <= row[field] < 2**32
                    for field in ('state', 'cltt', 'valid-lft'))):
            raise ValueError('Invalid lease fields.')
        result.append({field: row[field] for field in FIELDS})
    return {'result': 0, 'arguments': {'leases': result}} if result else {'result': 3}


def serve(subnet_id, prefix):
    READER.unlink(missing_ok=True)
    with socket.socket(socket.AF_UNIX) as server:
        server.bind(str(READER))
        READER.chmod(0o660)
        server.listen(16)
        if address := os.environ.get('NOTIFY_SOCKET'):
            with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as notify:
                notify.sendto(b'READY=1', address.replace('@', '\0', 1) if address.startswith('@') else address)
        while True:
            client, _ = server.accept()
            with client:
                deadline = time.monotonic()+2
                try:
                    request = receive(client, 384, deadline, request=True)
                    reply = lease(request, subnet_id, prefix, deadline)
                except (OSError, ValueError, TypeError, KeyError, AttributeError, RecursionError):
                    reply = ERROR
                try:
                    client.settimeout(max(0.001, deadline-time.monotonic()))
                    client.sendall(json.dumps(reply).encode())
                except OSError:
                    pass


def recount(scopes, totals, deadline):
    # Legacy memfiles keep pool_id=0 even after renewal. Count live memfile
    # rows by address only when the subnet counters include unattributed leases.
    ranges = {}
    for scope in scopes:
        subnet = scope['id']
        if subnet in totals:
            ranges[subnet] = []
            for pool in scope['pools']:
                first, last = (int(ipaddress.IPv4Address(v.strip())) for v in pool['pool'].split('-'))
                ranges[subnet].append((pool['pool-id'], first, last))
    assigned = {(subnet, pool_id): 0 for subnet, pools in ranges.items() for pool_id, _, _ in pools}
    seen, counts = set(), dict.fromkeys(totals, 0)
    cursor = '0.0.0.0'
    for _ in range(65):
        reply = backend({'command': 'lease4-get-page', 'arguments': {'from': cursor, 'limit': 128}},
                        deadline, 256*1024)
        rows = reply.get('arguments', {}).get('leases', [] if reply['result'] == 3 else None)
        if (type(reply['result']) is not int or reply['result'] not in (0, 3) or
                not isinstance(rows, list) or len(rows) > 128 or (reply['result'] == 3 and rows)):
            raise ValueError('Incomplete lease page.')
        for row in rows:
            address = int(ipaddress.IPv4Address(row['ip-address']))
            if address in seen or len(seen) == 8192:
                raise ValueError('Incomplete DHCP occupancy scan.')
            seen.add(address)
            subnet = row['subnet-id']
            if subnet in totals and row['state'] in (0, 1):
                counts[subnet] += 1
                for pool_id, first, last in ranges[subnet]:
                    if first <= address <= last:
                        assigned[subnet, pool_id] += 1
                        break
        if len(rows) < 128:
            if counts != totals:
                raise ValueError('Lease counts changed during occupancy scan.')
            return assigned
        cursor = rows[-1]['ip-address']
    raise ValueError('Incomplete DHCP occupancy scan.')


def capacity(scopes, response, deadline):
    if type(response['result']) is not int or response['result'] != 0:
        raise ValueError('Statistics unavailable.')
    data = response['arguments']

    def sample(key, *, initial_zero=False):
        # Kea first creates its allocation failure statistic on failure.
        if initial_zero and key not in data:
            return 0
        value = data[key][0][0]
        if type(value) is not int or value < 0:
            raise ValueError('Invalid Kea statistic.')
        return value

    pools, subnets, unclassified = [], [], {}
    for scope in scopes:
        number = scope['id']
        prefix = f'subnet[{number}].'
        measured = 0
        for pool in scope['pools']:
            pool_id = pool['pool-id']
            name = prefix+f'pool[{pool_id}].'
            assigned = sample(name+'assigned-addresses')
            measured += assigned
            pools.append({'subnet_id': number, 'pool': pool_id, 'total': sample(name+'total-addresses'),
                          'assigned': assigned})
        subnet_assigned = sample(prefix+'assigned-addresses')
        if measured != subnet_assigned:
            unclassified[number] = subnet_assigned
        subnets.append({'subnet_id': number, 'declined': sample(prefix+'declined-addresses'),
                        'allocation_failures': sample(prefix+'v4-allocation-fail', initial_zero=True)})
    if unclassified:
        counted = recount(scopes, unclassified, deadline)
        for pool in pools:
            if pool['subnet_id'] in unclassified:
                pool['assigned'] = counted[pool['subnet_id'], pool['pool']]
    return {'pools': pools, 'subnets': subnets}


def main(argv):
    if argv == ['statistics']:
        scopes = json.loads(CONFIG.read_bytes())['Dhcp4']['subnet4']
        deadline = time.monotonic()+2
        response = backend({'command': 'statistic-get-all'}, deadline, 8*1024*1024)
        print(json.dumps(capacity(scopes, response, deadline), separators=(',', ':')))
        return 0
    if len(argv) == 3 and argv[0] == 'leases':
        serve(int(argv[1]), ipaddress.IPv4Network(argv[2]))
        return 0
    return 64


if __name__ == '__main__':
    try:
        sys.exit(main(sys.argv[1:]))
    except (OSError, ValueError, TypeError, KeyError, IndexError, AttributeError, RecursionError):
        sys.exit(1)
