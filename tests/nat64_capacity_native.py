#!/usr/bin/env python3
"""Measure authorized local flows on each translator in a disconnected systemd VM."""

import argparse
import errno
import ipaddress as ip
import json
import math
from pathlib import Path
import selectors
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time

import translation_reference as ref
from translation_network_native import command, install, unit
from tun_policy_native import FOUR, SERVERS, SIX, UPPER


PORT = 11111
BLOCK = bytes(65536)
ANYCAST = '192.0.0.9'


def connection(address, kind):
    return socket.socket(socket.AF_INET6 if ':' in address else socket.AF_INET, kind)


def upload(fd, duration):
    deadline = time.monotonic() + duration
    total = 0
    while time.monotonic() < deadline:
        fd.sendall(BLOCK)
        total += len(BLOCK)
    fd.shutdown(socket.SHUT_WR)
    return total


def receive(fd):
    total = 0
    while data := fd.recv(65536):
        total += len(data)
    return total


def retransmissions(fd):
    # Linux tcp_info.tcpi_total_retrans is a native __u32 at offset 100.
    return struct.unpack_from('=I', fd.getsockopt(socket.IPPROTO_TCP, socket.TCP_INFO, 104), 100)[0]


def serve(address, ready):
    def tcp():
        with connection(address, socket.SOCK_STREAM) as listener:
            listener.bind((address, PORT))
            listener.listen()
            ready.touch()
            while True:
                fd, _ = listener.accept()
                with fd:
                    fd.settimeout(30)
                    with fd.makefile('rb', buffering=0) as header:
                        mode, duration = header.readline(32).decode().split()
                    if mode == 'upload':
                        fd.sendall(f'{receive(fd)}\n'.encode())
                    elif mode == 'download':
                        count = upload(fd, int(duration))
                        with fd.makefile('rb') as receipt:
                            assert int(receipt.readline(32)) == count
                        ready.with_suffix('.result').write_text(json.dumps([count, retransmissions(fd)]))

    # Both ports have working echo listeners. A denied probe therefore tests
    # the firewall even when the service is listening at its destination.
    with selectors.DefaultSelector() as events, connection(address, socket.SOCK_DGRAM) as allowed, \
            connection(address, socket.SOCK_DGRAM) as denied:
        for fd, port in ((allowed, PORT), (denied, 22222)):
            fd.bind((address, port))
            events.register(fd, selectors.EVENT_READ)
        threading.Thread(target=tcp, daemon=True).start()
        while True:
            for key, _ in events.select():
                data, peer = key.fileobj.recvfrom(65536)
                key.fileobj.sendto(data, peer)


def transfer(source, target, direction, duration):
    stop = threading.Event()
    rtts = []
    sent = 0

    def latency():
        nonlocal sent
        with connection(source, socket.SOCK_DGRAM) as probe:
            probe.bind((source, 0))
            probe.connect((target, PORT))
            while not stop.is_set():
                sent += 1
                payload = sent.to_bytes(8, 'big')
                start = time.monotonic()
                probe.send(payload)
                deadline = start + .25
                while (remaining := deadline-time.monotonic()) > 0:
                    probe.settimeout(remaining)
                    try:
                        response = probe.recv(64)
                    except TimeoutError:
                        break
                    if response == payload:
                        rtts.append((time.monotonic()-start)*1000)
                        break
                stop.wait(.03)

    with connection(source, socket.SOCK_STREAM) as fd:
        fd.settimeout(30)
        fd.bind((source, 0))
        fd.connect((target, PORT))
        probe = threading.Thread(target=latency)
        probe.start()
        try:
            start = time.monotonic()
            fd.sendall(f'{direction} {duration}\n'.encode())
            if direction == 'upload':
                count = upload(fd, duration)
                with fd.makefile('rb') as receipt:
                    assert int(receipt.readline(32)) == count
            else:
                count = receive(fd)
                fd.sendall(f'{count}\n'.encode())
            seconds = time.monotonic()-start
            assert seconds >= duration and count > 0
        finally:
            stop.set()
            probe.join()
        assert rtts, 'No UDP reply during TCP load'
        return {'bytes_received': count, 'seconds': seconds, 'mbit_s': 8*count/seconds/1e6,
                'loaded_udp_sent': sent, 'loaded_udp_lost': sent-len(rtts),
                'loaded_udp_p95_ms': sorted(rtts)[math.ceil(.95*len(rtts))-1],
                'sender_retransmissions': retransmissions(fd) if direction == 'upload' else None}


def pmtu(source, target):
    with connection(source, socket.SOCK_DGRAM) as fd:
        fd.settimeout(4)
        fd.bind((source, 0))
        fd.setsockopt(socket.IPPROTO_IPV6, 23, 2)  # IPV6_MTU_DISCOVER, IP_PMTUDISC_DO
        fd.setsockopt(socket.IPPROTO_IPV6, 25, 1)  # IPV6_RECVERR
        fd.connect((target, PORT))
        fd.send(bytes(1480))  # 1528-byte IPv6, 1508-byte IPv4
        try:
            fd.recv(2048)
        except OSError as error:
            assert error.errno == errno.EMSGSIZE, repr(error)
        else:
            raise AssertionError('Expected a translated Packet Too Big')
        _, control, _, _ = fd.recvmsg(2048, 256, socket.MSG_ERRQUEUE)
        errors = [struct.unpack_from('=IBBBBII', data) for level, kind, data in control
                  if level == socket.IPPROTO_IPV6 and kind == 25]
        assert any(row[:4] == (errno.EMSGSIZE, 3, 2, 0) and row[5] == 1512 for row in errors), errors
        assert fd.getsockopt(socket.IPPROTO_IPV6, 24) == 1512
        for size in (1464, 512):  # exact 1492-byte IPv4 boundary, then a small datagram
            fd.send(bytes(size))
            assert fd.recv(2048) == bytes(size)
        print('Public NAT64 translated IPv4 MTU 1492 into ICMPv6 type 2/code 0 MTU 1512; 1464- and 512-byte UDP replies received.')


def counters(device):
    stats = Path('/sys/class/net')/device/'statistics'
    return {name: int((stats/name).read_text()) for name in ('rx_packets', 'tx_packets', 'rx_dropped', 'tx_dropped')}


def cpu():
    result = {}
    for row in Path('/proc/stat').read_text().splitlines():
        key, *fields = row.split()
        if key.startswith('cpu') and key[3:].isdigit():
            user, nice, system, idle, iowait, irq, softirq, steal = map(int, fields[:8])
            result[key] = (user+nice+system+irq+softirq+steal, idle+iowait)
    return result


def run(root, package, seconds, rounds, wan_mbit):
    components = install(root, package)
    unit('start', 'systemd-networkd')
    for dev, prefix in (('c6', SIX+'/64'), ('p6', SERVERS+'/64'), ('c4', '10.240.40.0/24'), ('p4', '93.184.216.0/24')):
        ref.peer(dev, prefix)
    for dev, addr in [('c6', SIX+'3'), ('c6', UPPER+'3'), ('p6', SERVERS+'10')]:
        command('ip', '-n', dev, '-6', 'addr', 'add', addr+'/64', 'dev', 'eth0', 'nodad')
    command('ip', '-n', 'p4', 'addr', 'add', ANYCAST+'/32', 'dev', 'eth0')
    command('ip', 'route', 'add', ANYCAST+'/32', 'dev', 'p4')
    ref.ipv6_ready()
    unit('start', 'nftables')
    command('nft', '-f', root/'identity-egress.nft')
    unit('start', 'lanrith-nat64-network')
    # TAYGA reads the TUN MTU when it starts.
    command('ip', 'link', 'set', 'nat64', 'mtu', '2000')
    unit('start', *(component['unit'] for component in components.values()))
    for component in components.values():
        pid = unit('show', component['unit'], '-p', 'MainPID', '--value')
        assert Path('/proc', pid, 'exe').resolve() == Path('/usr/lib/lanrith/tayga-internal')
    command('ip', 'link', 'set', 'c6', 'mtu', '2000')
    command('ip', '-n', 'c6', 'link', 'set', 'eth0', 'mtu', '2000')
    command('ip', 'link', 'set', 'p4', 'mtu', '1492')
    command('ip', '-n', 'p4', 'link', 'set', 'eth0', 'mtu', '1492')

    if wan_mbit is not None:
        command('tc', 'qdisc', 'replace', 'dev', 'p4', 'root', 'cake', 'bandwidth', f'{wan_mbit}mbit',
                'dual-srchost', 'nat', 'besteffort', 'split-gso')
    print(json.dumps({'wan_mtu': 1492, 'wan_qdisc': json.loads(command('tc', '-j', 'qdisc', 'show', 'dev', 'p4')),
                      'hardware_qualified': False}), flush=True)

    mac = json.loads(command('ip', '-n', 'c4', '-j', 'link', 'show', 'eth0'))[0]['address']
    # Admit this synthetic attachment for the whole measurement window.
    validity = rounds*seconds*6+120
    ref.nft('add element inet lanrith tp_started { 0 }\n'+
            f'add element inet lanrith tp_bound4 {{ "c4" . {mac} . {FOUR} timeout {validity}s }}\n'+
            f'add element inet lanrith tp_dest4 {{ "c4" . {FOUR} timeout {validity}s }}\n'+
            f'add element netdev lanrith_identity tp_bound4 {{ "c4" . {mac} . {FOUR} timeout {validity}s }}')

    def target(name, v4):
        return str(ip.ip_network(components[name]['prefix']).network_address+int(ip.ip_address(v4)))

    def drops():
        state = json.loads(command('nft', '-j', 'list', 'counter', 'inet', 'lanrith', 'nat64_non_global_drops'))
        return next(row['counter']['packets'] for row in state['nftables'] if 'counter' in row)

    servers = {}
    try:
        cases = [('nat64', 'c6', SIX+'3', target('nat64', ANYCAST), 'p4', ANYCAST),
                 ('nat64-internal', 'c6', UPPER+'3', target('nat64-internal', FOUR), 'c4', FOUR),
                 ('nat46', 'c4', FOUR, '10.251.0.2', 'p6', SERVERS+'10')]
        script = str(Path(__file__).resolve())
        for name, _, _, _, server, address in cases:
            ready = root/(name+'.ready')
            child = subprocess.Popen(ref.inside(server, sys.executable, script, 'serve', address, str(ready)))
            servers[name] = child
            ref.await_file(ready, child)
        start = drops()
        # Send the ordinary synthetic DNS64 discovery destination once. It
        # never receives a service listener, or any route beyond this guest.
        flow = ref.Flow('c6', target('nat64', '192.0.0.170'), SIX+'3', PORT, 'udp')
        try:
            flow.check(False)
        finally:
            flow.close()
        assert drops() == start+1, 'the public guard must count the filtered request'
        for _, client, source, destination, _, _ in cases:
            flow = ref.Flow(client, destination, source, 22222, 'udp')
            try:
                flow.check(False)
            finally:
                flow.close()
        subprocess.run(ref.inside('c6', sys.executable, script, 'pmtu', SIX+'3', target('nat64', ANYCAST)),
                       check=True, timeout=20)
        for iteration in range(rounds):
            for name, client, source, destination, _, _ in cases:
                for direction in ('upload', 'download'):
                    before = {key: counters(key) for key in components}
                    start_cpu = cpu()
                    started = time.monotonic()
                    result = json.loads(subprocess.check_output(
                        ref.inside(client, sys.executable, script, 'transfer', source, destination, direction, str(seconds)),
                        text=True, timeout=seconds+25))
                    interval = time.monotonic()-started
                    after_cpu = cpu()
                    busy = {}
                    for core, previous in start_cpu.items():
                        active, idle = (right-left for left, right in zip(previous, after_cpu[core]))
                        busy[core] = round(100*active/(active+idle), 2)
                    deltas = {key: {field: now-before[key][field] for field, now in counters(key).items()} for key in components}
                    assert all(deltas[name][side+'_packets'] > 0 for side in ('rx', 'tx')), deltas
                    assert all(not any(stats.values()) for key, stats in deltas.items() if key != name), deltas
                    if direction == 'download':
                        ref.await_file(root/(name+'.result'), servers[name])
                        receipt = json.loads((root/(name+'.result')).read_text())
                        assert receipt[0] == result['bytes_received']
                        result['sender_retransmissions'] = receipt[1]
                        (root/(name+'.result')).unlink()
                    print(json.dumps({'component': name, 'direction': direction, 'iteration': iteration,
                                      'rx_pps': deltas[name]['rx_packets']/interval,
                                      'tx_pps': deltas[name]['tx_packets']/interval, 'tun': deltas[name], 'counter_interval_s': interval, 'cpu_busy_pct': busy,
                                      'hardware_qualified': False, **result}), flush=True)
        assert drops() == start+1
        print('WKP guard packets', drops(), 'after DNS-only discovery denial. Three denied ports checked.', flush=True)
    finally:
        for child in servers.values():
            child.terminate()
            child.wait(timeout=5)


if __name__ == '__main__':
    if sys.argv[1:2] == ['serve']:
        serve(sys.argv[2], Path(sys.argv[3]))
    elif sys.argv[1:2] == ['transfer']:
        print(json.dumps(transfer(*sys.argv[2:5], int(sys.argv[5]))))
    elif sys.argv[1:2] == ['pmtu']:
        pmtu(*sys.argv[2:])
    else:
        parser = argparse.ArgumentParser(description=__doc__)
        parser.add_argument('--tayga-deb', type=Path)
        parser.add_argument('--seconds', type=int, default=2)
        parser.add_argument('--rounds', type=int, default=1)
        parser.add_argument('--wan-mbit', type=int, help='apply a CAKE upload shaper to the synthetic WAN')
        args = parser.parse_args()
        if args.wan_mbit is not None and args.wan_mbit < 1:
            parser.error('wan-mbit must be positive')
        if min(args.seconds, args.rounds) < 1:
            parser.error('seconds and rounds must be positive')
        with tempfile.TemporaryDirectory() as temp:
            run(Path(temp)/'lab', args.tayga_deb, args.seconds, args.rounds, args.wan_mbit)
