#!/usr/bin/env python3
"""Qualify the six NAT46 mappings on numbered and routed client attachments."""

import argparse
from contextlib import ExitStack
import ipaddress as ip
import json
from pathlib import Path
import socket
import tempfile

import translation_reference as ref
from nat46_pmtu_native import bound_socket, fragmentation_needed
from translation_network_native import command, expect_failure, install, unit
from tun_policy_native import FOUR, SERVERS, SIX
from lanrith import translation_runtime as runtime


ROUTED = '198.18.46.1'
NEXT_HOP = 'fd42:1234:5678:30::'
CLIENTS = [('c4', FOUR), ('r4', ROUTED)]


def profile(raw):
    raw['hardware']['interfaces']['routed'] = {'name': 'r4', 'match': {'mac': '02:00:00:00:04:01'}}
    raw['networks']['routed'] = {'interface': 'routed', 'routed_prefixes': ['198.18.46.0/24'],
                                 'ipv6': {'subnet_id': 48, 'ra': False, 'gua': False}}
    maps = raw['translation']['nat46']['mappings']
    for i in (3, 4, 5):
        maps['service'+str(i)]['ipv6'] = SIX+str(10+i)
    rules = raw['access']['rules']
    rules.insert(0, {'action': 'allow', 'from': 'four', 'to': {'translation': 'nat46'},
                     'protocol': 'udp', 'ports': [33333], 'authorization': 'directory'})
    rules.insert(0, {'action': 'allow', 'from': {'network': 'routed', 'addresses': ROUTED},
                     'to': {'translation': 'nat46'}, 'protocol': ['tcp', 'udp'],
                     'ports': [11111], 'authorization': 'owner'})


def paths(manifest):
    maps = manifest['mappings']
    servers = {m['ipv6']: 'p6' if i < 3 else 'c6' for i, m in enumerate(maps.values())}
    assert manifest['route_contexts'] == {'clients': [list(c) for c in CLIENTS], 'servers': servers}
    prefix = ip.ip_network(manifest['prefix']).network_address
    cases = {}
    for client, address in CLIENTS:
        embedded = str(prefix+int(ip.ip_address(address)))
        for mapping in maps.values():
            alias, server = mapping['ipv4'], mapping['ipv6']
            cases[(alias, client, address, 'forward')] = 'nat46'
            cases[(embedded, servers[server], server, 'return')] = 'nat46'
    return cases


def check_lookups(cases, changed=None):
    for case, device in cases.items():
        target, interface, source, _ = case
        family = '-6' if ':' in target else '-4'
        row, = json.loads(command('ip', family, '-j', 'route', 'get', target, 'from', source, 'iif', interface))
        assert row['dev'] == ('r4' if case == changed else device), (case, row)


def check_route_health(manifest):
    cases = paths(manifest)
    assert {case for case in runtime.forwarding_cases(manifest) if case[-1] != 'local'} == set(cases)
    check_lookups(cases)
    for case in (next(c for c in cases if c[1:] == ('r4', ROUTED, 'forward')),
                 next(c for c in cases if c[1] == 'c6' and c[-1] == 'return')):
        target, interface, source, direction = case
        family = '-6' if ':' in target else '-4'
        command('ip', family, 'route', 'add', target, 'dev', 'r4', 'table', '143')
        command('ip', family, 'rule', 'add', 'pref', '113', 'iif', interface, 'from', source,
                'to', target, 'table', '143')
        try:
            assert all(runtime.owned_route('nat46', prefix) for prefix in manifest['routes'])
            check_lookups(cases, changed=case)
            expected = f'nat46 {direction} lookup for {target} from {source} on {interface} failed.'
            expect_failure(lambda: runtime.status(manifest), expected)
            print(expected, 'The other 23 lookups still selected nat46.', flush=True)
        finally:
            command('ip', family, 'rule', 'del', 'pref', '113')
            command('ip', family, 'route', 'flush', 'table', '143')
    runtime.status(manifest)


def setup_peers(manifest):
    ref.peer('p4', '93.184.216.0/24')
    ref.peer('c4', '10.240.40.0/24')
    ref.peer('c6', SIX+'/64')
    ref.peer('p6', SERVERS+'/64')
    ref.peer('r4', NEXT_HOP+'/64')
    # An IPv4 client /32 behind an IPv6-only numbered interface (RFC 5549).
    command('ip', '-n', 'r4', 'addr', 'add', ROUTED+'/32', 'dev', 'lo')
    command('ip', '-n', 'r4', '-4', 'route', 'add', 'default', 'via', 'inet6', NEXT_HOP+'1', 'dev', 'eth0')
    command('ip', '-4', 'route', 'add', '198.18.46.0/24', 'via', 'inet6', NEXT_HOP+'2', 'dev', 'r4')
    for address, interface in manifest['route_contexts']['servers'].items():
        command('ip', '-n', interface, '-6', 'addr', 'add', address+'/64', 'dev', 'eth0', 'nodad')


def bind_peers(stack, manifest):
    prefix = ip.ip_network(manifest['prefix']).network_address
    flows = []
    for mapping in manifest['mappings'].values():
        alias, server = mapping['ipv4'], mapping['ipv6']
        backend = manifest['route_contexts']['servers'][server]
        for kind in (socket.SOCK_STREAM, socket.SOCK_DGRAM):
            listener = stack.enter_context(bound_socket(backend, server, 11111, kind))
            if kind == socket.SOCK_STREAM:
                listener.listen()
            for interface, address in CLIENTS:
                sender = stack.enter_context(bound_socket(interface, address, 0, kind))
                sender.connect((alias, 11111))
                translated = str(prefix+int(ip.ip_address(address)))
                remote = (translated, sender.getsockname()[1])
                peer = listener
                if kind == socket.SOCK_STREAM:
                    conn, connected = listener.accept()
                    peer = stack.enter_context(conn)
                    peer.settimeout(2)
                    assert connected[:2] == remote
                flows.append((sender, peer, remote))
    return flows


def exchange(flows):
    for sender, peer, remote in flows:
        data = ('map '+sender.getpeername()[0]).encode()
        sender.sendall(data)
        if sender.type == socket.SOCK_DGRAM:
            payload, source = peer.recvfrom(256)
            assert source[:2] == remote and payload == data
            peer.sendto(payload, source)
        else:
            assert peer.recv(len(data), socket.MSG_WAITALL) == data
            peer.sendall(data)
        assert sender.recv(len(data), socket.MSG_WAITALL) == data


def check_denial(manifest):
    mapping = manifest['mappings']['service0']
    alias, server = mapping['ipv4'], mapping['ipv6']
    unused = '10.251.0.99'
    assert unused not in {m['ipv4'] for m in manifest['mappings'].values()}
    selectors = ((unused, 11111), (alias, 33333))
    chains = []
    for name, priority in (('before', -1), ('after', 1)):
        rules = [f'iifname "c4" oifname "nat46" ip saddr {FOUR} ip daddr {target} udp dport {port} counter'
                 for target, port in selectors]
        chains.append(f'chain {name} {{ type filter hook forward priority {priority}; policy accept;\n'
                      +'\n'.join(rules)+'\n}')
    ref.nft('table inet mapping_checks {\n'+'\n'.join(chains)+'\n}')

    def count(chain):
        result = json.loads(command('nft', '-j', 'list', 'chain', 'inet', 'mapping_checks', chain))
        return [expr['counter']['packets'] for row in result['nftables']
                for expr in row.get('rule', {}).get('expr', []) if 'counter' in expr]

    with bound_socket('c4', FOUR, 0) as client, bound_socket('p6', server, 33333) as backend:
        for target, port in selectors:
            client.sendto(b'ordinary request', (target, port))
        backend.settimeout(.4)
        try:
            backend.recv(256)
        except TimeoutError:
            pass
        else:
            raise AssertionError('Mapped backend received a request without a grant')
        assert count('before') == [1, 1] and count('after') == [0, 0]
        ref.nft(f'add element inet lanrith tp_grants4 {{ {FOUR} . {alias} . udp . 33333 timeout 30s }}')
        client.sendto(b'granted', (alias, 33333))
        data, peer = backend.recvfrom(256)
        assert data == b'granted'
        backend.sendto(data, peer)
        assert client.recvfrom(256) == (data, (alias, 33333))
        assert count('after') == [0, 1]
    print('Unused alias and absent grant each counted 1 before and 0 after the firewall. A scoped grant admitted its mapped exchange.', flush=True)


def run(root, package):
    manifest = install(root, package, configure=profile)['nat46']
    unit('start', 'systemd-networkd')
    setup_peers(manifest)
    unit('start', 'nftables')
    ref.command('nft', '-f', str(root/'identity-egress.nft'))
    mac = json.loads(command('ip', '-n', 'c4', '-j', 'link', 'show', 'eth0'))[0]['address']
    ref.nft('add element inet lanrith tp_started { 0 }\n'+
            f'add element inet lanrith tp_bound4 {{ "c4" . {mac} . {FOUR} timeout 120s }}\n'+
            f'add element inet lanrith tp_dest4 {{ "c4" . {FOUR} timeout 120s }}\n'+
            f'add element netdev lanrith_identity tp_bound4 {{ "c4" . {mac} . {FOUR} timeout 120s }}')
    unit('start', manifest['unit'])
    assert Path('/sys/class/net/nat46/mtu').read_text().strip() == '1500'
    check_route_health(manifest)
    check_denial(manifest)
    with ExitStack() as stack:
        flows = bind_peers(stack, manifest)
        exchange(flows)
        original = socket.if_nametoindex('nat46'), unit('show', manifest['unit'], '-p', 'MainPID', '--value')
        unit('restart', 'systemd-networkd')
        assert original == (socket.if_nametoindex('nat46'), unit('show', manifest['unit'], '-p', 'MainPID', '--value'))
        runtime.status(manifest)
        exchange(flows)
        print('All 24 TCP/UDP sockets reached their own mapped IPv6 address and retained their embedded client identity across networkd restart.', flush=True)
        sender, _, _ = next(flow for flow in flows if flow[0].type == socket.SOCK_DGRAM)
        command('ip', 'link', 'set', 'p6', 'mtu', '1280')
        fragmentation_needed(sender, manifest['ipv4'])
        exchange(flows)
        print('Local 1280-byte egress returned IPv4 fragmentation-needed (1260) and smaller requests and replies succeeded.', flush=True)
    unit('stop', 'nftables')
    assert unit('show', manifest['unit'], '-p', 'ActiveState', '--value') == 'inactive'
    assert not Path('/sys/class/net/nat46').exists() and all(not runtime.routes(prefix) for prefix in manifest['routes'])


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--tayga-deb', type=Path)
    args = parser.parse_args()
    with tempfile.TemporaryDirectory() as temp:
        run(Path(temp)/'lab', args.tayga_deb)
