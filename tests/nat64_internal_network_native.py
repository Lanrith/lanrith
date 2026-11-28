#!/usr/bin/env python3
"""Private NAT64 readiness and callbacks on six synthetic VLANs in an offline guest."""

import argparse
from contextlib import ExitStack
import ipaddress as ip
import json
from pathlib import Path
import socket
import subprocess
import tempfile
import time

import translation_reference as ref
from nat46_network_native import exchange
from nat46_pmtu_native import bound_socket
from translation_network_native import command, expect_failure, install, unit
from lanrith import boot_health, policy_runtime, translation_runtime as runtime


NAME = 'nat64-internal'
VLANS = (1, 11, 22, 23, 55, 98)
SUBNET = 'fd42:1234:5678:eeee::'
ACTIVE = {SUBNET+format(i, 'x'): '10.250.15.'+str(i) for i in range(132, 140)}
RETIRED = SUBNET+'8c'
RESERVED = {**ACTIVE, RETIRED: '10.250.15.140'}
ROUTED = '10.248.98.9'
PEERS = [(1, '10.240.1.2'), (98, ROUTED)]
PREFIXES = ('fd42:1234:5678:f000::/56', 'fd42:1234:5678:ff00::/60', 'fd42:9876:5432::/48')


def profile(raw):
    raw['hardware']['interfaces']['lan']['name'] = 'trunk'
    raw['uplink']['ipv6'] = {'address': '2001:db8:cafe::2/64', 'gateway': '2001:db8:cafe::1',
                              'downstream_prefix': '2001:db8:ac00::/48', 'delivery': 'routed'}
    raw['networks'] = {'v'+str(v): {'interface': 'lan', 'vlan': v, 'ipv4': f'10.240.{v}.0/24',
                                      'ipv6': {'subnet_id': v, 'ra': True, 'gua': True}} for v in VLANS}
    raw['networks']['mgmt'] = {'interface': 'four', 'role': 'management', 'ipv4': '10.244.0.0/24'}
    raw['networks']['v23']['additional_subnets'] = [SUBNET+'60/124', SUBNET+'80/124']
    raw['networks']['v98']['routed_prefixes'] = [ROUTED+'/32']
    raw['groups'] = {name: [p] for name, p in zip(('work', 'vip', 'vpn'), PREFIXES)}
    raw['routing'] = {'static_routes': [{'to': SUBNET+'/64', 'on_link': True, 'network': 'v23'},
                                        {'to': {'group': 'vip'}, 'on_link': True, 'network': 'v23'}],
                      'bgp': {'enabled': True, 'asn': 64520, 'network': 'v23', 'peer_groups': {
                          'nodes': {'remote_asn': 64521, 'peers': {'n': 'fd42:1234:5678:17::20'},
                                    'import': [{'group': 'work', 'prefix_length': 64, 'purpose': 'network'},
                                               {'group': 'vip', 'prefix_length': 128, 'purpose': 'service',
                                                'reply_mode': 'dsr'}], 'maximum_prefixes': 65},
                          'vpn': {'remote_asn': 64522, 'network': 'v1', 'peers': {'v': 'fd42:1234:5678:1::20'},
                                  'import': [{'group': 'vpn', 'exact': True, 'purpose': 'network'}],
                                  'maximum_prefixes': 1}}}}
    raw['translation']['nat64']['private_pool'] = '10.250.0.0/20'
    del raw['translation']['nat46']
    raw['administration']['networks'] = ['mgmt']
    raw['identity']['directories']['devices']['url'] = 'ldaps://[fd42:1234:5678:17::30]:636'
    raw['identity']['policy']['networks'] = ['v22']
    raw['access']['rules'] = [
        {'action': 'allow', 'from': {'network': 'v23', 'addresses': list(ACTIVE)}, 'to': ['v1', 'v98'],
         'protocol': ['tcp', 'udp'], 'ports': [11111], 'authorization': 'owner'},
        {'action': 'allow', 'from': {'addresses': 'fd42:1234:5678:fd65::af0:102'}, 'to': 'v23',
         'protocol': 'udp', 'ports': [33333], 'authorization': 'directory'},
        {'action': 'allow', 'from': ['v1', 'v98'], 'to': {'network': 'v23', 'addresses': list(RESERVED)},
         'protocol': ['tcp', 'udp'], 'ports': [22222], 'authorization': 'directory'}]


def links():
    ref.peer('p4', '93.184.216.0/24')
    ref.peer('c4', '10.244.0.0/24')
    command('ip', 'link', 'add', 'trunk', 'type', 'veth', 'peer', 'name', 'far')
    for name in ('trunk', 'far'):
        command('ip', 'link', 'set', name, 'up')
    for v in VLANS:
        host, ns = 'trunk.'+str(v), 'v'+str(v)
        command('ip', 'netns', 'add', ns)
        command('ip', 'link', 'add', 'link', 'trunk', 'name', host, 'type', 'vlan', 'id', str(v))
        command('ip', 'link', 'add', 'link', 'far', 'name', 'remote', 'type', 'vlan', 'id', str(v))
        command('ip', 'link', 'set', 'remote', 'netns', ns)
        command('ip', '-n', ns, 'link', 'set', 'remote', 'name', 'eth0')
        command('ip', '-n', ns, 'link', 'set', 'lo', 'up')
        command('ip', '-n', ns, 'link', 'set', 'eth0', 'up')
        command('ip', 'link', 'set', host, 'up')
        command('ip', 'addr', 'add', f'10.240.{v}.1/24', 'dev', host)
        command('ip', '-n', ns, 'addr', 'add', f'10.240.{v}.2/24', 'dev', 'eth0')
        command('ip', '-n', ns, 'route', 'add', 'default', 'via', f'10.240.{v}.1')
        for base in ('fd42:1234:5678:', '2001:db8:ac00:'):
            command('ip', '-6', 'addr', 'add', f'{base}{v:x}::1/64', 'dev', host, 'nodad')
        command('ip', '-n', ns, '-6', 'addr', 'add', f'fd42:1234:5678:{v:x}::2/64', 'dev', 'eth0', 'nodad')
        command('ip', '-n', ns, '-6', 'route', 'add', 'default', 'via', f'fd42:1234:5678:{v:x}::1')
    for suffix in ('61', '81'):
        command('ip', '-6', 'addr', 'add', SUBNET+suffix+'/124', 'dev', 'trunk.23', 'nodad')
    for address in RESERVED:
        command('ip', '-n', 'v23', '-6', 'addr', 'add', address+'/124', 'dev', 'eth0', 'nodad')
    for prefix, vlan in zip((*PREFIXES, SUBNET+'/64'), (23, 23, 1, 23)):
        command('ip', '-6', 'route', 'add', prefix, 'dev', 'trunk.'+str(vlan))
    command('ip', '-n', 'v98', 'addr', 'add', ROUTED+'/32', 'dev', 'lo')
    command('ip', 'route', 'add', ROUTED+'/32', 'via', '10.240.98.2', 'dev', 'trunk.98')


def embedded(manifest, ipv4):
    return str(ip.ip_network(manifest['prefix']).network_address+int(ip.ip_address(ipv4)))


def check_cases(manifest):
    contexts = manifest['route_contexts']
    peers = {(f'trunk.{v}', f'10.240.{v}.2') for v in VLANS} | {('trunk.98', ROUTED)}
    assert set(map(tuple, contexts['peers'])) == peers
    clients = {(f'trunk.{v}', f'{base}{v:x}::2') for base in ('fd42:1234:5678:', '2001:db8:ac00:') for v in VLANS}
    clients.update(('trunk.23', a) for a in [*ACTIVE, SUBNET+'62', SUBNET+'82'])
    clients.update(('trunk.'+str(v), str(ip.ip_network(p).network_address+1))
                   for p, v in zip(PREFIXES, (23, 23, 1)))
    assert set(map(tuple, contexts['clients'])) == clients
    cases = set(runtime.forwarding_cases(manifest))
    mapped = {(embedded(manifest, peer), 'trunk.23', controller, 'forward')
              for _, peer in peers for controller in ACTIVE}
    mapped |= {(alias, device, peer, 'return') for device, peer in peers for alias in ACTIVE.values()}
    assert mapped <= cases and len(mapped) == 112
    assert all(case[0] != RESERVED[RETIRED] and case[2] != RETIRED for case in cases)
    assert manifest['source_allocations'] == {'active': ACTIVE, 'reserved': RESERVED}
    maps = {line.split()[2]: line.split()[1] for line in Path(manifest['config']).read_text().splitlines()
            if line.startswith('map ')}
    assert maps == RESERVED
    assert len(cases) == len(list(runtime.forwarding_cases(manifest)))
    print(f'{len(cases)} route cases including {len(mapped)} mapped lookups, {len(clients)} IPv6 clients and '
          f'{len(peers)} IPv4 peers. All nine TAYGA reservations match.', flush=True)


def readiness(manifest):
    plan = {'native_translation': True, 'probes': [NAME]}
    contract = {'translation_manifests': [{'kind': NAME, 'manifest': '/usr/share/lanrith/'+NAME+'.json'}]}
    start = time.monotonic()
    boot_health.check_features(plan)
    print(f'Private boot readiness seconds {time.monotonic()-start:.3f}', flush=True)
    before = policy_runtime.translation_hash(contract)
    cases = [(ACTIVE[SUBNET+'8b'], 'trunk.98', ROUTED, 'return'),
             (embedded(manifest, ROUTED), 'trunk.23', SUBNET+'8b', 'forward')]
    for target, interface, source, direction in cases:
        family = '-4' if direction == 'return' else '-6'
        command('ip', family, 'route', 'add', target, 'dev', 'trunk.55', 'table', '143')
        command('ip', family, 'rule', 'add', 'pref', '113', 'iif', interface, 'from', source,
                'to', target, 'table', '143')
        try:
            assert all(runtime.owned_route(NAME, route) for route in manifest['routes'])
            message = f'{NAME} {direction} lookup for {target} from {source} on {interface} failed.'
            expect_failure(lambda: policy_runtime.translation_hash(contract), message)
            try:
                boot_health.check_features(plan)
            except boot_health.LocalRequirementFailed as error:
                assert str(error.__cause__) == message
            else:
                raise AssertionError(message)
            # Check the whole matrix in two real iproute2 batches with an independent expected device.
            for version in (4, 6):
                checks = [c for c in runtime.forwarding_cases(manifest) if c[-1] != 'local'
                          and ip.ip_address(c[0]).version == version]
                queries = ''.join(f'route get {dst} from {src} iif {dev}\n' for dst, dev, src, _ in checks)
                rows = ref.command('ip', '-'+str(version), '-j', '-batch', '-', data=queries).stdout.splitlines()
                assert len(checks) == len(rows)
                for case, row in zip(checks, rows):
                    assert json.loads(row)[0]['dev'] == ('trunk.55' if case == (target, interface, source, direction)
                                                         else NAME), case
            print(message, 'Both readiness callers rejected it. Other paths selected the TUN.', flush=True)
        finally:
            command('ip', family, 'rule', 'del', 'pref', '113')
            command('ip', family, 'route', 'flush', 'table', '143')
        boot_health.check_features(plan)
        assert policy_runtime.translation_hash(contract) == before


def outbound(manifest):
    for vlan, address in PEERS:
        destination = (embedded(manifest, address), 11111)
        with bound_socket('v'+str(vlan), address, 11111) as server:
            server.setsockopt(socket.SOL_SOCKET, 11, 1)  # Linux SO_NO_CHECK
            for controller, alias in ACTIVE.items():
                with bound_socket('v23', controller, 0) as client:
                    client.sendto(b'ordinary request', destination)
                    data, source = server.recvfrom(256)
                    assert data == b'ordinary request' and source[0] == f'10.240.{vlan}.1', source
                    # LAN postrouting masquerades the translated source. The
                    # original IPv4 conntrack tuple retains the actual TAYGA alias.
                    original = f'src={alias} dst={address} sport={client.getsockname()[1]} dport=11111 '
                    rows = command('conntrack', '-L', '-f', 'ipv4', '-p', 'udp', '--orig-src', alias,
                                   '--orig-dst', address)
                    assert original in rows, rows
                    server.sendto(b'ordinary reply', source)
                    reply, remote = client.recvfrom(256)
                    assert reply == b'ordinary reply' and remote[:2] == destination
    print('All 16 outbound datagrams used the expected pre-masquerade alias and received the translated SO_NO_CHECK reply.',
          flush=True)


def callbacks(manifest):
    def grants(controllers, protocols):
        entries = [f'{embedded(manifest, peer)} . {controller} . {protocol} . 22222 timeout 120s'
                   for _, peer in PEERS for controller in controllers for protocol in protocols]
        ref.nft('add element inet lanrith tp_grants6 { '+', '.join(entries)+' }')

    def denied(client, receiver, alias):
        client.sendto(b'callback', (alias, 22222))
        receiver.settimeout(.35)
        try:
            receiver.recvfrom(256)
        except TimeoutError:
            return
        raise AssertionError('Unexpected callback to '+alias)

    grants([RETIRED], ['udp'])
    first = next(iter(ACTIVE))
    with bound_socket('v1', PEERS[0][1], 0) as client:
        with bound_socket('v23', RETIRED, 22222) as retired:
            denied(client, retired, RESERVED[RETIRED])
        with bound_socket('v23', first, 22222) as live:
            denied(client, live, ACTIVE[first])
    grants(ACTIVE, ['tcp', 'udp'])

    def identity():
        return (socket.if_nametoindex(NAME), int(unit('show', 'lanrith-'+NAME, '-p', 'MainPID', '--value')))

    def connections():
        return {line.rsplit(' id=', 1)[1].strip() for family in ('ipv4', 'ipv6')
                for line in command('conntrack', '-L', '-f', family, '-o', 'id').splitlines()
                if 'dport=22222 ' in line and ' id=' in line}

    with ExitStack() as stack:
        flows = []
        for controller, alias in ACTIVE.items():
            for kind in (socket.SOCK_STREAM, socket.SOCK_DGRAM):
                listener = stack.enter_context(bound_socket('v23', controller, 22222, kind))
                if kind == socket.SOCK_STREAM:
                    listener.listen()
                for v, address in PEERS:
                    sender = stack.enter_context(bound_socket('v'+str(v), address, 0, kind))
                    sender.connect((alias, 22222))
                    remote = (embedded(manifest, address), sender.getsockname()[1])
                    peer = listener
                    if kind == socket.SOCK_STREAM:
                        connection, connected = listener.accept()
                        peer = stack.enter_context(connection)
                        peer.settimeout(2)
                        assert connected[:2] == remote
                    flows.append((sender, peer, remote))
        exchange(flows)
        previous, tracked = identity(), connections()
        assert previous[1] > 1 and len(tracked) >= 2*len(flows)
        unit('restart', 'systemd-networkd')
        assert identity() == previous and tracked <= connections()
        exchange(flows)
        runtime.status(manifest)
        print(f'{len(flows)} live TCP/UDP callbacks to eight aliases retained delivery, PID, ifindex and '
              f'{len(tracked)} connection IDs. An absent grant and a retired alias with a grant denied delivery.', flush=True)


def timed(label, action):
    started = time.monotonic()
    action()
    print(f'{label} seconds {time.monotonic()-started:.3f}', flush=True)


def run(root, package):
    manifest = install(root, package, configure=profile, retained=RESERVED)[NAME]
    unit('start', 'systemd-networkd')
    links()
    check_cases(manifest)
    timed('Clean TUN setup', lambda: runtime.configure(manifest, 'start'))
    command('ip', '-6', 'route', 'replace', manifest['prefix'], 'dev', 'trunk.55')
    timed('Cleanup with foreign aggregate', lambda: runtime.configure(manifest, 'stop'))
    runtime.configure(manifest, 'stop')
    assert not runtime.routes(manifest['pool']) and not Path('/sys/class/net', NAME).exists()
    assert runtime.routes(manifest['prefix'])[0]['dev'] == 'trunk.55'
    expect_failure(lambda: runtime.configure(manifest, 'start'), 'Conflicting translation route')
    command('ip', '-6', 'route', 'del', manifest['prefix'], 'dev', 'trunk.55')
    timed('Recovered TUN setup', lambda: runtime.configure(manifest, 'start'))
    runtime.status(manifest)
    # The synthetic routing policy refers to the FRR service account.
    command('systemd-sysusers', '--inline', 'u frr - "Routing" /')
    subprocess.run(['nft', '-c', '-f', '/etc/nftables.conf'], check=True, timeout=30)
    unit('start', 'nftables')
    ref.command('nft', '-f', str(root/'identity-egress.nft'))
    ref.nft('add element inet lanrith tp_started { 0 }')
    unit('start', manifest['unit'])
    readiness(manifest)
    outbound(manifest)
    callbacks(manifest)
    unit('stop', 'nftables')
    for name in (manifest['unit'], 'lanrith-'+NAME+'-network.service'):
        assert unit('show', name, '-p', 'ActiveState', '--value') == 'inactive'
    assert not Path('/sys/class/net', NAME).exists() and all(not runtime.routes(route) for route in manifest['routes'])
    print('Firewall stop withdrew the daemon, setup unit, both aggregates and the TUN.', flush=True)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--tayga-deb', type=Path)
    args = parser.parse_args()
    with tempfile.TemporaryDirectory() as temporary:
        run(Path(temporary)/'lab', args.tayga_deb)
