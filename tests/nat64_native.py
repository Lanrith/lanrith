#!/usr/bin/env python3
"""Real NAT64 daemons, immutable source allocation and hostile tuple tests."""

import copy
import fcntl
import hashlib
import ipaddress as ip
import json
import os
from pathlib import Path
import pwd
import select
import struct
import subprocess
import sys
import tempfile
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from lanrith import config, firewall, nat46, nat64, nat64_allocations, nat64_packets, nat64_runtime, translation, translation_runtime
from lanrith.release import ReleaseError
from packets import RAW, SERVER, ipv6_ready, ns, probe, run
from test_intent import minimal


def declaration():
    value = minimal()
    value['services'] = {'dns': {'enabled': False}, 'ntp': {'enabled': False}, 'dhcp4': {'enabled': False}}
    value['networks']['home'].pop('dhcp4')
    value['networks']['home'].pop('ipv4')
    value['networks']['home']['ipv6'] = {'subnet_id': 16, 'ra': False, 'gua': False}
    value['hardware']['interfaces']['servers'] = {'match': {'mac': '02:00:00:00:03:01'}}
    value['networks']['servers'] = {'interface': 'servers', 'ipv4': '192.0.2.0/24'}
    value['hardware']['interfaces']['guest'] = {'match': {'mac': '02:00:00:00:04:01'}}
    value['networks']['guest'] = {'interface': 'guest', 'ipv6': {'subnet_id': 32, 'ra': False, 'gua': False}}
    # A disconnected fixture uses globally scoped addresses because TAYGA rejects
    # documentation ranges beneath 64:ff9b::/96. It has no external NIC or route.
    value['uplink'] = {'interface': 'wan', 'ipv4': {'address': '93.184.216.1/24', 'gateway': '93.184.216.2'},
                       'ipv6': 'disabled'}
    value['translation'] = {'nat64': {'enabled': True}}
    value['access'] = {'default': 'deny', 'rules': [
        {'action': 'deny', 'from': {'network': 'home', 'addresses': 'fd42:1234:5678:10::90'},
         'to': {'addresses': ['192.0.2.2', '93.184.216.2']}},
        {'action': 'allow', 'from': 'home', 'to': {'translation': 'nat64'},
         'authorization': 'owner', 'protocol': ['tcp', 'udp', 'icmp']}]}
    return value


def udp4(source, destination, sport, dport, token):
    payload = token.encode()
    udp = struct.pack('!HHHH', sport, dport, 8+len(payload), 0)+payload
    header = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20+len(udp), 0, 0, 32, 17, 0,
                         ip.ip_address(source).packed, ip.ip_address(destination).packed)
    total = sum(struct.unpack('!10H', header))
    while total >> 16:
        total = (total & 65535)+(total >> 16)
    return header[:10]+struct.pack('!H', ~total & 65535)+header[12:]+udp


def main():
    assert os.geteuid() == 0 and Path('/dev/net/tun').is_char_device()
    assert {row['ifname'] for row in json.loads(run('ip', '-j', 'link').stdout)} == {'lo'}
    value = declaration()
    combined = '--with-nat46' in sys.argv
    if combined:
        value['networks']['home']['ipv4'] = '192.168.10.0/24'
        value['networks']['guest']['ipv4'] = '172.20.30.0/24'
        value['networks']['servers']['ipv6'] = {'subnet_id': 48, 'ra': False, 'gua': False}
        value['translation']['nat46'] = {'enabled': True, 'mappings': {
            'service-'+str(index): {'ipv4': '10.255.200.'+str(index+2),
                                   'ipv6': 'fd42:1234:5678:30::'+str(index+20)} for index in range(6)}}
        value['access']['rules'].append({'action': 'allow', 'from': 'home',
            'to': {'translation': 'nat46'}, 'authorization': 'owner', 'protocol': ['tcp', 'udp', 'icmp']})
    value = config.normalize(value)
    manifests = nat64.manifests(value)
    other = [m for m in translation.manifests(value) if m['component'] == 'nat46']
    for name, content in {**nat64.render(value), **nat46.render(value)}.items():
        path = Path('/')/name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)
    for index, manifest in enumerate(manifests+other):
        username = 'lanrith-'+manifest['interface']
        try:
            pwd.getpwnam(username)
        except KeyError:
            uid = 61001+index
            assert not any(account.pw_uid == uid for account in pwd.getpwall())
            with Path('/etc/passwd').open('a') as target:
                target.write(f'{username}:x:{uid}:{uid}::/:/usr/sbin/nologin\n')
            with Path('/etc/group').open('a') as target:
                target.write(f'{username}:x:{uid}:\n')
        Path(manifest['state_directory']).mkdir(parents=True, exist_ok=True, mode=0o700)
        if manifest['component'] == 'nat46':
            legacy = Path(manifest['state_directory'])
            (legacy/'legacy-state').write_bytes(b'synthetic retained state\n')
            os.chown(legacy, 65534, 65534)
            legacy.chmod(0)
        # Import an inactive legacy identity as well as allocating active
        # clients. The imported address must never become reusable space.
        if manifest['component'] == 'nat64':
            retained = str(ip.ip_network(manifest['pool']).network_address+77)
            path = Path(manifest['state_directory'])/'dynamic.map'
            path.write_text(f'{retained} fd42:1234:5678:10::60 1234\n')
            path.chmod(0o600)
        Path('/run/lanrith-'+manifest['interface']).mkdir(mode=0o755)
    run('ip', 'link', 'set', 'lo', 'up')
    for name, router, client in (('lan', 'fd42:1234:5678:10::1/64', 'fd42:1234:5678:10::2/64'),
                                 ('guest', 'fd42:1234:5678:20::1/64', 'fd42:1234:5678:20::2/64'),
                                 ('wan', '93.184.216.1/24', '93.184.216.2/24'),
                                 ('servers', '192.0.2.1/24', '192.0.2.2/24')):
        run('ip', 'netns', 'add', name+'-test')
        run('ip', 'link', 'add', name, 'type', 'veth', 'peer', 'name', 'eth0', 'netns', name+'-test')
        run('ip', 'address', 'add', router, 'dev', name, *(['nodad'] if ':' in router else []))
        run('ip', 'link', 'set', name, 'up')
        ns(name+'-test', 'ip', 'address', 'add', client, 'dev', 'eth0', *(['nodad'] if ':' in client else []))
        ns(name+'-test', 'ip', 'link', 'set', 'eth0', 'up')
        ns(name+'-test', 'ip', 'link', 'set', 'lo', 'up')
        ns(name+'-test', 'ip', '-6' if ':' in router else '-4', 'route', 'add', 'default', 'via', router.split('/')[0])
    ns('lan-test', 'ip', 'address', 'add', 'fd42:1234:5678:10::90/64', 'dev', 'eth0', 'nodad', 'preferred_lft', '0')
    if combined:
        for name, router, client in (('lan', '192.168.10.1/24', '192.168.10.2/24'),
                                     ('guest', '172.20.30.1/24', '172.20.30.2/24')):
            run('ip', 'address', 'add', router, 'dev', name)
            ns(name+'-test', 'ip', 'address', 'add', client, 'dev', 'eth0')
            ns(name+'-test', 'ip', 'route', 'add', 'default', 'via', router.split('/')[0])
        run('ip', '-6', 'address', 'add', 'fd42:1234:5678:30::1/64', 'dev', 'servers', 'nodad')
        for entry in other[0]['mappings'].values():
            ns('servers-test', 'ip', '-6', 'address', 'add', entry['ipv6']+'/64', 'dev', 'eth0', 'nodad')
        ns('servers-test', 'ip', '-6', 'route', 'add', 'default', 'via', 'fd42:1234:5678:30::1')
    run('sysctl', '-qw', 'net.ipv4.ip_forward=1', 'net.ipv6.conf.all.forwarding=1',
        'net.ipv4.conf.all.rp_filter=0', 'net.ipv4.conf.default.rp_filter=0')
    processes, streams, checks = [], [], []
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        nft = root/'firewall.nft'

        def load(settings):
            nft.write_text(firewall.render(settings))
            run('nft', '-f', str(nft))

        load(value)
        trace = (root/'trace.log').open('w+')
        tracer = subprocess.Popen(['nft', 'monitor', 'trace'], stdout=trace, stderr=subprocess.STDOUT)
        run('nft', 'insert', 'rule', 'inet', 'lanrith', 'source_guard', 'meta', 'nftrace', 'set', '1')
        for manifest in manifests:
            translation_runtime.configure(manifest, 'start')
            translation_runtime.status(manifest)
            stream = (root/(manifest['interface']+'.log')).open('w+')
            streams.append(stream)
            processes.append(subprocess.Popen(['python3', '-m', 'lanrith.nat64_runtime', manifest['interface']],
                env={**os.environ, 'PYTHONPATH': '/work'}, stdout=stream, stderr=subprocess.STDOUT))
        for manifest in other:
            translation_runtime.configure(manifest, 'start')
            account = pwd.getpwnam('lanrith-nat46')
            stream = (root/'nat46.log').open('w+')
            streams.append(stream)
            processes.append(subprocess.Popen(
                ['/usr/sbin/tayga', '--nodetach', '--config', manifest['config']],
                user=account.pw_uid, group=account.pw_gid, extra_groups=[], stdout=stream, stderr=subprocess.STDOUT))
        for name in ('wan', 'servers'):
            server_code = SERVER.replace("'peer':peer[0]", "'peer':peer[0],'peer_port':peer[1]")
            if name == 'servers' and combined:
                server_code = server_code.replace('for family in (socket.AF_INET,socket.AF_INET6):',
                    'for family,target in [(socket.AF_INET,"0.0.0.0")]+[(socket.AF_INET6,a) for a in sys.argv[2:]]:')
                server_code = server_code.replace("('::' if family==socket.AF_INET6 else '0.0.0.0',port)", '(target,port)')
            processes.append(subprocess.Popen(['nsenter', '--net=/run/netns/'+name+'-test', '--',
                'python3', '-c', server_code, str(root/(name+'.ready')),
                *([entry['ipv6'] for entry in other[0]['mappings'].values()] if combined else [])]))
        try:
            deadline = time.monotonic()+10
            while not all((root/(name+'.ready')).exists() for name in ('wan', 'servers')) and time.monotonic() < deadline:
                time.sleep(.1)
            assert all((root/(name+'.ready')).exists() for name in ('wan', 'servers'))
            ipv6_ready([(namespace, interface) for name in ('lan', 'guest', 'wan', 'servers')
                        for namespace, interface in ((None, name), (name+'-test', 'eth0'))])
            if combined:
                for entry in other[0]['mappings'].values():
                    for protocol in ('tcp', 'udp'):
                        probe('lan-test', entry['ipv4'], 8888, True, protocol, peer='fd42:1234:5678:fd46::c0a8:a02')
                        probe('guest-test', entry['ipv4'], 8888, False, protocol)
                    ns('lan-test', 'ping', '-n', '-4', '-c', '1', '-W', '2', entry['ipv4'])
                probe('lan-test', '10.255.200.99', 8888, False)
                checks.append('all six NAT46 mappings retain TCP UDP echo and denied-client behavior alongside both NAT64 daemons')
            for manifest, address in zip(manifests, ('93.184.216.2', '192.0.2.2')):
                target = str(ip.ip_network(manifest['prefix']).network_address+int(ip.ip_address(address)))
                # Trigger allocation, then wait for a durable map and a child
                # using it. The first unaffiliated packet remains dropped.
                ns('lan-test', 'python3', '-c',
                   'import socket,sys;s=socket.socket(socket.AF_INET6,socket.SOCK_DGRAM);s.sendto(b"warm",(sys.argv[1],8888))',
                   target)
                deadline = time.monotonic()+8
                while time.monotonic() < deadline:
                    assert all(process.poll() is None for process in processes)
                    try:
                        current = nat64_allocations.load(manifest, Path(manifest['state_directory']))
                    except ReleaseError as error:
                        # Atomic replacement unlinks the inspected inode and
                        # changes its ctime. Only this live polling loop retries
                        # the strict reader, within the original deadline.
                        if str(error) != 'Release file changed during inspection.':
                            raise
                        time.sleep(.1)
                        continue
                    if 'fd42:1234:5678:10::2' in current:
                        time.sleep(.3)
                        break
                    time.sleep(.1)
                assert 'fd42:1234:5678:10::2' in current
                peer = '93.184.216.1' if manifest['interface'] == 'nat64' else '192.0.2.1'
                for protocol in ('tcp', 'udp'):
                    probe('lan-test', target, 8888, True, protocol, peer=peer)
                    run('nft', '-j', 'list', 'table', 'inet', 'lanrith')
                    probe('lan-test', target, 8888, False, protocol, source='fd42:1234:5678:10::90')
                    probe('guest-test', target, 8888, False, protocol)
                ns('lan-test', 'ping', '-n', '-6', '-c', '1', '-W', '2', target)
                ns('lan-test', 'python3', '-c', '''
import socket,sys
s=socket.socket(socket.AF_INET6,socket.SOCK_DGRAM);s.settimeout(2)
s.connect((sys.argv[1],9999));s.send(b'closed-port')
try:s.recv(256)
except ConnectionRefusedError:sys.exit(0)
raise AssertionError('Expected a correlated NAT64 port error')
''', target)
            checks.append('public and private NAT64 translate TCP UDP echo and correlated port errors with exact client returns')
            for process in processes[:2]:
                children = Path('/proc', str(process.pid), 'task', str(process.pid), 'children').read_text().split()
                children = [child for child in children if Path('/proc', child, 'exe').exists() and
                            Path('/proc', child, 'exe').resolve().name in ('tayga', 'tayga-internal')]
                assert len(children) == 1
                status = Path('/proc', children[0], 'status').read_text()
                assert next(line.split()[1] for line in status.splitlines() if line.startswith('CapEff:')) == '0000000000000000'
            for manifest in manifests:
                nat64_runtime.status(manifest)
                runtime = Path('/run/lanrith-'+manifest['interface'])
                observation = json.loads((runtime/'status.json').read_bytes())
                self_digest = hashlib.sha256((runtime/'tayga.conf').read_bytes()).hexdigest()
                assert set(observation) == {'pid', 'start_ticks', 'monotonic', 'configuration_sha256'}
                assert observation['configuration_sha256'] == self_digest
                assert 0 <= float(Path('/proc/uptime').read_text().split()[0])-observation['monotonic'] < 4
            checks.append('the allocator owns retained state; both translator children have no effective capabilities and verified readiness')
            before = [nat64_allocations.load(manifest, Path(manifest['state_directory'])) for manifest in manifests]
            for index, manifest in enumerate(manifests):
                assert before[index]['fd42:1234:5678:10::60'] == str(ip.ip_network(manifest['pool']).network_address+77)
                processes[index].terminate()
                processes[index].wait(timeout=5)
                (Path('/run/lanrith-'+manifest['interface'])/'tayga.conf').unlink()
                processes[index] = subprocess.Popen(
                    ['python3', '-m', 'lanrith.nat64_runtime', manifest['interface']],
                    env={**os.environ, 'PYTHONPATH': '/work'}, stdout=streams[index], stderr=subprocess.STDOUT)
            time.sleep(1.5)
            for manifest, address in zip(manifests, ('93.184.216.2', '192.0.2.2')):
                nat64_runtime.status(manifest)
                target = str(ip.ip_network(manifest['prefix']).network_address+int(ip.ip_address(address)))
                probe('lan-test', target, 8888, True, 'udp')
            assert [nat64_allocations.load(m, Path(m['state_directory'])) for m in manifests] == before
            checks.append('allocator and translator restart retain imported inactive and dynamically assigned source identities')
            denied = copy.deepcopy(value)
            denied['access']['rules'] = []
            load(denied)
            time.sleep(1.2)
            for manifest, address in zip(manifests, ('93.184.216.2', '192.0.2.2')):
                target = str(ip.ip_network(manifest['prefix']).network_address+int(ip.ip_address(address)))
                probe('lan-test', target, 8888, False, 'udp')
            if combined:
                probe('lan-test', other[0]['mappings']['service-0']['ipv4'], 8888, False)
            assert [nat64_allocations.load(m, Path(m['state_directory'])) for m in manifests] == before
            checks.append('retained allocations and an enabled translator cannot bypass a policy reload that denies access')
            load(value)
            time.sleep(1.2)
            for manifest, address in zip(manifests, ('93.184.216.2', '192.0.2.2')):
                target = str(ip.ip_network(manifest['prefix']).network_address+int(ip.ip_address(address)))
                probe('lan-test', target, 8888, True, 'udp')
            checks.append('firewall reload restores allocation chains without changing identities or restoring stale tuple proofs')
            if combined:
                for entry in other[0]['mappings'].values():
                    probe('lan-test', entry['ipv4'], 8888, True)
                encoded_alias = str(ip.ip_network(manifests[1]['prefix']).network_address+int(ip.ip_address('10.255.200.2')))
                probe('lan-test', encoded_alias, 8888, False)
                checks.append('independent translation permissions do not authorize chaining translators or unmapped aliases')
            target = str(ip.ip_network(manifests[1]['prefix']).network_address+int(ip.ip_address('192.0.2.2')))
            receiver = subprocess.Popen(['nsenter', '--net=/run/netns/lan-test', '--', 'python3', '-c', '''
import json,pathlib,socket,sys
s=socket.socket(socket.AF_INET6,socket.SOCK_DGRAM);s.settimeout(5)
s.bind(('fd42:1234:5678:10::2',49000));s.connect((sys.argv[1],8888));s.send(b'checksum-probe')
answer=json.loads(s.recv(2048));pathlib.Path(sys.argv[2]).write_text(str(answer['peer_port']))
assert s.recv(2048)==b'zero-checksum-return'
''', target, str(root/'checksum.ready')])
            processes.append(receiver)
            deadline = time.monotonic()+4
            while not (root/'checksum.ready').exists() and time.monotonic() < deadline:
                time.sleep(.1)
            assert (root/'checksum.ready').exists()
            router_mac = json.loads(run('ip', '-j', 'link', 'show', 'servers').stdout)[0]['address']
            peer_mac = json.loads(ns('servers-test', 'ip', '-j', 'link', 'show', 'eth0').stdout)[0]['address']
            ns('servers-test', 'python3', '-c', RAW, '192.0.2.2', '192.0.2.1', router_mac, peer_mac,
               'zero-checksum-return', '8888', (root/'checksum.ready').read_text())
            assert receiver.wait(timeout=5) == 0, 'Private NAT64 lost a zero-checksum UDP return.'
            checks.append('private NAT64 calculates the required IPv6 checksum for an admitted zero-checksum IPv4 UDP return')
            # IPv4 destination intent is evaluated against the original IPv6
            # client, with the exact transport and actual output attachment.
            limited = copy.deepcopy(value)
            limited['access']['rules'] = [
                {'action': 'allow', 'from': {'network': 'home', 'addresses': 'fd42:1234:5678:10::2'},
                 'to': {'network': 'servers', 'addresses': '192.0.2.2'},
                 'protocol': 'tcp', 'ports': [8888], 'authorization': 'owner'},
                {'action': 'deny', 'from': 'home', 'to': 'any'},
                {'action': 'allow', 'from': 'home', 'to': 'any', 'authorization': 'owner'}]
            load(config.normalize(limited))
            time.sleep(1.2)
            internal = manifests[1]
            target = str(ip.ip_network(internal['prefix']).network_address+int(ip.ip_address('192.0.2.2')))
            probe('lan-test', target, 8888, True)
            probe('lan-test', target, 8889, False)
            probe('lan-test', target, 8888, False, 'udp')
            limited['access']['rules'][0]['to']['network'] = 'uplink'
            load(config.normalize(limited))
            time.sleep(1.2)
            probe('lan-test', target, 8888, False)
            checks.append('partial owner rules preserve IPv6 source IPv4 destination port protocol order and actual egress')
            for component, native, network in ((manifests[0], '93.184.216.2', 'uplink'),
                                                (manifests[1], '192.0.2.2', 'servers')):
                encoded = str(ip.ip_network(component['prefix']).network_address+int(ip.ip_address(native)))
                for selected in ({'interface': component['interface'], 'addresses': native},
                                 {'network': network, 'addresses': encoded}):
                    crossed = copy.deepcopy(value)
                    crossed['access'] = {'rules': [{'action': 'allow', 'from': 'home', 'to': selected,
                                                    'protocol': ['tcp', 'udp'], 'authorization': 'owner'}]}
                    load(config.normalize(crossed))
                    time.sleep(1.2)
                    for protocol in ('tcp', 'udp'):
                        probe('lan-test', encoded, 8888, False, protocol)
                    crossed['access']['rules'][0]['action'] = 'deny'
                    crossed['access']['rules'][0].pop('authorization')
                    crossed['access']['rules'].append({'action': 'allow', 'from': 'home',
                        'to': {'network': network, 'addresses': native},
                        'protocol': ['tcp', 'udp'], 'authorization': 'owner'})
                    load(config.normalize(crossed))
                    time.sleep(1.2)
                    for protocol in ('tcp', 'udp'):
                        probe('lan-test', encoded, 8888, True, protocol)
            checks.append('public and private NAT64 keep encoded and IPv4 destinations paired with their own attachment in allows and denies')

            load(value)
            time.sleep(1.2)
            # A translator's own hop-limit error needs the just-admitted tuple.
            ns('lan-test', 'python3', '-c', '''
import socket,sys
s=socket.socket(socket.AF_INET6,socket.SOCK_DGRAM);s.settimeout(2)
s.setsockopt(socket.IPPROTO_IPV6,socket.IPV6_UNICAST_HOPS,2)
s.setsockopt(socket.IPPROTO_IPV6,25,1)
s.connect((sys.argv[1],8888));s.send(b'translator-hop-limit')
try:s.recv(256)
except OSError:
 data,ancillary,flags,address=s.recvmsg(2048,2048,socket.MSG_ERRQUEUE)
 assert ancillary
 sys.exit(0)
raise AssertionError('Expected a correlated translator error')
''', target)
            # An unconfirmed IPv4 flow can be rejected locally for its MTU.
            run('ip', 'link', 'set', 'servers', 'mtu', '1280')
            ns('lan-test', 'python3', '-c', '''
import errno,socket,sys
s=socket.socket(socket.AF_INET6,socket.SOCK_DGRAM);s.settimeout(2)
s.setsockopt(socket.IPPROTO_IPV6,23,2)
s.connect((sys.argv[1],8888));s.send(b'x'*1400)
try:s.recv(256)
except OSError as error:
 assert error.errno==errno.EMSGSIZE,repr(error)
 sys.exit(0)
raise AssertionError('Expected translated path-MTU feedback')
''', target)
            run('ip', 'link', 'set', 'servers', 'mtu', '1500')
            checks.append('translator hop-limit and local IPv4 path-MTU errors return only with a recent exact admitted tuple')
            for process in processes[:2]:
                process.terminate();process.wait(timeout=5)
            current = nat64_allocations.load(internal, Path(internal['state_directory']))
            current = nat64_allocations.allocate(internal, current, ['fd42:1234:5678:10::3'])
            subprocess.run(['nft', '-f', '-'], input=nat64_packets.client_chains(internal, current),
                           text=True, check=True)
            descriptor = os.open('/dev/net/tun', os.O_RDWR | os.O_NONBLOCK)
            flags = int(Path('/sys/class/net/nat64-internal/tun_flags').read_text().strip(), 16)
            fcntl.ioctl(descriptor, 0x400454ca, struct.pack('16sH', b'nat64-internal', flags))
            pi = not bool(flags & 0x1000)
            router = json.loads(run('ip', '-j', 'link', 'show', 'lan').stdout)[0]['address']
            client = json.loads(ns('lan-test', 'ip', '-j', 'link', 'show', 'eth0').stdout)[0]['address']
            ns('lan-test', 'python3', '-c', RAW, 'fd42:1234:5678:10::2', target,
               router, client, 'proof-input', '40000', '8888')
            assert select.select([descriptor], [], [], 2)[0]
            os.read(descriptor, 65536)

            def emit(source, destination, sport, token, allowed):
                packet = udp4(source, destination, sport, 8888, token)
                os.write(descriptor, (struct.pack('!HH', 0, 0x0800) if pi else b'')+packet)
                time.sleep(.2)
                events = (root/'servers.ready.events').read_text()
                assert (token in events) == allowed, ('Unexpected NAT64 TUN permission', token, allowed)

            source = current['fd42:1234:5678:10::2']
            emit(source, '192.0.2.2', 40000, 'exact-nat64-tuple', True)
            assert select.select([descriptor], [], [], 1)[0]
            os.read(descriptor, 65536)
            emit(current['fd42:1234:5678:10::3'], '192.0.2.2', 40000, 'wrong-client', False)
            emit(source, '192.0.2.2', 40001, 'wrong-port', False)
            time.sleep(2.1)
            emit(source, '192.0.2.2', 40000, 'stale-tuple', False)
            wrong_router = json.loads(run('ip', '-j', 'link', 'show', 'guest').stdout)[0]['address']
            wrong_client = json.loads(ns('guest-test', 'ip', '-j', 'link', 'show', 'eth0').stdout)[0]['address']
            ns('guest-test', 'python3', '-c', RAW, 'fd42:1234:5678:10::2', target,
               wrong_router, wrong_client, 'wrong-native-interface', '40000', '8888')
            ns('guest-test', 'python3', '-c', RAW, source, '192.0.2.2',
               wrong_router, wrong_client, 'wrong-translated-interface', '40000', '8888')
            assert not select.select([descriptor], [], [], .3)[0]
            os.close(descriptor)
            checks.append('wrong mapped clients ports stale tuples and native or translated source spoofing gain no access')
        except BaseException:
            for stream in streams:
                stream.flush();stream.seek(0);print(stream.read(), file=sys.stderr)
            trace.flush();trace.seek(0);print(trace.read()[-25000:], file=sys.stderr)
            raise
        finally:
            tracer.terminate();tracer.wait(timeout=3);trace.close()
            for process in processes:
                if process.poll() is None:
                    process.terminate()
            for process in processes:
                process.wait(timeout=5)
            for stream in streams:
                stream.close()
            for manifest in manifests+other:
                translation_runtime.configure(manifest, 'stop')
    if other:
        assert (legacy/'legacy-state').read_bytes() == b'synthetic retained state\n' and legacy.stat().st_uid == 65534 and \
            legacy.stat().st_mode & 0o777 == 0, 'Static translation changed legacy state or custody.'
        checks.append('static NAT46 runs alongside NAT64 without reading or changing legacy state')
    print(json.dumps({'result': 'pass', 'private_image_qualified': False, 'checks': checks}), flush=True)


if __name__ == '__main__':
    main()
