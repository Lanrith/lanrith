#!/usr/bin/env python3
"""Real TAYGA translation in a disposable offline VM, including hostile TUN output."""

import fcntl
import copy
import ipaddress as ip
import json
import os
from pathlib import Path
import pwd
import select
import socket
import struct
import subprocess
import sys
import tempfile
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from lanrith import config, firewall, service_runtime, translation_runtime
from test_nat46 import declaration
from packets import CLIENT, RAW, SERVER, ipv6_ready, ns, probe, run


def udp6(source, destination, sport, dport, marker):
    source, destination = ip.ip_address(source), ip.ip_address(destination)
    payload = marker.encode()
    packet = struct.pack('!HHHH', sport, dport, len(payload)+8, 0)+payload
    data = source.packed+destination.packed+struct.pack('!I3xB', len(packet), 17)+packet
    if len(data) % 2:
        data += b'\0'
    total = sum(struct.unpack('!%dH' % (len(data)//2), data))
    while total >> 16:
        total = (total & 65535)+(total >> 16)
    packet = packet[:6]+struct.pack('!H', ~total & 65535 or 65535)+packet[8:]
    return struct.pack('!IHBB16s16s', 6 << 28, len(packet), 17, 32, source.packed, destination.packed)+packet


def main():
    assert os.geteuid() == 0
    assert {row['ifname'] for row in json.loads(run('ip', '-j', 'link').stdout)} == {'lo'}
    assert Path('/dev/net/tun').is_char_device(), 'Use the offline VM fixture when rootless containers lack TUN.'
    value = declaration()
    value['services'] = {'dns': {'enabled': False}, 'ntp': {'enabled': False}, 'dhcp4': {'enabled': False}}
    value['networks']['home'].pop('dhcp4')
    value['uplink'] = {'interface': 'wan', 'ipv4': 'disabled', 'ipv6': 'disabled'}
    value['hardware']['interfaces']['guest'] = {'match': {'mac': '02:00:00:00:04:01'}}
    value['networks']['guest'] = {'interface': 'guest', 'ipv4': '192.168.20.0/24'}
    value = config.normalize(value)
    files = config.render(value)
    manifest = json.loads(files['usr/share/lanrith/nat46.json'])
    Path(manifest['config']).write_text(files['etc/tayga-nat46.conf'])
    try:
        account = pwd.getpwnam('lanrith-nat46')
    except KeyError:
        assert not any(account.pw_uid == 61000 for account in pwd.getpwall())
        with Path('/etc/passwd').open('a') as target:
            target.write('lanrith-nat46:x:61000:61000::/var/lib/tayga-nat46:/usr/sbin/nologin\n')
        with Path('/etc/group').open('a') as target:
            target.write('lanrith-nat46:x:61000:\n')
        account = pwd.getpwnam('lanrith-nat46')
    Path(manifest['state_directory']).mkdir(parents=True, exist_ok=True)
    legacy = Path(manifest['state_directory'])
    marker = legacy/'legacy-state'
    marker.write_bytes(b'synthetic retained state\n')
    os.chown(legacy, 65534, 65534)
    legacy.chmod(0)
    run('ip', 'link', 'set', 'lo', 'up')
    for name, router, client in (('lan', '192.168.10.1/24', '192.168.10.2/24'),
                                 ('guest', '192.168.20.1/24', '192.168.20.2/24'),
                                 ('servers', 'fd42:1234:5678:20::1/64', 'fd42:1234:5678:20::10/64')):
        run('ip', 'netns', 'add', name+'-test')
        run('ip', 'link', 'add', name, 'type', 'veth', 'peer', 'name', 'eth0', 'netns', name+'-test')
        run('ip', 'address', 'add', router, 'dev', name, *(['nodad'] if ':' in router else []))
        run('ip', 'link', 'set', name, 'up')
        ns(name+'-test', 'ip', 'address', 'add', client, 'dev', 'eth0', *(['nodad'] if ':' in client else []))
        ns(name+'-test', 'ip', 'link', 'set', 'eth0', 'up')
        ns(name+'-test', 'ip', 'link', 'set', 'lo', 'up')
        ns(name+'-test', 'ip', '-6' if ':' in router else '-4', 'route', 'add', 'default', 'via', router.split('/')[0])
    mappings = list(manifest['mappings'].values())
    for entry in mappings[1:]:
        ns('servers-test', 'ip', 'address', 'add', entry['ipv6']+'/64', 'dev', 'eth0', 'nodad')
    ipv6_ready([(None, 'servers'), ('servers-test', 'eth0')])
    ns('lan-test', 'ip', 'address', 'add', '192.168.10.90/24', 'dev', 'eth0')
    run('sysctl', '-qw', 'net.ipv4.ip_forward=1', 'net.ipv6.conf.all.forwarding=1',
        'net.ipv4.conf.all.rp_filter=0', 'net.ipv4.conf.default.rp_filter=0')
    checks = []
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        nft = root/'firewall.nft'
        nft.write_text(firewall.render(value))
        run('nft', '--check', '-f', str(nft))
        run('nft', '-f', str(nft))
        translation_runtime.configure(manifest, 'start')
        translation_runtime.configure(manifest, 'start')
        translation_runtime.status(manifest)
        assert Path('/proc/sys/net/ipv4/conf/lan/accept_local').read_text().strip() == '0'
        # A root-owned fixture starts the same daemon with its generated account.
        # All capabilities are removed by setuid, as in the generated service.
        def unprivileged():
            os.setgroups([])
            os.setgid(account.pw_gid)
            os.setuid(account.pw_uid)
        daemon = subprocess.Popen(['tayga', '-d', '--config', manifest['config']],
                                  preexec_fn=unprivileged, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        # A UDP wildcard socket could choose a different service's source
        # address. Bind every map explicitly so replies retain their identity.
        server_code = SERVER.replace('for family in (socket.AF_INET,socket.AF_INET6):',
            'for family,target in [(socket.AF_INET6,address) for address in sys.argv[2:]]:')
        server_code = server_code.replace("('::' if family==socket.AF_INET6 else '0.0.0.0',port)", '(target,port)')
        server = subprocess.Popen(['nsenter', '--net=/run/netns/servers-test', '--',
                                   'python3', '-c', server_code, str(root/'ready'),
                                   *[entry['ipv6'] for entry in mappings]], stderr=subprocess.PIPE)
        trace_log = (root/'trace.log').open('w+')
        tracer = subprocess.Popen(['nft', 'monitor', 'trace'], stdout=trace_log, stderr=subprocess.PIPE)
        try:
            deadline = time.monotonic()+10
            while not (root/'ready').exists() and time.monotonic() < deadline:
                time.sleep(.1)
            assert (root/'ready').exists(), 'Fixture server failed to start'
            assert daemon.poll() is None, daemon.communicate()[0].decode()
            status = Path('/proc', str(daemon.pid), 'status').read_text()
            assert next(line.split()[1] for line in status.splitlines() if line.startswith('CapEff:')) == '0000000000000000'
            denied = copy.deepcopy(value)
            denied['access']['rules'] = []
            nft.write_text(config.render(denied)['etc/nftables.conf'])
            run('nft', '-f', str(nft))
            probe('lan-test', mappings[0]['ipv4'], 8888, False)
            nft.write_text(files['etc/nftables.conf'])
            run('nft', '-f', str(nft))
            checks.append('enabling NAT46 and its routes grants no access; daemon runs without capabilities')
            run('nft', 'insert', 'rule', 'inet', 'lanrith', 'source_guard',
                'meta', 'l4proto', 'udp', 'meta', 'nftrace', 'set', '1')
            for chain in ('source_guard', 'output'):
                run('nft', 'insert', 'rule', 'inet', 'lanrith', chain,
                    'meta l4proto { icmp, ipv6-icmp } meta nftrace set 1')
            embedded = str(ip.ip_network(manifest['prefix']).network_address+int(ip.ip_address('192.168.10.2')))
            for entry in mappings:
                for protocol in ('tcp', 'udp'):
                    probe('lan-test', entry['ipv4'], 8888, True, protocol, peer=embedded)
                    probe('lan-test', entry['ipv4'], 8888, False, protocol, source='192.168.10.90')
                    probe('guest-test', entry['ipv4'], 8888, False, protocol)
                ns('lan-test', 'ping', '-n', '-c', '1', '-W', '2', entry['ipv4'])
                ns('lan-test', 'python3', '-c', '''
import socket,sys
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.settimeout(2)
s.connect((sys.argv[1],9999));s.send(b'closed-port')
try:s.recv(256)
except ConnectionRefusedError:sys.exit(0)
raise AssertionError('Expected a correlated port-unreachable error')
''', entry['ipv4'])
            probe('lan-test', '10.255.200.100', 8888, False, 'udp')
            checks.append('all six mappings translate TCP UDP and ICMP with returns; denied and unmapped clients fail')
            run('ip', 'link', 'set', 'servers', 'mtu', '1280')
            ns('lan-test', 'python3', '-c', '''
import errno,socket,struct,sys
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.settimeout(2)
s.setsockopt(socket.IPPROTO_IP,10,2) # IP_MTU_DISCOVER=IP_PMTUDISC_DO
s.connect((sys.argv[1],8888));s.send(b'x'*1400)
try:s.recv(4096)
except OSError as e:
 assert e.errno==errno.EMSGSIZE,e
 assert s.getsockopt(socket.IPPROTO_IP,14)<=1260
 sys.exit(0)
raise AssertionError('Expected a translated packet-too-big error')
''', mappings[0]['ipv4'])
            run('ip', 'link', 'set', 'servers', 'mtu', '1500')
            ns('lan-test', 'python3', '-c', '''
import socket,struct,sys
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.settimeout(2)
s.setsockopt(socket.IPPROTO_IP,socket.IP_TTL,2)
s.setsockopt(socket.IPPROTO_IP,11,1) # IP_RECVERR
s.connect((sys.argv[1],8888));s.send(b'translator-hop-limit')
try:s.recv(4096)
except OSError:
 _,anc,_,_=s.recvmsg(4096,4096,socket.MSG_ERRQUEUE)
 assert any(level==socket.IPPROTO_IP and kind==11 and data[5]==11 for level,kind,data in anc),anc
 sys.exit(0)
raise AssertionError('Expected the translator time-exceeded error')
''', mappings[0]['ipv4'])
            checks.append('correlated port errors path-MTU feedback and translator hop-limit errors return to the initiating client')
            isolated = copy.deepcopy(value)
            isolated['services']['dns']['enabled'] = True
            isolated['access']['rules'] = [{'action': 'allow', 'from': 'any',
                'to': {'translation': 'nat46'}, 'protocol': 'udp', 'ports': [53], 'authorization': 'owner'}]
            isolated_files = config.render(isolated)
            plane = json.loads(isolated_files['usr/share/lanrith/service-plane.json'])
            Path('/etc/lanrith').mkdir(exist_ok=True)
            Path('/etc/lanrith/services.nft').write_text(isolated_files['etc/lanrith/services.nft'])
            nft.write_text(isolated_files['etc/nftables.conf'])
            run('nft', '-f', str(nft))
            service_runtime.start(plane)
            try:
                probe('lan-test', mappings[0]['ipv4'], 53, True, 'udp')
                probe(plane['namespace'], mappings[0]['ipv4'], 53, False, 'udp',
                      user='unbound', source=plane['endpoints']['dns'][0])
            finally:
                service_runtime.stop(plane)
            checks.append('a wildcard owner permission cannot bypass the managed service namespace boundary')
            # The rule is written for the IPv6 destination, yet retains the exact
            # IPv4 source and port after projection to the alias.
            limited = dict(value)
            limited['access'] = {'rules': [{'action': 'allow', 'from': {'network': 'home', 'addresses': '192.168.10.2'},
                'to': {'network': 'servers', 'addresses': mappings[0]['ipv6']},
                'protocol': 'tcp', 'ports': [8888], 'authorization': 'owner'}]}
            limited = config.normalize(limited)
            nft.write_text(firewall.render(limited))
            run('nft', '-f', str(nft))
            probe('lan-test', mappings[0]['ipv4'], 8888, True)
            probe('lan-test', mappings[0]['ipv4'], 8889, False)
            probe('lan-test', mappings[0]['ipv4'], 8888, False, 'udp')
            probe('lan-test', mappings[1]['ipv4'], 8888, False)
            checks.append('partial owner rule keeps source attachment address destination port and protocol')
            # Neither translated representation may borrow an attachment from
            # the other. An inert unmapped IPv4 alternative keeps the first
            # selector meaningful to the ordinary IPv4 compiler too.
            for selected in (
                    {'interface': 'nat46', 'addresses': [str(ip.ip_network(mappings[0]['ipv6']+'/64', strict=False)), '10.255.200.100']},
                    {'network': 'servers', 'addresses': '10.255.200.0/24'}):
                crossed = copy.deepcopy(value)
                crossed['access'] = {'rules': [{'action': 'allow', 'from': 'home', 'to': selected,
                                                'protocol': ['tcp', 'udp'], 'authorization': 'owner'}]}
                nft.write_text(config.render(crossed)['etc/nftables.conf'])
                run('nft', '-f', str(nft))
                for entry in mappings:
                    for protocol in ('tcp', 'udp'):
                        probe('lan-test', entry['ipv4'], 8888, False, protocol)
                crossed['access']['rules'][0]['action'] = 'deny'
                crossed['access']['rules'][0].pop('authorization')
                crossed['access']['rules'].append({'action': 'allow', 'from': 'home',
                    'to': {'translation': 'nat46'}, 'protocol': ['tcp', 'udp'], 'authorization': 'owner'})
                nft.write_text(config.render(crossed)['etc/nftables.conf'])
                run('nft', '-f', str(nft))
                for entry in mappings:
                    for protocol in ('tcp', 'udp'):
                        probe('lan-test', entry['ipv4'], 8888, True, protocol)
            checks.append('all six aliases keep native and translator addresses paired with their own attachment in allows and denies')

            nft.write_text(firewall.render(value))
            run('nft', '-f', str(nft))
            daemon.terminate()
            daemon.communicate(timeout=5)
            # Root-only fault injection stands in for hostile output from the
            # translator. It must not acquire permission from conntrack alone.
            descriptor = os.open('/dev/net/tun', os.O_RDWR | os.O_NONBLOCK)
            flags = int(Path('/sys/class/net/nat46/tun_flags').read_text().strip(), 16)
            fcntl.ioctl(descriptor, 0x400454ca, struct.pack('16sH', b'nat46', flags))
            pi = not bool(flags & 0x1000)
            def emit(source, target, sport, token, allowed):
                packet = udp6(source, target, sport, 8888, token)
                os.write(descriptor, (struct.pack('!HH', 0, 0x86dd) if pi else b'')+packet)
                time.sleep(.3)
                log = Path(str(root/'ready')+'.events').read_text()
                assert (token in log) == allowed, ('Unexpected TUN admission', token, allowed)
            router = json.loads(run('ip', '-j', 'link', 'show', 'lan').stdout)[0]['address']
            client = json.loads(ns('lan-test', 'ip', '-j', 'link', 'show', 'eth0').stdout)[0]['address']
            ns('lan-test', 'python3', '-c', RAW, '192.168.10.2', mappings[0]['ipv4'],
               router, client, 'proof-input', '40000', '8888')
            assert select.select([descriptor], [], [], 2)[0], 'Original admitted packet did not reach TUN'
            os.read(descriptor, 65536)
            emit(embedded, mappings[0]['ipv6'], 40000, 'proved-tuple', True)
            assert select.select([descriptor], [], [], 1)[0]
            os.read(descriptor, 65536)
            server_router = json.loads(run('ip', '-j', 'link', 'show', 'servers').stdout)[0]['address']
            server_client = json.loads(ns('servers-test', 'ip', '-j', 'link', 'show', 'eth0').stdout)[0]['address']
            ns('servers-test', 'python3', '-c', RAW, mappings[1]['ipv6'], embedded,
               server_router, server_client, 'wrong-reply-identity', '8888', '40000')
            assert not select.select([descriptor], [], [], .3)[0], 'A different map acquired a return path'
            other = str(ip.ip_address(embedded)+1)
            emit(other, mappings[0]['ipv6'], 40000, 'wrong-source', False)
            emit(embedded, mappings[1]['ipv6'], 40000, 'wrong-map', False)
            emit(embedded, mappings[0]['ipv6'], 40001, 'wrong-port', False)
            time.sleep(2.1)
            emit(embedded, mappings[0]['ipv6'], 40000, 'expired-tuple', False)
            os.close(descriptor)
            checks.append('TUN output requires recent exact client mapping and transport tuple; stale tuples fail')
            # A LAN cannot impersonate either a translated source or a different
            # network, even while a matching conntrack tuple exists.
            wrong_router = json.loads(run('ip', '-j', 'link', 'show', 'guest').stdout)[0]['address']
            wrong_client = json.loads(ns('guest-test', 'ip', '-j', 'link', 'show', 'eth0').stdout)[0]['address']
            ns('guest-test', 'python3', '-c', RAW, embedded, mappings[0]['ipv6'],
               wrong_router, wrong_client, 'spoof-translated', '40000', '8888')
            ns('guest-test', 'python3', '-c', RAW, '192.168.10.2', mappings[0]['ipv4'],
               wrong_router, wrong_client, 'spoof-native', '40000', '8888')
            time.sleep(.3)
            log = Path(str(root/'ready')+'.events').read_text()
            assert 'spoof-translated' not in log and 'spoof-native' not in log
            checks.append('native and translated source identities cannot move to the wrong interface')
        except BaseException:
            for name in ('n46_0_udp_forward', 'n46_0_udp_reply'):
                print(run('nft', 'list', 'set', 'inet', 'lanrith', name).stdout, flush=True)
            events = Path(str(root/'ready')+'.events')
            print(events.read_text() if events.exists() else 'No server datagrams', flush=True)
            tracer.terminate()
            tracer.communicate(timeout=5)
            trace_log.seek(0)
            print(trace_log.read()[-24000:], flush=True)
            raise
        finally:
            for process in (daemon, server, tracer):
                if process.poll() is None:
                    process.terminate()
                    output = process.communicate(timeout=5)
                    if process is daemon:
                        print(output[0].decode()[-2000:], flush=True)
            trace_log.close()
            translation_runtime.configure(manifest, 'stop')
            assert not any(row['ifname'] == 'nat46' for row in json.loads(run('ip', '-j', 'link').stdout))
            for prefix in manifest['routes']:
                assert not json.loads(run('ip', '-'+str(ip.ip_network(prefix).version), '-j', 'route',
                                          'show', 'exact', prefix).stdout)
            checks.append('stopping NAT46 removes its interface and both translation routes')
    assert marker.read_bytes() == b'synthetic retained state\n' and legacy.stat().st_uid == 65534 and \
        legacy.stat().st_mode & 0o777 == 0, 'Static translation changed legacy state or custody.'
    checks.append('static NAT46 runs without access to legacy state and preserves its bytes and custody')
    print(json.dumps({'result': 'pass', 'checks': checks, 'private_image_qualified': False}))


if __name__ == '__main__':
    main()
