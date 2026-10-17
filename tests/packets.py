#!/usr/bin/env python3
"""Exercise generated policy with real packets in private network namespaces."""

import argparse
import ipaddress
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from lanrith import config

SERVER = '''
import json,selectors,socket,sys
selector=selectors.DefaultSelector()
for family in (socket.AF_INET,socket.AF_INET6):
    for protocol in (socket.SOCK_STREAM,socket.SOCK_DGRAM):
        for port in (22,23,53,123,161,5353,8888,8889,12345):
            stream=socket.socket(family,protocol)
            stream.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
            if family==socket.AF_INET6:stream.setsockopt(socket.IPPROTO_IPV6,socket.IPV6_V6ONLY,1)
            stream.bind(('::' if family==socket.AF_INET6 else '0.0.0.0',port))
            if protocol==socket.SOCK_STREAM:stream.listen(32)
            stream.setblocking(False)
            selector.register(stream,selectors.EVENT_READ,protocol)
open(sys.argv[1],'x').close()
while True:
    for key,_ in selector.select():
        if key.data==socket.SOCK_STREAM:
            connection,peer=key.fileobj.accept()
            with connection:connection.sendall(json.dumps({'peer':peer[0]}).encode())
        else:
            data,peer=key.fileobj.recvfrom(4096)
            with open(sys.argv[1]+'.events','a') as events:
                events.write(json.dumps({'peer':peer[0],'data':data.decode()})+'\\n')
            key.fileobj.sendto(json.dumps({'peer':peer[0],'data':data.decode()}).encode(),peer)
'''

CLIENT = '''
import json,socket,sys
address,port,protocol=sys.argv[1:]
family=socket.AF_INET6 if ':' in address else socket.AF_INET
with socket.socket(family,socket.SOCK_STREAM if protocol=='tcp' else socket.SOCK_DGRAM) as stream:
    stream.settimeout(0.6)
    try:
        stream.connect((address,int(port)))
        if protocol=='udp':stream.send(b'lanrith-packet-test')
        result=json.loads(stream.recv(4096))
        print(json.dumps(result))
    except (TimeoutError,ConnectionError,OSError):sys.exit(10)
'''


def run(*arguments, **kwargs):
    result = subprocess.run(arguments, check=False, stdin=subprocess.DEVNULL, capture_output=True, text=True,
                            timeout=kwargs.pop('timeout', 20), **kwargs)
    if result.returncode:
        raise RuntimeError(Path(arguments[0]).name+' failed: '+result.stderr[-1024:])
    return result


def ns(name, *arguments):
    return run('nsenter', '--net=/run/netns/'+name, '--', *arguments)


def probe(namespace, address, port, allowed, protocol='tcp', peer=None):
    result = subprocess.run(['nsenter', '--net=/run/netns/'+namespace, '--', sys.executable, '-c', CLIENT,
                             address, str(port), protocol], capture_output=True, text=True, timeout=5)
    if result.returncode not in (0, 10) or (result.returncode == 0) != allowed:
        raise AssertionError(f'{namespace} to {address}:{port}/{protocol}: expected allowed={allowed}; '
                             f'exit={result.returncode}; diagnostic={result.stderr[-1024:]}')
    if peer is not None and json.loads(result.stdout)['peer'] != peer:
        raise AssertionError('NAT or source-address preservation differs from the compiled policy.')


def connection(router_name, client_name, addresses, number):
    run('ip', 'netns', 'add', client_name)
    run('ip', 'link', 'add', router_name, 'type', 'veth', 'peer', 'name', 'peer'+str(number))
    run('ip', 'link', 'set', router_name, 'netns', 'router')
    run('ip', 'link', 'set', 'peer'+str(number), 'netns', client_name)
    ns(client_name, 'ip', 'link', 'set', 'peer'+str(number), 'name', 'eth0')
    for namespace, interface in (('router', router_name), (client_name, 'eth0')):
        ns(namespace, 'ip', 'link', 'set', 'lo', 'up')
        ns(namespace, 'ip', 'link', 'set', interface, 'up')
    peers = []
    for address in addresses:
        gateway = ipaddress.ip_interface(address)
        client = ipaddress.ip_address(int(gateway.network.network_address)+2)
        if client == gateway.ip:
            client += 1
        flags = ['nodad'] if gateway.version == 6 else []
        ns('router', 'ip', 'address', 'add', address, 'dev', router_name, *flags)
        ns(client_name, 'ip', 'address', 'add', str(client)+'/'+str(gateway.network.prefixlen), 'dev', 'eth0', *flags)
        ns(client_name, 'ip', '-'+str(gateway.version), 'route', 'add', 'default', 'via', str(gateway.ip))
        peers.append((str(gateway.ip), str(client), gateway.version))
    return peers


def server(namespace, path):
    ready = path/(namespace+'.ready')
    process = subprocess.Popen(['nsenter', '--net=/run/netns/'+namespace, '--', sys.executable, '-c', SERVER, str(ready)],
                               stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
    deadline = time.monotonic()+5
    while not ready.exists():
        if process.poll() is not None or time.monotonic() > deadline:
            process.terminate()
            raise AssertionError('Synthetic listener could not start: '+process.communicate(timeout=5)[1][-1024:])
        time.sleep(0.02)
    return process


def exercise(example):
    value = config.load(Path(__file__).resolve().parents[1]/'examples'/example)
    with tempfile.TemporaryDirectory(prefix='lanrith-packets.') as temporary:
        work = Path(temporary)
        run('ip', 'netns', 'add', 'router')
        processes, namespaces = [], ['router', 'upstream']
        try:
            ns('router', 'sysctl', '-qw', 'net.ipv4.ip_forward=1', 'net.ipv6.conf.all.forwarding=1')
            wan = value['hardware']['interfaces'][value['uplink']['interface']]['name']
            uplink = connection(wan, 'upstream', ['198.51.100.1/24', '2001:db8:ffff::1/64'], 0)
            for gateway, remote, family in uplink:
                ns('router', 'ip', '-'+str(family), 'route', 'add', 'default', 'via', remote)
            clients = []
            for index, (key, network) in enumerate(value['networks'].items(), 1):
                namespace = 'client'+str(index)
                namespaces.append(namespace)
                clients.append((namespace, key, connection(network['name'], namespace, network['addresses'], index)))
            rules = work/'policy.nft'
            rules.write_text(config.render(value)['etc/nftables.conf'])
            ns('router', 'nft', '--file', str(rules))
            for namespace in namespaces:
                processes.append(server(namespace, work))
            for namespace, key, addresses in clients:
                for gateway, address, family in addresses:
                    probe(namespace, gateway, value['administration'].get('ssh_port', 22),
                          key in value['administration']['networks'])
                    probe(namespace, gateway, 23, False)
                    probe(namespace, gateway, 53, bool(value['networks'][key].get('dns')), 'udp')
                    for port in (123, 161, 5353, 12345):
                        probe(namespace, gateway, port, False, 'udp')
                    remote = next(peer for _, peer, version in uplink if version == family)
                    translated = '198.51.100.1' if family == 4 else address
                    probe(namespace, remote, 8888, key in value['access']['internet'],
                          peer=translated if key in value['access']['internet'] else None)
                    probe(namespace, remote, 8888, key in value['access']['internet'], 'udp',
                          peer=translated if key in value['access']['internet'] else None)
                    # Observe the upstream receiver, so asymmetric replies cannot
                    # make an admitted spoof look like a correctly rejected packet.
                    spoof = '203.0.113.99' if family == 4 else '2001:db8:dead::99'
                    ns(namespace, 'ip', 'address', 'add', spoof+('/32' if family == 4 else '/128'),
                       'dev', 'eth0', *(['nodad'] if family == 6 else []))
                    token = 'spoof-'+namespace+'-'+str(family)
                    ns(namespace, sys.executable, '-c',
                       'import socket,sys; s=socket.socket(socket.AF_INET6 if ":" in sys.argv[1] else '
                       'socket.AF_INET,socket.SOCK_DGRAM); s.bind((sys.argv[1],0)); '
                       's.sendto(sys.argv[3].encode(),(sys.argv[2],8888))', spoof, remote, token)
                    time.sleep(0.05)
                    events = (work/'upstream.ready.events').read_text()
                    if token in events:
                        raise AssertionError('A source outside the declared network reached the uplink.')
            for gateway, remote, family in uplink:
                probe('upstream', gateway, 22, False)
                for _, _, addresses in clients:
                    for _, address, version in addresses:
                        if family == version:
                            probe('upstream', address, 8888, False)
            if len(clients) >= 2:
                first, second = clients[:2]
                for left, right in ((first, second), (second, first)):
                    for _, address, _ in right[2]:
                        probe(left[0], address, 8888, False)
                value['access']['between_networks'] = [
                    {'from': first[1], 'to': second[1], 'protocol': 'tcp', 'ports': [8888]}]
                rules.write_text(config.render(value)['etc/nftables.conf'])
                ns('router', 'nft', '--file', str(rules))
                for _, address, family in second[2]:
                    probe(first[0], address, 8888, True,
                          peer=next(peer for _, peer, version in first[2] if version == family))
                    probe(first[0], address, 8889, False)
                for _, address, _ in first[2]:
                    probe(second[0], address, 8888, False)
        finally:
            for process in processes:
                process.terminate()
                try:
                    process.communicate(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.communicate(timeout=5)
            for namespace in reversed(namespaces):
                subprocess.run(['ip', 'netns', 'delete', namespace], capture_output=True)
    print(example+': management, isolation, explicit directional permits, disabled services, NAT44 and IPv6 source checks passed.')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--isolated', action='store_true')
    args = parser.parse_args()
    if not args.isolated:
        if os.geteuid() != 0:
            raise SystemExit('Packet checks require an isolated root namespace.')
        run('unshare', '--mount', '--net', '--fork', '--propagation', 'private', '--',
            sys.executable, str(Path(__file__).resolve()), '--isolated', timeout=180)
        print('Both synthetic topologies passed native IPv4 and IPv6 packet checks.')
        return
    Path('/run/netns').mkdir(parents=True, exist_ok=True)
    run('mount', '-t', 'tmpfs', '-o', 'mode=0700', 'tmpfs', '/run/netns')
    for example in ('minimal.yaml', 'segmented.yaml'):
        exercise(example)


if __name__ == '__main__':
    main()
