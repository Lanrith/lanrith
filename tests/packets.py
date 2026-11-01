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
from lanrith import config, extension_network, firewall, service_plane

SERVER = '''
import json,selectors,socket,sys
selector=selectors.DefaultSelector()
for family in (socket.AF_INET,socket.AF_INET6):
    for protocol in (socket.SOCK_STREAM,socket.SOCK_DGRAM):
        for port in (22,23,53,67,123,161,5353,8888,8889,9100,12345):
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
address,port,protocol=sys.argv[1:4]
family=socket.AF_INET6 if ':' in address else socket.AF_INET
with socket.socket(family,socket.SOCK_STREAM if protocol=='tcp' else socket.SOCK_DGRAM) as stream:
    stream.settimeout(0.6)
    try:
        if len(sys.argv)>4:stream.bind((sys.argv[4],0))
        stream.connect((address,int(port)))
        if protocol=='udp':stream.send(b'lanrith-packet-test')
        result=json.loads(stream.recv(4096))
        print(json.dumps(result))
    except (TimeoutError,ConnectionError,OSError):sys.exit(10)
'''

RAW = '''
import ipaddress,socket,struct,sys
source,destination,router_mac,client_mac,token,sport,dport=sys.argv[1:]
source,destination=ipaddress.ip_address(source),ipaddress.ip_address(destination)
def checksum(value):
    if len(value)%2:value+=b'\\0'
    total=sum(struct.unpack('!%dH'%(len(value)//2),value))
    while total>>16:total=(total&65535)+(total>>16)
    return (~total)&65535
payload=token.encode()
udp=struct.pack('!HHHH',int(sport),int(dport),8+len(payload),0)+payload
if source.version==4:
    header=struct.pack('!BBHHHBBH4s4s',0x45,0,20+len(udp),0,0,32,17,0,source.packed,destination.packed)
    header=header[:10]+struct.pack('!H',checksum(header))+header[12:]
    kind=0x0800
else:
    pseudo=source.packed+destination.packed+struct.pack('!I3xB',len(udp),17)
    udp=udp[:6]+struct.pack('!H',checksum(pseudo+udp) or 65535)+udp[8:]
    header=struct.pack('!IHBB16s16s',6<<28,len(udp),17,32,source.packed,destination.packed)
    kind=0x86dd
ethernet=bytes.fromhex(router_mac.replace(':',''))+bytes.fromhex(client_mac.replace(':',''))+struct.pack('!H',kind)
with socket.socket(socket.AF_PACKET,socket.SOCK_RAW) as stream:
    stream.bind(('eth0',0));stream.send(ethernet+header+udp)
'''


def run(*arguments, **kwargs):
    result = subprocess.run(arguments, check=False, stdin=subprocess.DEVNULL, capture_output=True, text=True,
                            timeout=kwargs.pop('timeout', 20), **kwargs)
    if result.returncode:
        raise RuntimeError(Path(arguments[0]).name+' failed: '+result.stderr[-1024:])
    return result


def ns(name, *arguments):
    return run('nsenter', '--net=/run/netns/'+name, '--', *arguments)


def ipv6_ready(attachments, seconds=5):
    """Wait for kernel DAD before starting a fixture's packet deadlines."""
    deadline = time.monotonic()+seconds
    while True:
        states = []
        for namespace, interface in attachments:
            command = ('ip', '-6', '-j', 'address', 'show', 'dev', interface)
            rows = json.loads((run(*command) if namespace is None else ns(namespace, *command)).stdout)
            states.extend(item for row in rows for item in row.get('addr_info', []))
        assert not any(item.get('dadfailed') for item in states), 'Fixture IPv6 address DAD failed.'
        if not any(item.get('tentative') for item in states):
            return
        assert time.monotonic() < deadline, 'Fixture IPv6 address readiness expired.'
        time.sleep(.05)


def probe(namespace, address, port, allowed, protocol='tcp', peer=None, user=None, source=None):
    client = CLIENT
    if user is not None:
        # Synthetic package-account check; never run against a real router.
        client = 'import os,pwd; account=pwd.getpwnam('+repr(user)+'); os.setgroups([]); os.setgid(account.pw_gid); os.setuid(account.pw_uid)\n'+client
    result = subprocess.run(['nsenter', '--net=/run/netns/'+namespace, '--', sys.executable, '-c', client,
                             address, str(port), protocol, *([source] if source else [])],
                             capture_output=True, text=True, timeout=5)
    if result.returncode not in (0, 10) or (result.returncode == 0) != allowed:
        raise AssertionError(f'{namespace} to {address}:{port}/{protocol}: expected allowed={allowed}; '
                             f'exit={result.returncode}; diagnostic={result.stderr[-1024:]}')
    if peer is not None and json.loads(result.stdout)['peer'] != peer:
        raise AssertionError('NAT or source-address preservation differs from the compiled policy.')


def reject_forgery(sender, source, destination, router_interface, token, observer, work, *, sport=40000, dport=8888):
    router_mac = json.loads(ns('router', 'ip', '-json', 'link', 'show', router_interface).stdout)[0]['address']
    client_mac = json.loads(ns(sender, 'ip', '-json', 'link', 'show', 'eth0').stdout)[0]['address']
    ns(sender, sys.executable, '-c', RAW, source, destination, router_mac, client_mac, token, str(sport), str(dport))
    time.sleep(0.1)
    path = work/(observer+'.ready.events')
    if path.exists() and token in path.read_text():
        raise AssertionError('A forged packet bypassed the mandatory source/forwarding guards.')


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


def server(namespace, path, uid=None):
    ready = path/(namespace+'.ready')
    code = SERVER
    if uid is not None:
        path.chmod(0o755)
        events = Path(str(ready)+'.events')
        events.touch()
        os.chown(events, uid, uid)
        code = code.replace('while True:', 'import os; os.setgroups([]); os.setgid('+str(uid)+'); os.setuid('+str(uid)+')\nwhile True:', 1)
    process = subprocess.Popen(['nsenter', '--net=/run/netns/'+namespace, '--', sys.executable, '-c', code, str(ready)],
                               stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
    deadline = time.monotonic()+5
    while not ready.exists():
        if process.poll() is not None or time.monotonic() > deadline:
            process.terminate()
            raise AssertionError('Synthetic listener could not start: '+process.communicate(timeout=5)[1][-1024:])
        time.sleep(0.02)
    return process


def reject_extension_tuple_reuse(work, gateway, client):
    ready = work/'extension-tuple-ready'
    code = '''
import socket,sys
with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as stream:
    stream.bind((sys.argv[1],40000));stream.settimeout(2)
    stream.sendto(b'legitimate-extension-flow',(sys.argv[2],8888))
    stream.recvfrom(4096)
    open(sys.argv[3],'x').close()
    try:
        data,peer=stream.recvfrom(4096)
    except TimeoutError:sys.exit(0)
    sys.exit(20)
'''
    process = subprocess.Popen(['nsenter', '--net=/run/netns/extension-client', '--', sys.executable,
                                '-c', code, client, gateway, str(ready)],
                               stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        deadline = time.monotonic()+4
        while not ready.exists():
            if process.poll() is not None or time.monotonic() > deadline:
                raise AssertionError('The legitimate extension tuple was not established.')
            time.sleep(0.02)
        ns('router', sys.executable, '-c',
           'import os,socket,sys; os.setgroups([]); os.setgid(1802); os.setuid(1802); '
           's=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); '
           's.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1); s.bind((sys.argv[1],8888)); '
           '\ntry:s.sendto(b"wrong-uid-stale-tuple",(sys.argv[2],40000))\n'
           'except PermissionError:pass', gateway, client)
        _, diagnostic = process.communicate(timeout=5)
        if process.returncode != 0:
            raise AssertionError('Another UID reused an extension tuple: '+diagnostic.decode()[-512:])
    finally:
        if process.poll() is None:
            process.kill()
            process.communicate(timeout=5)


def exercise_extensions():
    """Use arbitrary extension names/UIDs; no private application is installed."""
    value = config.load(Path(__file__).resolve().parents[1]/'examples/minimal.yaml')
    value['services']['dns'] = {'enabled': False}
    value['services']['ntp'] = {'enabled': False}
    value['observability'] = {'metrics': {'enabled': True, 'clients': [{'network': 'home'}]}}
    value = config.normalize(value)
    value['networks']['rescue'] = {'name': 'rescue0', 'addresses': ['198.18.0.11/24'],
                                  'forwarding': False, 'ra': False}
    plane = service_plane.topology(value)
    listeners = [{'user': 'example-agent', 'network': 'home', 'address': address,
                  'sources': [prefix], 'protocol': protocol, 'port': 8888}
                 for address, prefix in (('192.168.10.1', '192.168.10.0/24'),
                                         ('fd42:1000:1000:10::1', 'fd42:1000:1000:10::/64'))
                 for protocol in ('tcp', 'udp')]
    listeners.append({'user': 'example-agent', 'network': 'rescue', 'address': '198.18.0.11',
                      'sources': ['198.18.0.0/24'], 'protocol': 'tcp', 'port': 8888})
    plan = extension_network.resolve(value, [extension_network.declarations(
        {'listeners': listeners, 'services': [{'user': 'example-agent', 'service': 'metrics', 'family': family}
                                             for family in (4, 6)]},
        {'users': [{'name': 'example-agent', 'uid': 1801, 'gid': 1801}], 'groups': []})])
    with tempfile.TemporaryDirectory(prefix='lanrith-extension-packets.') as temporary:
        work = Path(temporary)
        # Give the namespace parser its generated service identity through a
        # private bind mount; never edit the host account registry.
        import pwd
        passwd = Path('/etc/passwd').read_text()
        if not any(line.startswith('lanrith-metrics:') for line in passwd.splitlines()):
            passwd += 'lanrith-metrics:*:1803:1803:Fixture:/nonexistent:/usr/sbin/nologin\n'
        for uid in (1801, 1802):
            try:
                pwd.getpwuid(uid)
            except KeyError:
                continue
            raise AssertionError('Synthetic extension UID is occupied.')
        (work/'passwd').write_text(passwd)
        run('mount', '--bind', str(work/'passwd'), '/etc/passwd')
        processes, namespaces = [], ['router', 'extension-client', 'extension-oob', 'upstream', 'services']
        try:
            run('ip', 'netns', 'add', 'router')
            client = connection('lan', 'extension-client', value['networks']['home']['addresses'], 1)
            oob = connection('rescue0', 'extension-oob', value['networks']['rescue']['addresses'], 2)
            wan = value['hardware']['interfaces'][value['uplink']['interface']]['name']
            uplink = connection(wan, 'upstream', ['198.51.100.1/24', '2001:db8:ffff::1/64'], 3)
            connection(plane['host_link'], 'services', plane['host_addresses'], 4)
            ns('services', 'ip', 'link', 'set', 'eth0', 'name', plane['service_link'])
            for address in plane['endpoints']['metrics']:
                ns('services', 'ip', 'address', 'add', address+('/32' if ':' not in address else '/128'),
                   'dev', plane['service_link'], *(['nodad'] if ':' in address else []))
            for _, remote, family in uplink:
                ns('router', 'ip', '-'+str(family), 'route', 'add', 'default', 'via', remote)
            sysctls = work/'routing.conf'
            sysctls.write_text(firewall.sysctls())
            ns('router', '/usr/lib/systemd/systemd-sysctl', str(sysctls))
            host_rules, peer_rules = work/'host.nft', work/'peer.nft'
            host_rules.write_text(firewall.render(value, extension_rules=plan))
            peer_rules.write_text(service_plane.namespace_firewall(value, plane, extension_rules=plan))
            ns('router', 'nft', '--file', str(host_rules))
            ns('services', 'nft', '--file', str(peer_rules))
            processes.append(server('router', work, uid=1801))
            processes.append(server('services', work))
            processes.append(server('upstream', work))
            for gateway, address, family in client:
                probe('extension-client', gateway, 8888, True)
                probe('extension-client', gateway, 8888, True, 'udp')
                probe('extension-client', gateway, 8889, False)
                probe('extension-client', oob[0][0], 8888, False)
                reject_forgery('upstream', address, gateway, wan, 'extension-wrong-ingress-'+str(family),
                               'router', work)
            probe('extension-oob', oob[0][0], 8888, True)
            for address in plane['endpoints']['metrics']:
                for uid, allowed in ((1801, True), (1802, False), (65534, False)):
                    code = 'import os; os.setgroups([]); os.setgid('+str(uid)+'); os.setuid('+str(uid)+')\n'+CLIENT
                    result = subprocess.run(['nsenter', '--net=/run/netns/router', '--',
                        sys.executable, '-c', code, address, '9100', 'tcp'], capture_output=True, timeout=5)
                    if result.returncode not in (0, 10) or (result.returncode == 0) != allowed:
                        raise AssertionError('Managed metrics access differs for extension UID '+str(uid)+': '+result.stderr.decode()[-512:])
                probe('router', address, 8888, False)
                reject_forgery('extension-client', plan['services'][0 if ':' not in address else 1]['source'],
                               address, 'lan', 'extension-host-source-forgery-'+str(':' in address), 'services', work,
                               dport=9100)
            for _, remote, _ in uplink:
                code = 'import os; os.setgroups([]); os.setgid(1801); os.setuid(1801)\n'+CLIENT
                result = subprocess.run(['nsenter', '--net=/run/netns/router', '--', sys.executable,
                    '-c', code, remote, '8888', 'tcp'], capture_output=True, timeout=5)
                if result.returncode != 10:
                    raise AssertionError('Extension obtained undeclared external access.')
            reject_extension_tuple_reuse(work, client[0][0], client[0][1])
            # Removing the declarations removes every new listener/dependency;
            # fresh connections cannot inherit their previous permission.
            host_rules.write_text(firewall.render(value))
            peer_rules.write_text(service_plane.namespace_firewall(value, plane))
            ns('router', 'nft', '--file', str(host_rules))
            ns('services', 'nft', '--file', str(peer_rules))
            for gateway, _, _ in client:
                probe('extension-client', gateway, 8888, False)
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
            run('umount', '/etc/passwd')
    print('Generic extension listeners, managed metrics UID access, OOB, spoof/stale-tuple denial and removal passed.')


def exercise(example):
    value = config.load(Path(__file__).resolve().parents[1]/'examples'/example)
    # Core services have a separate native namespace/daemon fixture.
    # This topology isolates routed access, NAT44 and source validation.
    value['services']['dns'] = {'enabled': False}
    value['services']['ntp'] = {'enabled': False}
    value = config.normalize(value)
    next(iter(value['networks'].values()))['routed_prefixes'] = ['10.30.0.0/16']
    with tempfile.TemporaryDirectory(prefix='lanrith-packets.') as temporary:
        work = Path(temporary)
        run('ip', 'netns', 'add', 'router')
        processes, namespaces = [], ['router', 'upstream']
        try:
            sysctls = work/'routing.conf'
            sysctls.write_text(config.render(value)['etc/sysctl.d/90-lanrith-routing.conf'])
            ns('router', '/usr/lib/systemd/systemd-sysctl', str(sysctls))
            wan = value['hardware']['interfaces'][value['uplink']['interface']]['name']
            uplink = connection(wan, 'upstream', ['198.51.100.1/24', '2001:db8:ffff::1/64'], 0)
            for gateway, remote, family in uplink:
                ns('router', 'ip', '-'+str(family), 'route', 'add', 'default', 'via', remote)
            clients = []
            for index, (key, network) in enumerate(value['networks'].items(), 1):
                namespace = 'client'+str(index)
                namespaces.append(namespace)
                clients.append((namespace, key, connection(network['name'], namespace, network['addresses'], index)))
            ns('router', '/usr/lib/systemd/systemd-sysctl', str(sysctls))
            rules = work/'policy.nft'
            rules.write_text(config.render(value)['etc/nftables.conf'])
            ns('router', 'nft', '--file', str(rules))
            for namespace in namespaces:
                processes.append(server(namespace, work))
            first_client = clients[0]
            next_hop = next(address for _, address, family in first_client[2] if family == 4)
            ns(first_client[0], 'ip', 'address', 'add', '10.30.0.2/16', 'dev', 'eth0')
            ns('router', 'ip', 'route', 'add', '10.30.0.0/16', 'via', next_hop)
            upstream = next(address for _, address, family in uplink if family == 4)
            probe(first_client[0], upstream, 8888, True, peer='198.51.100.1', source='10.30.0.2')
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
                    # Both reviewed examples explicitly permit their client
                    # networks to the uplink; do not derive expectations from
                    # the compiler's rule interpretation.
                    probe(namespace, remote, 8888, True, peer=translated)
                    probe(namespace, remote, 8888, True, 'udp', peer=translated)
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
                    # A synthetic global IPv6 source would otherwise remain
                    # preferred for later UDP replies to the upstream peer.
                    ns(namespace, 'ip', 'address', 'del', spoof+('/32' if family == 4 else '/128'), 'dev', 'eth0')
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
                value['access']['rules'] += [
                    {'action': 'allow', 'from': first[1], 'to': second[1], 'protocol': 'tcp', 'ports': [8888]}]
                rules.write_text(config.render(value)['etc/nftables.conf'])
                ns('router', 'nft', '--file', str(rules))
                for _, address, family in second[2]:
                    probe(first[0], address, 8888, True,
                          peer=next(peer for _, peer, version in first[2] if version == family))
                    probe(first[0], address, 8889, False)
                for _, address, _ in first[2]:
                    probe(second[0], address, 8888, False)
                # The same generic selector narrows a routed exception to
                # one host and one protocol; list ordering can deny it again.
                target = next(address for _, address, version in second[2] if version == 4)
                scoped = {'action': 'deny', 'from': first[1],
                          'to': {'network': second[1], 'addresses': target},
                          'protocol': 'tcp', 'ports': [8888]}
                value['access']['rules'].insert(0, scoped)
                rules.write_text(config.render(value)['etc/nftables.conf'])
                ns('router', 'nft', '--file', str(rules))
                probe(first[0], target, 8888, False)
                for _, address, version in second[2]:
                    if version == 6:
                        probe(first[0], address, 8888, True)
                value['access']['rules'][0]['action'] = 'allow'
                value['access']['rules'].pop()
                rules.write_text(config.render(value)['etc/nftables.conf'])
                ns('router', 'nft', '--file', str(rules))
                probe(first[0], target, 8888, True)
                probe(first[0], target, 8888, False, protocol='udp')
                probe(first[0], target, 8889, False)
                # Even an explicit wildcard permit cannot override isolation,
                # internal-source validation on WAN, or DHCP/link-local guards.
                value['networks'][second[1]]['forwarding'] = False
                value['access'] = {'rules': [{'action': 'allow', 'from': 'any', 'to': 'any'}]}
                rules.write_text(config.render(value)['etc/nftables.conf'])
                ns('router', 'nft', '--file', str(rules))
                for _, address, family in first[2]:
                    try:
                        probe('upstream', address, 8888, True, protocol='udp')
                    except AssertionError:
                        print('Synthetic route diagnostic: '+ns('router', 'ip', '-6', 'route').stdout, flush=True)
                        print('Synthetic upstream route diagnostic: '+ns('upstream', 'ip', '-6', 'route').stdout, flush=True)
                        print('Synthetic client route diagnostic: '+ns(first[0], 'ip', '-6', 'route').stdout, flush=True)
                        raise
                    subnet = next(ipaddress.ip_interface(item).network for item in value['networks'][first[1]]['addresses']
                                  if ipaddress.ip_interface(item).version == family)
                    fake = str(ipaddress.ip_address(int(subnet.network_address)+99))
                    reject_forgery('upstream', fake, address, wan, 'wan-forgery-'+str(family), first[0], work)
                for _, address, family in second[2]:
                    probe(first[0], address, 8888, False)
                    probe('upstream', address, 8888, False)
                    other = next(peer for _, peer, version in first[2] if version == family)
                    remote = next(peer for _, peer, version in uplink if version == family)
                    probe(second[0], other, 8888, False)
                    probe(second[0], remote, 8888, False)
                source_interface = value['networks'][first[1]]['name']
                remote4 = next(peer for _, peer, version in uplink if version == 4)
                remote6 = next(peer for _, peer, version in uplink if version == 6)
                reject_forgery(first[0], '0.0.0.0', remote4, source_interface, 'dhcp-source-forward',
                      'upstream', work, sport=68, dport=67)
                reject_forgery(first[0], 'fe80::99', remote6, source_interface, 'link-local-forward', 'upstream', work)
            # Host output uses generated service permissions, not the access list.
            for _, remote, family in uplink:
                probe('router', remote, 8888, False)
                probe('router', remote, 53, False, protocol='udp', user='unbound')
                probe('router', remote, 53, False, protocol='udp', user='nobody')
            # An undeclared attachment must not inherit even wildcard owner
            # permission or impersonate sources from a declared LAN.
            namespaces.append('unconfigured')
            connection('unexpected0', 'unconfigured', ['172.31.99.1/24', 'fd42:ffff::1/64'], 100)
            value['access'] = {'rules': [{'action': 'allow', 'from': 'any', 'to': 'any',
                                        'authorization': 'owner'}]}
            rules.write_text(config.render(value)['etc/nftables.conf'])
            ns('router', 'nft', '--file', str(rules))
            for _, address, family in first_client[2]:
                remote = next(peer for _, peer, version in uplink if version == family)
                reject_forgery('unconfigured', address, remote, 'unexpected0',
                               'undeclared-interface-'+str(family), 'upstream', work)
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
    print(example+': management, ordered host/port policy, isolation, NAT44, IPv4/IPv6 spoof guards and denied host egress passed.')


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
    exercise_extensions()


if __name__ == '__main__':
    main()
