#!/usr/bin/env python3
"""Qualify compiled TUN policy with stock TAYGA and no runtime YAML/compiler.

Prepare on the build host, then mount only this file, translation_reference.py,
the compiled fixture directory and the pinned TAYGA binary in an offline packet
container. --run never imports Lanrith or reads an owner configuration.
"""

import argparse
import grp
import ipaddress as ip
import json
import os
from pathlib import Path
import pwd
import select
import subprocess
import sys
import tempfile
import time

import translation_reference as ref


SIX = 'fd42:1234:5678:10::'
UPPER = 'fd42:1234:5678:10:8000::'
SERVERS = 'fd42:1234:5678:20::'
WAN = '93.184.216.2'
FOUR = '10.240.40.2'


def prepare(output):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    from lanrith import config, firewall, policy_agent, translation, tun_policy
    from test_intent import minimal

    raw = minimal()
    raw['hardware']['interfaces']['wan']['name'] = 'p4'
    raw['hardware']['interfaces']['lan']['name'] = 'c6'
    for key, name, mac in (('four', 'c4', '02:00:00:00:02:01'),
                           ('servers', 'p6', '02:00:00:00:03:01')):
        raw['hardware']['interfaces'][key] = {'name': name, 'match': {'mac': mac}}
    raw['uplink'] = {'interface': 'wan', 'ipv4': {'address': '93.184.216.1/24', 'gateway': WAN},
                     'ipv6': 'disabled'}
    raw['networks'] = {'six': {'interface': 'lan', 'ipv6': {'subnet_id': 16, 'ra': False, 'gua': False}},
                       'four': {'interface': 'four', 'ipv4': '10.240.40.0/24'},
                       'servers': {'interface': 'servers', 'ipv6': {'subnet_id': 32, 'ra': False, 'gua': False}}}
    raw['services'] = {name: {'enabled': False} for name in ('dns', 'ntp', 'dhcp4')}
    raw['administration']['networks'] = ['four']
    raw['translation'] = {'nat64': {'enabled': True, 'internet_pool': '10.249.0.0/24',
                                   'private_pool': '10.250.0.0/24'},
                          'nat46': {'enabled': True, 'pool': '10.251.0.0/24', 'mappings': {
                              'service'+str(i): {'ipv4': '10.251.0.'+str(i+2), 'ipv6': SERVERS+str(i+10)}
                              for i in range(6)}}}
    raw['identity'] = {'directories': {'devices': {'enabled': True,
        'url': 'ldaps://['+SERVERS+'30]:636', 'base_dn': 'dc=example,dc=test',
        'bind_dn': 'cn=router,dc=example,dc=test', 'credential': 'directory_bind',
        'ca_file': 'trust/directory.pem'}},
        'policy': {'enabled': True, 'directory': 'devices', 'networks': ['four']}}
    rules = [{'action': 'deny', 'from': {'network': 'six', 'addresses': SIX+'90'}, 'to': 'any'}]
    for source, destination in ((SIX+'2', 'uplink'), (SIX+'/65', 'uplink'),
                                (UPPER+'/65', 'four')):
        for protocols, ports in ((['tcp', 'udp'], {'ports': [11111]}), ('icmp', {})):
            rules.append({'action': 'allow', 'from': {'network': 'six', 'addresses': source},
                          'to': destination, 'protocol': protocols, 'authorization': 'owner', **ports})
    for protocols, ports in ((['tcp', 'udp'], {'ports': [11111]}), ('icmp', {})):
        rules.append({'action': 'allow', 'from': {'network': 'four', 'addresses': FOUR},
                      'to': {'translation': 'nat46'}, 'protocol': protocols, 'authorization': 'owner', **ports})
    for source, destination in (('any', {'network': 'six', 'addresses': SIX+'2'}),
                                ('servers', {'network': 'four', 'addresses': FOUR})):
        # A later broader owner permit deliberately tests terminal directory
        # matching. Missing/expired grants must not fall through to it.
        rules += [{'action': 'allow', 'from': source, 'to': destination, 'authorization': mode}
                  for mode in ('directory', 'owner')]
    raw['access'] = {'default': 'deny', 'rules': rules}
    raw['routing'] = {'asymmetric_replies': [
        {'mode': mode, 'from': {'network': 'servers', 'addresses': SERVERS+'14'},
         'to': {'network': 'six', 'addresses': SIX+'3'}}
        for mode in ('tcp_dsr', 'icmp_echo_reply')]}
    value = config.normalize(raw)
    output.mkdir(mode=0o700)
    (output/'accounts.passwd').write_text('root:x:0:0:root:/root:/bin/sh\n'
        'nobody:x:65534:65534:nobody:/:/usr/sbin/nologin\n'
        'router-policy-reader:x:61000:61000:synthetic reader:/:/usr/sbin/nologin\n')
    (output/'connlabel.conf').write_text(policy_agent.render(value, access_backend='tun')['etc/xtables/connlabel.conf'])
    retained = {SIX+'2': '10.250.0.200'}
    (output/'policy.nft').write_text(firewall.render(value, access_backend='tun', retained_allocations=retained))
    (output/'identity-egress.nft').write_text(tun_policy.identity_egress(value))
    (output/'baseline.json').write_text(json.dumps(policy_agent.baseline(value, retained), sort_keys=True)+'\n')
    runtime = output/'runtime/lanrith'
    runtime.mkdir(parents=True)
    for module in ('__init__.py', 'release.py', 'translation_runtime.py'):
        (runtime/module).write_bytes((Path(__file__).resolve().parents[1]/'lanrith'/module).read_bytes())
    for relative, text in translation.render_native(value, retained).items():
        path = output/'native-extra'/relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
    manifests = translation.manifests(value, retained)
    (output/'lab.json').write_text(json.dumps({'components': manifests, 'policy': tun_policy.compile(value, retained)},
                                             sort_keys=True, indent=2)+'\n')
    for manifest in manifests:
        (output/(manifest['interface']+'.conf')).write_text(manifest['text'])
    print(json.dumps({k: v for k, v in tun_policy.compile(value, retained).items()
                      if k not in ('declarations', 'rules')}))


def runtime_checks(root, publisher, components, children, checks, probe, flow):
    """Exercise actual helper-local evidence and kernel publication/deletion."""
    child = subprocess.Popen([publisher, '-test.run=^TestTUNPacketPublisher$', '-test.timeout=35s'],
        env={**os.environ, 'LANRITH_TUN_PACKET_FIXTURE': str(root)},
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    children.append(child)

    def call(command, **fields):
        child.stdin.write(json.dumps({'command': command, **fields})+'\n')
        child.stdin.flush()
        end, output = time.monotonic()+3, []
        while time.monotonic() < end:
            if not select.select([child.stdout], [], [], max(0, end-time.monotonic()))[0]:
                break
            line = child.stdout.readline()
            output.append(line)
            if line.strip() == 'ACK '+command:
                return
            if not line:
                break
        raise AssertionError('Publisher '+command+' failed: '+''.join(output))

    bindings = []
    for interface, addresses in (('c4', [FOUR]), ('c6', [SIX+'2', SIX+'3'])):
        mac = json.loads(ref.command(*ref.inside(interface, 'ip', '-j', 'link', 'show', 'eth0')).stdout)[0]['address']
        bindings.append({'interface': interface, 'mac': mac, 'addresses': addresses})
    call('initialize', bindings=bindings)
    checks.append('real publisher restores history, bindings and startup; empty conntrack deletion succeeds')
    callback6 = str(ip.ip_network(components['nat46']['prefix']).network_address+int(ip.ip_address(FOUR)))
    # The private NAT64 delegation contract admits private IPv4 peers. Its
    # public counterpart is independently scoped; test the actual LAN callback.
    callbacks = [('c4', '10.250.0.200', FOUR), ('p6', callback6, SERVERS+'10')]
    target = str(ip.ip_network(components['nat64']['prefix']).network_address+int(ip.ip_address(WAN)))
    for protocol in ('tcp', 'udp'):
        owners = [flow('c6', target, SIX+'2', 11111, protocol),
                  flow('c4', '10.251.0.2', FOUR, 11111, protocol)]
        for args in callbacks:
            probe('real publisher no grant denies callback', *args, 22222, protocol, False)
        call('grant', protocol=protocol)
        flows = [flow(*args, 22222, protocol) for args in callbacks]
        checks.append('real publisher grants both translated callbacks '+protocol)
        call('revoke')
        for obj in flows:
            obj.check(False)
            obj.close()
        for obj in owners:
            obj.check(True)
            obj.close()
        checks.append('real revocation stops live callbacks and retains owner flows '+protocol)
    call('grant', protocol='udp')
    flows = [flow(*args, 22222, 'udp') for args in callbacks]
    # Inspect real kernel connections, not only denied delivery. Retirement
    # must cover both local halves while leaving unrelated owner flows alone.
    labelled = ref.command('/usr/sbin/conntrack', '-L', '--label', 'lanrith-identity').stdout
    for address in (FOUR, SIX+'2', '10.250.0.200', callback6):
        assert ('src='+address+' ') in labelled or ('dst='+address+' ') in labelled, labelled
    controls = [('198.18.0.10', '198.18.0.11'), ('fd42:ffff::10', 'fd42:ffff::11')]
    for source, destination in controls:
        ref.command('/usr/sbin/conntrack', '-I', '-p', 'udp', '--orig-src', source,
            '--orig-dst', destination, '--sport', '23456', '--dport', '23457',
            '-t', '60', '--mark', '0x4c520001')
    call('rotate')
    assert not ref.command('/usr/sbin/conntrack', '-L', '--label', 'lanrith-identity').stdout
    for source, destination in controls:
        assert ref.command('/usr/sbin/conntrack', '-L', '--orig-src', source).stdout
    checks.append('identity rotation deletes labelled real and translated entries in both families; unrelated owner entries survive')
    call('replay')
    for obj in flows:
        obj.check(False)
        obj.close()
    checks.append('binding rotation deletes connections and rejects replay of old evidence')
    call('grant', protocol='udp', lease_ms=3500)
    flows = [flow(*args, 22222, 'udp') for args in callbacks]
    time.sleep(1.3)
    for obj in flows:
        obj.check(False)
        obj.close()
    checks.append('actual grant elements expire without a revocation message')
    call('close')
    probe('publisher shutdown closes ordinary traffic', 'c6', target, SIX+'2', 11111, 'udp', False)
    child.stdin.close()
    assert child.wait(timeout=2) == 0, child.stdout.read()


def asymmetric_checks(root, checks):
    """Observe delivery of replies whose requests never crossed this router."""
    # The general matrix gives p6 this address for a wrong-interface spoof.
    # Remove that test-only local route so these replies reach the router.
    ref.command(*ref.inside('p6', 'ip', '-6', 'addr', 'del', SIX+'3/128', 'dev', 'eth0'))
    receiver = '''import pathlib,socket,sys,time
fd=socket.socket(socket.AF_PACKET,socket.SOCK_RAW,socket.htons(0x86dd));fd.bind(('eth0',0));fd.settimeout(.25)
pathlib.Path(sys.argv[1]).touch()
token=sys.argv[2].encode();found=False;end=time.monotonic()+.3
while time.monotonic()<end:
    try:
        if token in fd.recv(65535):found=True;break
    except TimeoutError:break
print(int(found),flush=True)
'''
    sender = '''import socket,struct,sys
source,target,kind,flags,token=sys.argv[1:]
tcp=kind=='tcp';fd=socket.socket(socket.AF_INET6,socket.SOCK_RAW,socket.IPPROTO_TCP if tcp else socket.IPPROTO_ICMPV6)
if tcp:fd.setsockopt(socket.IPPROTO_IPV6,socket.IPV6_CHECKSUM,16)
fd.bind((source,0))
header=struct.pack('!HHIIBBHHH',44444,22222,1,1,80,int(flags),1024,0,0) if tcp else struct.pack('!BBHHH',int(flags),0,0,1234,1)
fd.sendto(header+token.encode(),(target,0))
'''
    cases = [('TCP ACK reply', SERVERS+'14', SIX+'3', 'tcp', 16, True),
             ('TCP SYN start', SERVERS+'14', SIX+'3', 'tcp', 2, False),
             ('TCP SYN ACK', SERVERS+'14', SIX+'3', 'tcp', 18, False),
             ('TCP reset', SERVERS+'14', SIX+'3', 'tcp', 20, False),
             ('wrong IPv6 source', SERVERS+'15', SIX+'3', 'tcp', 16, False),
             ('wrong IPv6 destination', SERVERS+'14', SIX+'2', 'tcp', 16, False),
             ('IPv6 echo reply', SERVERS+'14', SIX+'3', 'icmp', 129, True),
             ('IPv6 echo request', SERVERS+'14', SIX+'3', 'icmp', 128, False)]
    for index, (label, source, target, protocol, flags, allowed) in enumerate(cases):
        token = 'asymmetric-'+str(index)
        ready = root/(token+'.ready')
        child = subprocess.Popen(ref.inside('c6', sys.executable, '-c', receiver, str(ready), token),
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        try:
            ref.await_file(ready, child)
            ref.command(*ref.inside('p6', sys.executable, '-c', sender, source, target, protocol, str(flags), token))
            output, diagnostic = child.communicate(timeout=2)
            assert child.returncode == 0 and output.strip() == str(int(allowed)), (label, output, diagnostic)
            checks.append('asymmetric '+label+(' delivered' if allowed else ' denied'))
        finally:
            if child.poll() is None:
                child.kill()
                child.wait(timeout=2)


def lifecycle_checks(root, temporary, components, translators, children, checks, probe, flow):
    sys.path.insert(0, str(root/'runtime'))
    from lanrith.translation_runtime import reset_connections

    def connections(component):
        scopes = [ip.ip_network(component[key]) for key in ('pool', 'prefix')]
        rows = []
        for family in ('ipv4', 'ipv6'):
            text = ref.command('/usr/sbin/conntrack', '-L', '-f', family).stdout
            for row in text.splitlines():
                addresses = [ip.ip_address(field.split('=', 1)[1]) for field in row.split()
                             if field.startswith(('src=', 'dst='))]
                if any(address in scope for address in addresses for scope in scopes):
                    rows.append(row)
        return rows

    paths = {}
    for name, component in components.items():
        if name == 'nat46':
            paths[name] = ('c4', '10.251.0.2', FOUR)
        else:
            target = str(ip.ip_network(component['prefix']).network_address+int(ip.ip_address(WAN)))
            paths[name] = ('c6', target, SIX+'3')
    flows = [flow(*path, 11111, 'udp') for path in paths.values()]
    for name, component in components.items():
        assert connections(component), 'missing positive connection control for '+name
        other = next(c for key, c in components.items() if key != name)
        assert connections(other), 'missing unrelated connection control'
        child = translators[name]
        child.terminate()
        assert child.wait(timeout=2) == 0, 'translator did not stop cleanly'
        state = temporary/name/'dynamic.map'
        saved = state.read_bytes() if component['component'] == 'nat64' else None
        if saved is not None:
            assert saved and (SIX+'3').encode() in saved, 'native allocation was not saved'
        reset_connections(component)
        assert not connections(component), 'old component connections survived retirement'
        assert connections(other), 'restart retired unrelated component connections'
        checks.append('restart retires only '+name+' connections')
        log = (temporary/(name+'.log')).open('a')
        restarted = subprocess.Popen(child.args, stdin=subprocess.DEVNULL, stdout=log, stderr=log)
        log.close()
        children.append(restarted)
        translators[name] = restarted
        time.sleep(.1)
        assert restarted.poll() is None, 'translator restart failed'
        if saved is not None:
            assert state.read_bytes() == saved, 'native saved allocation changed during restart'
        for protocol in ('tcp', 'udp', 'icmp'):
            probe('traffic after native '+name+' restart', *paths[name], 11111, protocol)
    for obj in flows:
        obj.close()


def mtu_checks(components, checks):
    """Require actual translated too-big errors and continued small traffic."""
    client = '''import errno,json,socket,sys
source,target=sys.argv[1:];six=':' in source
fd=socket.socket(socket.AF_INET6 if six else socket.AF_INET,socket.SOCK_DGRAM)
fd.settimeout(1);fd.bind((source,0))
fd.setsockopt(socket.IPPROTO_IPV6 if six else socket.IPPROTO_IP,23 if six else 10,2)
fd.connect((target,11111));fd.send(b'large-pmtu-probe'+b'x'*1400)
try:fd.recv(4096);raise AssertionError('oversized datagram did not report its path MTU')
except OSError as e:assert e.errno==errno.EMSGSIZE,repr(e)
mtu=fd.getsockopt(socket.IPPROTO_IPV6 if six else socket.IPPROTO_IP,24 if six else 14)
assert 1000<mtu<1500,mtu
fd.send(b'small-pmtu-probe'+b'x'*900);assert fd.recv(4096)==b'small-pmtu-probe'+b'x'*900
print(json.dumps({'mtu':mtu}))
'''
    for interface in ('p4', 'p6'):
        ref.command('ip', 'link', 'set', interface, 'mtu', '1280')
    for name, component in components.items():
        if name == 'nat46':
            network, source, target = 'c4', FOUR, '10.251.0.2'
        else:
            network, source = 'c6', SIX+'3'
            target = str(ip.ip_network(component['prefix']).network_address+int(ip.ip_address(WAN)))
        result = ref.command(*ref.inside(network, sys.executable, '-c', client, source, target))
        checks.append(name+' translated path MTU '+str(json.loads(result.stdout)['mtu'])+' and small datagram reply')


def run(root, tayga, publisher=None, asymmetric=False, lifecycle=False, mtu=False):
    assert os.geteuid() == 0 and Path('/dev/net/tun').is_char_device()
    assert {row['ifname'] for row in json.loads(ref.command('ip', '-j', 'link').stdout)} == {'lo'}
    lab = json.loads((root/'lab.json').read_text())
    components = {c['interface']: c for c in lab['components']}
    children, checks, denied_tokens = [], [], []
    translators = {}

    def flow(name, target, source, port, protocol, allowed=True):
        obj = ref.Flow(name, target, source, port, protocol)
        children.append(obj.child)
        obj.check(allowed)
        if not allowed and obj.ready:
            token = f'reference-{obj.child.pid}-{obj.sequence}'
            denied_tokens.append(token)
            assert all(token not in path.read_text() for path in temporary.glob('*.received')), (
                'Denied payload reached a server despite the missing round trip')
        return obj

    def probe(label, name, target, source, port, protocol, allowed=True):
        obj = flow(name, target, source, port, protocol, allowed)
        obj.close()
        checks.append(label+' '+protocol)

    def grant(protocol, timeout=None):
        text = ''.join(f'flush set inet lanrith tp_{kind}{family}\n'
                       for family in (4, 6) for kind in ('grants', 'echo'))
        if timeout is not None:
            peer = str(ip.ip_network(components['nat64-internal']['prefix']).network_address+int(ip.ip_address(WAN)))
            for family, a, b in ((6, peer, SIX+'2'), (4, '10.251.0.2', FOUR)):
                kind = 'echo' if protocol == 'icmp' else 'grants'
                tuple_text = f'{a} . {b}'
                if kind == 'grants':
                    tuple_text += f' . {protocol} . 22222'
                text += f'add element inet lanrith tp_{kind}{family} {{ {tuple_text} timeout {timeout}s }}\n'
        ref.nft(text)

    with tempfile.TemporaryDirectory() as temporary:
        temporary = Path(temporary)
        temporary.chmod(0o755)
        try:
            ref.command('ip', 'link', 'set', 'lo', 'up')
            for name, prefix in (('c6', SIX+'/64'), ('p6', SERVERS+'/64'),
                                 ('c4', '10.240.40.0/24'), ('p4', '93.184.216.0/24')):
                address = ref.peer(name, prefix)
                addresses = [address]
                if name == 'c6':
                    for extra in (SIX+'3', SIX+'90', UPPER+'3'):
                        ref.command(*ref.inside(name, 'ip', '-6', 'addr', 'add', extra+'/64', 'dev', 'eth0', 'nodad'))
                        addresses.append(extra)
                if name == 'p6':
                    for mapping in components['nat46']['mappings'].values():
                        ref.command(*ref.inside(name, 'ip', '-6', 'addr', 'add', mapping['ipv6']+'/64', 'dev', 'eth0', 'nodad'))
                        addresses.append(mapping['ipv6'])
                    ref.command(*ref.inside(name, 'ip', '-6', 'addr', 'add', SIX+'3/128', 'dev', 'eth0', 'nodad'))
                if name == 'c4':
                    ref.command(*ref.inside(name, 'ip', '-4', 'addr', 'add', '10.240.40.90/24', 'dev', 'eth0'))
                    ref.command(*ref.inside(name, 'ip', '-4', 'addr', 'add', WAN+'/32', 'dev', 'eth0'))
                    addresses.append(WAN)
                observed = str(temporary/(name+'.received'))
                server = ref.SERVER.replace(
                    'data,peer=fd.recvfrom(4096);fd.sendto(data,peer)',
                    'data,peer=fd.recvfrom(4096);open('+repr(observed)+',"ab").write(data);fd.sendto(data,peer)')
                server = server.replace('if data:fd.sendall(data)',
                                        'if data:open('+repr(observed)+',"ab").write(data);fd.sendall(data)')
                ready = temporary/(name+'.ready')
                child = subprocess.Popen(ref.inside(name, sys.executable, '-c', server, str(ready), *addresses),
                                         stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
                children.append(child)
                ref.await_file(ready, child)
            ref.ipv6_ready()
            ref.command('nft', '-f', str(root/'policy.nft'))
            ref.command('nft', '-f', str(root/'identity-egress.nft'))
            account = pwd.getpwnam('nobody')
            for name, manifest in components.items():
                state = temporary/name
                state.mkdir(mode=0o700)
                os.chown(state, account.pw_uid, account.pw_gid)
                text = manifest['text'].replace(manifest['state_directory'], str(state))
                path = temporary/(name+'.conf')
                path.write_text(text)
                ref.command('ip', 'tuntap', 'add', 'dev', name, 'mode', 'tun', 'user', str(account.pw_uid))
                ref.command('ip', 'link', 'set', name, 'up')
                for route in manifest['routes']:
                    ref.command('ip', '-'+str(ip.ip_network(route).version), 'route', 'add', route, 'dev', name)
                log = (temporary/(name+'.log')).open('w')
                child = subprocess.Popen([tayga, '-d', '--config', str(path), '--user', 'nobody',
                                          '--group', grp.getgrgid(account.pw_gid).gr_name],
                                         stdin=subprocess.DEVNULL, stdout=log, stderr=log)
                log.close()
                children.append(child)
                translators[name] = child
            time.sleep(.1)
            assert all(p.poll() is None for p in children), 'Fixture daemon startup failed'
            for child in children[-len(components):]:
                status = Path('/proc', str(child.pid), 'status').read_text()
                assert next(line.split()[1] for line in status.splitlines() if line.startswith('CapEff:')) == '0000000000000000'
            for argv in (['nft', 'flush', 'ruleset'],
                         ['nft', 'add', 'element', 'inet', 'lanrith', 'tp_echo4', '{ 10.240.40.2 . 93.184.216.2 }'],
                         ['ip', 'route', 'add', '203.0.113.0/24', 'dev', 'c4']):
                attempt = subprocess.run(argv, user=61000, group=61000, extra_groups=[],
                                         capture_output=True, timeout=2)
                assert attempt.returncode != 0, 'Unprivileged mutation succeeded'
            checks.append('TAYGA has no capabilities; unprivileged rules grants routes mutations denied')
            # The image begins closed until durable history has been restored.
            target = str(ip.ip_network(components['nat64']['prefix']).network_address+int(ip.ip_address(WAN)))
            probe('startup closed before classification restore', 'c6', target, SIX+'3', 11111, 'udp', False)
            if publisher:
                runtime_checks(root, publisher, components, children, checks, probe, flow)
                print(json.dumps({'status': 'pass', 'checks': checks, 'count': len(checks),
                                  'runtime_yaml': False, 'real_policy_publisher': True}, sort_keys=True))
                return
            ref.nft('add element inet lanrith tp_started { 0 }')
            probe('owner permission does not bypass missing managed binding', 'c4', '10.251.0.2', FOUR, 11111, 'udp', False)
            link = json.loads(ref.command(*ref.inside('c4', 'ip', '-j', 'link', 'show', 'eth0')).stdout)[0]
            physical_mac = link['address']
            def binding(timeout=60, mac=physical_mac):
                ref.nft('flush set inet lanrith tp_bound4\nflush set inet lanrith tp_dest4\n'+
                    f'add element inet lanrith tp_bound4 {{ "c4" . {mac} . {FOUR} timeout {timeout}s }}\n'+
                    f'add element inet lanrith tp_dest4 {{ "c4" . {FOUR} timeout {timeout}s }}\n'+
                    'flush set netdev lanrith_identity tp_bound4\n'+
                    f'add element netdev lanrith_identity tp_bound4 {{ "c4" . {mac} . {FOUR} timeout {timeout}s }}')
            binding(mac='02:ff:ff:ff:ff:ff')
            probe('owner permission does not bypass wrong binding MAC', 'c4', '10.251.0.2', FOUR, 11111, 'udp', False)
            binding(1)
            bound_flow = flow('c4', '10.251.0.2', FOUR, 11111, 'udp')
            time.sleep(1.05)
            bound_flow.check(False)
            bound_flow.close()
            checks.append('existing owner flow stops when physical binding expires')
            binding()
            # A formerly managed identity cannot escape by using another LAN.
            ref.nft('add element inet lanrith tp_history_mac { '+physical_mac+' }\n'+
                    'add element inet lanrith tp_history6 { '+SIX+'3 }\n'+
                    'add element netdev lanrith_identity tp_history_mac { '+physical_mac+' }\n'+
                    'add element netdev lanrith_identity tp_history6 { '+SIX+'3 }')
            probe('historical address requires fresh ownership on unmanaged LAN', 'c6', target, SIX+'3', 11111, 'udp', False)
            six_mac = json.loads(ref.command(*ref.inside('c6', 'ip', '-j', 'link', 'show', 'eth0')).stdout)[0]['address']
            ref.nft(f'add element inet lanrith tp_bound6 {{ "c6" . {six_mac} . {SIX}3 timeout 60s }}\n'+
                    f'add element inet lanrith tp_dest6 {{ "c6" . {SIX}3 timeout 60s }}\n'+
                    f'add element netdev lanrith_identity tp_bound6 {{ "c6" . {six_mac} . {SIX}3 timeout 60s }}')
            if asymmetric:
                asymmetric_checks(temporary, checks)
                print(json.dumps({'status': 'pass', 'checks': checks, 'count': len(checks)}, sort_keys=True))
                return
            if lifecycle:
                lifecycle_checks(root, temporary, components, translators, children, checks, probe, flow)
                print(json.dumps({'status': 'pass', 'checks': checks, 'count': len(checks)}, sort_keys=True))
                return
            if mtu:
                mtu_checks(components, checks)
                print(json.dumps({'status': 'pass', 'checks': checks, 'count': len(checks)}, sort_keys=True))
                return
            for protocol in ('tcp', 'udp', 'icmp'):
                owners = []
                for name in ('nat64', 'nat64-internal'):
                    component = components[name]
                    target = str(ip.ip_network(component['prefix']).network_address+int(ip.ip_address(WAN)))
                    for suffix in ('2', '3'):
                        obj = flow('c6', target, SIX+suffix, 11111, protocol)
                        owners.append(obj)
                        checks.append(name+' owner request/reply '+suffix+' '+protocol)
                    probe(name+' ordered source deny', 'c6', target, SIX+'90', 11111, protocol, False)
                    probe(name+' wrong source group denied', 'c6', target, UPPER+'3', 11111, protocol, False)
                private = components['nat64-internal']
                target = str(ip.ip_network(private['prefix']).network_address+int(ip.ip_address(FOUR)))
                probe('private correct source group to LAN', 'c6', target, UPPER+'3', 11111, protocol)
                probe('private wrong source group to LAN denied', 'c6', target, SIX+'3', 11111, protocol, False)
                for mapping in components['nat46']['mappings'].values():
                    probe('NAT46 mapping '+mapping['ipv4'], 'c4', mapping['ipv4'], FOUR, 11111, protocol)
                probe('NAT46 denied client', 'c4', '10.251.0.2', '10.240.40.90', 11111, protocol, False)
                probe('NAT46 unmapped destination', 'c4', '10.251.0.99', FOUR, 11111, protocol, False)
                if protocol != 'icmp':
                    probe('undeclared NAT46 port denied', 'c4', '10.251.0.2', FOUR, 33333, protocol, False)
                target = str(ip.ip_network(private['prefix']).network_address+int(ip.ip_address(WAN)))
                probe('spoofed source on wrong interface', 'p6', target, SIX+'3', 11111, protocol, False)
                # An unexpected Linux route must not turn a WAN permission into
                # delivery through a LAN. Server receipts also reject one-way
                # disclosure that a round-trip-only negative could miss.
                ref.command('ip', '-4', 'route', 'replace', WAN+'/32', 'via', FOUR, 'dev', 'c4')
                probe('unexpected physical route denied', 'c6', target, SIX+'3', 11111, protocol, False)
                ref.command('ip', '-4', 'route', 'del', WAN+'/32', 'via', FOUR, 'dev', 'c4')
                probe('restored physical route works', 'c6', target, SIX+'3', 11111, protocol)
                callback6 = str(ip.ip_network(components['nat46']['prefix']).network_address+int(ip.ip_address(FOUR)))
                callbacks = [('p4', '10.250.0.200', WAN), ('p6', callback6, SERVERS+'10')]
                for client, target, source in callbacks:
                    probe('callback denied before broader owner permit', client, target, source, 22222, protocol, False)
                grant(protocol, 30)
                flows = [flow(client, target, source, 22222, protocol) for client, target, source in callbacks]
                checks.append('fresh callbacks in both directions '+protocol)
                if protocol == 'udp':
                    changed_mac = '02:ff:ff:ff:ff:fe'
                    ref.command(*ref.inside('c4', 'ip', 'link', 'set', 'eth0', 'address', changed_mac))
                    ref.command('ip', 'neigh', 'replace', FOUR, 'lladdr', changed_mac, 'nud', 'permanent', 'dev', 'c4')
                    probe('wrong final Ethernet neighbour denied', 'p6', callback6, SERVERS+'10', 22222, protocol, False)
                    ref.command(*ref.inside('c4', 'ip', 'link', 'set', 'eth0', 'address', physical_mac))
                    ref.command('ip', 'neigh', 'replace', FOUR, 'lladdr', physical_mac, 'nud', 'permanent', 'dev', 'c4')
                    probe('restored final Ethernet neighbour works', 'p6', callback6, SERVERS+'10', 22222, protocol)
                grant(protocol)
                for obj in flows:
                    obj.check(False)
                    obj.close()
                for obj in owners:
                    obj.check(True)
                    obj.close()
                checks.append('existing callbacks revoked; owner replies survive '+protocol)
                grant(protocol, 1)
                obj = flow(*callbacks[0], 22222, protocol)
                time.sleep(1.05)
                obj.check(False)
                obj.close()
                grant(protocol)
                checks.append('natural callback expiry '+protocol)
            assert all(token not in path.read_text() for token in denied_tokens
                       for path in temporary.glob('*.received')), 'Delayed denied payload reached a server'
            print(json.dumps({'status': 'pass', 'checks': checks, 'count': len(checks),
                              'runtime_yaml': False, 'runtime_compiler': False,
                              'access_rules': lab['policy']['access_rules']}, sort_keys=True))
        except Exception:
            print(json.dumps({'completed_checks': checks}), file=sys.stderr)
            print(ref.command('nft', 'list', 'ruleset', check=False).stdout[-12000:], file=sys.stderr)
            for path in temporary.glob('*.log'):
                print(path.name+': '+path.read_text()[-2000:], file=sys.stderr)
            raise
        finally:
            for child in reversed(children):
                if child.poll() is None:
                    child.terminate()
                child.wait(timeout=2)
            for name in ('c6', 'p6', 'c4', 'p4'):
                ref.command('ip', 'netns', 'del', name, check=False)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--prepare', type=Path)
    parser.add_argument('--run', type=Path)
    parser.add_argument('--tayga')
    parser.add_argument('--publisher')
    parser.add_argument('--asymmetric', action='store_true')
    parser.add_argument('--lifecycle', action='store_true')
    parser.add_argument('--mtu', action='store_true')
    args = parser.parse_args()
    assert bool(args.prepare) != bool(args.run)
    if args.prepare:
        prepare(args.prepare)
    else:
        assert args.tayga
        run(args.run, args.tayga, args.publisher, args.asymmetric, args.lifecycle, args.mtu)
