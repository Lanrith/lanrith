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
import subprocess
import sys
import tempfile
import time

import translation_reference as ref


SIX = 'fd42:1234:5678:10::'
UPPER = 'fd42:1234:5678:10:8000::'
SERVERS = 'fd42:1234:5678:20::'
WAN = '93.184.216.2'
FOUR = '192.0.2.2'


def prepare(output):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    from lanrith import config, firewall, translation, tun_policy
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
                       'four': {'interface': 'four', 'ipv4': '192.0.2.0/24'},
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
    value = config.normalize(raw)
    output.mkdir(mode=0o700)
    (output/'accounts.passwd').write_text('root:x:0:0:root:/root:/bin/sh\n'
        'nobody:x:65534:65534:nobody:/:/usr/sbin/nologin\n'
        'router-policy-reader:x:61000:61000:synthetic reader:/:/usr/sbin/nologin\n')
    retained = {SIX+'2': '10.250.0.200'}
    (output/'policy.nft').write_text(firewall.render(value, access_backend='tun', retained_allocations=retained))
    manifests = translation.manifests(value, retained)
    (output/'lab.json').write_text(json.dumps({'components': manifests, 'policy': tun_policy.compile(value, retained)},
                                             sort_keys=True, indent=2)+'\n')
    for manifest in manifests:
        (output/(manifest['interface']+'.conf')).write_text(manifest['text'])
    print(json.dumps({k: v for k, v in tun_policy.compile(value, retained).items()
                      if k not in ('declarations', 'rules')}))


def run(root, tayga):
    assert os.geteuid() == 0 and Path('/dev/net/tun').is_char_device()
    assert {row['ifname'] for row in json.loads(ref.command('ip', '-j', 'link').stdout)} == {'lo'}
    lab = json.loads((root/'lab.json').read_text())
    components = {c['interface']: c for c in lab['components']}
    children, checks, denied_tokens = [], [], []

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
                                 ('c4', '192.0.2.0/24'), ('p4', '93.184.216.0/24')):
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
                    ref.command(*ref.inside(name, 'ip', '-4', 'addr', 'add', '192.0.2.90/24', 'dev', 'eth0'))
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
            time.sleep(.1)
            assert all(p.poll() is None for p in children), 'Fixture daemon startup failed'
            for child in children[-len(components):]:
                status = Path('/proc', str(child.pid), 'status').read_text()
                assert next(line.split()[1] for line in status.splitlines() if line.startswith('CapEff:')) == '0000000000000000'
            for argv in (['nft', 'flush', 'ruleset'],
                         ['nft', 'add', 'element', 'inet', 'lanrith', 'tp_echo4', '{ 192.0.2.2 . 93.184.216.2 }'],
                         ['ip', 'route', 'add', '203.0.113.0/24', 'dev', 'c4']):
                attempt = subprocess.run(argv, user=61000, group=61000, extra_groups=[],
                                         capture_output=True, timeout=2)
                assert attempt.returncode != 0, 'Unprivileged mutation succeeded'
            checks.append('TAYGA has no capabilities; unprivileged rules grants routes mutations denied')
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
                probe('NAT46 denied client', 'c4', '10.251.0.2', '192.0.2.90', 11111, protocol, False)
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
    args = parser.parse_args()
    assert bool(args.prepare) != bool(args.run)
    if args.prepare:
        prepare(args.prepare)
    else:
        assert args.tayga
        run(args.run, args.tayga)
