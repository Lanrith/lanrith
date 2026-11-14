#!/usr/bin/env python3
"""Run each independent translator combination without directory services.

--prepare imports the compiler on the build host. --run consumes compiled files
only, in a disposable offline namespace. Disabled translators must have neither
routes nor forwarding; explicitly permitted ordinary traffic must still work.
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
from tun_policy_native import FOUR, SERVERS, SIX, WAN


def prepare(output):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    from lanrith import config, translation
    from test_intent import minimal

    for nat64 in (False, True):
        for nat46 in (False, True):
            raw = minimal()
            raw['hardware']['interfaces']['wan']['name'] = 'p4'
            raw['hardware']['interfaces']['lan']['name'] = 'c6'
            for key, name, mac in (('four', 'c4', '02:00:00:00:02:01'), ('servers', 'p6', '02:00:00:00:03:01')):
                raw['hardware']['interfaces'][key] = {'name': name, 'match': {'mac': mac}}
            raw['uplink'] = {'interface': 'wan', 'ipv4': {'address': '93.184.216.1/24', 'gateway': WAN}, 'ipv6': 'disabled'}
            raw['networks'] = {
                'six': {'interface': 'lan', 'ipv6': {'subnet_id': 16, 'ra': False, 'gua': False}},
                'four': {'interface': 'four', 'ipv4': '10.240.40.0/24'},
                'servers': {'interface': 'servers', 'ipv6': {'subnet_id': 32, 'ra': False, 'gua': False}}}
            raw['administration']['networks'] = ['four']
            raw['services'] = {name: {'enabled': False} for name in ('dns', 'ntp', 'dhcp4')}
            raw['translation'] = {
                'nat64': {'enabled': nat64, 'internet_pool': '10.249.0.0/24', 'private_pool': '10.250.0.0/24'},
                'nat46': {'enabled': nat46, 'pool': '10.251.0.0/24', 'mappings': {
                    'service'+str(i): {'ipv4': '10.251.0.'+str(i+2), 'ipv6': SERVERS+str(i+10)} for i in range(6)}}}
            raw['access'] = {'default': 'deny', 'rules': [
                {'action': 'deny', 'from': {'network': 'six', 'addresses': SIX+'90'}, 'to': 'any'},
                *[{'action': 'allow', 'authorization': 'owner', 'from': source, 'to': destination,
                   'protocol': ['tcp', 'udp', 'icmp']} for source, destination in (
                       ('six', 'uplink'), ('six', 'servers'), ('four', 'uplink'), ('four', 'servers'))]]}
            value = config.normalize(raw)
            files = config.render(value, access_backend='tun')
            root = output/(str(int(nat64))+str(int(nat46)))
            root.mkdir(parents=True)
            (root/'policy.nft').write_text(files['etc/nftables.conf'])
            (root/'lab.json').write_text(json.dumps({'nat64': nat64, 'nat46': nat46,
                'components': translation.manifests(value),
                'prefixes': ['64:ff9b::/96', 'fd42:1234:5678:fd65::/96']}, sort_keys=True)+'\n')
            assert not any('policy-helper' in name or 'policy-runtime' in name for name in files)


def run(root, tayga):
    assert os.geteuid() == 0 and Path('/run/.containerenv').exists()
    assert {r['ifname'] for r in json.loads(ref.command('ip', '-j', 'link').stdout)} == {'lo'}
    lab = json.loads((root/'lab.json').read_text())
    components = {c['interface']: c for c in lab['components']}
    expected = ({'nat64', 'nat64-internal'} if lab['nat64'] else set()) | ({'nat46'} if lab['nat46'] else set())
    assert set(components) == expected
    checks, children = [], []
    with tempfile.TemporaryDirectory() as temporary:
        temporary = Path(temporary)
        temporary.chmod(0o755)
        try:
            ref.command('ip', 'link', 'set', 'lo', 'up')
            for name, prefix in (('c6', SIX+'/64'), ('p6', SERVERS+'/64'), ('c4', '10.240.40.0/24'), ('p4', '93.184.216.0/24')):
                addresses = [ref.peer(name, prefix)]
                extras = [SIX+'90'] if name == 'c6' else ([SERVERS+str(i+10) for i in range(6)] if name == 'p6' else [])
                for address in extras:
                    ref.command(*ref.inside(name, 'ip', 'addr', 'add', address+'/64', 'dev', 'eth0', 'nodad'))
                    addresses.append(address)
                ready = temporary/(name+'.ready')
                child = subprocess.Popen(ref.inside(name, sys.executable, '-c', ref.SERVER, str(ready), *addresses),
                    stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
                children.append(child)
                ref.await_file(ready, child)
            ref.ipv6_ready()
            ref.command('nft', '-f', str(root/'policy.nft'))
            account = pwd.getpwnam('nobody')
            for name, component in components.items():
                state = temporary/name
                state.mkdir(mode=0o700)
                os.chown(state, account.pw_uid, account.pw_gid)
                path = temporary/(name+'.conf')
                path.write_text(component['text'].replace(component['state_directory'], str(state)))
                ref.command('ip', 'tuntap', 'add', 'dev', name, 'mode', 'tun', 'user', str(account.pw_uid))
                ref.command('ip', 'link', 'set', name, 'up')
                for route in component['routes']:
                    ref.command('ip', '-'+str(ip.ip_network(route).version), 'route', 'add', route, 'dev', name)
                log = (temporary/(name+'.log')).open('w')
                child = subprocess.Popen([str(tayga), '-d', '--config', str(path), '--user', 'nobody',
                    '--group', grp.getgrgid(account.pw_gid).gr_name], stdin=subprocess.DEVNULL, stdout=log, stderr=log)
                log.close()
                children.append(child)
            time.sleep(.1)
            assert all(c.poll() is None for c in children)
            links = {r['ifname'] for r in json.loads(ref.command('ip', '-j', 'link').stdout)}
            assert links & {'nat64', 'nat64-internal', 'nat46'} == expected
            checks.append('only enabled translators have a TUN')
            for family in (4, 6):
                routes = json.loads(ref.command('ip', '-'+str(family), '-j', 'route').stdout)
                assert not any(r.get('dev') in {'nat64', 'nat64-internal', 'nat46'}-expected for r in routes)
            checks.append('disabled translator routes absent')
            def probe(label, network, target, source, protocol, allowed):
                flow = ref.Flow(network, target, source, 11111, protocol)
                children.append(flow.child)
                flow.check(allowed)
                flow.close()
                checks.append(label+' '+protocol)
            for protocol in ('tcp', 'udp', 'icmp'):
                probe('ordinary IPv4 Internet', 'c4', WAN, FOUR, protocol, True)
                probe('ordinary IPv6 forwarding', 'c6', SERVERS+'10', SIX+'2', protocol, True)
                for prefix in lab['prefixes']:
                    target = str(ip.ip_network(prefix).network_address+int(ip.ip_address(WAN)))
                    probe('NAT64 follows enablement', 'c6', target, SIX+'2', protocol, lab['nat64'])
                    probe('owner deny remains terminal', 'c6', target, SIX+'90', protocol, False)
                for i in range(6):
                    probe('NAT46 mapping '+str(i), 'c4', '10.251.0.'+str(i+2), FOUR, protocol, lab['nat46'])
                probe('unmapped alias', 'c4', '10.251.0.90', FOUR, protocol, False)
            print(json.dumps({'status': 'pass', 'nat64': lab['nat64'], 'nat46': lab['nat46'], 'checks': checks,
                              'runtime_compiler': False, 'runtime_yaml': False, 'directory_dependency': False}, sort_keys=True))
        finally:
            for child in reversed(children):
                if child.poll() is None:
                    child.terminate()
                child.wait(timeout=2)
            for name in ('c6', 'p6', 'c4', 'p4'):
                ref.command('ip', 'netns', 'del', name, check=False)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument('--prepare', type=Path)
    mode.add_argument('--run', type=Path)
    parser.add_argument('--tayga', type=Path)
    args = parser.parse_args()
    if args.prepare:
        prepare(args.prepare)
    else:
        assert args.tayga is not None
        run(args.run, args.tayga)
