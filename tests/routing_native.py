#!/usr/bin/env python3
"""Exercise the compiled import policy, peer capabilities and final kernel decisions offline."""

import argparse
from contextlib import ExitStack
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from lanrith import config, routing_runtime
from test_routing import declaration


LAN = 'fd42:1234:5678:10::'
WORK_A = 'fd42:1234:5678:401::/64'
WORK_B = 'fd42:1234:5678:402::/64'
VIP = 'fd42:1234:5678:610::42/128'
VPN = 'fd42:9876:5432::/48'
OUTSIDE = 'fd42:1234:5678:900::/64'
BAD_LENGTH = 'fd42:1234:5678:401::/65'
DIRECT = 'fd42:1234:5678:500::9'
DIRECT_VIP = 'fd42:1234:5678:500::42/128'
UNRELATED = '2001:db8:ffff::9'
PEERS = {'node-a': LAN+'20', 'node-b': LAN+'21', 'vpn': LAN+'e101'}


def run(*args):
    result = subprocess.run(args, text=True, capture_output=True, timeout=30)
    if result.returncode:
        raise RuntimeError(f'{args}: {result.stderr[-2000:]}')
    return result.stdout


def ns(name, *args):
    return run('nsenter', '--net=/run/netns/'+name, '--', *args)


def eventually(check, description, timeout=45):
    end = time.monotonic()+timeout
    while time.monotonic() < end:
        if check():
            return
        time.sleep(.25)
    raise AssertionError('Timed out waiting for '+description)


def scenario():
    value = declaration()
    value['services'] = {'dns': {'enabled': False}, 'ntp': {'enabled': False}}
    value['networks']['home']['dhcp4'] = {'enabled': False}
    value['hardware']['interfaces']['guest'] = {'name': 'lan.30', 'match': {'mac': '02:00:00:00:30:01'}}
    value['networks']['guest'] = {'interface': 'guest', 'ipv4': '192.168.30.0/24',
                                 'ipv6': {'subnet_id': 30, 'gua': False}}
    value['groups'].update(work_a=[WORK_A], work_b=[WORK_B], vips=['fd42:1234:5678:610::/120'])
    bgp = value['routing']['bgp']
    groups = bgp['peer_groups']
    del groups['nodes']
    for name, workload in [('node-a', 'work_a'), ('node-b', 'work_b')]:
        groups[name] = {'remote_asn': 64521, 'hold_seconds': 9, 'peers': {name: PEERS[name]},
                        'import': [{'group': workload, 'purpose': 'network', 'exact': True, 'fallback': 'bgp_only'},
                                   {'group': 'vips', 'purpose': 'service', 'prefix_length': 128, 'fallback': 'bgp_only'}]}
    value['groups']['direct_vip'] = [DIRECT_VIP]
    groups['node-a']['import'].append({'group': 'direct_vip', 'purpose': 'service',
                                        'exact': True, 'fallback': 'routing_table'})
    groups['vpn'].pop('services')
    groups['vpn']['import'][0]['fallback'] = 'bgp_only'
    bgp['import_ownership'] = [
        {'prefix': WORK_A, 'origins': [PEERS['node-a']]}, {'prefix': WORK_B, 'origins': [PEERS['node-b']]},
        {'prefix': VIP, 'origins': [PEERS['node-a'], PEERS['node-b']]}, {'prefix': OUTSIDE, 'origins': []},
        {'prefix': VPN, 'origins': [groups['vpn']['dynamic']['range']]}]
    return value


def connect_peers():
    ns('router', 'ip', 'link', 'add', 'lan', 'type', 'bridge')
    for index, (name, address) in enumerate(PEERS.items()):
        port = 'port'+str(index)
        ns('router', 'ip', 'link', 'add', port, 'type', 'veth', 'peer', 'name', 'eth0', 'netns', name)
        ns('router', 'ip', 'link', 'set', port, 'master', 'lan')
        ns('router', 'ip', 'link', 'set', port, 'up')
        ns(name, 'ip', '-6', 'addr', 'add', address+'/64', 'dev', 'eth0', 'nodad')
        ns(name, 'ip', 'link', 'set', 'eth0', 'up')
    ns('router', 'ip', 'link', 'set', 'lan', 'up')
    ns('router', 'ip', '-6', 'addr', 'add', LAN+'1/64', 'dev', 'lan', 'nodad')


def vty(directory, *commands):
    output = ''
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
        client.settimeout(10)
        client.connect(str(directory/'bgpd.vty'))
        for command in ('enable', *commands):
            client.sendall(command.encode()+b'\0')
            reply = b''
            while len(reply) < 4 or reply[-4:-1] != b'\0\0\0':
                chunk = client.recv(65536)
                assert chunk, 'FRR control socket closed.'
                reply += chunk
            message, status = reply[:-4], reply[-1]
            assert status == 0, (command, message, status)
            output += message.decode()
    return output


def peer_config(name, password):
    vpn = name == 'vpn'
    announcements = [VPN, 'fd42:9876:5432:1::/64'] if vpn else [WORK_A, WORK_B, VIP, DIRECT_VIP, BAD_LENGTH]
    router = LAN+'1'
    return '\n'.join([
        'frr defaults traditional', f'hostname {name}', f'router bgp {64522 if vpn else 64521}',
        ' bgp router-id 192.0.2.'+str(20+list(PEERS).index(name)), ' no bgp default ipv4-unicast',
        ' no bgp ebgp-requires-policy', ' no bgp network import-check',
        f' neighbor {router} remote-as 64520', f' neighbor {router} timers 3 9',
        f' neighbor {router} timers connect 1', f' neighbor {router} update-source {PEERS[name]}',
        *([f' neighbor {router} password {password}'] if vpn else []),
        ' address-family ipv6 unicast', f'  neighbor {router} activate',
        *('  network '+p for p in announcements+[OUTSIDE, '::/0']), ' exit-address-family', ''])


def qualify(systemd, appliance):
    assert os.geteuid() == 0 and socket.if_nameindex() == [(1, 'lo')]
    if systemd:
        assert Path('/proc/1/comm').read_text().strip() == 'systemd'
        assert not Path('/usr/share/lanrith/installed.json').exists()
        if appliance:
            assert appliance.is_mount() and (appliance/'usr/share/lanrith/platform-version').is_file()
    else:
        mapped_root = Path('/proc/self/uid_map').read_text().splitlines()[0].split()
        assert Path('/run/.containerenv').exists() or mapped_root[0] == '0' and int(mapped_root[1]) > 0
    package = ['chroot', str(appliance)] if appliance else []
    files = config.render(scenario())
    children, streams, namespaces = {}, [], []
    with tempfile.TemporaryDirectory(prefix='routing.') as temporary, ExitStack() as mounts:
        work = Path(temporary)
        work.chmod(0o755)
        if appliance:
            assert systemd
            for name in ('tmp', 'run', 'proc', 'sys', 'dev'):
                target = str(appliance/name)
                if name in ('tmp', 'run'):
                    run('mount', '-t', 'tmpfs', 'tmpfs', target)
                else:
                    run('mount', '--bind', '/'+name, target)
                mounts.callback(run, 'umount', target)
            target = appliance/str(work).lstrip('/')
            target.mkdir()
            run('mount', '--bind', str(work), str(target))
            mounts.callback(run, 'umount', str(target))
            run('chroot', str(appliance), 'install', '-d', '-o', 'frr', '-g', 'frr', '/run/frr')
            for binary in ('bgpd', 'zebra'):
                path = appliance/'usr/lib/frr'/binary
                print(binary, hashlib.sha256(path.read_bytes()).hexdigest(), flush=True)
        elif systemd:
            print('FRR package', run('dpkg-query', '-W', '-f', '${Version}', 'frr'), flush=True)
        credential_dir = work/'credentials'
        credential_dir.mkdir(mode=0o700)
        password = 'synthetic-offline-bgp-key'
        (credential_dir/'vpn_bgp').write_text(password)
        (credential_dir/'vpn_bgp').chmod(0o600)
        routing_runtime.materialize(json.loads(files['usr/share/lanrith/routing.json']),
                                    credential_dir, work/'router.conf')
        router_config = (work/'router.conf').read_text()

        def start(name, binary, contents):
            directory = work/(name+'-'+binary)
            directory.mkdir(exist_ok=True)
            directory.chmod(0o777)
            (directory/(binary+'.vty')).unlink(missing_ok=True)
            path = directory/'daemon.conf'
            path.write_text(contents)
            log = (directory/'daemon.log').open('a')
            streams.append(log)
            args = ['nsenter', '--net=/run/netns/'+name, '--', *package, '/usr/lib/frr/'+binary,
                    '-f', str(path), '-i', str(directory/'pid'), '--vty_socket', str(directory),
                    '-z', str(work/(name+'-zebra')/'zserv.api'), '-A', '127.0.0.1', '--limit-fds', '1024']
            if name != 'router':
                args += ['-S', '-Z']
            child = children[name, binary] = subprocess.Popen(args, stdout=log, stderr=log)
            eventually(lambda: (directory/(binary+'.vty')).exists() or child.poll() is not None, name+' '+binary)
            assert child.poll() is None, (directory/'daemon.log').read_text()
            return directory

        def stop(name):
            child = children.pop((name, 'bgpd'))
            child.terminate()
            child.wait(timeout=10)

        def route_to(address):
            result = subprocess.run(['nsenter', '--net=/run/netns/router', '--', 'ip', '-6', '-j',
                                     'route', 'get', address], text=True, capture_output=True, timeout=10)
            if result.returncode:
                assert 'No route to host' in result.stderr, (address, result.stderr)
                return 'unreachable'
            row = json.loads(result.stdout)[0]
            return row.get('gateway', row['dev'])

        def lookup(prefix, allowed):
            network = ipaddress.ip_network(prefix)
            address = network.network_address if network.prefixlen == 128 else network.network_address+9
            eventually(lambda: route_to(str(address)) in allowed, f'kernel lookup of {address} in {allowed}')

        def imported(name):
            output = vty(router, 'show bgp ipv6 unicast neighbors '+PEERS[name]+' routes json')
            return set(json.loads(output).get('routes', {}))

        def established(name):
            peers = json.loads(vty(router, 'show bgp ipv6 unicast summary json')).get('peers', {})
            return peers.get(PEERS[name], {}).get('state') == 'Established'

        def check_all():
            expected = {'node-a': {WORK_A, VIP, DIRECT_VIP}, 'node-b': {WORK_B, VIP}, 'vpn': {VPN}}
            for name, prefixes in expected.items():
                eventually(lambda: established(name) and imported(name) == prefixes, name+' import policy')
                peer = work/(name+'-bgpd')
                exported = json.loads(vty(peer, f'show bgp ipv6 unicast neighbors {LAN}1 routes json'))
                assert not exported.get('routes'), (name, exported)
                remote_info = json.loads(vty(peer, f'show bgp neighbors {LAN}1 json'))[LAN+'1']
                local_info = json.loads(vty(router, f'show bgp neighbors {PEERS[name]} json'))[PEERS[name]]
                remote_gr = remote_info['gracefulRestartInfo']
                local_gr = local_info['gracefulRestartInfo']
                assert remote_gr['nBit'] is False and local_gr['nBit'] is True, (remote_gr, local_gr)
            lookup(WORK_A, [PEERS['node-a']])
            lookup(DIRECT_VIP, [PEERS['node-a']])
            lookup(WORK_B, [PEERS['node-b']])
            lookup(VPN, [PEERS['vpn']])
            lookup(VIP, [PEERS['node-a'], PEERS['node-b']])

        def announce(name, prefix, enabled):
            peer = work/(name+'-bgpd')
            asn = 64522 if name == 'vpn' else 64521
            vty(peer, 'configure terminal', f'router bgp {asn}', 'address-family ipv6 unicast',
                ('network ' if enabled else 'no network ')+prefix, 'end')

        try:
            for name in ('router', *PEERS, 'wrong'):
                if name == 'router' and systemd:
                    run('ip', 'netns', 'attach', name, str(os.getpid()))
                else:
                    run('ip', 'netns', 'add', name)
                namespaces.append(name)
                ns(name, 'ip', 'link', 'set', 'lo', 'up')
            connect_peers()
            ns('router', 'ip', 'link', 'add', 'lan.30', 'type', 'veth', 'peer', 'name', 'eth0', 'netns', 'wrong')
            ns('router', 'ip', 'link', 'set', 'lan.30', 'up')
            ns('router', 'ip', '-6', 'addr', 'add', 'fd42:1234:5678:1e::1/64', 'dev', 'lan.30', 'nodad')
            ns('wrong', 'ip', 'link', 'set', 'eth0', 'up')
            ns('wrong', 'ip', '-6', 'addr', 'add', 'fd42:1234:5678:1e::20/64', 'dev', 'eth0', 'nodad')
            ns('router', 'ip', 'link', 'add', 'wan', 'type', 'dummy')
            ns('router', 'ip', 'link', 'set', 'wan', 'up')
            ns('router', 'ip', '-6', 'addr', 'add', '2001:db8:1::1/64', 'dev', 'wan', 'nodad')
            ns('router', 'ip', '-6', 'route', 'add', 'default', 'dev', 'wan')
            ns('router', 'ip', '-6', 'route', 'add', 'fd42:1234:5678:500::/64', 'dev', 'lan')

            fallback = 'etc/systemd/network/10-bgp-fallback.network'
            if systemd:
                for path in (fallback, 'etc/systemd/networkd.conf.d/60-lanrith-route-owners.conf'):
                    dest = Path('/')/path
                    dest.parent.mkdir(exist_ok=True, parents=True)
                    dest.write_text(files[path])
                run('systemctl', 'start', 'systemd-networkd')
            else:
                for section in files[fallback].split('[Route]')[1:]:
                    route = dict(line.split('=', 1) for line in section.strip().splitlines())
                    ns('router', 'ip', '-6', 'route', 'add', route['Type'], route['Destination'],
                       'proto', 'static', 'metric', route['Metric'])
            firewall = work/'router.nft'
            firewall.write_text(files['etc/nftables.conf'])
            ns('router', *package, '/usr/sbin/nft', '-f', str(firewall))
            for prefix in (WORK_A, WORK_B, VIP, VPN):
                lookup(prefix, ['unreachable'])
            assert route_to(UNRELATED) == 'wan' and route_to(DIRECT) == 'lan'
            start('router', 'zebra', 'hostname synthetic-router\n')
            router = start('router', 'bgpd', router_config)
            for name in PEERS:
                start(name, 'bgpd', peer_config(name, password))
            check_all()
            print('Three sessions established, router N-bit clear, peer N-bit set; exclusive and shared routes match.', flush=True)
            for name, prefix in [('node-a', WORK_A), ('vpn', VPN), ('node-a', DIRECT_VIP)]:
                announce(name, prefix, False)
                lookup(prefix, ['lan'] if prefix == DIRECT_VIP else ['unreachable'])
                lookup(WORK_B, [PEERS['node-b']])
                assert established(name) and route_to(DIRECT) == 'lan' and route_to(UNRELATED) == 'wan'
                announce(name, prefix, True)
                lookup(prefix, [PEERS[name]])
            announce('node-a', VIP, False)
            lookup(VIP, [PEERS['node-b']])
            announce('node-b', VIP, False)
            lookup(VIP, ['unreachable'])
            announce('node-a', VIP, True)
            lookup(VIP, [PEERS['node-a']])
            announce('node-b', VIP, True)
            def pinned_sessions():
                return {name: json.loads(vty(router, f'show bgp neighbors {PEERS[name]} json'))[
                    PEERS[name]]['connectionsEstablished'] for name in ('node-a', 'node-b')}

            before = pinned_sessions()
            if systemd:
                run('systemctl', 'restart', 'systemd-networkd')
                check_all()

            # A change at a single peer must preserve the other established routes.
            stop('vpn')
            lookup(VPN, ['unreachable'])
            start('vpn', 'bgpd', peer_config('vpn', 'wrong-test-password'))
            eventually(lambda: 'e101' in ns('vpn', 'ss', '-H', '-nt', 'state', 'syn-sent'),
                       'fresh connection with the retired key')
            assert not established('vpn')
            lookup(WORK_A, [PEERS['node-a']])
            lookup(DIRECT_VIP, [PEERS['node-a']])
            lookup(WORK_B, [PEERS['node-b']])
            stop('vpn')
            start('vpn', 'bgpd', peer_config('vpn', password))
            check_all()

            assert pinned_sessions() == before, 'An unrelated pinned BGP session restarted.'

            program = ('import socket,sys;s=socket.socket(socket.AF_INET6);s.settimeout(.5)\n'
                       'try:s.connect(("fd42:1234:5678:1e::1",179))\n'
                       'except OSError:sys.exit(10)\n')
            result = subprocess.run(['nsenter', '--net=/run/netns/wrong', '--', 'python3', '-c', program])
            assert result.returncode == 10, 'Undeclared peer reached BGP.'
            stop('router')
            for prefix in (WORK_A, WORK_B, VIP, VPN):
                lookup(prefix, ['unreachable'])
            router = start('router', 'bgpd', router_config)
            check_all()
            ns('router', 'ip', 'link', 'set', 'lan', 'down')
            for prefix in (WORK_A, WORK_B, VIP, VPN):
                lookup(prefix, ['unreachable'])
            assert route_to(UNRELATED) == 'wan'
            print('Ordinary withdrawals, independent peer loss, MD5 rejection, default and direct fallback, '
                  'and router restart passed.', flush=True)
        except BaseException:
            for path in work.glob('*/daemon.log'):
                print(path.parent.name, path.read_text()[-1500:])
            print('Kernel routes', ns('router', 'ip', '-6', 'route'))
            raise
        finally:
            for child in reversed(list(children.values())):
                child.terminate()
            for child in children.values():
                try:
                    child.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    child.kill()
                    child.wait()
            for stream in streams:
                stream.close()
            for name in reversed(namespaces):
                run('ip', 'netns', 'del', name)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(__doc__)
    parser.add_argument('--systemd', action='store_true')
    parser.add_argument('--appliance-root', type=Path)
    args = parser.parse_args()
    qualify(args.systemd, args.appliance_root)
