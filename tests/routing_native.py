#!/usr/bin/env python3
"""Real FRR peering and import/withdrawal checks in an offline container."""

import json
import os
import socket
from pathlib import Path
import subprocess
import sys
import tempfile
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from lanrith import config, routing_runtime
from test_routing import declaration


def run(*args, **kwargs):
    result = subprocess.run(args, text=True, capture_output=True, timeout=20, **kwargs)
    if result.returncode:
        raise RuntimeError(str(args[:2])+': '+result.stderr[-2000:])
    return result.stdout


def ns(name, *args):
    return run('nsenter', '--net=/run/netns/'+name, '--', *args)


def eventually(check, timeout=30):
    end = time.monotonic()+timeout
    while time.monotonic() < end:
        if check():
            return
        time.sleep(.2)
    raise AssertionError('FRR state did not converge within the test bound.')


def main():
    assert os.geteuid() == 0 and Path('/run/.containerenv').exists()
    assert {p.name for p in Path('/sys/class/net').iterdir()} == {'lo'}
    children, streams, namespaces = [], [], []
    with tempfile.TemporaryDirectory(prefix='lanrith-routing.') as temporary:
        work = Path(temporary)
        work.chmod(0o755)
        value = declaration()
        # This scenario tests one pinned peer. The separate dynamic scenario
        # below exercises the authenticated listener and exact VPN import.
        del value['routing']['bgp']['peer_groups']['vpn']
        value['services'] = {'dns': {'enabled': False}, 'ntp': {'enabled': False}}
        value['networks']['home']['dhcp4'] = {'enabled': False}
        value['hardware']['interfaces']['guest'] = {'name': 'lan.30', 'match': {'mac': '02:00:00:00:30:01'}}
        value['networks']['guest'] = {'interface': 'guest', 'ipv4': '192.168.30.0/24',
                                     'ipv6': {'subnet_id': 30, 'gua': False}}
        value = config.normalize(value)
        files = config.render(value)
        try:
            for name in ('router', 'peer', 'wrong'):
                run('ip', 'netns', 'add', name)
                namespaces.append(name)
                ns(name, 'ip', 'link', 'set', 'lo', 'up')
            for name, iface, subnet, address in (('peer', 'lan', '10', '20'), ('wrong', 'lan.30', '1e', '20')):
                ns('router', 'ip', 'link', 'add', iface, 'type', 'veth', 'peer', 'name', 'eth0', 'netns', name)
                ns('router', 'ip', '-6', 'addr', 'add', f'fd42:1234:5678:{subnet}::1/64', 'dev', iface, 'nodad')
                ns(name, 'ip', '-6', 'addr', 'add', f'fd42:1234:5678:{subnet}::{address}/64', 'dev', 'eth0', 'nodad')
                ns('router', 'ip', 'link', 'set', iface, 'up')
                ns(name, 'ip', 'link', 'set', 'eth0', 'up')
            ns('router', 'ip', 'link', 'add', 'wan', 'type', 'dummy')
            firewall = work/'router.nft'
            firewall.write_text(files['etc/nftables.conf'])
            ns('router', 'nft', '-f', str(firewall))

            def daemon(namespace, binary, text, *, zebra=False):
                directory = work/(namespace+'-'+binary)
                directory.mkdir(mode=0o777, exist_ok=True)
                directory.chmod(0o777)
                (directory/(binary+'.vty')).unlink(missing_ok=True)
                path = directory/'daemon.conf'
                path.write_text(text)
                stream = (directory/'daemon.log').open('w')
                streams.append(stream)
                args = ['nsenter', '--net=/run/netns/'+namespace, '--', '/usr/lib/frr/'+binary,
                        '-f', str(path), '-i', str(directory/'pid'), '--vty_socket', str(directory),
                        '-z', str(work/(namespace+'-zebra')/'zserv.api'), '-A', '127.0.0.1',
                        '--limit-fds', '1024']
                if binary == 'bgpd':
                    args += ['-S'] if not zebra else []
                    if not zebra:
                        args += ['-Z']
                child = subprocess.Popen(args, stdout=stream, stderr=stream)
                children.append(child)
                eventually(lambda: (directory/(binary+'.vty')).exists() or child.poll() is not None)
                assert child.poll() is None, (directory/'daemon.log').read_text()
                return directory

            router_zebra = daemon('router', 'zebra', 'hostname test-router\n')
            router = daemon('router', 'bgpd', files['etc/frr/frr.conf'], zebra=True)
            peer_text = '''frr defaults traditional
hostname synthetic-peer
router bgp 64521
 bgp router-id 192.0.2.20
 no bgp default ipv4-unicast
 no bgp ebgp-requires-policy
 no bgp network import-check
 neighbor fd42:1234:5678:10::1 remote-as 64520
 neighbor fd42:1234:5678:10::1 timers 3 9
 address-family ipv6 unicast
  neighbor fd42:1234:5678:10::1 activate
  network fd42:1234:5678:401::/64
  network fd42:1234:5678:402::/65
  network fd42:1234:5678:600::/64
  network ::/0
 exit-address-family
'''
            peer = daemon('peer', 'bgpd', peer_text)

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

            def routes():
                raw = vty(router, 'show bgp ipv6 unicast json')
                if not raw.lstrip().startswith('{'):
                    raise AssertionError('Unexpected FRR response: '+repr(raw))
                return json.loads(raw).get('routes', {})

            accepted = 'fd42:1234:5678:401::/64'
            eventually(lambda: accepted in routes())
            assert set(routes()) == {accepted}, routes()
            eventually(lambda: any(r.get('dst') == accepted for r in json.loads(
                ns('router', 'ip', '-6', '-j', 'route', 'show', 'protocol', 'bgp'))))
            # The peer receives no exported connected, static or learned routes.
            exported = json.loads(vty(peer, 'show bgp ipv6 unicast neighbors fd42:1234:5678:10::1 routes json'))
            assert not exported.get('routes'), exported
            vty(peer, 'configure terminal', 'router bgp 64521', 'address-family ipv6 unicast',
                'no network '+accepted, 'end')
            eventually(lambda: accepted not in routes())
            eventually(lambda: all(r.get('dst') != accepted for r in json.loads(
                ns('router', 'ip', '-6', '-j', 'route', 'show', 'protocol', 'bgp'))))

            # A source outside the pinned set cannot open the BGP listener.
            program = ('import socket,sys;s=socket.socket(socket.AF_INET6);s.settimeout(.5)\n'
                       'try:s.connect(("fd42:1234:5678:1e::1",179))\n'
                       'except OSError:sys.exit(10)\n')
            result = subprocess.run(['nsenter', '--net=/run/netns/wrong', '--', 'python3', '-c', program])
            assert result.returncode == 10, 'Undeclared peer reached the BGP listener.'
            for child in children[1:]:
                child.terminate()
                child.wait(timeout=5)
            children = children[:1]
            vpn = declaration()['routing']['bgp']['peer_groups']['vpn']
            vpn.pop('services')
            value['routing']['bgp']['peer_groups']['vpn'] = vpn
            files = config.render(value)
            firewall.write_text(files['etc/nftables.conf'])
            ns('router', 'nft', '-f', str(firewall))
            credential_dir = work/'credentials'
            credential_dir.mkdir(mode=0o700)
            (credential_dir/'vpn_bgp').write_text('synthetic-bgp-test-password')
            (credential_dir/'vpn_bgp').chmod(0o600)
            routing_runtime.materialize(json.loads(files['usr/share/lanrith/routing.json']),
                                        credential_dir, work/'authenticated.conf')
            router = daemon('router', 'bgpd', (work/'authenticated.conf').read_text(), zebra=True)
            ns('peer', 'ip', '-6', 'addr', 'add', 'fd42:1234:5678:10::e101/64', 'dev', 'eth0', 'nodad')
            vpn_text = '''frr defaults traditional
hostname synthetic-vpn-peer
router bgp 64522
 bgp router-id 192.0.2.21
 no bgp default ipv4-unicast
 no bgp ebgp-requires-policy
 no bgp network import-check
 neighbor fd42:1234:5678:10::1 remote-as 64520
 neighbor fd42:1234:5678:10::1 update-source fd42:1234:5678:10::e101
 neighbor fd42:1234:5678:10::1 password synthetic-bgp-test-password
 neighbor fd42:1234:5678:10::1 timers 3 9
 address-family ipv6 unicast
  neighbor fd42:1234:5678:10::1 activate
  network fd42:9876:5432::/48
  network fd42:9876:5432:1::/64
  network ::/0
 exit-address-family
'''
            peer = daemon('peer', 'bgpd', vpn_text)
            accepted = 'fd42:9876:5432::/48'
            eventually(lambda: accepted in routes())
            assert set(routes()) == {accepted}, routes()
            summary = json.loads(vty(router, 'show bgp ipv6 unicast summary json'))
            assert summary['peers']['fd42:1234:5678:10::e101']['state'] == 'Established', summary
            # Replace the key at the client and force a fresh connection.
            # A previously established session must not hide a failed MD5 gate.
            child = children.pop()
            child.terminate()
            child.wait(timeout=5)
            eventually(lambda: accepted not in routes())
            peer = daemon('peer', 'bgpd', vpn_text.replace('synthetic-bgp-test-password', 'wrong-test-password'))
            time.sleep(4)
            assert not routes(), routes()
            assert 'e101' in ns('peer', 'ss', '-H', '-nt', 'state', 'syn-sent'), (
                'The negative control must attempt an authenticated TCP connection.')
            child = children.pop()
            child.terminate()
            child.wait(timeout=5)
            peer = daemon('peer', 'bgpd', vpn_text)
            eventually(lambda: accepted in routes())
            print('FRR accepted only the declared /64, installed and withdrew its kernel route, '
                  'rejected wrong-length/out-of-pool/default advertisements, exported no routes, '
                  'denied an undeclared peer, and admitted an exact dynamic VPN prefix only '
                  'with the declared MD5 credential.')
        except BaseException:
            for path in work.glob('*/daemon.log'):
                print(path.name, path.read_text()[-5000:])
            raise
        finally:
            for child in reversed(children):
                child.terminate()
            for child in children:
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
    main()
