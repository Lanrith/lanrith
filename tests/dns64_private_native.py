#!/usr/bin/env python3
"""Qualify DNS64 forward, reverse and TCP traffic in an offline systemd VM."""

import argparse
from contextlib import ExitStack
import ipaddress as ip
import json
from pathlib import Path
import shutil
import subprocess
import sys
import time

from discovery_dns_native import DEVICE, DEVICE6, PARENT, announce, device_socket, prepare
from dns_migration_native import install as install_files
from lanrith import config
from test_authoritative import declaration
from unbound_native import network, run, upstream

CLIENT = 'fd42:1234:5678:50::2'
SECOND = '192.168.30.45'
PORT = 9163
REVERSE = '7.27.172.in-addr.arpa'
PREFIX = ip.ip_network('fd42:1234:5678:fd65::/96')
ROOT = Path(__file__).resolve().parents[1]


def declare(value):
    for name, suffix in [('sensors', '30'), ('client', '50')]:
        value['hardware']['interfaces'][name] = {'name': name, 'match': {'mac': '02:00:00:00:'+suffix+':01'}}
    value['networks']['sensors'] = {'interface': 'sensors', 'ipv4': '192.168.30.0/24'}
    value['networks']['client'] = {'interface': 'client', 'ipv6': {'subnet_id': 0x50, 'ra': False}, 'dns': True}
    discovery = value['services']['discovery']
    discovery['networks'].append('sensors')
    auth = value['services']['dns']['authoritative']
    auth['zones'][PARENT.rstrip('.')]['discovery_delegation']['views'].append('sensors')
    auth['zones']['home.arpa']['records']['external'] = {'CNAME': 'only4.public.example.net.'}
    auth['zones']['home.arpa']['records']['unsigned'] = {'CNAME': 'only4.secure.example.net.'}
    auth['zones'][REVERSE] = {}
    value['access']['rules'] = [
        {'action': 'allow', 'authorization': 'owner', 'protocol': 'tcp', 'ports': [PORT],
         'from': {'network': 'client', 'addresses': CLIENT}, 'to': {'network': network, 'addresses': address}}
        for network, address in [('home', DEVICE), ('sensors', SECOND)]]


def install(platform, files):
    # This synthetic trust anchor requires DNSSEC at a second public fixture zone.
    # Its unsigned address data exercises the public validator for an external alias.
    with Path('/etc/unbound/unbound.conf.d/98-fixture.conf').open('a') as conf:
        conf.write('  trust-anchor: "secure.example.net. IN DS 12345 13 2 '+'ab'*32+'"\n')
    # Dynamic DNS and mDNS can supply addresses that seed validation excludes.
    with Path('/usr/share/lanrith/zones/db.home.arpa').open('a') as zone:
        zone.write('zero4 IN A 0.0.0.0\nzero6 IN AAAA ::\nalias4 IN CNAME zero4\nalias6 IN CNAME zero6\n')
    with Path('/usr/share/lanrith/zones/db.'+REVERSE).open('a') as zone:
        zone.write('44 IN PTR bound.home.arpa.\n')
    install_files({name: content for name, content in files.items() if
                   'nat64-internal' in name and name.startswith(('usr/lib/systemd/', 'usr/lib/sysusers.d/',
                       'usr/lib/tmpfiles.d/', 'usr/share/lanrith/', 'etc/tayga'))})
    library = Path('/usr/lib/lanrith/lanrith')
    for name in ('release.py', 'translation_runtime.py', '__init__.py'):
        shutil.copy2(ROOT/'lanrith'/name, library/name)
    shutil.copy2(platform/'usr/lib/lanrith/tayga-internal', library.parent)
    for path in ('usr/sbin/conntrack', 'usr/lib/x86_64-linux-gnu/libnetfilter_conntrack.so.3',
                 'usr/lib/x86_64-linux-gnu/libnfnetlink.so.0'):
        if not (Path('/')/path).exists():
            shutil.copy2(platform/path, Path('/')/path)
    run('systemd-sysusers', '80-lanrith-nat64-internal.conf')
    run('systemd-tmpfiles', '--create', '80-lanrith-nat64-internal.conf')
    network('sensors', '192.168.30.1', SECOND)
    run('ip', '-n', 'lan', 'addr', 'add', DEVICE+'/24', 'dev', 'eth0')
    run('ip', '-n', 'lan', 'addr', 'add', '192.168.10.46/24', 'dev', 'eth0')
    run('ip', 'netns', 'exec', 'sensors', 'ethtool', '--offload', 'eth0', 'tx', 'off')
    run('ethtool', '--offload', 'sensors', 'tx', 'off')
    run('ip', 'netns', 'add', 'client')
    run('ip', 'link', 'add', 'client', 'type', 'veth', 'peer', 'name', 'eth0', 'netns', 'client')
    run('ip', '-6', 'addr', 'add', 'fd42:1234:5678:50::1/64', 'dev', 'client', 'nodad')
    run('ip', 'link', 'set', 'client', 'up')
    run('ip', '-n', 'client', 'link', 'set', 'eth0', 'up')
    run('ip', '-n', 'client', '-6', 'addr', 'add', CLIENT+'/64', 'dev', 'eth0', 'nodad')
    run('ip', '-n', 'client', '-6', 'route', 'add', 'default', 'via', 'fd42:1234:5678:50::1')
    assert not json.loads(run('ip', '-n', 'client', '-4', '-j', 'address', 'show', 'scope', 'global').stdout)
    run('modprobe', 'tun')


def synth(address):
    return PREFIX.network_address + int(ip.ip_address(address))


def query(entry, name, kind):
    namespace, address, port = entry
    result = run('ip', 'netns', 'exec', namespace, 'dig', '+tries=1', '+time=32',
                 '+noall', '+comments', '+answer', '@'+address, '-p', str(port), name, kind)
    return result.stdout


def has_answer(response, kind, target):
    return any(row[3:] == [kind, target] for line in response.splitlines()
               if (row := line.split()) and not line.startswith(';'))


def server(stack, namespace, address):
    ready = Path('/run')/('dns64-server-'+address)
    program = """import pathlib,socket,sys
with socket.create_server((sys.argv[1], int(sys.argv[2]))) as server:
    pathlib.Path(sys.argv[3]).touch()
    while True:
        client, _ = server.accept()
        with client:
            client.sendall(b'fixture response')
"""
    child = subprocess.Popen(['ip', 'netns', 'exec', namespace, sys.executable, '-c', program,
                              address, str(PORT), ready])
    stack.callback(child.wait, timeout=5)
    stack.callback(child.terminate)
    for _ in range(100):
        if ready.exists():
            return
        assert child.poll() is None
        time.sleep(.05)
    raise RuntimeError('IPv4 test service failed to listen.')


def connect(address, allowed=True):
    program = """import socket,sys
try:
    with socket.create_connection((sys.argv[1],int(sys.argv[2])),timeout=2) as client:
        assert client.recv(64) == b'fixture response'
except OSError:
    sys.exit(2)
"""
    result = run('ip', 'netns', 'exec', 'client', sys.executable, '-c', program, address, str(PORT), check=False)
    assert result.returncode == (0 if allowed else 2), (address, result.stderr)


def reverse_listener():
    command = ['ip', 'netns', 'exec', 'lanrith-services']
    name = synth('172.27.7.44').reverse_pointer
    for user, group, admitted in [('unbound', 'unbound', True), ('nobody', 'nogroup', False)]:
        result = run(*command, 'setpriv', '--reuid='+user, '--regid='+group, '--clear-groups',
                     'dig', '+tcp', '+short', '+tries=1', '+time=1', '@127.0.0.1', '-p', '5356',
                     name, 'PTR', check=False)
        assert (result.returncode == 0) == admitted, (user, result.stdout)
        if admitted:
            assert result.stdout.strip() == 'bound.home.arpa.', result.stdout
    listeners = run(*command, 'ss', '-Hlnut', 'sport = :5356').stdout.splitlines()
    assert len(listeners) == 2 and all(row.startswith('tcp') for row in listeners), listeners
    print('Only Unbound reached the TCP reverse listener from an unprivileged namespace account.', flush=True)


def local_transports(client, private):
    # Both families remain available on the links. The rendered resolver's
    # do-not-query policy must still admit its selected local upstreams.
    value = declaration()
    value['translation'] = {'nat64': {'enabled': True}}
    value['services']['dns']['authoritative']['zones'][REVERSE] = {}
    for v4, v6 in [('dhcp', 'disabled'), ('disabled', 'ra'), ('disabled', 'disabled')]:
        value['uplink'].update(ipv4=v4, ipv6=v6)
        files = config.render(value)
        # The previous discovery profile's include belongs to that profile.
        Path('/etc/unbound/unbound.conf.d/61-lanrith-discovery.conf').unlink(missing_ok=True)
        install_files({name: content for name, content in files.items() if name.startswith('etc/unbound/')})
        run('systemctl', 'restart', 'lanrith-dns64-reverse', 'lanrith-dns64-private', 'unbound')
        for entry in (client, private):
            response = query(entry, synth('172.27.7.44').reverse_pointer, 'PTR')
            assert has_answer(response, 'PTR', 'bound.home.arpa.'), (v4, v6, entry, response)
        print('Internal PTR reached BIND with uplink modes', v4, v6, flush=True)


def qualify(platform, bridge):
    endpoints = prepare(platform, bridge, discovery_only=False, dns64=True, configure=declare, install_profile=install)
    client = ('client', endpoints['dns'][1], 53)
    private = ('lanrith-services', '::1', 5354)
    work = Path('/run/private-dns64-fixture')
    work.mkdir()
    with ExitStack() as stack:
        upstream(work, stack, tls=False,
                 extra_zones='  local-zone: "secure.example.net." static\n'
                             '  local-data: "secure.example.net. 60 IN SOA ns.secure.example.net. hostmaster.secure.example.net. 1 60 60 60 60"\n'
                             '  local-data: "only4.secure.example.net. 60 IN A 93.184.216.34"\n')
        device = stack.enter_context(device_socket())
        sensor = stack.enter_context(device_socket(SECOND, 'sensors'))
        for namespace, address in [('lan', DEVICE), ('lan', '192.168.10.46'), ('sensors', SECOND)]:
            server(stack, namespace, address)
        run('systemctl', 'start', 'lanrith-nat64-internal')
        for phase in ['initial', 'resolver', 'translator']:
            if phase == 'resolver':
                run('systemctl', 'restart', 'lanrith-dns64-private', 'unbound')
            if phase == 'translator':
                run('systemctl', 'restart', 'lanrith-nat64-internal')
            for view, peer, address in [('home', device, DEVICE), ('sensors', sensor, SECOND)]:
                label = 'only4-'+phase
                announce(peer, label, ipv4=address, reverse=True)
                name = label+'.'+view+'.'+PARENT
                response = query(client, name, 'AAAA')
                assert has_answer(response, 'AAAA', str(synth(address))), response
                destination = next(parts[4] for row in response.splitlines() if (parts := row.split())[3:4] == ['AAAA'])
                connect(destination)
                print(phase, name, destination, 'TCP response received', flush=True)
        announce(device, 'denied', ipv4='192.168.10.46')
        result = query(client, 'denied.home.'+PARENT, 'AAAA')
        assert has_answer(result, 'AAAA', str(synth('192.168.10.46'))), result
        connect(str(synth('192.168.10.46')), allowed=False)
        announce(device, 'native', ipv6=DEVICE6)
        for entry in [private, client]:
            for name, kind, answer in [('native.home.'+PARENT, 'AAAA', DEVICE6),
                    ('external.home.arpa.', 'AAAA', '64:ff9b::5db8:d822'),
                    (synth('172.27.7.44').reverse_pointer, 'PTR', 'bound.home.arpa.'),
                    (synth(SECOND).reverse_pointer, 'PTR', 'only4-translator.sensors.'+PARENT)]:
                response = query(entry, name, kind)
                assert has_answer(response, kind, answer), (entry, name, response)
            for name in [synth('172.27.7.99').reverse_pointer, synth('93.184.216.34').reverse_pointer,
                         ip.ip_address('fd42:1234:5678:9999::1').reverse_pointer]:
                response = query(entry, name, 'PTR')
                assert 'status: NXDOMAIN' in response, (entry, name, response)
            response = query(entry, 'unsigned.home.arpa.', 'AAAA')
            assert 'status: SERVFAIL' in response and 'ANSWER: 0' in response, response
            response = query(entry, synth('192.168.30.47').reverse_pointer, 'PTR')
            assert 'status: NOERROR' in response and 'ANSWER: 0' in response, response
            for label in ['alias4', 'alias6', 'zero4', 'zero6']:
                for kind in ['AAAA', 'A']:
                    response = query(entry, label+'.home.arpa.', kind)
                    assert ('status: NXDOMAIN' in response or 'status: NOERROR' in response) and not any(
                        row.split()[3] in ('A', 'AAAA') for row in response.splitlines() if row and row[0] != ';'), response
            print('Known and missing PTRs, native AAAA, external alias and zero guards passed at', entry, flush=True)
        log = (work/'plain.log').read_text()
        assert 'public.example.net' in log and not any(suffix in log for suffix in
            ['in-addr.arpa.', 'ip6.arpa.', PARENT, 'home.arpa.']), log
        reverse_listener()
        local_transports(('lan', endpoints['dns'][1], 53), private)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--platform', type=Path, required=True)
    parser.add_argument('--bridge', type=Path, required=True)
    args = parser.parse_args()
    try:
        qualify(args.platform, args.bridge)
    except Exception:
        print(run('journalctl', '-b', '-u', 'lanrith-dns64-reverse', '-u', 'lanrith-nat64-internal*',
                  '-u', 'unbound', '-u', 'lanrith-dns64-private', '-u', 'discovery-bridge-dns',
                  '-n', '50', '-o', 'cat', check=False).stdout, flush=True)
        raise
