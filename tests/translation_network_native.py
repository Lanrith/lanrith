#!/usr/bin/env python3
"""Test translator lifecycle and effective routes in an offline systemd VM."""

import argparse
import ipaddress as ip
import json
import os
from pathlib import Path
import pwd
import shutil
import socket
import subprocess
import sys
import tempfile
import time
from unittest.mock import patch

import translation_reference as ref
from nat46_pmtu_native import nat46_pmtu
from tun_policy_native import FOUR, SERVERS, SIX, UPPER, WAN, prepare
from lanrith import translation_runtime as runtime
from lanrith.release import ReleaseError


def command(*args):
    return subprocess.run(args, check=True, text=True, capture_output=True, timeout=60).stdout


def unit(*args):
    return command('systemctl', *args).strip()


def expect_failure(action, contains):
    try:
        action()
    except (ReleaseError, OSError) as error:
        assert contains in str(error), str(error)
        return
    raise AssertionError('Expected failure: '+contains)


def lifecycle(manifest):
    name = manifest['interface']
    uid = pwd.getpwnam('lanrith-'+name).pw_uid
    pool, prefix = manifest['routes']
    start = lambda: runtime.configure(manifest, 'start')
    stop = lambda: runtime.configure(manifest, 'stop')
    start()
    command('ip', '-6', 'route', 'replace', prefix, 'dev', 'p6')
    stop()
    stop()
    assert runtime.existing(manifest, uid) is None and not runtime.routes(pool)
    assert runtime.routes(prefix)[0]['dev'] == 'p6'
    expect_failure(start, 'Conflicting')
    command('ip', '-6', 'route', 'del', prefix, 'dev', 'p6')
    start()
    runtime.status(manifest)
    stop()

    # Start with an owned, down TUN, original source setting, and a foreign
    # address. Introduce an ordinary concurrent writer at the last insertion.
    index = runtime.create_link(manifest, uid)
    command('ip', 'address', 'add', '192.0.2.78/32', 'dev', name)
    command('ip', '-6', 'address', 'add', 'fdab::78/128', 'dev', name, 'nodad')
    previously = runtime.address_state(name)['addr_info']
    setting = Path('/proc/sys/net/ipv4/conf', name, 'accept_local')
    old = setting.read_text()
    original = runtime.run

    def competing(*arguments, **kwargs):
        if arguments[:5] == ('ip', '-6', 'route', 'add', prefix):
            command('ip', '-6', 'route', 'add', prefix, 'dev', 'p6')
        return original(*arguments, **kwargs)

    with patch.object(runtime, 'run', side_effect=competing):
        expect_failure(start, 'Conflicting')
    assert runtime.existing(manifest, uid) == index
    assert setting.read_text() == old
    state = runtime.address_state(name)
    assert 'UP' not in state['flags'] and state['addr_info'] == previously, state
    assert not runtime.routes(pool) and runtime.routes(prefix)[0]['dev'] == 'p6'
    command('ip', '-6', 'route', 'del', prefix, 'dev', 'p6')
    command('ip', 'address', 'del', '192.0.2.78/32', 'dev', name)

    command('ip', '-6', 'address', 'del', 'fdab::78/128', 'dev', name)

    def same_route(*arguments, **kwargs):
        if arguments[:5] == ('ip', '-6', 'route', 'add', prefix):
            command(*arguments)
        return original(*arguments, **kwargs)

    with patch.object(runtime, 'run', side_effect=same_route):
        start()
    runtime.status(manifest)
    stop()
    command('ip', 'link', 'add', name, 'type', 'dummy')
    expect_failure(stop, 'unowned')
    assert socket.if_nametoindex(name) != index
    command('ip', 'link', 'del', name)


def test_health(components):
    for name, target in (('nat46', '10.251.0.4'), ('nat64-internal', '10.250.0.200')):
        manifest = components[name]
        command('ip', 'route', 'add', target+'/32', 'dev', 'c4')
        expect_failure(lambda: runtime.status(manifest), target)
        assert runtime.owned_route(name, manifest['pool'])
        command('ip', 'route', 'del', target+'/32', 'dev', 'c4')
        runtime.status(manifest)
    manifest = components['nat64']
    target = str(ip.ip_network(manifest['prefix']).network_address+int(ip.ip_address(WAN)))
    command('ip', '-6', 'route', 'add', target+'/128', 'dev', 'p6', 'table', '123')
    command('ip', '-6', 'rule', 'add', 'pref', '101', 'iif', 'c6', 'from', SIX+'2/128', 'table', '123')
    expect_failure(lambda: runtime.status(manifest), f'{target} from {SIX}2 on c6')
    command('ip', '-6', 'rule', 'del', 'pref', '101')
    command('ip', '-6', 'route', 'flush', 'table', '123')
    runtime.status(manifest)


def install(root, package, *, configure=None, retained=None):
    source = Path('/opt/fixture-platform')
    assert source.is_mount() and Path('/proc/1/comm').read_text().strip() == 'systemd'
    assert {name for _, name in socket.if_nameindex()} == {'lo'}
    prepare(root, owner_callback_port=22223, configure=configure, retained=retained)
    for path in (root/'native-extra').rglob('*'):
        if path.is_file():
            target = Path('/')/path.relative_to(root/'native-extra')
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(path, target)
    shutil.copytree(root/'runtime', '/usr/lib/lanrith', dirs_exist_ok=True)
    if package is None:
        shutil.copy2(source/'usr/lib/lanrith/tayga-internal', '/usr/lib/lanrith/')
    else:
        command('dpkg', '--install', str(package))
        version = command('dpkg-deb', '-f', str(package), 'Version').strip()
        assert command('dpkg-query', '-W', '-f=${Version}', 'lanrith-tayga-internal') == version
    for relative in ('usr/sbin/conntrack', 'usr/lib/x86_64-linux-gnu/libnetfilter_conntrack.so.3',
                     'usr/lib/x86_64-linux-gnu/libnfnetlink.so.0'):
        if not (Path('/')/relative).exists():
            shutil.copy2(source/relative, Path('/')/relative)
    Path('/etc/xtables').mkdir(exist_ok=True)
    shutil.copy2(root/'connlabel.conf', '/etc/xtables/connlabel.conf')
    shutil.copy2(root/'policy.nft', '/etc/nftables.conf')
    route_policy = 'etc/systemd/networkd.conf.d/60-lanrith-route-owners.conf'
    (Path('/')/route_policy).parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source/route_policy, Path('/')/route_policy)
    command('systemd-sysusers', '--inline', 'u router-policy-reader - "Policy reader" /')
    command('systemd-sysusers')
    command('systemd-tmpfiles', '--create', '--prefix=/var/lib/tayga', '--prefix=/var/lib/tayga-nat64-internal')
    unit('daemon-reload')
    command('sysctl', '-qw', 'net.ipv4.ip_forward=1', 'net.ipv6.conf.all.forwarding=1')
    return {c['interface']: c for c in json.loads((root/'lab.json').read_text())['components']}


def run(root, package):
    components = install(root, package)
    children = []
    flows = []
    unit('start', 'systemd-networkd')
    for name, prefix in (('c6', SIX+'/64'), ('p6', SERVERS+'/64'),
                         ('c4', '10.240.40.0/24'), ('p4', '93.184.216.0/24')):
        addresses = [ref.peer(name, prefix)]
        extras = [SIX+'3', UPPER+'3'] if name == 'c6' else (
            [m['ipv6'] for m in components['nat46']['mappings'].values()] if name == 'p6' else [])
        for address in extras:
            command(*ref.inside(name, 'ip', '-6', 'addr', 'add', address+'/64', 'dev', 'eth0', 'nodad'))
            addresses.append(address)
        ready = root/(name+'.ready')
        env = {**os.environ, 'LANRITH_TEST_UDP_NO_CHECK': '1'} if name == 'c4' else os.environ
        child = subprocess.Popen(ref.inside(name, sys.executable, '-c', ref.SERVER, str(ready), *addresses), env=env)
        children.append(child)
        ref.await_file(ready, child)
    try:
        for component in components.values():
            before = time.monotonic()
            lifecycle(component)
            print(component['interface'], 'lifecycle and recovery seconds', round(time.monotonic()-before, 2), flush=True)
        unit('start', 'nftables')
        ref.command('nft', '-f', str(root/'identity-egress.nft'))
        unit('start', *(c['unit'] for c in components.values()))
        for manifest in components.values():
            runtime.status(manifest)
        test_health(components)
        mac = json.loads(command(*ref.inside('c4', 'ip', '-j', 'link', 'show', 'eth0')))[0]['address']
        ref.nft('add element inet lanrith tp_started { 0 }\n'+
                f'add element inet lanrith tp_bound4 {{ "c4" . {mac} . {FOUR} timeout 120s }}\n'+
                f'add element inet lanrith tp_dest4 {{ "c4" . {FOUR} timeout 120s }}\n'+
                f'add element netdev lanrith_identity tp_bound4 {{ "c4" . {mac} . {FOUR} timeout 120s }}')
        callback = ('c4', '10.250.0.200', FOUR, 22222)
        denied = ref.Flow(*callback, 'udp')
        denied.check(False)
        denied.close()
        original = str(ip.ip_network(components['nat64-internal']['prefix']).network_address+int(ip.ip_address(FOUR)))
        private_udp = ref.Flow('c6', original, UPPER+'3', 11111, 'udp')
        flows.append(private_udp)
        private_udp.check(True)
        print('IPv6 client received an admitted IPv4 UDP reply sent with SO_NO_CHECK', flush=True)
        ref.nft(f'add element inet lanrith tp_grants6 {{ {original} . {SIX}2 . tcp . 22222 timeout 120s, '
                f'{original} . {SIX}2 . udp . 22222 timeout 120s }}')
        public = str(ip.ip_network(components['nat64']['prefix']).network_address+int(ip.ip_address(WAN)))
        for args in (('c6', public, SIX+'3', 11111), callback, ('c4', '10.251.0.2', FOUR, 11111)):
            for protocol in ('tcp', 'udp'):
                flow = ref.Flow(*args, protocol)
                flows.append(flow)
                flow.check(True)

        def identity():
            return [(socket.if_nametoindex(name), unit('show', manifest['unit'], '-p', 'MainPID', '--value'))
                    for name, manifest in components.items()]

        def conntrack_ids():
            return {line.split(' id=')[-1].strip() for family in ('ipv4', 'ipv6')
                    for line in command('conntrack', '-L', '-f', family, '-o', 'id').splitlines()
                    if line.startswith(('tcp ', 'udp '))}

        before, tracked = identity(), conntrack_ids()
        assert len(tracked) >= len(flows)
        unit('restart', 'systemd-networkd')
        assert identity() == before and tracked <= conntrack_ids()
        for flow in flows:
            flow.check(True)
        for manifest in components.values():
            runtime.status(manifest)
        nat46_pmtu(components['nat46'])
        for flow in flows:
            flow.check(True)
        unit('stop', 'nftables')
        for name, manifest in components.items():
            assert unit('show', manifest['unit'], '-p', 'ActiveState', '--value') == 'inactive'
            assert not runtime.existing(manifest, pwd.getpwnam('lanrith-'+name).pw_uid)
            assert all(not runtime.routes(prefix) for prefix in manifest['routes'])
        print('All three translators retained live TCP, UDP, conntrack, PID and ifindex through networkd restart; firewall stop withdrew all.', flush=True)
    finally:
        for flow in flows:
            flow.close()
        for child in children:
            child.terminate()
            child.wait(timeout=5)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--tayga-deb', type=Path, help='Install a local qualification package in the disposable guest')
    args = parser.parse_args()
    with tempfile.TemporaryDirectory() as temp:
        try:
            run(Path(temp)/'lab', args.tayga_deb)
        except Exception:
            print(subprocess.getoutput('journalctl -n 45 --no-pager'))
            raise
