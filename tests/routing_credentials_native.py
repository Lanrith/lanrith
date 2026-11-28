#!/usr/bin/env python3
"""Qualify image-selected FRR startup and TCP MD5 key reversal under a disposable PID 1."""

import argparse
import grp
import ipaddress
import json
import os
from pathlib import Path
import secrets
import shutil
import socket
import stat
import subprocess
import sys
import tempfile
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from lanrith import build
from routing_native import PEERS, VPN, WORK_A, WORK_B, connect_peers, eventually, ns, peer_config, run, scenario, vty

FRR = 'frr.service'
PREPARE = 'lanrith-routing-credentials.service'
GATE = 'lanrith-credential-bgp-token.service'
CONFIG = Path('/run/lanrith-routing/frr.conf')
IMAGE_DIRS = ['usr/share/lanrith', 'usr/lib/lanrith']


def copy(source, dest):
    dest.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source, dest)


def attempt(*command):
    return subprocess.run(command, text=True, capture_output=True, timeout=30)


def make_slots(work, keys):
    value = scenario()
    source = work/'vpn_bgp'
    value['credentials'] = {'vpn_bgp': {'file': str(source)}}
    base = work/'base.tar'
    base.write_bytes(b'synthetic')
    trees = []
    for i, key in enumerate(keys):
        source.touch(mode=0o600)
        source.write_text(key+'\n')
        workspace = work/str(i)
        build.assembly(value, base, workspace, version='0.1.0', sequence=i+1)
        trees.append(workspace/'mkosi.extra')
    source.unlink()
    return trees


def setup_manager(package, tree):
    # The guest supplies PID 1. RootDirectory selects the immutable appliance
    # binaries, libraries, FRR accounts and YANG modules for vendor commands.
    units = Path('/etc/systemd/system')
    group = run('chroot', str(package), 'getent', 'group', 'frr').split(':')[2]
    run('groupadd', '--non-unique', '--gid', group, 'frr')
    run('mount', '-t', 'tmpfs', 'tmpfs', str(package/'run'))
    for directory in [Path('/run/frr'), package/'run/frr']:
        directory.mkdir(mode=0o755)
        os.chown(directory, int(run('chroot', str(package), 'id', '-u', 'frr')), int(group))
    for rel in ['usr/bin/lanrith-credentials', 'etc/frr/daemons', 'etc/nftables.conf']:
        copy(tree/rel, Path('/')/rel)
    for name in (FRR, 'nftables.service'):
        vendor = package/'usr/lib/systemd/system'/name
        copy(vendor, Path('/usr/lib/systemd/system')/name)
        drop = units/(name+'.d')
        drop.mkdir(exist_ok=True)
        inputs = ('BindPaths=/run/frr\nBindReadOnlyPaths=/etc/frr/daemons\n'
                  if name == FRR else 'BindReadOnlyPaths=/etc/nftables.conf\n')
        (drop/'90-fixture-package.conf').write_text(
            f'[Service]\nRootDirectory={package}\nMountAPIVFS=yes\nBindLogSockets=yes\n'+inputs)
    for name in (PREPARE, GATE):
        copy(tree/'usr/lib/systemd/system'/name, Path('/usr/lib/systemd/system')/name)
    for name in (PREPARE, FRR):
        shutil.copytree(tree/'etc/systemd/system'/(name+'.d'), units/(name+'.d'), dirs_exist_ok=True)
    for rel in IMAGE_DIRS:
        (Path('/')/rel).mkdir(parents=True, exist_ok=True)
    run('systemctl', 'daemon-reload')
    assert run('systemctl', 'show', FRR, '-p', 'FragmentPath', '--value').strip() == '/usr/lib/systemd/system/frr.service'
    assert run('systemctl', 'show', FRR, '-p', 'CanReload', '--value').strip() == 'no'
    assert not run('systemctl', 'show', FRR, '-p', 'ExecReload', '--value').strip()
    print(run('systemctl', '--version').splitlines()[0], flush=True)
    print(run('chroot', str(package), '/usr/lib/frr/bgpd', '--version').splitlines()[0], flush=True)
    print('Debian FRR unit: CanReload=no, ExecReload empty.', flush=True)


def peer(name, key, package):
    unit = 'fixture-'+name
    directory = Path('/run')/unit
    directory.mkdir(mode=0o700, exist_ok=True)
    (package/'run'/unit).mkdir(mode=0o700, exist_ok=True)
    conf = directory/'bgpd.conf'
    conf.touch(mode=0o600)
    conf.write_text(peer_config(name, key))
    run('systemd-run', '--quiet', '--collect', '--unit='+unit, '-p', 'RootDirectory='+str(package),
        '-p', 'MountAPIVFS=yes', '-p', 'BindPaths='+str(directory), '-p', 'NetworkNamespacePath=/run/netns/'+name,
        '/usr/lib/frr/bgpd', '-S', '-Z', '-f', str(conf), '-i', str(directory/'pid'),
        '--vty_socket', str(directory), '-A', '127.0.0.1', '--limit-fds', '1024')


def sessions():
    result = vty(Path('/run/frr'), 'show bgp ipv6 unicast summary json')
    return json.loads(result).get('peers', {})


def route(prefix, expected):
    dest = str(ipaddress.ip_network(prefix).network_address + 1)
    reply = attempt('ip', '-j', '-6', 'route', 'get', dest)
    if expected is None:
        return reply.returncode == 2 and 'unreachable' in reply.stderr.lower()
    return reply.returncode == 0 and json.loads(reply.stdout)[0].get('gateway') == expected


def ready(name, prefix):
    return sessions().get(PEERS[name], {}).get('state') == 'Established' and route(prefix, PEERS[name])


def pinned():
    for name, prefix in [('node-a', WORK_A), ('node-b', WORK_B)]:
        eventually(lambda: ready(name, prefix), name+' route')
    return {name: sessions()[PEERS[name]]['connectionsEstablished'] for name in ('node-a', 'node-b')}


def md5_failures():
    rows = Path('/proc/net/netstat').read_text().splitlines()
    index = next(i for i, line in enumerate(rows) if line.startswith('TcpExt:'))
    return int(dict(zip(rows[index].split(), rows[index+1].split(), strict=True))['TCPMD5Failure'])


def qualify(package):
    assert os.geteuid() == 0 and Path('/proc/1/comm').read_text().strip() == 'systemd'
    assert socket.if_nameindex() == [(1, 'lo')] and not Path('/usr/share/lanrith/installed.json').exists()
    assert package.is_mount() and (package/'usr/share/lanrith/platform-version').is_file()
    with tempfile.TemporaryDirectory() as temporary:
        work = Path(temporary)
        keys = [secrets.token_hex(24), secrets.token_hex(24)]
        trees = make_slots(work, keys)
        setup_manager(package, trees[0])
        for name in PEERS:
            run('ip', 'netns', 'add', name)
            ns(name, 'ip', 'link', 'set', 'lo', 'up')
        run('ip', 'netns', 'attach', 'router', str(os.getpid()))
        connect_peers()
        for name in ('node-a', 'node-b'):
            peer(name, None, package)

        def select(slot):
            for rel in IMAGE_DIRS:
                dest = Path('/')/rel
                if subprocess.run(['mountpoint', '-q', dest], timeout=5).returncode == 0:
                    run('umount', str(dest))
                run('mount', '--bind', str(trees[slot]/rel), str(dest))
                run('mount', '--make-private', str(dest))
                run('mount', '-o', 'remount,bind,ro', str(dest))
            info = json.loads(Path('/usr/share/lanrith/installed.json').read_bytes())
            assert info['deployment_sequence'] == slot+1 and info['credential_delivery'] == 'image'

        def stop_slot():
            run('systemctl', 'stop', FRR, PREPARE, GATE)
            assert not CONFIG.parent.exists()
            assert not (Path('/run/frr')/'bgpd.pid').exists()

        try:
            for phase, slot in [('original', 0), ('candidate', 1), ('fallback', 0), ('restored-candidate', 1)]:
                select(slot)
                start = time.monotonic()
                run('systemctl', 'start', FRR)
                eventually(lambda: Path('/run/frr/bgpd.vty').is_socket(), 'packaged bgpd')
                before = pinned()
                assert CONFIG.stat().st_uid == 0 and CONFIG.stat().st_gid == grp.getgrnam('frr').gr_gid
                assert stat.S_IMODE(CONFIG.stat().st_mode) == 0o640 and stat.S_IMODE(CONFIG.parent.stat().st_mode) == 0o750
                run('setpriv', '--reuid=nobody', '--regid=frr', '--clear-groups', 'test', '-r', str(CONFIG))
                assert attempt('runuser', '-u', 'nobody', '--', 'test', '-r', str(CONFIG)).returncode == 1
                assert CONFIG.read_text().count(keys[slot]) == 1 and keys[1-slot] not in CONFIG.read_text()
                if phase != 'original':
                    wrong = md5_failures()
                    peer('vpn', keys[1-slot], package)
                    eventually(lambda: md5_failures() > wrong, 'peer authentication mismatch at the router')
                    assert sessions().get(PEERS['vpn'], {}).get('state') != 'Established'
                    assert route(VPN, None) and pinned() == before
                    run('systemctl', 'stop', 'fixture-vpn.service')
                peer_start = time.monotonic()
                peer('vpn', keys[slot], package)
                eventually(lambda: ready('vpn', VPN), 'authenticated VPN route')
                print(f'{phase} route ready {time.monotonic()-start:.1f}s from service activation, '
                      f'{time.monotonic()-peer_start:.1f}s from matching peer start', flush=True)
                reload_result = attempt('systemctl', 'reload', FRR)
                assert reload_result.returncode and 'not applicable' in reload_result.stderr
                assert ready('vpn', VPN) and pinned() == before
                run('systemctl', 'stop', 'fixture-vpn.service')
                stop_slot()

            # Damage only a disposable copy of the selected image's input.
            select(0)
            target = Path('/usr/lib/lanrith/credentials/core')
            broken = work/'invalid'
            broken.mkdir(mode=0o700)
            run('mount', '--bind', str(broken), str(target))
            for reason in ('missing', 'malformed'):
                if reason == 'malformed':
                    file = broken/'vpn_bgp'
                    file.touch(mode=0o600)
                    file.write_text('invalid synthetic token')
                assert attempt('systemctl', 'start', FRR).returncode
                assert run('systemctl', 'show', GATE, '-p', 'Result', '--value').strip() == 'exit-code'
                assert not CONFIG.exists() and not Path('/run/frr/bgpd.pid').exists()
                run('systemctl', 'reset-failed', GATE)
            print('Both image inputs failed closed before FRR startup.', flush=True)
        finally:
            for dest in [Path('/usr/lib/lanrith/credentials/core'), *(Path('/')/rel for rel in IMAGE_DIRS)]:
                if subprocess.run(['mountpoint', '-q', dest], timeout=5).returncode == 0:
                    run('umount', str(dest))
            journal = run('journalctl', '-b', '--no-pager')
            assert all(key not in journal for key in keys), 'Routing key disclosed in the journal'
            if sys.exc_info()[0]:
                print(run('journalctl', '-b', '-u', GATE, '-u', PREPARE, '-u', FRR, '--no-pager', '-n', '35'))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--appliance-root', required=True, type=Path)
    qualify(parser.parse_args().appliance_root)
