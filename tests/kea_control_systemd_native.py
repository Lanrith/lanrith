#!/usr/bin/env python3
"""Exercise delayed LAN activation, DHCP recovery and confined observations under systemd."""

import argparse
import csv
import grp
import json
import os
from pathlib import Path
import pwd
import shutil
import signal
import socket
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT/'tests')]
from lanrith import config, kea_listeners, router_metrics_runtime
from dhcp_native import CLIENT
from kea_control_native import command, reader_access
from phase_b_native import DHCP_CLIENT
from test_radius import declaration

UNIT = 'kea-dhcp4-server.service'
EXTRA = ROOT/'mkosi/base/mkosi.extra'


def stage(files):
    """Install generated service configuration into the disposable guest."""
    units = Path('/run/systemd/system')
    helpers = Path('/usr/lib/lanrith')
    library = helpers/'lanrith'
    library.mkdir(parents=True, exist_ok=True)
    for module in ('kea_runtime.py', 'kea_listeners.py', 'kea_observer.py'):
        shutil.copyfile(ROOT/'lanrith'/module, library/module)
        (library/module).chmod(0o644)
    for name in ('verify-kea-sockets', 'wait-for-kea-interfaces'):
        shutil.copyfile(EXTRA/'usr/lib/lanrith'/name, helpers/name)
        (helpers/name).chmod(0o755)
    for path, body in files.items():
        if path.startswith('usr/lib/systemd/system/lanrith-kea-'):
            (units/Path(path).name).write_text(body)
        if path.startswith('etc/systemd/system/'+UNIT+'.d/'):
            target = units/(UNIT+'.d')/Path(path).name
            target.parent.mkdir(exist_ok=True)
            target.write_text(body)
    for path in (EXTRA/'etc/systemd/system'/(UNIT+'.d')).glob('*.conf'):
        shutil.copyfile(path, units/(UNIT+'.d')/path.name)
    manifest = kea_listeners.MANIFEST
    manifest.parent.mkdir(parents=True, exist_ok=True)
    manifest.write_text(files['usr/share/lanrith/kea-listeners.json'])
    manifest.chmod(0o644)
    account = pwd.getpwnam('_kea')
    kea = Path('/etc/kea/kea-dhcp4.conf')
    kea.write_text(files['etc/kea/kea-dhcp4.conf'])
    os.chown(kea, 0, account.pw_gid)
    kea.chmod(0o640)
    return account


def wait_active(unit):
    end = time.monotonic()+25
    while subprocess.run(['systemctl', 'is-active', '--quiet', unit]).returncode:
        assert time.monotonic() < end, unit+' did not become active'
        time.sleep(0.1)


def fixture(output):
    assert os.geteuid() == 0 and Path('/proc/1/comm').read_text().strip() == 'systemd'
    assert not Path('/usr/share/lanrith/installed.json').exists()
    assert {row['ifname'] for row in json.loads(command('ip', '-j', 'link'))} == {'lo'}
    assert not output.exists()
    value = declaration()
    value['networks']['home']['dhcp4'] = {'pools': ['192.168.10.100-192.168.10.100']}
    value['networks']['devices']['dhcp4'] = {'id': 79, 'pools': ['192.168.22.100-192.168.22.100'],
        'reservations': [{'mac': '02:00:00:00:01:02', 'address': '192.168.22.190'},
                         {'mac': '02:00:00:00:22:79', 'address': '192.168.22.120'}]}
    value['observability'] = {'metrics': {'enabled': True, 'clients': [{'network': 'home'}]}}
    files = config.render(value)
    account = stage(files)
    command('groupadd', '--system', 'lanrith-kea-lease-readers')
    group = grp.getgrnam('lanrith-kea-lease-readers').gr_gid
    state = Path('/var/lib/kea')
    state.mkdir(parents=True, exist_ok=True)
    os.chown(state, account.pw_uid, account.pw_gid)
    lease = {'address': '192.168.22.120', 'hwaddr': '02:00:00:00:22:79', 'client_id': '',
             'valid_lifetime': '3600', 'expire': str(int(time.time())+600), 'subnet_id': '79',
             'fqdn_fwd': '0', 'fqdn_rev': '0', 'hostname': '', 'state': '0', 'user_context': ''}
    with (state/'kea-leases4.csv').open('w') as stream:
        writer = csv.DictWriter(stream, fieldnames=list(lease), lineterminator='\n')
        writer.writeheader()
        writer.writerow(lease)
    os.chown(state/'kea-leases4.csv', account.pw_uid, account.pw_gid)

    def client(ns, *argv):
        return command('ip', 'netns', 'exec', ns, *argv)

    scopes = [('one', 'lan.1', '192.168.10'), ('two', 'lan.22', '192.168.22')]
    command('ip', 'link', 'add', 'wan', 'type', 'dummy')  # stays down for every stage
    for ns, name, base in scopes:
        command('ip', 'netns', 'add', ns)
        command('ip', 'link', 'add', name, 'type', 'veth', 'peer', 'name', 'eth0', 'netns', ns)
        command('ip', 'address', 'add', base+'.1/24', 'dev', name)
        command('ip', 'link', 'set', name, 'up')
        if ns == 'two':
            client(ns, 'ip', 'link', 'set', 'eth0', 'address', lease['hwaddr'])
            client(ns, 'ip', 'link', 'set', 'eth0', 'up')
            client(ns, 'ip', 'route', 'add', '255.255.255.255/32', 'dev', 'eth0')
    command('systemctl', 'daemon-reload')
    command('systemctl', 'start', '--no-block', UNIT)

    def pending():
        end = time.monotonic()+8
        while command('systemctl', 'show', '-P', 'SubState', UNIT).strip() != b'start-pre':
            assert time.monotonic() < end
            time.sleep(.1)
        assert subprocess.run(['/usr/lib/lanrith/verify-kea-sockets']).returncode != 0

    pending()
    client('one', 'ip', 'link', 'set', 'eth0', 'up')
    client('one', 'ip', 'route', 'add', '255.255.255.255/32', 'dev', 'eth0')
    wait_active(UNIT)
    command('/usr/lib/lanrith/verify-kea-sockets')
    command('systemctl', 'stop', UNIT)
    command('ip', 'address', 'del', '192.168.22.1/24', 'dev', 'lan.22')
    command('systemctl', 'start', '--no-block', UNIT)
    pending()
    command('ip', 'address', 'add', '192.168.22.1/24', 'dev', 'lan.22')
    wait_active(UNIT)
    command('/usr/lib/lanrith/verify-kea-sockets')
    for ns, _, base in scopes:
        expected = [base+'.100'] + ([base+'.190'] if ns == 'two' else [])
        client(ns, 'python3', '-c', DHCP_CLIENT, 'acquire', base+'.1', *expected)
    with socket.socket(socket.AF_UNIX) as reader:
        reader.settimeout(5)
        reader.connect('/run/lanrith-kea-statistics.sock')
        with reader.makefile('rb') as stream:
            stats = json.load(stream)
    assert len(stats['pools']) == 2 and all(p['assigned'] == p['total'] == 1 for p in stats['pools']), stats
    assert all(s['allocation_failures'] > 0 and s['declined'] == 0 for s in stats['subnets']), stats
    text = router_metrics_runtime.collect(json.loads(files['usr/share/lanrith/router-metrics.json']))
    assert 'lanrith_router_metrics_query_success{collector="dhcp4"} 1\n' in text
    for pool in stats['pools']:
        labels = f'pool="{pool["pool"]}",subnet_id="{pool["subnet_id"]}"'
        assert f'lanrith_router_dhcp4_pool_assigned_addresses{{{labels}}} 1\n' in text
        assert f'lanrith_router_dhcp4_pool_capacity_addresses{{{labels}}} 1\n' in text
    for subnet in stats['subnets']:
        labels = f'subnet_id="{subnet["subnet_id"]}"'
        assert f'lanrith_router_dhcp4_allocation_failures_total{{{labels}}} {subnet["allocation_failures"]}\n' in text
        assert f'lanrith_router_dhcp4_declined_addresses{{{labels}}} 0\n' in text
    wait_active('lanrith-kea-leases.service')
    reader_access(group)
    pid = int(command('systemctl', 'show', '-P', 'MainPID', UNIT))
    assert not kea_listeners.listeners(pid, {socket.if_nametoindex('lan.1')}), 'Unexpected listener went undetected'
    os.kill(pid, signal.SIGKILL)
    end = time.monotonic()+16
    while int(command('systemctl', 'show', '-P', 'MainPID', UNIT)) in (0, pid):
        assert time.monotonic() < end
        time.sleep(.2)
    wait_active(UNIT)
    command('/usr/lib/lanrith/verify-kea-sockets')
    reader_access(group)
    client('two', 'ip', 'address', 'add', lease['address']+'/24', 'dev', 'eth0')
    client('two', 'python3', '-c', CLIENT, lease['address'], '192.168.22.1', lease['hwaddr'])
    command('systemctl', 'stop', 'nftables.service')
    time.sleep(3.2)
    assert command('systemctl', 'show', '-P', 'ActiveState', UNIT).strip() == b'inactive'
    command('systemctl', 'start', 'nftables.service', UNIT)
    command('/usr/lib/lanrith/verify-kea-sockets')
    command('systemctl', 'stop', UNIT)
    command('systemctl', 'reset-failed', UNIT)
    command('ip', 'address', 'del', '192.168.22.1/24', 'dev', 'lan.22')
    assert subprocess.run(['systemctl', 'start', UNIT], timeout=24).returncode != 0
    assert subprocess.run(['/usr/lib/lanrith/verify-kea-sockets']).returncode != 0
    command('systemctl', 'stop', UNIT)
    output.write_text(json.dumps({'result': 'pass', 'capacity': stats, 'checked': [
        'late carrier', 'late IPv4', 'permanently missing IPv4', 'undeclared listener rejected', 'WAN offline', 'two-scope DHCP options', 'retained unicast renewal after crash',
        'scoped broker', 'firewall deliberate stop and explicit restore']}))
    print('Packaged DHCP listeners, crash recovery, scoped reads and pool capacity passed.')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--result', type=Path, required=True)
    try:
        fixture(parser.parse_args().result)
    except Exception:
        for cmd in (['systemctl', 'status', UNIT, 'lanrith-kea-leases.service'],
                    ['journalctl', '--no-pager', '-n', '60']):
            result = subprocess.run(cmd, capture_output=True)
            sys.stderr.buffer.write(result.stdout[-10000:])
        raise
