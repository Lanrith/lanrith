#!/usr/bin/env python3
"""Run generated native translator units in an offline systemd container.

Only compiled inputs are mounted. This tests real service privilege boundaries,
restart hooks, native allocation persistence and removal of owned routes.
"""

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


def unit(*arguments):
    return subprocess.run(['systemctl', *arguments], check=True, capture_output=True,
                          text=True, timeout=20).stdout


def main(root):
    assert os.geteuid() == 0 and Path('/run/.containerenv').exists()
    assert Path('/proc/1/comm').read_text().strip() == 'systemd'
    assert {row['ifname'] for row in json.loads(ref.command('ip', '-j', 'link').stdout)} == {'lo'}
    sys.path.insert(0, '/usr/lib/lanrith')
    from lanrith.translation_runtime import status
    components = {c['interface']: c for c in json.loads((root/'lab.json').read_text())['components']}
    units = ['lanrith-'+name+'.service' for name in components]
    children, checks = [], []

    def connections(component):
        scopes = [ip.ip_network(component[key]) for key in ('pool', 'prefix')]
        rows = []
        for family in ('ipv4', 'ipv6'):
            for row in ref.command('conntrack', '-L', '-f', family).stdout.splitlines():
                addresses = [ip.ip_address(field.split('=', 1)[1]) for field in row.split()
                             if field.startswith(('src=', 'dst='))]
                if any(address in scope for address in addresses for scope in scopes):
                    rows.append(row)
        return rows

    def probe(name, protocol):
        component = components[name]
        if name == 'nat46':
            network, target, source = 'c4', '10.251.0.2', FOUR
        else:
            network, source = 'c6', SIX+'3'
            target = str(ip.ip_network(component['prefix']).network_address+int(ip.ip_address(WAN)))
        flow = ref.Flow(network, target, source, 11111, protocol)
        children.append(flow.child)
        flow.check(True)
        flow.close()

    def process(name):
        service = 'lanrith-'+name+'.service'
        assert unit('show', service, '-p', 'ActiveState', '--value').strip() == 'active'
        pid = int(unit('show', service, '-p', 'MainPID', '--value'))
        data = dict(line.split(':', 1) for line in Path('/proc', str(pid), 'status').read_text().splitlines())
        assert set(data['Uid'].split()) == {str(pwd.getpwnam('lanrith-'+name).pw_uid)}
        for field in ('CapEff', 'CapPrm', 'CapBnd', 'CapAmb'):
            assert int(data[field].strip(), 16) == 0, (name, field, data[field])
        assert data['NoNewPrivs'].strip() == '1'
        status(components[name])
        return pid

    with tempfile.TemporaryDirectory() as temporary:
        temporary = Path(temporary)
        try:
            ref.command('ip', 'link', 'set', 'lo', 'up')
            for name, prefix in (('c6', SIX+'/64'), ('p6', SERVERS+'/64'),
                                 ('c4', '10.240.40.0/24'), ('p4', '93.184.216.0/24')):
                addresses = [ref.peer(name, prefix)]
                extras = [SIX+'3'] if name == 'c6' else (
                    [entry['ipv6'] for entry in components['nat46']['mappings'].values()] if name == 'p6' else [])
                for address in extras:
                    ref.command(*ref.inside(name, 'ip', '-6', 'addr', 'add', address+'/64', 'dev', 'eth0', 'nodad'))
                    addresses.append(address)
                ready = temporary/(name+'.ready')
                child = subprocess.Popen(ref.inside(name, sys.executable, '-c', ref.SERVER, str(ready), *addresses),
                    stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
                children.append(child)
                ref.await_file(ready, child)
            ref.ipv6_ready()
            # Load the real dependency before installing the separate netdev
            # hooks, so its initial flush cannot erase those hooks afterward.
            unit('start', 'nftables.service')
            ref.command('nft', '-f', str(root/'identity-egress.nft'))
            unit('start', *units)
            for name in components:
                process(name)
                checks.append(name+' real units own TUN/routes; translator has no capabilities')
            ref.nft('add element inet lanrith tp_started { 0 }')
            mac = json.loads(ref.command(*ref.inside('c4', 'ip', '-j', 'link', 'show', 'eth0')).stdout)[0]['address']
            ref.nft(f'add element inet lanrith tp_bound4 {{ "c4" . {mac} . {FOUR} timeout 90s }}\n'
                    f'add element inet lanrith tp_dest4 {{ "c4" . {FOUR} timeout 90s }}\n'
                    f'add element netdev lanrith_identity tp_bound4 {{ "c4" . {mac} . {FOUR} timeout 90s }}')
            for name in components:
                for protocol in ('tcp', 'udp', 'icmp'):
                    probe(name, protocol)
                    checks.append(name+' real unit '+protocol+' request/reply')
            for name, component in components.items():
                service = 'lanrith-'+name+'.service'
                old_pid = process(name)
                unit('stop', service)
                assert not connections(component), 'graceful stop left component connections'
                state = Path(component['state_directory'])/'dynamic.map'
                saved = state.read_bytes() if component['component'] == 'nat64' else None
                if saved is not None:
                    assert saved and (SIX+'3').encode() in saved, 'native dynamic allocation was not saved'
                unit('start', service)
                assert process(name) != old_pid
                if saved is not None:
                    assert state.read_bytes() == saved, 'startup changed persisted allocation data'
                probe(name, 'udp')
                checks.append(name+' graceful stop cleans connections and restart preserves native state')
                other = next(key for key in components if key != name)
                probe(other, 'udp')
                assert connections(component) and connections(components[other])
                old_pid = process(name)
                unit('kill', '--signal=KILL', service)
                end = time.monotonic()+8
                while time.monotonic() < end:
                    pid = int(unit('show', service, '-p', 'MainPID', '--value'))
                    active = unit('show', service, '-p', 'ActiveState', '--value').strip()
                    if pid and pid != old_pid and active == 'active':
                        break
                    time.sleep(.05)
                else:
                    raise AssertionError('automatic restart failed: '+name)
                process(name)
                assert not connections(component), 'crash restart retained stale component connections'
                assert connections(components[other]), 'crash restart retired unrelated connections'
                probe(name, 'udp')
                checks.append(name+' SIGKILL triggers bounded restart and scoped cleanup; fresh traffic works')
            for name in components:
                unit('stop', 'lanrith-'+name+'-network.service')
                assert unit('show', 'lanrith-'+name+'.service', '-p', 'ActiveState', '--value').strip() == 'inactive'
                assert name not in {row['ifname'] for row in json.loads(ref.command('ip', '-j', 'link').stdout)}
                for prefix in components[name]['routes']:
                    assert not json.loads(ref.command('ip', '-'+str(ip.ip_network(prefix).version), '-j', 'route', 'show', 'exact', prefix).stdout)
                checks.append(name+' stopping network unit also stops translator and removes owned routes')
            print(json.dumps({'status': 'pass', 'checks': checks, 'count': len(checks),
                              'real_systemd_units': True, 'runtime_yaml': False, 'runtime_compiler': False}, sort_keys=True))
        except Exception:
            print(json.dumps({'completed_checks': checks}), file=sys.stderr)
            result = subprocess.run(['journalctl', '--no-pager', '-n', '100'], capture_output=True, text=True, timeout=2)
            print(result.stdout, file=sys.stderr)
            raise
        finally:
            subprocess.run(['systemctl', 'stop', *units], capture_output=True, timeout=20, check=False)
            for child in reversed(children):
                if child.poll() is None:
                    child.terminate()
                child.wait(timeout=2)
            for name in ('c6', 'p6', 'c4', 'p4'):
                ref.command('ip', 'netns', 'del', name, check=False)


if __name__ == '__main__':
    main(Path(sys.argv[1]))
