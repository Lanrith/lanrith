#!/usr/bin/env python3
"""Qualify scoped image-delivered SNMP in an empty, disposable Debian systemd guest."""

import copy
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from lanrith import build, config, credential_image, snmp
from snmp_slot_probe import get, profile, qualify
from test_snmp import fixture


PREFIX = 'fd42:1234:5678:10::'
RETAINED = [PREFIX+'56/128', PREFIX+'57/128']
EXCEPTION = PREFIX+'100/120'
UNIT = 'snmpd.service'
GATE = 'lanrith-credential-snmp-user.service'


def run(*args, **kwargs):
    result = subprocess.run(args, capture_output=True, timeout=35, text=True, **kwargs)
    if result.returncode:
        raise AssertionError(f'{args[0]} {args[1]} failed: {result.stderr[:1000]}')
    return result.stdout


def appliance_tools():
    # Minimal systemd qualification media may lack Net-SNMP. Its read-only
    # appliance mount contains the selected binaries and their Debian libraries.
    mount = Path('/opt/fixture-platform')
    for binary in ('/usr/sbin/snmpd', '/usr/bin/snmpget'):
        if mount.is_dir():
            shutil.copy2(mount/binary[1:], binary)
        for _ in range(8):
            missing = re.findall(r'^\s*(\S+) => not found', run('ldd', binary), re.M)
            if not missing:
                break
            for name in missing:
                target = Path('/usr/lib/x86_64-linux-gnu')/name
                shutil.copy2(mount/str(target)[1:], target)
        else:
            raise AssertionError('Packaged Net-SNMP dependencies are unavailable.')
    if subprocess.run(['getent', 'passwd', 'Debian-snmp'], capture_output=True).returncode:
        run('useradd', '--system', '--no-create-home', '--user-group', 'Debian-snmp')


def network(server):
    run('mount', '--make-shared', '/run')
    run('ip', 'netns', 'add', 'pollers')
    run('ip', 'link', 'add', 'lan', 'type', 'veth', 'peer', 'name', 'eth0', 'netns', 'pollers')
    run('ip', 'link', 'set', 'lan', 'up')
    run('ip', 'address', 'add', PREFIX+'1/64', 'dev', 'lan', 'nodad')
    run('ip', 'address', 'add', server+'/128', 'dev', 'lo', 'nodad')
    run('ip', '-n', 'pollers', 'link', 'set', 'eth0', 'up')
    run('ip', '-n', 'pollers', 'link', 'set', 'lo', 'up')
    for suffix in ('56', '57', '111', '112', '211'):
        run('ip', '-n', 'pollers', 'address', 'add', PREFIX+suffix+'/64', 'dev', 'eth0', 'nodad')
    run('ip', '-n', 'pollers', 'route', 'add', 'default', 'via', PREFIX+'1')


def require_scopes(files, server, remote):
    unit = files['usr/lib/systemd/system/'+UNIT]
    admitted = set(re.findall(r'^IPAddressAllow=(.+)$', unit, re.M))
    assert admitted == set(remote) | {server+'/128', '::1/128'}
    addresses = '{ '+', '.join(sorted(remote))+' }'
    rules = [line.strip() for line in files['etc/nftables.conf'].splitlines()
             if 'udp dport 161 ' in line or 'udp sport 161 ' in line]
    assert rules == [
        f'iifname "lan" ip6 saddr {addresses} ip6 daddr {server} udp dport 161 accept',
        f'ip6 daddr {server} udp dport 161 drop',
        f'oifname "lan" ip6 saddr {server} ip6 daddr {addresses} udp sport 161 ct direction reply ct state established accept',
        f'oifname != "lo" ip6 saddr {server} udp sport 161 drop',
    ]


def prepare(root, intent):
    base = root/'base.tar'
    base.write_bytes(b'synthetic overlay-only assembly')
    source = root/'input.conf'
    intent['credentials'] = {'monitor_user': {'file': str(source)}}
    slots = {}
    for seq, remote in ((9, [*RETAINED, EXCEPTION]), (10, RETAINED)):
        value = copy.deepcopy(intent)
        value['observability']['snmp']['clients'] = [{'network': 'home', 'addresses': addr} for addr in remote]
        source.write_bytes(credential_image.snmp_grammar().configuration(profile(seq)))
        source.chmod(0o600)
        stage = root/str(seq)
        build.assembly(value, base, stage, version='0.1.0', sequence=seq)
        slots[seq] = stage/'mkosi.extra'
        require_scopes(config.render(value), snmp.listener(config.normalize(value)), remote)
    return slots


def copy_one(tree, name, dest=None):
    target = Path(dest or '/'+name)
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(tree/name, target)


def main():
    assert sys.argv[1:] == ['--disposable-systemd'] and os.geteuid() == 0
    assert Path('/proc/1/comm').read_text().strip() == 'systemd'
    assert {row['ifname'] for row in json.loads(run('ip', '-j', 'link'))} == {'lo'}
    assert not Path('/usr/share/lanrith/installed.json').exists()
    appliance_tools()
    value = fixture()
    value['observability']['snmp']['username'] = profile(9)['username']
    server = snmp.listener(config.normalize(value))
    network(server)
    units = Path('/run/systemd/system')
    units.mkdir(parents=True, exist_ok=True)
    # The fixture has already constructed the network and applies the generated
    # firewall below. PID 1 controls the unmodified agent, gate and their sandbox.
    for unit in ('lanrith-services.service', 'nftables.service'):
        (units/unit).write_text('[Service]\nType=oneshot\nRemainAfterExit=yes\nExecStart=/bin/true\n')
    with tempfile.TemporaryDirectory(dir='/run') as tmp:
        slots = prepare(Path(tmp), value)
        base = slots[9]
        shutil.copytree(base/'usr/lib/lanrith', '/usr/lib/lanrith', dirs_exist_ok=True)
        for name in ('usr/bin/lanrith-credentials', 'etc/snmp/snmpd.conf',
                     'etc/lanrith/integrations/snmp-runtime-policy.json', 'usr/lib/tmpfiles.d/80-lanrith-snmp.conf'):
            copy_one(base, name)
        for unit in (GATE, UNIT):
            copy_one(base, 'usr/lib/systemd/system/'+unit, units/unit)
        copy_one(base, 'etc/systemd/system/'+UNIT+'.d/50-lanrith-credentials.conf',
                 units/(UNIT+'.d/50-lanrith-credentials.conf'))
        run('systemd-tmpfiles', '--create', '/usr/lib/tmpfiles.d/80-lanrith-snmp.conf')
        previous = None
        pinned = '['+PREFIX+'111]:49161'
        for seq in (9, 10, 9):
            tree = slots[seq]
            for name in ('usr/share/lanrith', 'usr/lib/lanrith/credentials'):
                target = Path('/')/name
                target.mkdir(parents=True, exist_ok=True)
                run('mount', '--bind', tree/name, target)
                run('mount', '-o', 'remount,bind,ro', target)
            copy_one(tree, 'usr/lib/systemd/system/'+UNIT, units/UNIT)
            run('systemctl', 'daemon-reload')
            run('nft', '-f', tree/'etc/nftables.conf')
            run('systemctl', 'start', UNIT)
            try:
                deadline = time.monotonic()+15
                while server not in run('ss', '-lun6', 'sport = :161'):
                    assert time.monotonic() < deadline, 'Net-SNMP did not bind its selected address.'
                    time.sleep(.2)
                current = qualify(seq, 'lan')
                for addr in RETAINED:
                    get(server, seq, 'lan', source=addr.split('/')[0], namespace='pollers')
                if previous:
                    assert current['engine_id'] == previous['engine_id']
                    assert current['engine_boots'] > previous['engine_boots']
                get(server, seq, 'lan', source=PREFIX+'211', namespace='pollers', expected='withdrawn')
                if seq == 9:
                    for source in (pinned, PREFIX+'112'):
                        get(server, seq, 'lan', source=source, namespace='pollers')
                if previous is None:
                    # Withdraw just the firewall exception while the same daemon,
                    # address filter and conntrack entry remain in place.
                    run('nft', '-f', slots[10]/'etc/nftables.conf')
                    run('nft', '-f', '-', input='table inet observe_snmp {\n counter old_tuple {}\n'
                        'chain seen {\n type filter hook input priority -1; policy accept;\n'
                        f'iifname "lan" ip6 saddr {PREFIX}111 ip6 daddr {server} udp sport 49161 udp dport 161 '
                        'ct state established counter name old_tuple\n}\n}\n')
                    get(server, seq, 'lan', source=pinned, namespace='pollers', expected='withdrawn')
                    seen = json.loads(run('nft', '-j', 'list', 'counter', 'inet', 'observe_snmp', 'old_tuple'))
                    assert next(item['counter']['packets'] for item in seen['nftables'] if 'counter' in item) > 0
                if previous is None or seq == 10:
                    get(server, seq, 'lan', source=PREFIX+'112', namespace='pollers', expected='withdrawn')
                    for addr in RETAINED:
                        get(server, seq, 'lan', source=addr.split('/')[0], namespace='pollers')
                print(json.dumps(current), flush=True)
                previous = current
            finally:
                run('systemctl', 'stop', UNIT, GATE)
                run('umount', '/usr/lib/lanrith/credentials')
                run('umount', '/usr/share/lanrith')
    print('Two pollers retained, exact exception withdrawn on an established tuple, A/B/A profiles verified.')


if __name__ == '__main__':
    main()
