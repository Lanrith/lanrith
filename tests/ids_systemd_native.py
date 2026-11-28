#!/usr/bin/env python3
"""Exercise the WAN sensor, selective observer and rotation in a disposable offline guest."""

import argparse
import gzip
import json
import os
from pathlib import Path
import pwd
import shutil
import subprocess
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from lanrith import config, ids, ids_observer
from ids_native import SYN
from test_intent import minimal

PROJECT = Path(__file__).resolve().parents[1]
EVE = Path('/var/log/suricata/eve.json')


def run(*cmd, **kwargs):
    return subprocess.run(cmd, check=True, text=True, **kwargs)


def until(fn, seconds=45):
    end = time.monotonic()+seconds
    while time.monotonic() < end:
        try:
            if result := fn():
                return result
        except (FileNotFoundError, json.JSONDecodeError):
            pass
        time.sleep(.2)
    raise AssertionError('Timed out waiting for '+fn.__name__)


def send(seq):
    mac = Path('/sys/class/net/wan/address').read_text().strip()
    peer = subprocess.check_output(['ip', 'netns', 'exec', 'peer', 'cat', '/sys/class/net/eth0/address'], text=True).strip()
    run('ip', 'netns', 'exec', 'peer', 'python3', '-c', SYN, '192.0.2.2', '192.0.2.1', mac, peer, str(42000+seq))


def events(path):
    opener = gzip.open if path.suffix == '.gz' else open
    with opener(path, 'rt') as stream:
        return [json.loads(line) for line in stream if line.strip()]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--isolated', action='store_true', required=True)
    parser.parse_args()
    assert os.geteuid() == 0 and Path('/proc/1/comm').read_text().strip() == 'systemd'
    assert {p.name for p in Path('/sys/class/net').iterdir()} == {'lo'}
    assert '8.0.8 RELEASE' in subprocess.check_output(['suricata', '-V'], text=True)
    value = minimal()
    value['uplink']['ipv4'] = {'address': '192.0.2.1/24', 'gateway': '192.0.2.2'}
    value['observability'] = {'ids': {'enabled': True, 'forward_alerts': True},
        'metrics': {'enabled': True, 'clients': ['home']},
        'logs': {'enabled': True, 'endpoint': 'https://192.168.10.4/otlp', 'tls_server_name': 'logs.test'}}
    for name, contents in ids.render(config.normalize(value)).items():
        path = Path('/')/name
        path.parent.mkdir(parents=True, exist_ok=True)
        if name == 'etc/suricata/lanrith.yaml':
            assert 'interval: 30' in contents
            contents = contents.replace('interval: 30', 'interval: 2')
        path.write_text(contents)
    module = Path('/usr/lib/lanrith/lanrith/ids_observer.py')
    module.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(PROJECT/'lanrith/ids_observer.py', module)
    rule = Path('/usr/share/lanrith/suricata.rules')
    rule.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(PROJECT/'mkosi/base/mkosi.extra/usr/share/lanrith/suricata.rules', rule)
    run('systemd-sysusers')
    user = pwd.getpwnam('lanrith-ids')
    run('ip', 'netns', 'add', 'peer')
    run('ip', 'link', 'add', 'wan', 'type', 'veth', 'peer', 'name', 'eth0', 'netns', 'peer')
    run('ip', 'address', 'add', '192.0.2.1/24', 'dev', 'wan')
    run('ip', 'link', 'set', 'wan', 'up')
    run('ip', '-n', 'peer', 'link', 'set', 'eth0', 'up')
    run('ip', '-n', 'peer', 'address', 'add', '192.0.2.2/24', 'dev', 'eth0')
    run('systemctl', 'daemon-reload')
    run('systemctl', 'start', 'lanrith-ids.service')

    def fresh():
        state = ids_observer.read_observation()
        return state if state['totals']['capture_packets'] else None

    def ownership():
        info = EVE.parent.stat()
        assert info.st_uid == user.pw_uid and info.st_gid == user.pw_gid and info.st_mode & 0o777 == 0o750
        assert EVE.stat().st_uid == user.pw_uid and EVE.stat().st_mode & 0o007 == 0
        assert subprocess.run(['runuser', '-u', 'nobody', '--', 'test', '-r', str(EVE)]).returncode == 1
        assert subprocess.run(['runuser', '-u', user.pw_name, '--', 'test', '-w', str(rule)]).returncode == 1

    def engine_ready():
        invocation = subprocess.check_output(
            ['systemctl', 'show', '--value', '-p', 'InvocationID', 'lanrith-ids.service'], text=True).strip()
        stdout = subprocess.check_output(['journalctl', '--no-pager', '-o', 'cat',
                                          '_SYSTEMD_INVOCATION_ID='+invocation], text=True)
        return 'engine started' in stdout.lower()
    until(engine_ready)
    until(lambda: EVE.exists())
    send(1)
    until(lambda: any(r.get('src_port') == 42001 for r in events(EVE)))
    ownership()
    run('systemd-tmpfiles', '--create', '--prefix=/var/log/suricata')
    ownership()
    sample = until(fresh, 90)
    print('Native capture totals', sample['totals'], flush=True)
    first = EVE.stat().st_ino
    # Exercise the generated size-check service with a reduced fixture threshold.
    rotate = Path('/etc/lanrith/ids.logrotate')
    rotate.write_text(rotate.read_text().replace('size 16M', 'size 1'))
    run('systemctl', 'start', 'lanrith-ids-rotate.service')
    assert EVE.stat().st_ino != first and EVE.with_name('eve.json.1').stat().st_ino == first
    ownership()
    send(2)
    until(lambda: any(r.get('src_port') == 42002 for r in events(EVE)))
    archived = events(EVE.with_name('eve.json.1'))
    assert [r['src_port'] for r in archived if r['event_type'] == 'alert'] == [42001]
    assert [r['src_port'] for r in events(EVE) if r['event_type'] == 'alert'] == [42002]
    state = until(lambda: (s if (s := fresh()) and s['delta'] is not None else None), 90)
    print('Native interval after rotation', state['delta'], flush=True)
    # Fill four archive generations and verify delayed compression and pruning.
    for seq in range(3, 7):
        run('systemctl', 'start', 'lanrith-ids-rotate.service')
        send(seq)
        until(lambda: any(r.get('src_port') == 42000+seq for r in events(EVE)))
    assert sorted(path.name for path in EVE.parent.glob('eve.json.*')) == [
        'eve.json.1', 'eve.json.2.gz', 'eve.json.3.gz', 'eve.json.4.gz']
    for seq in range(2, 6):
        age = 6-seq
        archive = EVE.with_name('eve.json.'+str(age)+('.gz' if age > 1 else ''))
        assert [row['src_port'] for row in events(archive) if row['event_type'] == 'alert'] == [42000+seq]

    # The EVE datagram sender must be the sensor uid; unexpected fields cannot reach the journal.
    injection = """import json,socket,sys,time
s=socket.socket(socket.AF_UNIX,socket.SOCK_DGRAM)
s.sendto(json.dumps({'event_type':'alert','timestamp':'2026-01-01T10:00:00+00:00',
'in_iface':'wan','alert':{'signature_id':1000002},'extra':'WITHHELD_FIELD'}).encode(),sys.argv[1])
"""
    run('python3', '-c', injection, '/run/lanrith-ids-observer.sock')
    run('runuser', '-u', user.pw_name, '--', 'python3', '-c', injection, '/run/lanrith-ids-observer.sock')
    run('systemctl', 'restart', 'lanrith-ids.service')
    until(engine_ready)
    ownership()
    def journal():
        raw = subprocess.check_output(['journalctl', '--no-pager', '-o', 'cat',
            '_SYSTEMD_UNIT=lanrith-ids-observer.service'], text=True)
        rows = [json.loads(l) for l in raw.splitlines() if l.startswith('{')]
        if not any(row['sid'] == 1000002 for row in rows):
            return None
        assert len([row for row in rows if row['sid'] == 1000001]) == 6
        assert len([row for row in rows if row['sid'] == 1000002]) == 1
        assert all(set(row) == {'sid', 'interface', 'event_time'} and row['interface'] == 'wan' for row in rows)
        assert 'WITHHELD_FIELD' not in raw
        return rows
    print('Projected journal events', until(journal), flush=True)
    run('systemctl', 'stop', 'lanrith-ids-observer.socket', 'lanrith-ids-observer.service')
    run('systemctl', 'is-active', '--quiet', 'lanrith-ids.service')
    send(7)
    until(lambda: any(r.get('src_port') == 42007 for r in events(EVE)))
    # A stopped sensor must leave a failed reopen visible to the maintenance caller.
    run('systemctl', 'stop', 'lanrith-ids.service')
    result = subprocess.run(['logrotate', '--force', '--state', '/tmp/ids-force.state', '/etc/lanrith/ids.logrotate'])
    assert result.returncode != 0
    print('Sensor ownership, consecutive rotation records, remote projection, and failed reopen verified.')


if __name__ == '__main__':
    main()
