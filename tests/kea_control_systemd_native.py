#!/usr/bin/env python3
"""Qualify the actual Kea unit's generated post-start check in an offline guest."""

import argparse
import csv
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import pwd
import shutil
import stat
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT/'tests')]
from lanrith import config
from kea_control_native import command, query, collector_access, generated_collector_access
from test_radius import declaration


def qualify(output):
    assert os.geteuid() == 0 and Path('/proc/1/comm').read_text().strip() == 'systemd'
    assert not Path('/usr/share/lanrith/installed.json').exists(), 'Refuse an installed router.'
    assert {row['ifname'] for row in json.loads(command('ip', '-json', 'link'))} == {'lo'}
    assert not Path('/run/kea/kea4-ctrl-socket').exists()
    assert not output.exists()
    account = pwd.getpwnam('_kea')
    value = declaration()
    value['networks']['devices']['dhcp4']['id'] = 79
    value = config.normalize(value)
    files = config.render(value)
    raw = files['etc/kea/kea-dhcp4.conf'].encode()
    path = Path('/etc/kea/kea-dhcp4.conf')
    path.write_bytes(raw)
    os.chown(path, 0, account.pw_gid)
    path.chmod(0o640)
    library = Path('/usr/lib/lanrith/lanrith')
    library.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(ROOT/'lanrith/kea_runtime.py', library/'kea_runtime.py')
    (library/'kea_runtime.py').chmod(0o644)
    dropin = Path('/run/systemd/system/kea-dhcp4-server.service.d')
    dropin.mkdir(parents=True)
    hardening = 'mkosi/base/mkosi.extra/etc/systemd/system/kea-dhcp4-server.service.d/30-lanrith-hardening.conf'
    shutil.copyfile(ROOT/hardening, dropin/'30-lanrith-hardening.conf')
    (dropin/'60-lanrith-control.conf').write_text(files[
        'etc/systemd/system/kea-dhcp4-server.service.d/60-lanrith-control.conf'])
    state = Path('/var/lib/kea')
    state.mkdir(parents=True, exist_ok=True)
    os.chown(state, account.pw_uid, account.pw_gid)
    state.chmod(0o750)
    expire = int(time.time())+600
    lease = {'address': '192.168.22.120', 'hwaddr': '02:00:00:00:22:79', 'client_id': '',
             'valid_lifetime': '3600', 'expire': str(expire), 'subnet_id': '79',
             'fqdn_fwd': '0', 'fqdn_rev': '0', 'hostname': 'synthetic-unit', 'state': '0', 'user_context': ''}
    with (state/'kea-leases4.csv').open('w') as stream:
        writer = csv.DictWriter(stream, fieldnames=list(lease), lineterminator='\n')
        writer.writeheader()
        writer.writerow(lease)
    os.chown(state/'kea-leases4.csv', account.pw_uid, account.pw_gid)
    (state/'kea-leases4.csv').chmod(0o600)
    names, observations = [], []
    try:
        for network in value['networks'].values():
            name = network['name']
            command('ip', 'link', 'add', name, 'type', 'dummy')
            names.append(name)
            for address in network['addresses']:
                command('ip', 'address', 'add', address, 'dev', name)
            command('ip', 'link', 'set', name, 'up')
        command('systemctl', 'daemon-reload')
        for iteration in range(2):
            command('systemctl', '--job-mode=ignore-dependencies',
                    'restart' if iteration else 'start', 'kea-dhcp4-server.service')
            assert command('systemctl', 'is-active', 'kea-dhcp4-server.service').strip() == b'active'
            pid = int(command('systemctl', 'show', '--value', '--property=MainPID', 'kea-dhcp4-server.service'))
            status = dict(line.split(':', 1) for line in Path('/proc/'+str(pid)+'/status').read_text().splitlines())
            assert int(status['Uid'].split()[1]) == account.pw_uid
            assert int(status['CapEff'], 16) == int(status['CapBnd'], 16) == 0x2400
            assert status['NoNewPrivs'].strip() == '1'
            assert stat.S_IMODE(Path('/run/kea/kea4-ctrl-socket').stat().st_mode) == 0o660
            collector_access()
            generated_collector_access(files['usr/lib/systemd/system/lanrith-policy-bindings.service'])
            for name, arguments in [('lease4-get-by-hw-address', {'hw-address': lease['hwaddr']}),
                                    ('lease4-get-page', {'from': '0.0.0.0', 'limit': 128})]:
                rows = query(name, arguments)
                assert len(rows) == 1 and rows[0]['subnet-id'] == 79
                assert rows[0]['cltt']+rows[0]['valid-lft'] == expire
            observations.append({'main_pid': pid, 'socket_mode': '0660', 'uid': account.pw_uid,
                                 'original_expiry': expire, 'lease_queries': 'pass',
                                 'capability_empty_collector_with_declared_group': 'pass',
                                 'capability_empty_root_without_group': 'denied',
                                 'generated_radius_collector_dac_socket_access': 'pass'})
        assert path.read_bytes() == raw
    except Exception:
        diagnostic = subprocess.run(['journalctl', '--no-pager', '-u', 'kea-dhcp4-server.service', '-n', '25'],
                                    capture_output=True, timeout=10)
        sys.stderr.buffer.write(diagnostic.stdout[-8192:])  # Synthetic fixture only.
        raise
    finally:
        subprocess.run(['systemctl', 'stop', 'kea-dhcp4-server.service'], capture_output=True, timeout=15)
        for name in names:
            subprocess.run(['ip', 'link', 'delete', name], capture_output=True, timeout=5)
    result = {'schema': 1, 'test': 'offline-generated-kea-systemd-readiness', 'result': 'pass',
        'assessed_at': datetime.now(timezone.utc).isoformat(), 'observations': observations,
        'systemd_version': command('systemctl', '--version').decode().splitlines()[0],
        'kea_version': command('kea-dhcp4', '-v').decode().strip(),
        'native_configuration_sha256': hashlib.sha256(raw).hexdigest(),
        'generated_post_start': files['etc/systemd/system/kea-dhcp4-server.service.d/60-lanrith-control.conf'],
        'source_sha256': {name: hashlib.sha256((ROOT/name).read_bytes()).hexdigest() for name in
            ('lanrith/config.py', 'lanrith/build.py', 'lanrith/kea_runtime.py', hardening,
             'lanrith/policy_agent.py', 'tests/kea_control_native.py',
             'tests/kea_control_systemd_native.py', 'tests/test_radius.py')},
        'full_systemd_sandbox_applied': True, 'boot_dependency_order_qualified': False,
        'external_network': False, 'private_image_qualified': False, 'production_changed': False}
    with output.open('x') as stream:
        json.dump(result, stream, sort_keys=True, indent=2)
        stream.write('\n')
    print('Actual generated Kea systemd post-start readiness and restart passed.')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--result', type=Path, required=True)
    qualify(parser.parse_args().result)
