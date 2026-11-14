#!/usr/bin/env python3
"""Qualify generated Kea lease queries in an offline disposable mount/network namespace."""

import argparse
import csv
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import pwd
import socket
import stat
import struct
import subprocess
import sys
import time
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT/'tests')]
from lanrith import config
from test_radius import declaration


def command(*args):
    result = subprocess.run(args, capture_output=True, timeout=20)
    if result.returncode:
        # Only this isolated fixture's synthetic data reaches the diagnostic.
        sys.stderr.buffer.write((result.stdout+b'\n'+result.stderr)[-4096:])
    result.check_returncode()
    return result.stdout


def query(name, arguments):
    mode = stat.S_IMODE(Path('/run/kea/kea4-ctrl-socket').stat().st_mode)
    assert mode == 0o660, f'Kea administrative socket has incompatible mode {mode:04o}.'
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as stream:
        stream.settimeout(2)
        stream.connect('/run/kea/kea4-ctrl-socket')
        _, uid, _ = struct.unpack('3i', stream.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
        assert uid == pwd.getpwnam('_kea').pw_uid, 'Generated Kea service has the wrong peer UID.'
        stream.sendall(json.dumps({'command': name, 'arguments': arguments}).encode())
        stream.shutdown(socket.SHUT_WR)
        body = bytearray()
        while True:
            block = stream.recv(min(65536, (256 << 10)+1-len(body)))
            if not block:
                break
            body.extend(block)
            assert len(body) <= 256 << 10
    value = json.loads(body)
    assert value['result'] == 0, 'Generated Kea configuration cannot serve '+name+': '+json.dumps(value)
    return value['arguments']['leases']


def collector_access():
    """Exercise the base collector and private observer's capability-empty role."""
    account = pwd.getpwnam('_kea')
    program = '''
import json,os,pathlib,socket,struct,sys
assert os.getuid()==os.geteuid()==0
status=dict(line.split(':',1) for line in pathlib.Path('/proc/self/status').read_text().splitlines())
assert int(status['CapEff'],16)==int(status['CapBnd'],16)==0 and status['NoNewPrivs'].strip()=='1'
with socket.socket(socket.AF_UNIX) as connection:
 connection.settimeout(2)
 try: connection.connect('/run/kea/kea4-ctrl-socket')
 except PermissionError: sys.exit(10)
 _,uid,_=struct.unpack('3i',connection.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12))
 assert uid==int(sys.argv[1])
 connection.sendall(b'{"command":"lease4-get-page","arguments":{"from":"0.0.0.0","limit":128}}')
 connection.shutdown(socket.SHUT_WR)
 raw=bytearray()
 while True:
  block=connection.recv(4096)
  if not block: break
  raw.extend(block);assert len(raw)<=65536
 value=json.loads(raw);assert value['result']==0 and len(value['arguments']['leases'])==1
'''
    for groups, expected in ((str(account.pw_gid), 0), ('', 10)):
        result = subprocess.run(['setpriv', '--reuid=0', '--regid=0',
            *(['--groups='+groups] if groups else ['--clear-groups']), '--bounding-set=-all',
            '--inh-caps=-all', '--ambient-caps=-all', '--no-new-privs',
            sys.executable, '-c', program, str(account.pw_uid)], capture_output=True, timeout=5)
        assert result.returncode == expected, (
            'Declared capability-empty collector access differs: '+str(result.returncode)+' expected '+str(expected))


def generated_collector_access(unit):
    """Check the generated RADIUS collector's distinct existing DAC envelope.

    The generated unit replaces the base unit and retains DAC access for its
    journal/host evidence. A capability-empty observer test does not qualify
    that different service. This check covers its socket access only.
    """
    lines = unit.splitlines()
    for field in ('User=root', 'Group=root', 'NoNewPrivileges=yes',
                  'CapabilityBoundingSet=CAP_DAC_OVERRIDE CAP_DAC_READ_SEARCH'):
        assert lines.count(field) == 1
    assert not any(line.startswith('SupplementaryGroups=') for line in lines)
    program = '''
import json,os,pathlib,socket
assert os.getuid()==os.geteuid()==0 and os.getgid()==os.getegid()==0 and os.getgroups()==[]
status=dict(line.split(':',1) for line in pathlib.Path('/proc/self/status').read_text().splitlines())
assert int(status['CapEff'],16)==int(status['CapBnd'],16)==6 and status['NoNewPrivs'].strip()=='1'
with socket.socket(socket.AF_UNIX) as connection:
 connection.settimeout(2);connection.connect('/run/kea/kea4-ctrl-socket')
 connection.sendall(b'{"command":"lease4-get-page","arguments":{"from":"0.0.0.0","limit":128}}')
 connection.shutdown(socket.SHUT_WR);raw=bytearray()
 while True:
  block=connection.recv(4096)
  if not block: break
  raw.extend(block);assert len(raw)<=65536
 value=json.loads(raw);assert value['result']==0 and len(value['arguments']['leases'])==1
'''
    command('setpriv', '--reuid=0', '--regid=0', '--clear-groups',
            '--bounding-set=-all,+dac_override,+dac_read_search',
            '--inh-caps=-all', '--ambient-caps=-all', '--no-new-privs', sys.executable, '-c', program)


def qualify(output):
    assert os.geteuid() == 0
    assert not Path('/usr/share/lanrith/installed.json').exists(), 'Refuse an installed router.'
    assert {row['ifname'] for row in json.loads(command('ip', '-json', 'link'))} == {'lo'}
    if output is not None:
        assert not output.exists()
    command('mount', '-t', 'tmpfs', '-o', 'mode=0755', 'tmpfs', '/run')
    account = pwd.getpwnam('_kea')
    Path('/run/kea').mkdir(mode=0o750)
    os.chown('/run/kea', account.pw_uid, account.pw_gid)
    Path('/run/lock/kea').mkdir(mode=0o750, parents=True)
    os.chown('/run/lock/kea', account.pw_uid, account.pw_gid)
    value = declaration()
    value['networks']['devices']['dhcp4']['id'] = 79
    value = config.normalize(value)
    files = config.render(value)
    generated_unit = files['usr/lib/systemd/system/lanrith-policy-bindings.service']
    raw = files['etc/kea/kea-dhcp4.conf'].encode()
    post = files['etc/systemd/system/kea-dhcp4-server.service.d/60-lanrith-control.conf']
    assert 'ExecStartPost=/usr/bin/python3 /usr/lib/lanrith/lanrith/kea_runtime.py $MAINPID\n' in post
    collector_unit = ROOT/'mkosi/base/mkosi.extra/usr/lib/systemd/system/lanrith-policy-bindings.service'
    assert all(line in collector_unit.read_text().splitlines() for line in
               ('User=root', 'Group=root', 'SupplementaryGroups=_kea', 'CapabilityBoundingSet=', 'NoNewPrivileges=yes'))
    # Hosted checkouts can have non-traversable home directories. Stage the
    # exact runtime bytes on this private /run mount; do not change checkout or
    # home permissions to let the service identity read build-time sources.
    helper = Path('/run/lanrith-kea-readiness.py')
    helper.write_bytes((ROOT/'lanrith/kea_runtime.py').read_bytes())
    helper.chmod(0o644)
    hardening = ROOT/'mkosi/base/mkosi.extra/etc/systemd/system/kea-dhcp4-server.service.d/30-lanrith-hardening.conf'
    mask, = [line.split('=', 1)[1] for line in hardening.read_text().splitlines() if line.startswith('UMask=')]
    checks, names = [], []
    with tempfile.TemporaryDirectory(prefix='lanrith-kea-query.', dir='/etc/kea') as temporary:
        root = Path(temporary)
        root.chmod(0o755)
        config_path = root/'kea-dhcp4.conf'
        config_path.write_bytes(raw)
        config_path.chmod(0o644)
        state = root/'leases'
        state.mkdir(mode=0o750)
        os.chown(state, account.pw_uid, account.pw_gid)
        Path('/var/lib/kea').mkdir(parents=True, exist_ok=True)
        command('mount', '--bind', str(state), '/var/lib/kea')
        now = int(time.time())
        lease = {'address': '192.168.22.120', 'hwaddr': '02:00:00:00:22:79', 'client_id': '',
                 'valid_lifetime': '3600', 'expire': str(now+600), 'subnet_id': '79',
                 'fqdn_fwd': '0', 'fqdn_rev': '0', 'hostname': 'synthetic-query', 'state': '0', 'user_context': ''}
        lease_path = state/'kea-leases4.csv'
        with lease_path.open('w') as stream:
            writer = csv.DictWriter(stream, fieldnames=list(lease), lineterminator='\n')
            writer.writeheader()
            writer.writerow(lease)
        os.chown(lease_path, account.pw_uid, account.pw_gid)
        lease_path.chmod(0o600)
        process = None
        try:
            for network in value['networks'].values():
                name = network['name']
                command('ip', 'link', 'add', name, 'type', 'dummy')
                names.append(name)
                for address in network['addresses']:
                    command('ip', 'address', 'add', address, 'dev', name)
                command('ip', 'link', 'set', name, 'up')
            query_types = [('lease4-get-by-hw-address', {'hw-address': lease['hwaddr']}),
                           ('lease4-get-page', {'from': '0.0.0.0', 'limit': 128})]
            for iteration in range(2):
                log_path = root/('kea-'+str(iteration)+'.log')
                with log_path.open('wb') as log:
                    process = subprocess.Popen(['setpriv', '--reuid='+str(account.pw_uid),
                        '--regid='+str(account.pw_gid), '--clear-groups',
                        '--bounding-set=-all,+net_bind_service,+net_raw',
                        '--inh-caps=-all,+net_bind_service,+net_raw',
                        '--ambient-caps=-all,+net_bind_service,+net_raw', '--no-new-privs',
                        '/usr/sbin/kea-dhcp4', '-c', str(config_path)], stdin=subprocess.DEVNULL,
                        stdout=log, stderr=subprocess.STDOUT,
                        umask=int(mask, 8),
                        env={'PATH': '/usr/sbin:/usr/bin', 'LC_ALL': 'C', 'KEA_PIDFILE_DIR': '/run/kea',
                             'KEA_LOCKFILE_DIR': '/run/lock/kea'})
                    deadline = time.monotonic()+10
                    while b'DHCP4_STARTED' not in log_path.read_bytes():
                        assert process.poll() is None and time.monotonic() < deadline, (
                            'Synthetic Kea startup failed: '+log_path.read_text()[-2048:])
                        time.sleep(0.05)
                    status = dict(line.split(':', 1) for line in Path('/proc/'+str(process.pid)+'/status').read_text().splitlines())
                    assert int(status['Uid'].split()[1]) == account.pw_uid
                    assert int(status['CapEff'], 16) == int(status['CapBnd'], 16) == 0x2400
                    assert status['NoNewPrivs'].strip() == '1'
                    # Execute the generated post-start operation under the same
                    # unprivileged identity/capability envelope as the service.
                    command('setpriv', '--reuid='+str(account.pw_uid), '--regid='+str(account.pw_gid),
                        '--clear-groups', '--bounding-set=-all,+net_bind_service,+net_raw',
                        '--inh-caps=-all,+net_bind_service,+net_raw',
                        '--ambient-caps=-all,+net_bind_service,+net_raw', '--no-new-privs',
                        sys.executable, str(helper), str(process.pid))
                    collector_access()
                    generated_collector_access(generated_unit)
                    if not iteration:
                        checks.extend(['capability-empty root collector with declared _kea group can read',
                                       'capability-empty root without _kea group denied',
                                       'generated RADIUS collector retains its declared DAC socket access'])
                    for name, arguments in query_types:
                        leases = query(name, arguments)
                        assert len(leases) == 1 and leases[0]['ip-address'] == lease['address']
                        assert leases[0]['hw-address'] == lease['hwaddr'] and leases[0]['subnet-id'] == 79
                        assert leases[0]['state'] == 0 and leases[0]['cltt']+leases[0]['valid-lft'] == int(lease['expire'])
                        checks.append(name+(' after restart' if iteration else ' from generated configuration'))
                    if not iteration:
                        for denied_uid in (65534, 1702):
                            denied = subprocess.run(['setpriv', '--reuid='+str(denied_uid),
                                '--regid='+str(denied_uid), '--clear-groups', '--bounding-set=-all',
                                '--no-new-privs', sys.executable, '-c',
                                'import socket; s=socket.socket(socket.AF_UNIX); s.connect("/run/kea/kea4-ctrl-socket")'],
                                capture_output=True, timeout=5)
                            assert denied.returncode != 0 and b'PermissionError' in denied.stderr, (
                                'Ordinary UID reached live administrative Kea IPC.')
                            checks.append('ordinary UID '+str(denied_uid)+' denied live administrative control socket')
                    process.terminate()
                    assert process.wait(timeout=10) == 0
                    process = None
            assert config_path.read_bytes() == raw, 'Native configuration changed during qualification.'
            checks.append('generated native configuration used without fixture hook injection')
        finally:
            if process is not None:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)
            for name in names:
                subprocess.run(['ip', 'link', 'delete', name], capture_output=True, timeout=5)
            command('umount', '/var/lib/kea')
    if output is not None:
        result = {'schema': 1, 'test': 'offline-generated-kea-control-queries', 'result': 'pass',
            'assessed_at': datetime.now(timezone.utc).isoformat(), 'checks': checks,
            'kea_version': command('kea-dhcp4', '-v').decode().strip(),
            'native_configuration_sha256': hashlib.sha256(raw).hexdigest(),
            'native_configuration_modified': False, 'service_uid': account.pw_uid,
            'effective_and_bounding_capabilities': ['CAP_NET_BIND_SERVICE', 'CAP_NET_RAW'],
            'no_new_privileges': True, 'full_systemd_sandbox_qualified': False,
            'socket_mode': '0660', 'generated_post_start_operation': True,
            'collector_dac_capabilities': [], 'collector_supplementary_group': '_kea',
            'generated_collector_socket_access': {
                'capabilities': ['CAP_DAC_OVERRIDE', 'CAP_DAC_READ_SEARCH'],
                'supplementary_groups': [],
                'unit_sha256': hashlib.sha256(generated_unit.encode()).hexdigest(),
                'complete_binding_producer_qualified': False},
            'source_sha256': {name: hashlib.sha256((ROOT/name).read_bytes()).hexdigest() for name in
                ('lanrith/config.py', 'lanrith/build.py', 'lanrith/kea_runtime.py', 'tests/kea_control_native.py',
                 'lanrith/policy_agent.py', 'tests/test_radius.py', 'tests/native.py',
                 'mkosi/base/mkosi.extra/usr/lib/systemd/system/lanrith-policy-bindings.service',
                 'mkosi/base/mkosi.extra/etc/systemd/system/kea-dhcp4-server.service.d/30-lanrith-hardening.conf')},
            'private_image_qualified': False, 'production_changed': False}
        with output.open('x') as stream:
            json.dump(result, stream, sort_keys=True, indent=2)
            stream.write('\n')
    print('Native generated Kea control queries, retained expiry and UID boundary passed.')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--result', type=Path)
    parser.add_argument('--isolated', action='store_true')
    args = parser.parse_args()
    assert os.geteuid() == 0, 'Use an isolated root test environment.'
    if args.isolated:
        qualify(args.result)
    else:
        subprocess.run(['unshare', '--mount', '--net', '--fork', '--propagation', 'private', '--',
            sys.executable, str(Path(__file__).resolve()), '--isolated',
            *(['--result', str(args.result)] if args.result is not None else [])], check=True, timeout=75)
