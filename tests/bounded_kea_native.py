#!/usr/bin/env python3
"""Exercise native Kea packets with the candidate paired policy component."""

import argparse
import csv
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys
import time
import uuid

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from lanrith import config, policy_agent


IMAGE = 'sha256:4ab633990b5614597c52f08138a3b664557c0589d8a2f81925219c210f6da237'


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run(*args, timeout=15):
    return subprocess.run(args, check=True, capture_output=True, text=True, timeout=timeout).stdout


def declaration():
    return {
        'schema': 1, 'hostname': 'dhcp-packet-test',
        'hardware': {'interfaces': {
            'uplink': {'name': 'wan', 'match': {'mac': '02:00:00:00:01:01'}},
            'first': {'name': 'lan10', 'match': {'mac': '02:00:00:00:01:10'}},
            'second': {'name': 'lan13', 'match': {'mac': '02:00:00:00:01:13'}}}},
        'uplink': {'interface': 'uplink', 'ipv4': {'address': '10.243.0.1/24', 'gateway': '10.243.0.2'},
                   'ipv6': 'disabled', 'masquerade': False},
        'addressing': {'ula_prefix': 'fdca:1a2b::/48'},
        'networks': {
            'first': {'interface': 'first', 'ipv4': '10.240.0.0/24'},
            'second': {'interface': 'second', 'ipv4': '10.240.3.0/24',
                       'dhcp4': {'id': 73, 'pools': ['10.240.3.100-10.240.3.110']}}},
        # This fixture qualifies DHCP only. Full default DNS/NTP/NAT boot is
        # a separate gate; no generated core dependency is removed to run it.
        'services': {'dns': {'enabled': False}, 'ntp': {'enabled': False}},
        'access': {'default': 'deny', 'rules': []},
        'administration': {'networks': ['first'], 'authorized_keys': [
            'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFhpcHJoRXhhbXBsZU9ubHlOb3RBVXNlcklkZW50aXR5']},
    }


def image_accounts(image):
    code = '''import hashlib,json,os,pathlib,pwd,subprocess
a=pwd.getpwnam('_kea')
print(json.dumps({'uid':a.pw_uid,'gid':a.pw_gid,
 'accounts':{n:pathlib.Path('/etc/'+n).read_text() for n in ('passwd','group')},
 'kea_sha256':hashlib.sha256(pathlib.Path('/usr/sbin/kea-dhcp4').read_bytes()).hexdigest(),
 'kea_version':subprocess.check_output(['/usr/sbin/kea-dhcp4','-v'],text=True).strip(),
 'visible_cpus':os.cpu_count()}))'''
    return json.loads(run('podman', 'run', '--rm', '--pull=never', '--network=none',
        '--cap-drop=ALL', '--security-opt=no-new-privileges', '--read-only', '--tmpfs=/tmp',
        '--memory=256m', '--pids-limit=32', image, 'python3', '-I', '-c', code))


def qualify(binary, work, image, denied, initial_counter=0):
    if not 0 <= initial_counter <= 4194300:
        raise ValueError('isolated counter must leave room for both configuration activations')
    binary = binary.resolve(strict=True)
    binary_hash = digest(binary)
    work.mkdir(mode=0o700, parents=True, exist_ok=False)
    work = work.resolve(strict=True)
    inputs, signals, state = (work/name for name in ('inputs', 'signals', 'state'))
    inputs.mkdir(mode=0o755)
    signals.mkdir(mode=0o700)
    state.mkdir(mode=0o750)
    metadata = image_accounts(image)
    accounts = {n: data.encode('ascii') for n, data in metadata.pop('accounts').items()}
    value = config.normalize(declaration())
    files = config.render(value)
    native = files['etc/kea/kea-dhcp4.conf'].encode()
    model = policy_agent.bounded_baseline(value, accounts)
    assert len(model['network_model']['host_dhcp4']) == 1
    assert model['network_model']['host_dhcp4'][0]['uid'] == metadata['uid'] != 0
    (inputs/'kea.json').write_bytes(native)
    (inputs/'policy-baseline.json').write_bytes(json.dumps(model, sort_keys=True).encode())
    name = 'lanrith-bounded-kea-'+uuid.uuid4().hex
    fixture_name = 'TestKernelBoundedKeaDeniedFixture' if denied else 'TestKernelBoundedKeaFixture'
    fixture_log = (work/'fixture.log').open('w')
    fixture = subprocess.Popen([
        # Keep the namespace holder until the dependent Kea container stops.
        'podman', 'run', '--name', name, '--pull=never', '--network=none',
        '--cap-drop=ALL', '--cap-add=NET_ADMIN', '--cap-add=NET_RAW',
        '--security-opt=no-new-privileges', '--read-only', '--tmpfs=/tmp',
        '--memory=1g', '--pids-limit=128', '--sysctl', 'net.ipv4.ip_forward=1',
        '--sysctl', 'net.ipv6.conf.all.forwarding=1', '-v', str(binary)+':/runner/test:ro',
        '-v', str(inputs)+':/inputs:ro', '-v', str(signals)+':/signals',
        '-e', 'ROUTER_POLICY_KERNEL_TEST=isolated', '-e', 'ROUTER_POLICY_KEA_FIXTURE=isolated',
        '-e', 'ROUTER_POLICY_KEA_INITIAL_COUNTER='+str(initial_counter),
        image, '/runner/test', '-test.v', '-test.run=^'+fixture_name+'$',
    ], stdout=fixture_log, stderr=subprocess.STDOUT)
    server, server_name, server_log = None, None, None
    episodes = []

    def remove_container(target):
        exists = subprocess.run(['podman', 'container', 'exists', target], capture_output=True, timeout=15, check=False)
        assert exists.returncode in (0, 1), 'Cannot inspect isolated container cleanup.'
        if exists.returncode == 0:
            run('podman', 'rm', '--force', '--time=0', target)
        absent = subprocess.run(['podman', 'container', 'exists', target], capture_output=True, timeout=15, check=False)
        assert absent.returncode == 1, 'Isolated container survived cleanup.'

    def wait_signal(filename):
        deadline = time.monotonic()+15
        while not (signals/filename).exists():
            if fixture.poll() is not None or time.monotonic() >= deadline:
                raise RuntimeError('Kea packet fixture did not reach '+filename+'\n'+(work/'fixture.log').read_text())
            time.sleep(.02)

    def stop_server():
        nonlocal server, server_log
        if server is not None:
            if server.poll() is None:
                run('podman', 'stop', '--time=5', server_name)
            code = server.wait(timeout=10)
            server_log.close()
            server, server_log = None, None
            assert code == 0, 'Kea did not terminate cleanly.'

    def start_server(episode):
        nonlocal server, server_name, server_log
        server_name = name+'-server-'+str(episode)
        log_path = work/f'kea-{episode}.log'
        server_log = log_path.open('w')
        server = subprocess.Popen([
            'podman', 'run', '--rm', '--name', server_name, '--pull=never',
            '--network=container:'+name, '--user='+str(metadata['uid'])+':'+str(metadata['gid']),
            '--cap-drop=ALL', '--cap-add=NET_RAW', '--cap-add=NET_BIND_SERVICE',
            '--security-opt=no-new-privileges', '--read-only', '--tmpfs=/tmp',
            '--memory=256m', '--pids-limit=32', '-v', str(inputs/'kea.json')+':/configuration/kea.json:ro',
            '-v', str(state)+':/var/lib/kea:U', '-e', 'KEA_PIDFILE_DIR=/tmp',
            '-e', 'KEA_LOCKFILE_DIR=/tmp', image, '/usr/sbin/kea-dhcp4', '-c', '/configuration/kea.json',
        ], stdout=server_log, stderr=subprocess.STDOUT)
        deadline = time.monotonic()+10
        while 'DHCP4_STARTED' not in log_path.read_text():
            if server.poll() is not None or time.monotonic() >= deadline:
                raise RuntimeError('Isolated Kea startup failed: '+log_path.read_text())
            time.sleep(.02)
        status = json.loads(run('podman', 'exec', server_name, 'python3', '-I', '-c',
            "import json,pathlib;print(json.dumps(dict(l.split(':',1) for l in pathlib.Path('/proc/1/status').read_text().splitlines())))"))
        assert [int(n) for n in status['Uid'].split()] == [metadata['uid']]*4
        assert all(int(status[n], 16) == 0x2400 for n in ('CapEff', 'CapPrm', 'CapBnd'))
        assert status['NoNewPrivs'].strip() == '1'
        assert 1 <= int(status['Threads']) <= 16
        episodes.append({'episode': episode, 'uid': metadata['uid'], 'threads': int(status['Threads']),
                         'capabilities': ['NET_RAW', 'NET_BIND_SERVICE']})

    try:
        wait_signal('ready-for-server')
        start_server(0)
        (signals/'server-ready').write_text('server started\n')
        if not denied:
            wait_signal('restart-requested')
            stop_server()
            start_server(1)
            (signals/'server-restarted').write_text('server restarted\n')
        fixture_exit = fixture.wait(timeout=50)
        stop_server()
        assert fixture_exit == 0 and (signals/'kea-qualified').is_file(), (work/'fixture.log').read_text()
        remove_container(name)
        run('podman', 'unshare', 'chown', '-R', '0:0', str(state))
        leases = {}
        with (state/'kea-leases4.csv').open() as stream:
            for row in csv.DictReader(stream):
                if row['address']:
                    assert row['subnet_id'] == '73' and row['valid_lifetime'] == '3600'
                    leases[row['address']] = row['hwaddr']
        assert len(leases) == (0 if denied else 3), leases
        if not denied:
            assert set(leases.values()) == {'02:00:00:00:00:13', '02:00:00:00:00:14', '02:00:00:00:00:15'}
        assert (inputs/'kea.json').read_bytes() == native and digest(binary) == binary_hash
        report = {'schema': 1, 'passed': True, 'denied': denied, 'nft_image': image,
            'initial_ownership_counter': initial_counter,
            'binary_sha256': binary_hash, 'native_configuration_sha256': hashlib.sha256(native).hexdigest(),
            'model_sha256': digest(inputs/'policy-baseline.json'), 'kea': metadata,
            'server_episodes': episodes, 'persisted_leases': leases,
            'container_cleanup_verified': True,
            'account_registry_sha256': {n: hashlib.sha256(data).hexdigest() for n, data in accounts.items()},
            'full_router_or_image_qualified': False}
        (work/'report.json').write_text(json.dumps(report, sort_keys=True, indent=2)+'\n')
        print(json.dumps(report, sort_keys=True), flush=True)
        return 0
    finally:
        for target in (server_name, name):
            if target:
                remove_container(target)
        if server is not None:
            server.wait(timeout=15)
        if server_log is not None:
            server_log.close()
        if fixture.poll() is None:
            fixture.wait(timeout=15)
        fixture_log.close()
        # :U ownership changes are confined to this newly created state path.
        subprocess.run(['podman', 'unshare', 'chown', '-R', '0:0', str(state)], capture_output=True, timeout=15, check=False)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--work', type=Path, required=True)
    parser.add_argument('--image', default=IMAGE)
    parser.add_argument('--denied', action='store_true', help='run Kea while the compiled DHCP permission is absent')
    parser.add_argument('--initial-counter', type=int, default=0,
                        help='seed only isolated fixture state before either configuration activation')
    args = parser.parse_args()
    if not re.fullmatch(r'sha256:[0-9a-f]{64}', args.image):
        parser.error('--image must pin a locally available tool image by SHA-256')
    if not 0 <= args.initial_counter <= 4194300:
        parser.error('--initial-counter must be between 0 and 4194300')
    return qualify(args.binary, args.work, args.image, args.denied, args.initial_counter)


if __name__ == '__main__':
    raise SystemExit(main())
