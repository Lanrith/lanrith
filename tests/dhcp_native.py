#!/usr/bin/env python3
"""Renew a retained synthetic lease across native Kea restarts with a pinned ID."""

import argparse
import csv
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from lanrith import config
from vm import lease_snapshot


ROOT = Path(__file__).resolve().parents[1]
CLIENT = '''
import json,os,socket,struct,sys
address,gateway,mac=sys.argv[1:]
xid=int.from_bytes(os.urandom(4),'big')
zero=b'\\0'*4
header=struct.pack('!BBBBIHH4s4s4s4s16s64s128s',1,1,6,0,xid,0,0,
    socket.inet_aton(address),zero,zero,zero,bytes.fromhex(mac.replace(':',''))+b'\\0'*10,b'\\0'*64,b'\\0'*128)
packet=header+b'\\x63\\x82\\x53\\x63'+bytes([53,1,3,55,3,1,3,6,255])
with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as stream:
    stream.settimeout(3);stream.bind((address,68));stream.sendto(packet,(gateway,67))
    response,peer=stream.recvfrom(4096)
assert len(response)>=240 and response[0]==2 and struct.unpack('!I',response[4:8])[0]==xid
assert response[236:240]==b'\\x63\\x82\\x53\\x63'
options={};offset=240
while offset<len(response):
    code=response[offset];offset+=1
    if code==255:break
    if code==0:continue
    assert offset<len(response)
    length=response[offset];offset+=1
    assert code not in options and offset+length<=len(response)
    options[code]=response[offset:offset+length];offset+=length
assert options[53]==bytes([5]),'retained lease did not receive DHCPACK'
assert socket.inet_ntoa(response[16:20])==address
assert options[3]==socket.inet_aton(gateway)
assert options[6]==socket.inet_aton('10.255.254.10')
print(json.dumps({'reply':'DHCPACK','address':address,'router':gateway,'dns':'10.255.254.10'}))
'''


def command(*args, timeout=15, **kwargs):
    result = subprocess.run(args, stdin=subprocess.DEVNULL, capture_output=True, timeout=timeout, **kwargs)
    if result.returncode:
        # The fixture contains synthetic lease data only.
        sys.stderr.buffer.write((result.stdout+b'\n'+result.stderr)[-4096:])
    result.check_returncode()
    return result


def stop(process):
    process.terminate()
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=5)


def qualify(result):
    assert not Path('/usr/share/lanrith/installed.json').exists()
    assert {row['ifname'] for row in json.loads(command('ip', '-json', 'link').stdout)} == {'lo'}
    # Native tmpfiles has not run in this executable-only fixture. Supply its
    # runtime directories in a private mount rather than using host state.
    command('mount', '-t', 'tmpfs', '-o', 'mode=0755', 'tmpfs', '/run')
    Path('/run/netns').mkdir(mode=0o700)
    Path('/run/kea').mkdir(mode=0o750)
    Path('/run/lock/kea').mkdir(mode=0o750, parents=True)
    with tempfile.TemporaryDirectory(prefix='lanrith-lease-id.', dir='/etc/kea') as temporary:
        work = Path(temporary)
        work.chmod(0o755)
        leases = work/'leases'
        leases.mkdir()
        Path('/var/lib/kea').mkdir(parents=True, exist_ok=True)
        command('mount', '--bind', str(leases), '/var/lib/kea')
        process = None
        try:
            command('ip', 'netns', 'add', 'lease-client')
            command('ip', 'link', 'add', 'lan', 'type', 'veth', 'peer', 'name', 'lease-peer')
            command('ip', 'link', 'set', 'lease-peer', 'netns', 'lease-client')
            command('ip', 'address', 'add', '192.168.10.1/24', 'dev', 'lan')
            command('ip', 'link', 'set', 'lan', 'up')
            command('ip', 'link', 'set', 'lo', 'up')
            def client(*args):
                return command('nsenter', '--net=/run/netns/lease-client', '--', *args)
            client('ip', 'link', 'set', 'lo', 'up')
            client('ip', 'link', 'set', 'lease-peer', 'up')
            client('ip', 'address', 'add', '192.168.10.120/24', 'dev', 'lease-peer')
            mac = json.loads(client('ip', '-json', 'link', 'show', 'lease-peer').stdout)[0]['address']
            value = config.load(ROOT/'examples/minimal.yaml')
            value['networks']['home']['dhcp4']['id'] = 79
            # A canonical owner snapshot must keep the scope and binding ID.
            value = config.normalize(json.loads(json.dumps(config.normalize(value), sort_keys=True)))
            native = json.loads(config.render(value)['etc/kea/kea-dhcp4.conf'])
            assert native['Dhcp4']['subnet4'][0]['id'] == 79
            # Read-only native statistics prove the old record was loaded;
            # an ACK alone could also come from creating a replacement lease.
            native['Dhcp4']['control-socket'] = {
                'socket-type': 'unix', 'socket-name': '/run/kea/kea4-ctrl-socket'}
            # The packaged AppArmor profile permits this production basename's
            # PID file and the declared logger lock directory.
            config_path = work/'kea-dhcp4.conf'
            config_path.write_text(json.dumps(native))
            command('kea-dhcp4', '-t', str(config_path))
            lease = {'address': '192.168.10.120', 'hwaddr': mac, 'client_id': '', 'valid_lifetime': '3600',
                     'expire': str(int(time.time())+600), 'subnet_id': '79', 'fqdn_fwd': '0', 'fqdn_rev': '0',
                     'hostname': 'synthetic-retained', 'state': '0', 'user_context': ''}
            # The older memfile schema has no pool_id. Kea upgrades its own
            # records; this fixture never rewrites a retained lease identity.
            lease_path = Path('/var/lib/kea/kea-leases4.csv')
            with lease_path.open('w') as stream:
                writer = csv.DictWriter(stream, fieldnames=list(lease), lineterminator='\n')
                writer.writeheader()
                writer.writerow(lease)
            replies = []
            for iteration in range(2):
                log_path = work/('kea-'+str(iteration)+'.log')
                with log_path.open('wb') as output:
                    process = subprocess.Popen(['kea-dhcp4', '-c', str(config_path)],
                        stdin=subprocess.DEVNULL, stdout=output, stderr=subprocess.STDOUT,
                        env={**os.environ, 'KEA_PIDFILE_DIR': '/run/kea',
                             'KEA_LOCKFILE_DIR': '/run/lock/kea'})
                    deadline = time.monotonic()+5
                    while b'DHCP4_STARTED' not in log_path.read_bytes():
                        if process.poll() is not None or time.monotonic() > deadline:
                            raise AssertionError('Synthetic Kea startup failed: '+log_path.read_text()[-2048:])
                        time.sleep(0.05)
                    try:
                        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as control:
                            control.settimeout(2)
                            control.connect('/run/kea/kea4-ctrl-socket')
                            name = 'subnet[79].assigned-addresses'
                            control.sendall(json.dumps({'command': 'statistic-get',
                                'arguments': {'name': name}}).encode())
                            control.shutdown(socket.SHUT_WR)
                            data = b''
                            while True:
                                chunk = control.recv(4096)
                                if not chunk:
                                    break
                                data += chunk
                                assert len(data) <= 65536
                            stats = json.loads(data)
                            assert stats['result'] == 0 and stats['arguments'][name][0][0] == 1
                        replies.append(json.loads(client(sys.executable, '-c', CLIENT,
                            lease['address'], '192.168.10.1', mac).stdout))
                    finally:
                        stop(process)
                        process = None
                retained = lease_snapshot(lease_path)[lease['address']]
                assert retained['subnet_id'] == '79' and retained['hwaddr'] == mac
                assert int(retained['expire']) > int(lease['expire'])
            # Native parser checks the upper bound as well as the live value.
            native['Dhcp4']['subnet4'][0]['id'] = 4294967294
            config_path.write_text(json.dumps(native))
            command('kea-dhcp4', '-t', str(config_path))
        finally:
            if process is not None:
                stop(process)
            subprocess.run(['ip', 'netns', 'delete', 'lease-client'], capture_output=True)
            subprocess.run(['ip', 'link', 'delete', 'lan'], capture_output=True)
            command('umount', '/var/lib/kea')
        if result is not None:
            report = {'schema': 1, 'result': 'pass', 'test': 'offline-retained-dhcp4-subnet-identity',
                'assessed_at': datetime.now(timezone.utc).isoformat(), 'private_image_qualified': False,
                'checks': ['legacy-memfile-load', 'native-assigned-addresses-before-each-renewal',
                           'retained-unicast-renewal-dhcpack', 'lease-preserved-across-two-starts',
                           'canonical-owner-snapshot-preserves-id', 'native-upper-bound-parse'],
                'renewals': replies,
                'source_sha256': {name: hashlib.sha256((ROOT/name).read_bytes()).hexdigest() for name in
                    ('lanrith/intent.py', 'lanrith/config.py', 'lanrith/policy_agent.py', 'lanrith/policy_runtime.py',
                     'tests/dhcp_native.py', 'tests/native.py', 'tests/test_dhcp_identity.py')}}
            with result.open('xb') as stream:
                stream.write((json.dumps(report, sort_keys=True)+'\n').encode())
    print('Native DHCPv4 retained lease ID, renewal, restart and boundary checks passed.')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--isolated', action='store_true')
    parser.add_argument('--result', type=Path)
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.error('Use an isolated root test environment.')
    if args.isolated:
        qualify(args.result)
    else:
        command('unshare', '--mount', '--net', '--fork', '--propagation', 'private', '--',
                sys.executable, str(Path(__file__).resolve()), '--isolated',
                *(['--result', str(args.result)] if args.result else []), timeout=60)
        print('Offline DHCPv4 identity qualification passed.')


if __name__ == '__main__':
    main()
