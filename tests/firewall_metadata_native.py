#!/usr/bin/env python3
"""Offline NFLOG feasibility gate; not an admitted image/runtime endpoint."""

import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import signal
import shutil
import socket
import subprocess
import sys
import tempfile
import time

SOURCE = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(SOURCE), str(SOURCE/'tests')]
from lanrith import config, firewall_metadata as wire
from test_intent import minimal


def run(*args, input=None, check=True, timeout=5):
    if args[0] == 'nft':
        args = ('/usr/sbin/nft', *args[1:])
    return subprocess.run(args, input=input, capture_output=True, timeout=timeout, check=check)


def receive(root):
    prefixes = json.loads((root/'manifest.json').read_text())['prefixes']
    with wire.kernel_listener() as source:
        wire.discard_configuration_capability()
        status = dict(line.split(':', 1) for line in Path('/proc/self/status').read_text().splitlines())
        ready = {'uid': os.geteuid(), 'capabilities': {key: status[key].strip() for key in
            ('CapEff', 'CapPrm', 'CapInh', 'CapAmb', 'CapBnd', 'NoNewPrivs')}, 'port': source.getsockname()[0]}
        forbidden = run('nft', 'add', 'table', 'inet', 'forbidden', check=False)
        assert forbidden.returncode != 0
        ready['firewall_write_denied'] = True
        try:
            other = wire.kernel_listener()
        except OSError as error:
            assert error.errno == 1
            ready['reconfiguration_denied'] = True
        else:
            other.close()
            raise AssertionError('Receiver regained group configuration authority.')
        (root/'ready.json').write_text(json.dumps(ready))
        source.settimeout(.2)
        rows, deadline = [], time.monotonic()+30
        while time.monotonic() < deadline:
            try:
                data, ancillary, flags, sender = source.recvmsg(wire.MAX_DATAGRAM)
            except socket.timeout:
                continue
            assert not flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC)
            rows.extend(wire.decode(data, sender, prefixes))
            assert len(rows) <= 128
            (root/'rows.json').write_text(json.dumps(rows))


def wait(probe, timeout=5):
    deadline = time.monotonic()+timeout
    while True:
        value = probe()
        if value:
            return value
        assert time.monotonic() < deadline, 'NFLOG fixture deadline expired.'
        time.sleep(.05)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--receive', type=Path)
    parser.add_argument('--result', type=Path)
    parser.add_argument('--service', action='store_true')
    parser.add_argument('--base', type=Path)
    args = parser.parse_args()
    if args.receive:
        receive(args.receive)
        return
    assert os.geteuid() == 0 and args.result and not args.result.exists()
    assert Path('/run/.containerenv').is_file() or Path('/.dockerenv').is_file()
    for kind in ('net', 'mnt'):
        outer = os.environ.get('LANRITH_FIXTURE_OUTER_'+kind.upper(), '')
        assert outer.isdecimal() and os.stat('/proc/self/ns/'+kind).st_ino != int(outer), 'Use a disposable isolated fixture.'
    subject, sources, userspace, dependencies, nft_version = None, None, None, None, None
    if args.base:
        assert args.service
        from lanrith import firewall_qualification as gate
        from lanrith.release import file_record
        subject, sources = file_record(args.base), gate.implementation(SOURCE)
        with tempfile.TemporaryDirectory(prefix='nft-subject.', dir='/run') as temporary:
            candidate = Path(temporary)
            selected = gate.subject(args.base, destination=candidate)
            assert Path('/usr/sbin/nft').is_file() and not Path('/usr/sbin/nft').is_symlink()
            shutil.copyfile(candidate/'nft', '/usr/sbin/nft')
            Path('/usr/sbin/nft').chmod(0o755)
        # Trace the staged subject, then prove that every loaded shared object
        # matches the archive. No builder executable or library fallback.
        for key in tuple(os.environ):
            if key.startswith('LD_'):
                del os.environ[key]
        os.environ['PATH'] = '/usr/sbin:/usr/bin:/sbin:/bin'
        dependencies = gate.library_inventory()
        userspace = gate.subject(args.base, dependencies)
        assert userspace == {gate.NFT: selected[gate.NFT], **dependencies}, 'Staged nft libraries differ from the exact base.'
        assert file_record(Path('/usr/sbin/nft'))['sha256'] == selected[gate.NFT]
        nft_version = run('/usr/sbin/nft', '--version').stdout.decode('ascii').strip()
    root = Path(tempfile.mkdtemp(prefix='firewall-metadata.', dir='/run'))
    root.chmod(0o750)
    os.chown(root, 2001, 2001)
    value = minimal()
    value['services'] = {'dns': {'enabled': False}, 'ntp': {'enabled': False}}
    value['networks']['home'].pop('dhcp4')
    value['networks']['home']['ipv6'] = {'subnet_id': 16, 'ra': False, 'gua': False}
    value['uplink']['ipv4'] = {'address': '192.0.2.2/24', 'gateway': '192.0.2.1'}
    value['uplink']['ipv6'] = {'address': '2001:db8:10::2/64', 'gateway': '2001:db8:10::1',
                              'downstream_prefix': '2001:db8:10::/48'}
    value['access'] = {'default': 'deny', 'rules': [{'action': 'allow', 'from': 'home', 'to': 'uplink',
                                                'protocol': 'udp', 'ports': [23456]}]}
    baseline = config.render(value)['etc/nftables.conf']
    observed, manifest = wire.instrument(baseline)
    (root/'manifest.json').write_text(json.dumps(manifest))
    children, spaces = [], []
    try:
        run('ip', 'link', 'set', 'lo', 'up')
        for space, interface, host4, peer4, host6, peer6 in (
                ('nflog-client', 'lan', '192.168.10.1', '192.168.10.10', 'fd42:1234:5678:10::1', 'fd42:1234:5678:10::10'),
                ('nflog-server', 'wan', '192.0.2.2', '192.0.2.1', '2001:db8:10::2', '2001:db8:10::1')):
            run('ip', 'netns', 'add', space)
            spaces.append(space)
            run('ip', 'link', 'add', interface, 'type', 'veth', 'peer', 'name', 'peer0', 'netns', space)
            run('ip', 'link', 'set', interface, 'up')
            for address in (host4+'/24', host6+'/64'):
                run('ip', 'address', 'add', address, 'dev', interface, 'nodad')
            for command in (('link', 'set', 'lo', 'up'), ('link', 'set', 'peer0', 'up'),
                ('address', 'add', peer4+'/24', 'dev', 'peer0'), ('address', 'add', peer6+'/64', 'dev', 'peer0', 'nodad'),
                ('route', 'add', 'default', 'via', host4), ('-6', 'route', 'add', 'default', 'via', host6)):
                run('nsenter', '--net=/run/netns/'+space, '--', 'ip', *command)
        run('sysctl', '-w', 'net.ipv4.ip_forward=1', 'net.ipv6.conf.all.forwarding=1')
        run('nft', '-c', '-f', '-', input=observed.encode())
        run('nft', '-f', '-', input=observed.encode())
        if args.service:
            from firewall_service_native import Receiver
            receiver = Receiver(value, baseline, root)
        else:
            receiver = subprocess.Popen(['setpriv', '--reuid=2001', '--regid=2001', '--clear-groups',
                '--inh-caps=+net_admin', '--ambient-caps=+net_admin', '--bounding-set=-all,+net_admin', '--no-new-privs',
                'python3', '-B', str(Path(__file__)), '--receive', str(root)], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        children.append(receiver)
        def ready():
            assert receiver.poll() is None, receiver.communicate()
            return json.loads((root/'ready.json').read_text()) if (root/'ready.json').exists() else None
        role = wait(ready)
        assert role['uid'] != 0 and all(int(role['capabilities'][key], 16) == 0 for key in ('CapEff', 'CapPrm', 'CapInh', 'CapAmb'))
        assert role['firewall_write_denied'] and role['reconfiguration_denied']
        try:
            duplicate = wire.kernel_listener()
        except OSError as error:
            assert error.errno in (1, 17)  # Occupied group stays with its current owner.
        else:
            duplicate.close()
            raise AssertionError('NFLOG group ownership was replaced.')
        stranger = run('setpriv', '--reuid=2002', '--regid=2002', '--clear-groups', '--bounding-set=-all', '--no-new-privs',
            'python3', '-I', '-c', 'import sys;sys.path.insert(0,"/source");from lanrith.firewall_metadata import kernel_listener;kernel_listener()', check=False)
        assert stranger.returncode != 0 and b'PermissionError' in stranger.stderr
        server_code = '''import json,pathlib,socket,threading,time
received=[]
def listen(family,address,port):
 s=socket.socket(family,socket.SOCK_DGRAM);s.bind((address,port))
 while True:
  data,peer=s.recvfrom(1024);received.append(port);s.sendto(data,peer)
  pathlib.Path(PATH).write_text(json.dumps(received))
for family,address in [(socket.AF_INET,"192.0.2.1"),(socket.AF_INET6,"2001:db8:10::1")]:
 for port in (23456,54321):threading.Thread(target=listen,args=(family,address,port),daemon=True).start()
pathlib.Path(READY).write_text("ready")
while True:time.sleep(1)
'''.replace('PATH', repr(str(root/'server.json'))).replace('READY', repr(str(root/'server-ready')))
        server = subprocess.Popen(['nsenter', '--net=/run/netns/nflog-server', '--', 'python3', '-I', '-c', server_code],
                                  stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        children.append(server)
        wait(lambda: (root/'server-ready').exists())
        time.sleep(.2)
        def udp(address, port, *, allowed=False, count=1):
            code = ('import socket;s=socket.socket(socket.AF_INET'+('6' if ':' in address else '')+',socket.SOCK_DGRAM);'
                's.settimeout(.3);'+'\nfor _ in range('+str(count)+'):s.sendto(b"PRIVATE_FIREWALL_PAYLOAD",('+repr(address)+','+str(port)+'))\n'+
                ('assert s.recvfrom(1024)[0]==b"PRIVATE_FIREWALL_PAYLOAD"' if allowed else
                 'try:s.recvfrom(1024)\nexcept socket.timeout:pass\nelse:raise AssertionError("Denied UDP reached a listener")'))
            run('nsenter', '--net=/run/netns/nflog-client', '--', 'python3', '-I', '-c', code)
        for family, router, destination in ((4, '192.168.10.1', '192.0.2.1'), (6, 'fd42:1234:5678:10::1', '2001:db8:10::1')):
            udp(destination, 23456, allowed=True)
            for target in (router, destination):
                udp(target, 54321)
                tcp = ('import socket;s=socket.socket(socket.AF_INET'+('6' if family == 6 else '')+',socket.SOCK_STREAM);'
                    's.settimeout(.2)\ntry:s.connect(('+repr(target)+',54322))\nexcept socket.timeout:pass\n'
                    'else:raise AssertionError("Denied TCP was admitted")')
                run('nsenter', '--net=/run/netns/nflog-client', '--', 'python3', '-I', '-c', tcp)
                ping = run('nsenter', '--net=/run/netns/nflog-client', '--', 'ping', '-'+str(family), '-n', '-c', '1', '-W', '1', target, check=False)
                assert ping.returncode == 1, ping.stderr
        def rows():
            assert receiver.poll() is None, receiver.communicate()
            try:return json.loads((root/'rows.json').read_text())
            except (FileNotFoundError, json.JSONDecodeError):return []
        def observed_matrix():
            value = rows()
            expected = {(family, hook, protocol) for family in (4, 6) for hook in ('input', 'forward')
                        for protocol in ('udp', 'tcp', 'icmp' if family == 4 else 'icmpv6')}
            return value if {(row['family'], row['hook'], row['protocol']) for row in value} >= expected else None
        actual = wait(observed_matrix)
        receiver.send_signal(signal.SIGSTOP)
        udp('192.0.2.1', 54321, count=1000)
        udp('192.0.2.1', 23456, allowed=True)
        receiver.send_signal(signal.SIGCONT)
        time.sleep(.3)
        actual = rows()
        assert len(actual) < 1000 and 'PRIVATE_FIREWALL_PAYLOAD' not in json.dumps(actual)
        receiver.terminate()
        receiver.wait(timeout=3)
        udp('192.0.2.1', 54321, count=100)
        udp('192.0.2.1', 23456, allowed=True)
        received = json.loads((root/'server.json').read_text())
        assert set(received) == {23456} and len(received) >= 4
        nft = json.loads(run('nft', '-j', 'list', 'chain', 'inet', 'lanrith', 'forward').stdout)
        default = nft['nftables'][-1]['rule']
        counter = next(item['counter'] for item in default['expr'] if 'counter' in item)
        assert counter['packets'] >= 1100
        assert any('drop' in item for item in default['expr'])
        extra_checks = receiver.qualify_lifecycle(udp) if args.service else []
        result = {'schema': 1, 'result': 'pass', 'scope': 'NFLOG codec and unchanged generated default-deny proof only',
            'implementation_sha256': {'lanrith/firewall_metadata.py': hashlib.sha256((SOURCE/'lanrith/firewall_metadata.py').read_bytes()).hexdigest(),
                                      'tests/firewall_metadata_native.py': hashlib.sha256(Path(__file__).read_bytes()).hexdigest()},
            'checks': ['exact generated nft syntax and original rules preserved', 'nonroot receiver discards all effective/permitted/inheritable/ambient capabilities',
                'receiver cannot write firewall or reconfigure the group', 'group cannot be stolen; unrelated UID cannot bind',
                'real IPv4/IPv6 TCP/UDP/ICMP input and forward default-deny tuples',
                'stalled and absent receiver plus exhausted sampling never admits denied traffic or blocks allowed traffic', *extra_checks],
            'receiver': role, 'records': actual, 'unconditional_forward_drops': counter['packets'],
            'allowed_echoes': len(received), 'payload_exported': False, 'runtime_endpoint_admitted': False,
            'generated_service_tested': args.service,
            'assembly_sha256': receiver.assembly if args.service else None,
            'private_image_qualified': False, 'external_network': False,
            'limits': ['no current release, base or full-image admission' if args.service else 'no service, spool, account-allocation or extension admission integration',
                       'no earlier guard, explicit-owner deny, policy-helper, translator, output or service-namespace observations',
                       'TCP/ICMP validation proves sampled drop-path metadata; no claim of allowed TCP/ICMP application service',
                       'synthetic namespaces/packets; no full image or persistent lifecycle']}
        if args.base:
            assert file_record(args.base) == subject and gate.implementation(SOURCE) == sources
            result.update(test='offline-firewall-observations', assessed_at=datetime.datetime.now(datetime.timezone.utc).isoformat(),
                filesystem_sha256=subject['sha256'], source_sha256=sources, base_userspace_sha256=userspace,
                builder_libraries_sha256=dependencies, nft_sha256=userspace[gate.NFT], nft_version=nft_version,
                kernel_release=os.uname().release, image_boot_qualified=False)
        args.result.write_text(json.dumps(result, sort_keys=True, indent=2)+'\n')
        print(json.dumps({'result': 'pass', 'records': len(actual), 'default_drops': counter['packets']}))
    finally:
        for child in reversed(children):
            if child.poll() is None:
                child.send_signal(signal.SIGCONT)
                child.terminate()
                child.wait(timeout=3)
            if child.returncode:
                stdout, stderr = child.communicate()
                if stderr:sys.stderr.buffer.write(stderr[-12000:])
        run('nft', 'flush', 'ruleset', check=False)
        for space in reversed(spaces):run('ip', 'netns', 'delete', space, check=False)


if __name__ == '__main__':
    main()
