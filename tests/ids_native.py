#!/usr/bin/env python3
"""Exercise unprivileged, detect-only WAN capture in an offline container."""

import json
import argparse
import datetime
import os
from pathlib import Path
import pwd
import shutil
import shlex
import subprocess
import sys
import tempfile
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from lanrith import config, firewall, ids, ids_qualification
from lanrith.release import canonical, file_record, require
from packets import SERVER, ns, probe, run
from test_intent import minimal


SYN = '''
import ipaddress,socket,struct,sys
source,destination,router,client,port=sys.argv[1:]
source,destination=ipaddress.ip_address(source).packed,ipaddress.ip_address(destination).packed
def checksum(data):
 total=sum(struct.unpack('!%dH'%(len(data)//2),data))
 while total>>16:total=(total&65535)+(total>>16)
 return (~total)&65535
tcp=struct.pack('!HHIIBBHHH',int(port),22,1234,0,0x50,2,8192,0,0)
pseudo=source+destination+struct.pack('!BBH',0,6,len(tcp))
tcp=tcp[:16]+struct.pack('!H',checksum(pseudo+tcp))+tcp[18:]
header=struct.pack('!BBHHHBBH4s4s',0x45,0,40,1234,0,64,6,0,source,destination)
header=header[:10]+struct.pack('!H',checksum(header))+header[12:]
ether=bytes.fromhex(router.replace(':',''))+bytes.fromhex(client.replace(':',''))+struct.pack('!H',0x0800)
s=socket.socket(socket.AF_PACKET,socket.SOCK_RAW);s.bind(('eth0',0));s.send(ether+header+tcp)
'''


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--base', type=Path)
    parser.add_argument('--result', type=Path)
    args = parser.parse_args()
    require((args.base is None) == (args.result is None), 'IDS result and exact base must be selected together.')
    project = Path(__file__).resolve().parents[1]
    sources = ids_qualification.implementation(project)
    subject = file_record(args.base) if args.base else None
    binary = file_record(Path('/usr/bin/suricata'))['sha256']
    base_binary = ids_qualification.base_binary(args.base) if args.base else None
    require(not subject or base_binary == binary, 'Native detector differs from the exact base executable.')
    require(not args.result or args.result.is_absolute() and args.result.parent.resolve() == args.result.parent and
            args.result.parent.is_dir() and not args.result.exists() and not args.result.is_symlink(),
            'IDS evidence requires a new canonical result path.')
    assert os.geteuid() == 0 and (Path('/run/.containerenv').exists() or Path('/.dockerenv').exists())
    assert {p.name for p in Path('/sys/class/net').iterdir()} == {'lo'}
    value = minimal()
    value['services'] = {key: {'enabled': False} for key in ('dns', 'ntp', 'dhcp4')}
    value['networks']['home'].pop('dhcp4')
    value['uplink'] = {'interface': 'wan', 'ipv4': {'address': '192.0.2.1/24', 'gateway': '192.0.2.2'},
                       'ipv6': 'disabled'}
    value['observability'] = {'ids': {'enabled': True}}
    value = config.normalize(value)
    files = ids.render(value)
    for name, text in files.items():
        path = Path('/')/name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
    rule = Path('/usr/share/lanrith/suricata.rules')
    rule.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(project/'mkosi/base/mkosi.extra/usr/share/lanrith/suricata.rules', rule)
    assert all(line.startswith('alert ') for line in rule.read_text().splitlines() if line and not line.startswith('#'))
    assert not any(account.pw_uid == 61010 for account in pwd.getpwall())
    with Path('/etc/passwd').open('a') as stream:
        stream.write('lanrith-ids:x:61010:61010::/:/usr/sbin/nologin\n')
    with Path('/etc/group').open('a') as stream:
        stream.write('lanrith-ids:x:61010:\n')
    Path('/var/log/suricata').mkdir(parents=True, exist_ok=True)
    os.chown('/var/log/suricata', 61010, 61010)
    Path('/var/log/suricata').chmod(0o750)
    daemon_command = shlex.split(next(line.removeprefix('ExecStart=') for line in
        files['usr/lib/systemd/system/lanrith-ids.service'].splitlines() if line.startswith('ExecStart=')))
    processes = []
    with tempfile.TemporaryDirectory(prefix='lanrith-ids.') as temporary:
        work = Path(temporary)
        run('suricata', '-T', '-c', '/etc/suricata/lanrith.yaml', '-l', str(work), '--init-errors-fatal')
        for name, router, client in (('wan', '192.0.2.1/24', '192.0.2.2/24'),
                                     ('lan', '192.168.10.1/24', '192.168.10.2/24')):
            run('ip', 'netns', 'add', name+'-test')
            run('ip', 'link', 'add', name, 'type', 'veth', 'peer', 'name', 'eth0', 'netns', name+'-test')
            run('ip', 'address', 'add', router, 'dev', name)
            run('ip', 'link', 'set', name, 'up')
            ns(name+'-test', 'ip', 'address', 'add', client, 'dev', 'eth0')
            ns(name+'-test', 'ip', 'link', 'set', 'eth0', 'up')
            ns(name+'-test', 'ip', 'link', 'set', 'lo', 'up')
            ns(name+'-test', 'ip', 'route', 'add', 'default', 'via', router.split('/')[0])
        (work/'firewall.nft').write_text(firewall.render(value))
        run('nft', '-f', str(work/'firewall.nft'))
        before = run('nft', '-j', 'list', 'ruleset').stdout
        processes.append(subprocess.Popen(['nsenter', '--net=/run/netns/wan-test', '--',
                                           'python3', '-c', SERVER, str(work/'server.ready')]))
        try:
            with (work/'suricata.log').open('w+') as log:
                daemon = subprocess.Popen([
                    'setpriv', '--reuid=61010', '--regid=61010', '--clear-groups',
                    '--inh-caps=+net_raw', '--ambient-caps=+net_raw', '--bounding-set=-all,+net_raw',
                    '--no-new-privs',
                    *daemon_command
                ], stdout=log, stderr=subprocess.STDOUT, cwd='/')
                processes.append(daemon)
                deadline = time.monotonic()+15
                while time.monotonic() < deadline:
                    assert daemon.poll() is None, (work/'suricata.log').read_text()[-6000:]
                    if 'engine started' in (work/'suricata.log').read_text().lower():
                        break
                    time.sleep(.1)
                else:
                    raise AssertionError((work/'suricata.log').read_text()[-6000:])
                status = dict(line.split(':', 1) for line in Path('/proc', str(daemon.pid), 'status').read_text().splitlines())
                assert set(status['Uid'].split()) == {'61010'}
                assert int(status['CapEff'].strip(), 16) == 1 << 13
                assert int(status['CapBnd'].strip(), 16) == 1 << 13
                assert status['NoNewPrivs'].strip() == '1'
                assert len(list(Path('/proc', str(daemon.pid), 'task').iterdir())) <= 32
                assert int(status['VmRSS'].split()[0])*1024 < 512*1024*1024
                probe('lan-test', '192.0.2.2', 8888, True)

                def send(name, port):
                    router = json.loads(run('ip', '-j', 'link', 'show', name).stdout)[0]['address']
                    client = json.loads(ns(name+'-test', 'ip', '-j', 'link', 'show', 'eth0').stdout)[0]['address']
                    ns(name+'-test', 'python3', '-c', SYN, '192.0.2.2', '192.168.10.2',
                       router, client, str(port))

                def alerts():
                    path = Path('/var/log/suricata/eve.json')
                    return [row for row in (json.loads(line) for line in path.read_text().splitlines())
                            if row.get('event_type') == 'alert'] if path.exists() else []

                send('wan', 40001)
                deadline = time.monotonic()+8
                while not alerts() and time.monotonic() < deadline:
                    time.sleep(.2)
                assert any(row['alert']['signature_id'] == 1000001 and row['in_iface'] == 'wan'
                           for row in alerts()), (work/'suricata.log').read_text()[-6000:]
                send('lan', 40002)
                time.sleep(1)
                assert not any(row.get('src_port') == 40002 for row in alerts())
                assert before == run('nft', '-j', 'list', 'ruleset').stdout
                probe('lan-test', '192.0.2.2', 8888, True)
                daemon.terminate()
                daemon.wait(timeout=10)
                probe('lan-test', '192.0.2.2', 8888, True)
        finally:
            for process in processes:
                if process.poll() is None:
                    process.terminate()
                process.wait(timeout=10)
            for name in ('lan-test', 'wan-test'):
                run('ip', 'netns', 'del', name)
    require(sources == ids_qualification.implementation(project) and
            binary == file_record(Path('/usr/bin/suricata'))['sha256'] and
            (not subject or file_record(args.base) == subject), 'Native IDS inputs changed during qualification.')
    report = {'schema': 1, 'test': 'offline-wan-ids', 'result': 'pass',
        'assessed_at': datetime.datetime.now(datetime.timezone.utc).isoformat(),
        'checks': sorted(ids_qualification.CHECKS),
        'daemon_working_directory': '/',
        'daemon_command': daemon_command,
        'detector_uid': 61010, 'no_new_privileges': True,
        'effective_capabilities': 1 << 13, 'bounding_capabilities': 1 << 13,
        'binary_sha256': binary, 'base_binary_sha256': base_binary, 'base_binary_match': base_binary == binary,
        'filesystem_sha256': subject['sha256'] if subject else None,
        'implementation_sha256': sources, 'source_sha256': sources['tests/ids_native.py'],
        'external_network': False, 'image_boot_qualified': False}
    if args.result:
        with args.result.open('xb') as stream:
            stream.write(canonical(report))
    print(json.dumps(report))


if __name__ == '__main__':
    main()
