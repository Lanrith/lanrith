#!/usr/bin/python3
"""Exercise interrupted namespace ownership and WAN reappearance in a disposable no-NIC VM."""

import fcntl
import json
import os
from pathlib import Path
from unittest.mock import patch
import shutil
import signal
import stat
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from lanrith import config, radius_runtime, service_runtime as runtime
from credentials_native import native_radius_clients
from kea_control_systemd_native import stage as stage_kea
from ssh_listeners_systemd import stage as stage_ssh
from test_authoritative import declaration
from test_radius import declaration as radius_declaration
from unbound_native import network, run, write

UNIT = 'lanrith-services.service'
UNITS = Path('/etc/systemd/system')
PUBLIC = Path('/run/netns/lanrith-services')
MARK = Path('/run/service-cut')
PLAN = Path('/usr/share/lanrith/service-plane.json')
SCRIPT = Path('/usr/lib/lanrith/lanrith/service_runtime.py')
DAEMONS = ('named', 'unbound', 'chrony', 'freeradius')
LAN = 'lan.1'
NTP = """import socket,sys
with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as s:
    s.settimeout(2)
    s.sendto(bytes([0x23])+bytes(47),(sys.argv[1],123))
    packet,_=s.recvfrom(512)
    assert len(packet)>=48 and packet[0]&7==4
"""


def until(predicate):
    end = time.monotonic()+12
    while not predicate():
        assert time.monotonic() < end, predicate.__name__
        time.sleep(.1)


def cut(point):
    plane = json.loads(PLAN.read_bytes())
    original = runtime.run

    def boundary(args):
        output = original(args)
        if point == 'namespace' and args[-1] == str(PUBLIC) and args[0] == 'mount':
            assert runtime.STATE.exists() and PUBLIC.exists() and not Path('/sys/class/net/lr-services').exists()
        elif point == 'firewall' and args[-3:] == ['nft', '-f', '/etc/lanrith/services.nft']:
            assert all('UP' not in links[name]['flags'] for links, name in (
                       (runtime.links(), plane['host_link']), (runtime.links(PUBLIC), plane['service_link'])))
            assert 'policy drop' in original(['nsenter', '--net='+str(PUBLIC), '--', 'nft', 'list', 'ruleset'])
        else:
            return output
        MARK.write_text(point)
        os.kill(os.getpid(), signal.SIGKILL)

    runtime.run = boundary
    runtime.start(plane)
    raise AssertionError('Missed interruption')


def orphaned_command():
    # Killing the controller while its command lives must leave the lock held.
    marker = Path('/run/service-lock-held')
    process = subprocess.Popen([sys.executable, __file__, '--hold'])
    try:
        until(marker.exists)
        process.kill()
        process.wait(timeout=5)
        with runtime.descriptor(runtime.DIRECTORY, os.O_RDONLY | os.O_DIRECTORY) as fd:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                pass
            else:
                raise AssertionError('A surviving command lost its namespace lifecycle lock')
    finally:
        marker.unlink(missing_ok=True)
        if process.poll() is None:
            process.kill()
            process.wait(timeout=5)


def configuration():
    value = declaration()
    value['uplink'] = {'interface': 'wan', 'ipv4': 'disabled', 'ipv6': {
        'address': '2001:db8:10::2/48', 'gateway': '2001:db8:10::1',
        'downstream_prefix': '2001:db8:10::/48', 'delivery': 'on_link'}}
    value['services']['dns']['authoritative'].pop('writers')
    value['services']['dns']['authoritative']['zones']['example.test']['persistent'] = False
    value['services']['ntp'] = {'enabled': True, 'upstreams': ['192.0.2.1']}
    value['administration']['serial'] = {'enabled': False}
    value['networks']['home']['vlan'] = 1
    value['networks']['devices'] = {'interface': 'lan', 'vlan': 22, 'ipv4': '192.168.22.0/24',
                                     'dhcp4': {'enabled': False}}
    value['identity'] = {'radius': radius_declaration()['identity']['radius']}
    value['identity']['radius']['admission'] = {'network': 'devices'}
    value['services']['discovery'] = {'enabled': True, 'domain': 'neighbors.example.net', 'alias_prefix': 'src-',
                                     'networks': ['home'], 'browse': ['_example._tcp']}
    value['observability'] = {
        'metrics': {'enabled': True, 'clients': [{'network': 'home'}]},
        'logs': {'enabled': True, 'endpoint': 'https://192.168.10.31/otlp', 'tls_server_name': 'logs.example.test'},
        'snmp': {'enabled': True, 'username': 'synthetic-monitor', 'credential': 'monitor_user',
                 'clients': [{'network': 'home', 'addresses': 'fd42:1234:5678:10::50/128'}]}}
    return value


def stage():
    files = config.render(configuration())
    for account in ('alloy', 'discovery-bridge-dns', 'discovery-bridge-collector',
                    'discovery-bridge-publisher', 'lanrith-metrics', 'avahi'):
        if run('getent', 'passwd', account, check=False).returncode:
            run('useradd', '--system', '--no-create-home', '--shell', '/usr/sbin/nologin', account)
    for name, content in files.items():
        if (name in ['usr/share/lanrith/service-plane.json', 'usr/lib/systemd/system/'+UNIT,
                     'etc/lanrith/services.nft', 'etc/nftables.conf', 'etc/bind/named.conf', 'etc/chrony/chrony.conf',
                     'etc/systemd/network/20-uplink.network'] or
                name.startswith(('usr/share/lanrith/zones/', 'etc/freeradius/3.0/'))):
            write('/'+name, content)
    write('/etc/unbound/unbound.conf', files['etc/unbound/unbound.conf.d/lanrith.conf'])
    SCRIPT.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(ROOT/'lanrith/service_runtime.py', SCRIPT)
    policy = json.loads(files['usr/share/lanrith/radius.json'])
    references = [policy['proxy']['credential_name'], *(client['credential_name'] for client in policy['clients'])]
    secrets = dict.fromkeys(references, 'A'*32)
    write('/etc/freeradius/3.0/clients.conf', radius_runtime.clients_configuration(policy, secrets))
    write('/etc/freeradius/3.0/proxy.conf', radius_runtime.proxy_configuration(policy, secrets))
    for directory, account in (('/run/named', 'bind'), ('/run/chrony', '_chrony'), ('/run/freeradius', 'freerad')):
        Path(directory).mkdir(exist_ok=True, mode=0o750)
        shutil.chown(directory, account, account)
    # The services use ordinary packaged daemons, static fixture credentials and clock control disabled.
    commands = {'named': '/usr/sbin/named -f -n 1 -u bind -c /etc/bind/named.conf',
                'unbound': '/usr/sbin/unbound -d -p -c /etc/unbound/unbound.conf',
                'chrony': '/usr/sbin/chronyd -x -n -f /etc/chrony/chrony.conf',
                'freeradius': '/usr/sbin/freeradius -f -lstdout'}
    for service, command in commands.items():
        write(UNITS/(service+'.service'), '[Unit]\nBindsTo='+UNIT+'\nAfter='+UNIT+'\n[Service]\n'
              'Type=exec\nNetworkNamespacePath='+str(PUBLIC)+'\nExecStart='+command+'\n')
    stage_ssh(files)
    write(UNITS/'lanrith-ssh-host-key.service', '[Service]\nType=oneshot\nRemainAfterExit=yes\n'
          'ExecStart=/usr/bin/test -s /var/lib/lanrith/ssh-host-keys/ssh_host_ed25519_key\n')
    account = stage_kea(files)
    Path('/var/lib/kea').mkdir(exist_ok=True)
    os.chown('/var/lib/kea', account.pw_uid, account.pw_gid)
    return json.loads(PLAN.read_bytes()), policy


def services(plane):
    def dns():
        target = plane['endpoints']['dns'][0]
        return run('ip', 'netns', 'exec', LAN, 'dig', '+short', '+tries=1', '+time=1', '@'+target,
                   'router.home.arpa.', 'A', check=False).stdout.strip() == '192.168.10.1'
    until(dns)
    run('ip', 'netns', 'exec', LAN, 'python3', '-c', NTP, plane['endpoints']['ntp'][0])


def proxies(device):
    return {line.split()[0] for line in run('ip', '-6', 'neigh', 'show', 'proxy', 'dev', device).stdout.splitlines()}


def wan_appearance(plane):
    run('ip', 'link', 'add', 'wan', 'type', 'veth', 'peer', 'name', 'eth0', 'netns', 'upstream')
    run('ip', '-n', 'upstream', 'link', 'set', 'eth0', 'up')
    run('ip', '-n', 'upstream', '-6', 'addr', 'add', '2001:db8:10::1/48', 'dev', 'eth0', 'nodad')
    expected = set(plane['proxy'])
    assert expected == {'2001:db8:10:fe02::'+suffix for suffix in ('1', '10', '11', '12', '30', '40', '50', '60')}
    until(lambda: proxies('wan') == expected)
    address = Path('/sys/class/net/wan/address').read_text().strip()
    sentinel = '2001:db8:10:fe02::ffff'
    run('ip', 'netns', 'exec', 'upstream', 'python3', '-c',
        'import socket,sys\ns=socket.socket(socket.AF_INET6,socket.SOCK_DGRAM)\n'
        'for a in sys.argv[1:]: s.sendto(b"neighbor check",(a,9))', *sorted(expected), sentinel)

    def resolved():
        neighbors = json.loads(run('ip', '-n', 'upstream', '-j', '-6', 'neigh', 'show', 'dev', 'eth0').stdout)
        assert all(row.get('lladdr') != address for row in neighbors if row['dst'] == sentinel)
        return expected <= {row['dst'] for row in neighbors if row.get('lladdr') == address}
    until(resolved)
    print('WAN ifindex', runtime.links()['wan']['ifindex'], 'resolved', sorted(expected), flush=True)
    return runtime.links()['wan']['ifindex']


def qualify():
    assert os.geteuid() == 0 and Path('/proc/1/comm').read_text().strip() == 'systemd'
    assert run('systemd-detect-virt', '--vm').stdout.strip()
    assert not Path('/usr/share/lanrith/installed.json').exists() and set(runtime.links()) == {'lo'}
    for arguments in (('uname', '-r'), ('systemctl', '--version'), ('ip', '-Version'), ('nft', '--version')):
        print(run(*arguments).stdout.splitlines()[0], flush=True)
    plane, radius = stage()
    orphaned_command()
    # The first attachment can have equal numeric ifindices in different namespaces.
    runtime.start(plane)
    runtime.stop(plane)
    # A fresh installation must never adopt matching names without a record.
    run('ip', 'netns', 'add', plane['namespace'])
    run('ip', 'link', 'add', plane['host_link'], 'type', 'dummy')
    foreign_namespace = runtime.file_id(PUBLIC)
    foreign_link = runtime.links()[plane['host_link']]['ifindex']
    for action in ('start', 'stop'):
        assert run(sys.executable, SCRIPT, action, check=False).returncode
        assert foreign_namespace == runtime.file_id(PUBLIC)
        assert foreign_link == runtime.links()[plane['host_link']]['ifindex']
    run('ip', 'netns', 'del', plane['namespace'])
    run('ip', 'link', 'del', plane['host_link'])
    network(LAN, '192.168.10.1', '192.168.10.20')
    run('ip', '-6', 'address', 'add', 'fd42:1234:5678:10::1/64', 'dev', LAN, 'nodad')
    run('ip', 'netns', 'add', 'upstream')
    run('ip', 'link', 'add', 'unrelated', 'type', 'dummy')
    run('ip', '-6', 'neigh', 'add', 'proxy', '2001:db8:bad::1', 'dev', 'unrelated')
    run('sysctl', '-qw', 'net.ipv4.ip_forward=1', 'net.ipv6.conf.all.forwarding=1')
    run('systemctl', 'daemon-reload')
    run('systemctl', 'start', 'systemd-networkd', 'nftables', 'ssh', 'kea-dhcp4-server')
    independent = ['ssh.service', 'kea-dhcp4-server.service', 'systemd-networkd.service']
    def pids(names):
        return [int(run('systemctl', 'show', '-P', 'MainPID', name).stdout) for name in names]
    original = pids(independent)
    assert all(pid > 1 for pid in original)
    dropin = UNITS/(UNIT+'.d/99-fixture.conf')
    write(dropin, '[Service]\nExecStart=\nExecStart=/usr/bin/python3 '+str(Path(__file__).resolve())+' --cut firewall\n')
    run('systemctl', 'daemon-reload')
    assert run('systemctl', 'start', UNIT, check=False).returncode
    assert MARK.read_text() == 'firewall'
    assert not PUBLIC.exists() and not runtime.STATE.exists() and plane['host_link'] not in runtime.links()
    dropin.unlink()
    run('systemctl', 'daemon-reload')
    # Interrupt a direct invocation before veth creation. Only the next start gets to clean this one.
    assert run(sys.executable, __file__, '--cut', 'namespace', check=False).returncode == -signal.SIGKILL
    assert MARK.read_text() == 'namespace' and PUBLIC.exists() and runtime.STATE.exists()
    stale = PUBLIC.stat()
    assert stat.S_IMODE(runtime.DIRECTORY.stat().st_mode) == 0o700
    assert stat.S_IMODE(runtime.STATE.stat().st_mode) == 0o600
    assert run('runuser', '-u', 'nobody', '--', 'test', '-r', str(runtime.STATE), check=False).returncode
    start = time.monotonic()
    run('systemctl', 'start', UNIT)
    elapsed = time.monotonic() - start
    assert elapsed < 30 and PUBLIC.stat().st_ino != stale.st_ino
    print(f'One start recovered the interrupted setup in {elapsed:.2f}s', flush=True)
    run('systemctl', 'start', *DAEMONS)
    services(plane)
    namespace = runtime.file_id(PUBLIC)
    daemons = pids(DAEMONS)
    runtime.start(plane)
    assert runtime.file_id(PUBLIC) == namespace
    first = wan_appearance(plane)
    services(plane)
    run('ip', 'link', 'del', 'wan')
    services(plane)
    assert 'wan' not in runtime.links() and runtime.file_id(PUBLIC) == namespace
    assert wan_appearance(plane) != first
    services(plane)
    assert pids(DAEMONS) == daemons
    assert proxies(LAN) == set() and proxies('unrelated') == {'2001:db8:bad::1'}
    # A partial stop has already lost both veth ends. ExecStopPost must still clean the namespace.
    run('ip', 'link', 'del', plane['host_link'])
    run('systemctl', 'stop', UNIT)
    assert not PUBLIC.exists() and not runtime.PIN.exists() and not runtime.STATE.exists()
    assert proxies('wan') == set(plane['proxy'])
    runtime.stop(plane)
    run('systemctl', 'start', UNIT, *DAEMONS)
    services(plane)
    native_radius_clients(radius, ['ip', 'netns', 'exec', LAN])
    # Replacing a namespace name must leave the foreign namespace and its device intact.
    run('ip', 'netns', 'del', plane['namespace'])
    run('ip', 'netns', 'add', plane['namespace'])
    run('ip', '-n', plane['namespace'], 'link', 'add', 'foreign', 'type', 'dummy')
    foreign = runtime.file_id(PUBLIC)
    run('systemctl', 'stop', UNIT, check=False)
    assert runtime.file_id(PUBLIC) == foreign and 'foreign' in runtime.links(PUBLIC)
    assert runtime.STATE.exists() and not runtime.PIN.exists() and plane['host_link'] not in runtime.links()
    assert run('systemctl', 'start', UNIT, check=False).returncode and runtime.file_id(PUBLIC) == foreign
    run('ip', 'netns', 'del', plane['namespace'])
    runtime.stop(plane)
    runtime.start(plane)
    run('ip', 'link', 'del', plane['host_link'])
    run('ip', 'link', 'add', plane['host_link'], 'type', 'dummy')
    link_id = runtime.links()[plane['host_link']]['ifindex']
    assert run(sys.executable, SCRIPT, 'stop', check=False).returncode
    assert runtime.links()[plane['host_link']]['ifindex'] == link_id and not PUBLIC.exists()
    assert run(sys.executable, SCRIPT, 'start', check=False).returncode
    run('ip', 'link', 'del', plane['host_link'])
    runtime.stop(plane)
    # Removing a published handle alone leaves the private anchor available for both peer checks.
    runtime.start(plane)
    run('ip', 'netns', 'del', plane['namespace'])
    runtime.stop(plane)
    runtime.stop(plane)
    assert not runtime.STATE.exists() and plane['host_link'] not in runtime.links()
    # A foreign interface in our namespace must survive releasing the verified veth.
    runtime.start(plane)
    run('ip', '-n', plane['namespace'], 'link', 'add', 'extra', 'type', 'dummy')
    assert run(sys.executable, SCRIPT, 'stop', check=False).returncode
    assert 'extra' in runtime.links(PUBLIC) and plane['host_link'] not in runtime.links()
    run('ip', '-n', plane['namespace'], 'link', 'del', 'extra')
    runtime.stop(plane)
    # A failed unmount is reported. Teardown still releases the other verified handle.
    runtime.start(plane)
    runtime.STATE.chmod(0o644)
    assert run(sys.executable, SCRIPT, 'stop', check=False).returncode and plane['host_link'] in runtime.links()
    runtime.STATE.chmod(0o600)
    real_run = runtime.run
    def fail_public_unmount(arguments):
        if arguments == ['umount', '--lazy', '--', str(PUBLIC)]:
            raise OSError('fixture unmount failure')
        return real_run(arguments)
    with patch.object(runtime, 'run', fail_public_unmount):
        try:
            runtime.stop(plane)
        except ValueError as error:
            assert 'fixture unmount failure' in str(error)
        else:
            raise AssertionError('Teardown did not report unmount failure')
    assert PUBLIC.exists() and runtime.STATE.exists() and not runtime.PIN.exists()
    runtime.stop(plane)
    assert not PUBLIC.exists() and not runtime.STATE.exists()
    assert proxies('unrelated') == {'2001:db8:bad::1'} and pids(independent) == original
    run('/usr/lib/lanrith/verify-kea-sockets')
    run('/usr/lib/lanrith/verify-ssh-listeners')
    print('Passed protected ownership, peer loss, foreign collisions, DNS, NTP, RADIUS and independent DHCP/SSH.', flush=True)


if __name__ == '__main__':
    if sys.argv[1:] == ['--hold']:
        with runtime.locked():
            runtime.run([sys.executable, '-c', 'from pathlib import Path\nimport time\n'
                         'p=Path("/run/service-lock-held");p.touch()\nwhile p.exists(): time.sleep(.05)'])
    elif len(sys.argv) == 3 and sys.argv[1] == '--cut':
        cut(sys.argv[2])
    else:
        try:
            qualify()
        except Exception:
            print(run('journalctl', '-b', '-n', '85', '-o', 'cat').stdout, flush=True)
            raise
