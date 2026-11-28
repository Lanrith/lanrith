#!/usr/bin/python3
"""Exercise promotion's compiled local checks on a disposable systemd VM with no NIC."""

import json
import os
from pathlib import Path
import shutil
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from lanrith import boot_health, build, config, runtime, service_runtime
from kea_control_systemd_native import stage as stage_kea
from ssh_listeners_systemd import stage as stage_ssh
from test_authoritative import declaration
from unbound_native import network, run, write


HEALTH = 'lanrith-health.service'
TARGET = 'boot-complete.target'


def gate():
    plan = json.loads(Path('/usr/share/lanrith/health.json').read_bytes())
    boot_health.check(plan)


def qualify():
    assert os.geteuid() == 0 and Path('/proc/1/comm').read_text().strip() == 'systemd'
    assert run('systemd-detect-virt', '--vm').stdout.strip()
    assert not Path('/usr/share/lanrith/installed.json').exists()
    assert {row['ifname'] for row in json.loads(run('ip', '-j', 'link').stdout)} == {'lo'}
    value = declaration()
    value['uplink'] = {'interface': 'wan', 'ipv4': {'address': '198.51.100.2/24', 'gateway': '198.51.100.1'},
                       'ipv6': 'disabled'}
    value['services']['ntp'] = {'enabled': True, 'upstreams': ['offline-peer.home.arpa']}
    value['administration']['serial'] = {'enabled': False}
    authority = value['services']['dns']['authoritative']
    del authority['writers']
    authority['zones']['home.arpa']['persistent'] = True
    value['routing'] = {'static_routes': [{'to': '192.0.2.0/24', 'network': 'home', 'on_link': True}]}
    files = config.render(value)
    root = Path('/run/boot-health-fixture')
    root.mkdir()
    base = root/'base.tar'
    base.write_bytes(b'synthetic')
    build.assembly(config.normalize(value), base, root/'assembly', version='0.1.0', sequence=2)
    overlay = root/'assembly/mkosi.extra'
    units = Path('/etc/systemd/system')
    plan = json.loads(files['usr/share/lanrith/health.json'])
    write('/usr/share/lanrith/health.json', json.dumps(plan))
    write(units/HEALTH, (overlay/'usr/lib/systemd/system'/HEALTH).read_text())
    write(units/(HEALTH+'.d/fixture.conf'), '[Service]\nExecStart=\nExecStart=/usr/bin/python3 '
          + str(Path(__file__).resolve())+' --gate\n')
    (units/(TARGET+'.requires')).mkdir(exist_ok=True)
    (units/(TARGET+'.requires')/HEALTH).symlink_to('../'+HEALTH)
    for name in ('systemd-networkd', 'nftables', 'lanrith-services', 'lanrith-recovery-key'):
        write(units/(name+'.service'), '[Service]\nType=oneshot\nRemainAfterExit=yes\nExecStart=/bin/true\n')
    write(units/'fixture-observer.service', '[Service]\nType=oneshot\nExecStart=/bin/false\n')
    write(units/'named.service', '[Service]\nType=notify\nNetworkNamespacePath=/run/netns/lanrith-services\n'
          'ExecStart=/usr/sbin/named -f -n 1 -u bind -c /etc/bind/named.conf\n')
    write(units/'unbound.service', '[Service]\nType=notify\nNetworkNamespacePath=/run/netns/lanrith-services\n'
          'ExecStart=/usr/sbin/unbound -d -p -c /etc/unbound/unbound.conf\n')
    stage_ssh(files)
    write(units/'lanrith-ssh-host-key.service', '[Service]\nType=oneshot\nRemainAfterExit=yes\n'
          'ExecStart=/usr/bin/test -s /var/lib/lanrith/ssh-host-keys/ssh_host_ed25519_key\n')
    ssh_snippet = '/etc/ssh/sshd_config.d/00-lanrith.conf'
    ssh_config = files[ssh_snippet[1:]]
    write('/etc/lanrith/chrony-resolv.conf', files['etc/lanrith/chrony-resolv.conf'])
    write('/etc/chrony/chrony.conf', files['etc/chrony/chrony.conf'])
    write(units/'chrony.service', '[Service]\nType=exec\nUser=_chrony\nGroup=_chrony\n'
          'RuntimeDirectory=chrony\nRuntimeDirectoryMode=0750\nStateDirectory=chrony\nAmbientCapabilities=CAP_NET_BIND_SERVICE\n'
          'NetworkNamespacePath=/run/netns/lanrith-services\n'
          'BindReadOnlyPaths=/etc/lanrith/chrony-resolv.conf:/etc/resolv.conf\n'
          'ExecStart=/usr/sbin/chronyd -x -n -U -u _chrony -f /etc/chrony/chrony.conf\n')
    Path('/run/named').mkdir(exist_ok=True)
    shutil.chown('/run/named', 'bind', 'bind')
    for name in ('etc/nftables.conf', 'etc/lanrith/services.nft', 'etc/bind/named.conf'):
        write('/'+name, files[name])
    write('/etc/unbound/unbound.conf', files['etc/unbound/unbound.conf.d/lanrith.conf'])
    Path('/etc/resolv.conf').unlink(missing_ok=True)
    write('/etc/resolv.conf', files['etc/resolv.conf'])
    zone = Path('/var/cache/bind/db.home.arpa')
    for name, body in files.items():
        if name.startswith('usr/share/lanrith/zones/db.'):
            write('/var/cache/bind/'+Path(name).name, body)
    desired = zone.read_text()
    dynamic = 'kept IN TXT "operator data"\n'
    zone.write_text(desired+dynamic)
    account = stage_kea(files)
    Path('/var/lib/kea').mkdir(exist_ok=True)
    os.chown('/var/lib/kea', account.pw_uid, account.pw_gid)
    network('lan', '192.168.10.1', '192.168.10.20')
    # The carrier is local and the declared gateway has no peer. Only its FIB entry can be required.
    run('ip', 'link', 'add', 'wan', 'type', 'dummy')
    run('ip', 'address', 'add', '198.51.100.2/24', 'dev', 'wan')
    run('ip', 'link', 'set', 'wan', 'up')
    run('ip', 'route', 'add', 'default', 'via', '198.51.100.1', 'dev', 'wan')
    lan6 = next(a for a in plan['interfaces'][0]['addresses'] if ':' in a)
    run('ip', '-6', 'address', 'add', lan6, 'dev', 'lan', 'nodad')
    run('ip', 'route', 'add', '192.0.2.0/24', 'dev', 'lan')
    run('nft', '-f', '/etc/nftables.conf')
    service_runtime.start(json.loads(files['usr/share/lanrith/service-plane.json']))
    run('systemctl', 'daemon-reload')

    def start(expected=None):
        result = run('systemctl', 'start', TARGET, check=False)
        if expected is None:
            if result.returncode:
                raise AssertionError(result.stderr+run('journalctl', '-b', '-u', HEALTH, '-u', 'named', '-u', 'unbound',
                                         '-u', 'kea-dhcp4-server', '-u', 'chrony', '-u', 'ssh', '-n', '80', '-o', 'cat').stdout)
            assert run('systemctl', 'is-active', TARGET).stdout.strip() == 'active'
        else:
            assert result.returncode != 0 and run('systemctl', 'is-active', TARGET, check=False).returncode
            journal = run('journalctl', '-b', '-u', HEALTH, '-n', '22', '-o', 'cat').stdout
            assert expected in journal, journal
            run('systemctl', 'reset-failed', HEALTH)

    def stop():
        run('systemctl', 'stop', TARGET)

    def observer():
        assert run('systemctl', 'start', 'fixture-observer', check=False).returncode
        assert 'fixture-observer.service' in run('systemctl', '--failed', '--no-legend').stdout

    observer()
    start()
    assert run('systemctl', 'show', '-P', 'ActiveState', HEALTH).stdout.strip() == 'inactive'
    stop()
    run('systemctl', 'reset-failed', 'fixture-observer.service')
    start()
    observer()
    assert run('systemctl', 'is-active', TARGET).stdout.strip() == 'active'
    stop()
    run('systemctl', 'reset-failed', 'fixture-observer.service')
    run('ip', 'route', 'del', '192.0.2.0/24', 'dev', 'lan')
    start('route 192.0.2.0/24')
    observer()
    start('route 192.0.2.0/24')
    run('ip', 'route', 'add', '192.0.2.0/24', 'dev', 'lan')
    run('ip', 'route', 'replace', 'default', 'via', '198.51.100.3', 'dev', 'wan')
    start('route 0.0.0.0/0 on wan')
    run('ip', 'route', 'replace', 'default', 'via', '198.51.100.1', 'dev', 'wan')
    zone.write_text(''.join(line for line in desired.splitlines(keepends=True)
                            if not line.startswith('dns IN AAAA '))+dynamic)
    run('systemctl', 'restart', 'named')
    start('authoritative DNS answer for dns.home.arpa. AAAA')
    zone.write_text(desired+dynamic)
    run('systemctl', 'restart', 'named')
    # Replace the interface under an active daemon. Its raw socket no longer serves the new ifindex.
    run('ip', 'link', 'del', 'lan')
    run('ip', 'netns', 'del', 'lan')
    network('lan', '192.168.10.1', '192.168.10.20')
    run('ip', '-6', 'address', 'add', lan6, 'dev', 'lan', 'nodad')
    run('ip', 'route', 'add', '192.0.2.0/24', 'dev', 'lan')
    start('Kea scope listeners')
    run('systemctl', 'restart', 'kea-dhcp4-server')
    assert run('systemctl', 'is-active', TARGET, check=False).returncode
    # Promotion must requeue a target whose first dependency job failed.
    runtime.complete_target()
    assert run('systemctl', 'is-active', TARGET).stdout.strip() == 'active'
    stop()
    ssh_listener = 'ListenAddress '+lan6.split('/')[0]+'\n'
    assert ssh_listener in ssh_config
    write(ssh_snippet, ssh_config.replace(ssh_listener, ''))
    run('systemctl', 'restart', 'ssh.service')
    start('SSH management listeners')
    write(ssh_snippet, ssh_config)
    run('systemctl', 'restart', 'ssh.service')
    resolver = Path('/etc/resolv.conf')
    resolver.write_text('nameserver 192.0.2.254\n')
    start('Host DNS resolver differs')
    resolver.write_text(files['etc/resolv.conf'])
    start()
    assert run('dig', '+short', '+tries=1', '+time=2', 'kept.home.arpa.', 'TXT').stdout.strip() == '"operator data"'
    stop()
    unbound = Path('/etc/unbound/unbound.conf')
    original = unbound.read_text()
    endpoint = plan['dns']['listeners'][1]
    entry = '  interface: '+endpoint+'\n'
    assert entry in original
    unbound.write_text(original.replace(entry, ''))
    run('systemctl', 'restart', 'unbound')
    start('Unbound tcp listener '+endpoint)
    unbound.write_text(original)
    run('systemctl', 'restart', 'unbound')
    private_resolver = Path('/etc/lanrith/chrony-resolv.conf')
    private_resolver.write_text('nameserver 192.0.2.254\n')
    start('NTP client resolver differs')
    private_resolver.write_text(files['etc/lanrith/chrony-resolv.conf'])
    start()
    # Both upstream families disabled: the private BIND route remains local.
    value['uplink'] = {'interface': 'wan', 'ipv4': 'disabled', 'ipv6': 'disabled'}
    isolated = config.render(value)
    unbound.write_text(isolated['etc/unbound/unbound.conf.d/lanrith.conf'])
    run('systemctl', 'restart', 'unbound')
    isolated_dns = json.loads(isolated['usr/share/lanrith/health.json'])['dns']
    boot_health.check_dns(isolated_dns, lambda args, label: run(*args).stdout)
    unbound.write_text(original)
    run('systemctl', 'restart', 'unbound')
    # Staging reuses this generated oneshot while the original target is already active.
    run('ip', 'route', 'del', '192.0.2.0/24', 'dev', 'lan')
    assert run('systemctl', 'start', HEALTH, check=False).returncode
    print('passed offline SSH, Kea, authoritative and host DNS, Chrony DNS, route and advisory timing checks', flush=True)


if __name__ == '__main__':
    if sys.argv[1:] == ['--gate']:
        gate()
    else:
        qualify()
