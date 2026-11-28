#!/usr/bin/env python3
"""Qualify delayed SSH administration on a disposable systemd guest with no NIC."""

import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from lanrith import config

UNIT = 'ssh.service'
CHECK = '/usr/lib/lanrith/verify-ssh-listeners'
SNIPPET = 'etc/ssh/sshd_config.d/00-lanrith.conf'
V4 = '192.168.10.1'
V6 = 'fd42:1000:1000:10::1'
PORT = 2222


def run(*args, check=True):
    return subprocess.run(args, check=check, text=True, capture_output=True, timeout=35)


def write(path, content):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content)


def stage(files, *, provision_key=True):
    generators = Path('/run/systemd/system-generators')
    generators.mkdir(exist_ok=True)
    (generators/'systemd-ssh-generator').symlink_to('/dev/null')
    platform = Path('/opt/fixture-platform')
    for name in ('usr/sbin/sshd', 'usr/bin/ssh-keygen', 'usr/lib/openssh/sshd-session',
                 'usr/lib/openssh/sshd-auth', 'usr/lib/x86_64-linux-gnu/libwrap.so.0',
                 'usr/lib/x86_64-linux-gnu/libwtmpdb.so.0', 'etc/ssh/sshd_config', 'usr/lib/systemd/system/ssh.service'):
        dest = Path('/')/name
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(platform/name, dest)
    if run('getent', 'passwd', 'sshd', check=False).returncode:
        run('useradd', '--system', '--home-dir', '/run/sshd', '--shell', '/usr/sbin/nologin', 'sshd')
    for filename in ('10-lanrith-firewall.conf', '20-lanrith-persistent-host-key.conf'):
        path = Path('etc/systemd/system/ssh.service.d')/filename
        write(Path('/')/path, (platform/path).read_text())
    for path, content in files.items():
        if (path == SNIPPET or path.endswith('/ssh-listeners.json') or 'ssh.service.d/' in path or
                path.startswith('usr/lib/systemd/system/lanrith-ssh-listeners.')):
            write('/'+path, content)
    helper = Path(CHECK)
    helper.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(ROOT/'mkosi/base/mkosi.extra'/CHECK[1:], helper)
    if provision_key:
        key = Path('/var/lib/lanrith/ssh-host-keys/ssh_host_ed25519_key')
        key.parent.mkdir(parents=True, exist_ok=True)
        run('ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-f', key)
    for directory in ('/run/sshd', '/var/tmp/lanrith-update'):
        Path(directory).mkdir(exist_ok=True)


def parser_profiles(value):
    def effective():
        output = run('/usr/sbin/sshd', '-T', '-C', 'user=admin,host=fixture,addr=192.168.10.20').stdout
        return dict(line.split(' ', 1) for line in output.splitlines())

    default = effective()
    assert [default[k] for k in ('allowagentforwarding', 'allowtcpforwarding', 'allowstreamlocalforwarding',
                                 'x11forwarding')] == ['yes'] * 4
    keys = ('maxauthtries', 'logingracetime', 'clientaliveinterval', 'clientalivecountmax', 'maxstartups')
    assert [default[k] for k in keys] == ['6', '120', '0', '3', '10:30:100']
    value['administration'].update(ssh_forwarding={'agent': True, 'tcp': False, 'unix': False, 'x11': False},
                                  ssh_limits={'max_auth_tries': 3, 'login_grace_seconds': 30,
                                              'client_alive_interval_seconds': 300, 'client_alive_count_max': 2})
    write('/'+SNIPPET, config.render(value)[SNIPPET])
    declared = effective()
    assert [declared[k] for k in keys] == ['3', '30', '300', '2', '10:30:100']
    assert [declared[k] for k in ('allowagentforwarding', 'allowtcpforwarding', 'allowstreamlocalforwarding',
                                  'x11forwarding')] == ['yes', 'no', 'no', 'no']
    value['administration']['root_access'] = 'disabled'
    value['administration']['ssh_forwarding']['agent'] = False
    files = config.render(value)
    write('/'+SNIPPET, files[SNIPPET])
    assert effective()['allowagentforwarding'] == 'no'
    path = 'etc/systemd/system/ssh.service.d/60-lanrith-rootless.conf'
    write('/'+path, files[path])


def wait(predicate, timeout=50):
    until = time.monotonic() + timeout
    while not predicate():
        assert time.monotonic() < until, run('journalctl', '-b', '-n', '100', '-o', 'cat').stdout
        time.sleep(.3)


def check_banner(address):
    with socket.create_connection((address, PORT), timeout=5) as client:
        with client.makefile('rb') as stream:
            line = stream.readline(255)
        assert line.startswith(b'SSH-2.0-OpenSSH_'), (line, run('journalctl', '-b', '-u', UNIT, '-n', '25', '-o', 'cat').stdout)


def qualify():
    assert sys.argv[1:] == ['--disposable-systemd']
    assert os.geteuid() == 0 and 'rdinit=/fixture-init' in Path('/proc/cmdline').read_text()
    assert {row['ifname'] for row in json.loads(run('ip', '-j', 'link').stdout)} == {'lo'}
    value = config.load(ROOT/'examples/minimal.yaml')
    value['administration']['ssh_port'] = PORT
    files = config.render(value)
    stage(files)
    parser_profiles(value)
    print('Audited Debian sshd -T accepted default, agent-only and rootless profiles.', flush=True)
    # The guest has no persistent identities or firewall from an appliance.
    write('/run/systemd/system/nftables.service', '[Service]\nType=oneshot\nRemainAfterExit=yes\nExecStart=/bin/true\n')
    write('/run/systemd/system/lanrith-ssh-host-key.service', '[Service]\nType=oneshot\nRemainAfterExit=yes\n'
          'ExecStart=/usr/bin/test -s /var/lib/lanrith/ssh-host-keys/ssh_host_ed25519_key\n')
    run('systemctl', 'stop', 'ssh.socket', check=False)
    run('systemctl', 'mask', '--runtime', 'ssh.socket')
    lan = Path('/run/systemd/network/01-managed-lan.network')
    full = files['etc/systemd/network/40-home.network']
    write(lan, full.replace(f'Address={V6}/64\n', ''))
    run('ip', 'link', 'add', 'lan', 'type', 'veth', 'peer', 'name', 'peer')
    run('systemctl', 'daemon-reload')
    run('systemctl', 'start', 'systemd-networkd.service')
    run('systemctl', 'start', UNIT)
    assert run('systemctl', 'show', '-P', 'Result', UNIT).stdout.strip() == 'exec-condition'
    assert run(CHECK, check=False).returncode and run('systemctl', 'is-active', 'lanrith-ssh-listeners.timer').returncode == 0
    run('ip', 'link', 'set', 'peer', 'up')
    wait(lambda: run('systemctl', 'is-active', '--quiet', UNIT, check=False).returncode == 0)
    assert f'{V4}:{PORT}' in run('ss', '-nlt').stdout
    assert V6 in run(CHECK, check=False).stderr
    print('Delayed carrier recovered IPv4 SSH automatically. Missing IPv6 kept readiness incomplete.', flush=True)
    # Hold a synthetic ordinary TCP socket on the late address. The verifier
    # must distinguish it from sshd's listener, even when the address is ready.
    with socket.socket(socket.AF_INET6, socket.SOCK_STREAM) as other:
        other.setsockopt(socket.IPPROTO_IPV6, 78, 1)  # Linux IPV6_FREEBIND
        other.bind((V6, PORT))
        other.listen()
        write(lan, full)
        run('networkctl', 'reload')
        wait(lambda: any(a['local'] == V6 and not a.get('tentative') for row in
                         json.loads(run('ip', '-j', 'address', 'show', 'dev', 'lan').stdout) for a in row['addr_info']))
        assert run(CHECK, check=False).returncode
        run('systemctl', 'start', 'lanrith-ssh-listeners.service')
        assert f'{V4}:{PORT}' in run('ss', '-nlt').stdout
    wait(lambda: run(CHECK, check=False).returncode == 0)
    previous = run('systemctl', 'show', '-P', 'ExecReload', UNIT).stdout
    assert 'pid=0' not in previous, previous
    for _ in range(2):
        run('systemctl', 'start', 'lanrith-ssh-listeners.service')
    assert previous == run('systemctl', 'show', '-P', 'ExecReload', UNIT).stdout
    journal = run('journalctl', '-b', '-o', 'cat', '-u', 'lanrith-ssh-listeners.service').stdout
    print(journal, flush=True)
    assert 'SSH listener check failed' not in journal, journal
    for address in (V4, V6):
        check_banner(address)
    run('systemctl', 'stop', UNIT)
    assert run('systemctl', 'is-active', '--quiet', 'lanrith-ssh-listeners.timer', check=False).returncode
    print('Late IPv6 recovered with a validated reload. Healthy repair and explicit stop were idempotent.', flush=True)

    value['hardware']['interfaces']['oob'] = {'match': {'mac': '02:00:00:00:01:03'}}
    value['networks']['oob'] = {'interface': 'oob', 'role': 'management', 'ipv4': '192.0.2.0/24'}
    value['administration'].update(networks=['oob'], root_access='enabled')
    files = config.render(value)
    for path in (SNIPPET, 'usr/share/lanrith/ssh-listeners.json', 'etc/systemd/system/ssh.service.d/10-lanrith-firewall.conf'):
        write('/'+path, files[path])
    Path('/etc/systemd/system/ssh.service.d/60-lanrith-rootless.conf').unlink()
    write('/run/systemd/system/lanrith-firewall-floor.service',
          '[Service]\nType=oneshot\nRemainAfterExit=yes\nExecStart=/bin/true\n')
    write('/run/systemd/network/01-oob.network', files['etc/systemd/network/40-oob.network'])
    run('ip', 'link', 'add', 'oob', 'type', 'veth', 'peer', 'name', 'unplugged')
    run('networkctl', 'reload')
    run('systemctl', 'daemon-reload')
    run('systemctl', 'start', UNIT)
    assert Path('/sys/class/net/oob/carrier').read_text().strip() == '0'
    run(CHECK)
    run('ip', 'link', 'set', 'unplugged', 'up')
    check_banner('192.0.2.1')
    print('Single-address OOB listener became ready without carrier and served SSH after reconnect.', flush=True)

    # Lose the last address in the narrow gap after the address condition has
    # already passed. This exercises the package's specific main-process 255.
    run('systemctl', 'stop', UNIT)
    trigger = Path('/run/fixture-remove-ssh-address')
    write(trigger, '#!/bin/sh\nip address del 192.0.2.1/24 dev oob\n')
    trigger.chmod(0o700)
    dropin = Path('/etc/systemd/system/ssh.service.d/99-fixture.conf')
    write(dropin, '[Service]\nExecStartPre=/run/fixture-remove-ssh-address\n')
    run('systemctl', 'daemon-reload')
    assert run('systemctl', 'start', UNIT, check=False).returncode
    assert run('systemctl', 'show', '-P', 'ExecMainStatus', UNIT).stdout.strip() == '255'
    dropin.unlink()
    run('systemctl', 'daemon-reload')
    run('networkctl', 'reconfigure', 'oob')
    wait(lambda: run(CHECK, check=False).returncode == 0)
    check_banner('192.0.2.1')
    print('All-address bind failure after the startup check recovered automatically.', flush=True)



if __name__ == '__main__':
    try:
        qualify()
    except subprocess.CalledProcessError as error:
        print(error.stderr, file=sys.stderr)
        print(run('journalctl', '-b', '-n', '80', '-o', 'cat').stdout, file=sys.stderr)
        raise
