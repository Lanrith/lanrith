#!/usr/bin/env python3
"""Exercise console policy in a disposable systemd guest with two connected UARTs.

Use a VGA device and a null-modem connection between ttyS1 and ttyS2. ttyS0
carries the fixture receipt. The native-tools guest mounts the audited Debian
filesystem at /opt/fixture-platform. With ttyS0 already configured, add these
QEMU arguments using a socket path in a private temporary directory.

    -device VGA
    -chardev socket,id=uart_a,path=PATH,server=on,wait=off -serial chardev:uart_a
    -chardev socket,id=uart_b,path=PATH -serial chardev:uart_b

All accounts, keys and state are temporary.
"""

import hashlib
import os
from pathlib import Path
import re
import secrets
import select
import shutil
import subprocess
import sys
import tempfile
import time
import tty

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from lanrith import build, config

PLATFORM = Path('/opt/fixture-platform')
SERIAL = 'serial-getty@ttyS1.service'
WATCHDOG = 'lanrith-serial-idle-watchdog.service'
HIDE_CHILDREN = Path('/run/console-qa-children-unavailable')
MARKER = Path('/var/lib/lanrith/recovery-key-verified')
COUNTER = Path('/run/lanrith-serial-auth/ttyS1')


def run(*args, **kwargs):
    return subprocess.run(args, check=True, capture_output=True, timeout=45, **kwargs)


def install(source, relative):
    target = Path('/')/relative
    target.parent.mkdir(parents=True, exist_ok=True)
    if (source/relative).is_symlink() and (source/relative).readlink() == Path('/dev/null'):
        target.symlink_to('/dev/null')
    else:
        shutil.copy2(source/relative, target)


def wait_for(check, seconds=40):
    deadline = time.monotonic() + seconds
    while not check():
        if time.monotonic() >= deadline:
            raise AssertionError('Guest condition timed out.')
        time.sleep(.15)


class Terminal:
    def __init__(self, fd):
        self.fd = fd
        self.buffer = b''

    def expect(self, pattern, timeout=45):
        deadline = time.monotonic() + timeout
        while not (match := re.search(pattern, self.buffer)):
            remaining = deadline - time.monotonic()
            if remaining <= 0 or not select.select([self.fd], [], [], remaining)[0]:
                raise AssertionError('Terminal event timed out: '+repr(pattern))
            chunk = os.read(self.fd, 8192)
            if not chunk:
                raise AssertionError('Terminal closed.')
            self.buffer = (self.buffer+chunk)[-16384:]
        self.buffer = self.buffer[match.end():]

    def send(self, data):
        os.write(self.fd, data+b'\r')


def stage(work, password):
    for path in ('usr/bin/sudo', 'usr/bin/login', 'usr/sbin/agetty', 'etc/pam.d/login', 'etc/pam.d/sshd',
                 'etc/pam.d/common-account', 'etc/pam.d/common-session', 'etc/pam.d/common-session-noninteractive',
                 'etc/sudoers', 'etc/sudo.conf', 'usr/sbin/sshd', 'usr/lib/openssh/sshd-session',
                 'usr/lib/openssh/sshd-auth', 'usr/lib/x86_64-linux-gnu/libwrap.so.0',
                 'usr/lib/x86_64-linux-gnu/libwtmpdb.so.0', 'usr/lib/x86_64-linux-gnu/security/pam_rssh.so',
                 'usr/lib/systemd/system/getty@.service', 'usr/lib/systemd/system/serial-getty@.service'):
        install(PLATFORM, path)
    shutil.copytree(PLATFORM/'usr/libexec/sudo', '/usr/libexec/sudo', symlinks=True, dirs_exist_ok=True)
    run('useradd', '-m', '-s', '/bin/bash', '-p', 'x', 'consoleqa')
    if subprocess.run(['id', 'sshd'], capture_output=True).returncode:
        run('useradd', '--system', '--home-dir', '/run/sshd', '--shell', '/usr/sbin/nologin', 'sshd')
    for key in ('host', 'enrolled', 'unlisted'):
        run('ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-f', work/key)
    value = config.load(ROOT/'examples/minimal.yaml')
    value['hardware']['boot'] = {'console': 'tty0', 'recovery_console': 'ttyS2'}
    value['administration'].update(username='consoleqa', authorized_keys=[(work/'enrolled.pub').read_text().strip()],
                                  serial={'enabled': True, 'tty': 'ttyS1', 'timeout_seconds': 30,
                                          'cooldown': {'attempts': 2, 'seconds': 60}})
    salt = os.urandom(16)
    digest = hashlib.scrypt(password, salt=salt, n=32768, r=8, p=1, dklen=32, maxmem=64*1024*1024)
    credential = work/'serial.hash'
    credential.write_text('scrypt:32768:8:1:'+salt.hex()+':'+digest.hex()+'\n')
    credential.chmod(0o600)
    base = work/'base.tar'
    base.write_bytes(b'fixture overlay only')
    build.assembly(value, base, work/'assembly', version='0.1.0', sequence=1, serial_hash=credential)
    overlay = work/'assembly/mkosi.extra'
    for path in ('etc/pam.d/lanrith-sudo-auth', 'etc/pam.d/sudo', 'etc/pam.d/sudo-i', 'etc/security/authorized_keys',
                 'etc/security/admin.serial-passphrase.hash', 'etc/sudoers.d/60-lanrith',
                 'usr/lib/lanrith/verify-serial-passphrase', 'usr/lib/lanrith/serial-idle-watchdog',
                 'usr/lib/systemd/system/lanrith-serial-idle-watchdog.service', 'usr/share/lanrith/administration.json'):
        install(overlay, path)
    for path in (overlay/'etc/systemd/system').glob('*getty@*.service.d/*.conf'):
        install(overlay, path.relative_to(overlay))
    # The disposable guest runs only basic.target. The marker represents the
    # already-tested enrollment transaction. No fixture program enrolls a disk.
    Path('/run/systemd/system/lanrith-recovery-key.service').write_text(
        '[Service]\nType=oneshot\nExecStart=/bin/true\nRemainAfterExit=yes\n')
    # Fault injection lives in this guest's watcher namespace only. The control
    # process, UART, PAM, manager, timer and unit shutdown all remain real.
    wrapper = work/'watchdog-qa.py'
    wrapper.write_text("""import runpy
from pathlib import Path
from unittest.mock import patch

helper = runpy.run_path('/usr/lib/lanrith/serial-idle-watchdog')
main = helper['main']
read_children = helper['has_login_child']

def children(pid):
    if Path('/run/console-qa-children-unavailable').exists():
        raise PermissionError('fixture observation unavailable')
    return read_children(pid)

with patch.dict(main.__globals__, has_login_child=children):
    main()
""")
    dropin = Path('/run/systemd/system')/(WATCHDOG+'.d')
    dropin.mkdir()
    (dropin/'fixture.conf').write_text(f'[Service]\nExecStart=\nExecStart=/usr/bin/python3 {wrapper}\n')
    generators = Path('/run/systemd/system-generators')
    generators.mkdir(exist_ok=True)
    (generators/'systemd-ssh-generator').symlink_to('/dev/null')
    run('systemctl', 'daemon-reload')
    run('systemctl', 'start', 'systemd-user-sessions.service')
    assert Path('/usr/bin/sudo').stat().st_mode & 0o4000
    return value


def check_ssh(work, password, *, trusted):
    cmd = ['ssh', '-tt', '-F', '/dev/null', '-o', 'BatchMode=yes', '-o', 'IdentitiesOnly=yes',
           '-o', 'StrictHostKeyChecking=accept-new', '-o', 'UserKnownHostsFile='+str(work/'known'),
           '-i', str(work/'enrolled'), '-p', '2266', 'consoleqa@127.0.0.1']
    for mode in ('', '-i'):
        if trusted:
            result = run(cmd[0], '-A', *cmd[1:], 'sudo -K && sudo '+mode+' id -u')
            assert b'0' in result.stdout.splitlines()
        else:
            for forwarding in ('-a', '-A'):
                # Wait for echo to be disabled before sending the local-only
                # disposable credential on this remote pseudo-terminal.
                command = ("stty -echo && sudo -K && printf 'READY\\n' && IFS= read -r token && "
                           "printf '%s\\n' \"$token\" | sudo -S -p '' "+mode+" id -u")
                with subprocess.Popen([cmd[0], forwarding, *cmd[1:], command], stdin=subprocess.PIPE,
                                      stdout=subprocess.PIPE, stderr=subprocess.DEVNULL) as process:
                    try:
                        stream = Terminal(process.stdout.fileno())
                        stream.expect(rb'READY\r?\n')
                        process.stdin.write(password+b'\n')
                        process.stdin.flush()
                        assert process.wait(timeout=45) == 1
                    finally:
                        process.kill()


def exercise(work, term, password):
    value = stage(work, password)
    MARKER.parent.mkdir(parents=True, exist_ok=True)
    assert not MARKER.exists()
    for unit in ('getty@tty1', 'autovt@tty2', 'autovt@tty6', 'serial-getty@ttyS2', SERIAL):
        run('systemctl', 'start', unit)
        assert run('systemctl', 'show', '-P', 'ConditionResult', unit).stdout.strip() == b'no'
    run('stty', '-F', '/dev/ttyS1', '9600')
    assert run('stty', '-F', '/dev/ttyS1', 'speed').stdout.strip() == b'9600'
    MARKER.write_text('synthetic committed enrollment\n')
    for num in (1, 2, 6):
        unit = ('getty@' if num == 1 else 'autovt@')+'tty'+str(num)
        run('systemctl', 'start', unit)
        assert run('systemctl', 'show', '-P', 'SubState', unit).stdout.strip() == b'exited'
        display = Path('/dev/vcs'+str(num)).read_bytes()
        assert b'use SSH on the management network or the serial port ttyS1.' in display
        assert b'login:' not in display.lower()
    assert b'/usr/bin/echo' in run('systemctl', 'show', '-P', 'ExecStart', 'serial-getty@ttyS2').stdout
    print('Committed enrollment gates monitor, on-demand, reserved and serial units. VT notices displayed.', flush=True)

    Path('/run/sshd').mkdir(exist_ok=True)
    ssh_conf = work/'sshd_config'
    ssh_conf.write_text('Port 2266\nListenAddress 127.0.0.1\nHostKey '+str(work/'host')+'\n'
                        'AuthorizedKeysFile /etc/security/authorized_keys\nAllowUsers consoleqa\nUsePAM yes\n'
                        'PasswordAuthentication no\nKbdInteractiveAuthentication no\nAllowAgentForwarding yes\n')
    run('ip', 'link', 'set', 'lo', 'up')
    run('/usr/sbin/sshd', '-f', ssh_conf)
    agent = work/'agent.sock'
    os.environ['SSH_AUTH_SOCK'] = str(agent)
    with subprocess.Popen(['ssh-agent', '-D', '-a', str(agent)], stdout=subprocess.DEVNULL,
                          stderr=subprocess.DEVNULL) as agent_process:
        try:
            wait_for(agent.exists)
            run('ssh-add', work/'unlisted')
            check_ssh(work, password, trusted=False)
            print('Unlisted and absent forwarded keys and the serial secret were denied on SSH PTYs.', flush=True)
            assert not COUNTER.exists()
            run('ssh-add', work/'enrolled')
            run('systemctl', 'start', SERIAL)
            run('systemctl', 'is-active', '--quiet', WATCHDOG)
            term.expect(rb'login: ')
            assert run('stty', '-F', '/dev/ttyS1', 'speed').stdout.strip() == b'115200'
            def submit(secret):
                term.send(b'consoleqa')
                term.expect(rb'Password: ?')
                term.send(secret)

            pids = set()
            for count in (1, 2):
                pids.add(run('systemctl', 'show', '-P', 'MainPID', SERIAL).stdout.strip())
                submit(b'incorrect-fixture')
                term.expect(rb'login: ')
                assert int(COUNTER.read_text().split()[0]) == count
            assert len(pids) == 2
            print('Two independent real login processes recorded the port cooldown.', flush=True)
            before = COUNTER.read_text()
            submit(password)
            term.expect(rb'login: ')
            assert COUNTER.read_text() == before
            check_ssh(work, password, trusted=True)
            assert time.monotonic_ns() < int(before.split()[1]) and COUNTER.read_text() == before
            print('Both fresh SSH sudo modes passed with the enrolled agent during serial cooldown.', flush=True)
            wait_for(lambda: time.monotonic_ns() >= int(before.split()[1]))
            submit(password)
            term.expect(rb'\$ ')
            assert not COUNTER.exists()
            for mode in (b'', b'-i'):
                term.send(b"sudo -K && sudo -p 'LOCAL_AUTH ' "+mode+b" id -u")
                # Anchor the exact prompt at line start to exclude the command echo.
                term.expect(rb'(?:^|\n)LOCAL_AUTH ')
                term.send(password)
                term.expect(rb'(?:^|\n)0\r?\n')
                term.expect(rb'\$ ')
            print('Configured UART logged in and both fresh sudo modes returned UID 0.', flush=True)
            def start_job():
                pidfile = Path('/tmp/console-qualification.pid')
                pidfile.unlink(missing_ok=True)
                term.send(b"sh -c 'echo $$ >/tmp/console-qualification.pid; while sleep 1; do echo FG_TICK; done'")
                term.expect(rb'(?:^|\n)FG_TICK\r?\n')
                return Path('/proc')/pidfile.read_text().strip()

            foreground = start_job()
            time.sleep(21)
            os.write(term.fd, b' ')  # A keystroke while the foreground program owns the UART.
            last_input = time.monotonic()
            time.sleep(13)
            assert foreground.exists()  # Past the original idle deadline.
            HIDE_CHILDREN.touch()
            time.sleep(7)
            HIDE_CHILDREN.unlink()
            wait_for(lambda: not foreground.exists(), seconds=18)
            elapsed = time.monotonic() - last_input
            assert 28 <= elapsed <= 39, elapsed
            term.expect(rb'login: ', timeout=18)
            print(f'Near-deadline UART input extended the login. Output and a read error left expiry at {elapsed:.1f}s.', flush=True)

            submit(password)
            term.expect(rb'\$ ')
            foreground = start_job()
            invocation = run('systemctl', 'show', '-P', 'InvocationID', SERIAL).stdout
            HIDE_CHILDREN.touch()
            lost = time.monotonic()
            wait_for(lambda: not foreground.exists(), seconds=38)
            elapsed = time.monotonic() - lost
            assert elapsed <= 39, elapsed
            wait_for(lambda: int(run('systemctl', 'show', '-P', 'ControlPID', SERIAL).stdout) > 0)
            assert int(run('systemctl', 'show', '-P', 'MainPID', SERIAL).stdout) == 0
            assert run('systemctl', 'show', '-P', 'InvocationID', SERIAL).stdout != invocation
            assert b'serial observation deadline reached' in run('journalctl', '-b', '-u', WATCHDOG).stdout
            check_ssh(work, password, trusted=True)
            assert int(run('systemctl', 'show', '-P', 'MainPID', SERIAL).stdout) == 0
            HIDE_CHILDREN.unlink()
            term.expect(rb'login: ', timeout=12)
            print(f'Persistent observation failure closed the session in {elapsed:.1f}s and held the next prompt until recovery.', flush=True)

            submit(password)
            term.expect(rb'\$ ')
            foreground = start_job()
            invocation = run('systemctl', 'show', '-P', 'InvocationID', SERIAL).stdout
            run('systemctl', 'kill', '--kill-whom=main', '--signal=SIGKILL', WATCHDOG)
            term.expect(rb'login: ', timeout=15)
            assert not foreground.exists()
            assert run('systemctl', 'show', '-P', 'InvocationID', SERIAL).stdout != invocation
            print('Watcher loss terminated the foreground job and restored a fresh supervised prompt.', flush=True)

            value['administration']['serial'] = {'enabled': False}
            ssh_only = config.render(value)
            for name in ('etc/pam.d/lanrith-sudo-auth', 'usr/share/lanrith/administration.json'):
                (Path('/')/name).write_text(ssh_only[name])
            check_ssh(work, password, trusted=True)
            print('The SSH-only profile also passed fresh ordinary and login-shell elevation.', flush=True)
        finally:
            agent_process.terminate()


def main():
    assert os.geteuid() == 0 and Path('/proc/1/comm').read_text().strip() == 'systemd'
    assert run('systemd-detect-virt').stdout.strip() == b'qemu' and PLATFORM.is_mount()
    with tempfile.TemporaryDirectory(dir='/run', prefix='console-qualification-') as work:
        fd = os.open('/dev/ttyS2', os.O_RDWR | os.O_NOCTTY | os.O_NONBLOCK)
        try:
            tty.setraw(fd)
            exercise(Path(work), Terminal(fd), secrets.token_urlsafe(32).encode())
        except Exception:
            print(run('systemctl', 'show', '-p', 'MainPID,SubState,NRestarts,ExecStart', SERIAL).stdout.decode())
            print(run('journalctl', '-b', '-u', WATCHDOG, '--lines=30').stdout.decode())
            print(Path('/proc/tty/driver/serial').read_text())
            raise
        finally:
            os.close(fd)


if __name__ == '__main__':
    main()
