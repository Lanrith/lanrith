#!/usr/bin/env python3
"""Qualify real UEFI boots and A/B updates using disposable regular-file disks."""

import argparse
import ast
from contextlib import ExitStack
import datetime
import hashlib
import inspect
import json
import os
from pathlib import Path
import re
import select
import shlex
import shutil
import socket
import subprocess
import sys
import tarfile
import tempfile
import threading
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from lanrith import build, config, media, release

PROJECT = Path(__file__).resolve().parents[1]
OWNER = '4d953754-9f66-43ac-b649-e576c951c8cb'
PASSPHRASE = 'disposable-qualification-state-passphrase'


def run(*arguments, timeout=180, **kwargs):
    result = subprocess.run(arguments, stdin=subprocess.DEVNULL, capture_output=True, timeout=timeout, **kwargs)
    release.require(result.returncode == 0, Path(arguments[0]).name+' failed: '+
                    result.stderr[-2048:].decode(errors='replace'))
    return result.stdout


def stop(process):
    if process is not None and process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=15)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=15)


def regular(path):
    release.require(path.is_absolute() and path.is_file() and not path.is_symlink() and
                    path.resolve() == path, 'VM disks and firmware must be canonical regular files.')
    return path


def connect(path, process):
    deadline = time.monotonic()+30
    while time.monotonic() < deadline:
        release.require(process.poll() is None, 'Qualification subprocess exited before its socket was ready.')
        client = socket.socket(socket.AF_UNIX)
        try:
            client.connect(str(path))
            client.settimeout(1)
            return client
        except (FileNotFoundError, ConnectionRefusedError):
            client.close()
            time.sleep(0.1)
    raise release.ReleaseError('Qualification socket did not become ready.')


class SerialReader:
    """Drain console output while SSH, image assembly or staging is blocked."""

    LIMIT = 4*1024*1024

    def __init__(self, stream):
        self.stream = stream
        self.data = b''
        self.closed = False
        self.condition = threading.Condition()
        self.stopping = threading.Event()
        self.thread = threading.Thread(target=self.receive, daemon=True)
        self.thread.start()

    def receive(self):
        while not self.stopping.is_set():
            try:
                data = self.stream.recv(65536)
            except socket.timeout:
                continue
            except OSError:
                data = b''
            with self.condition:
                if not data:
                    self.closed = True
                    self.condition.notify_all()
                    return
                self.data = (self.data+data)[-self.LIMIT:]
                self.condition.notify_all()

    def close(self):
        self.stopping.set()
        try:
            self.stream.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        self.thread.join(timeout=5)
        self.stream.close()
        release.require(not self.thread.is_alive(), 'Qualification console reader did not stop.')
        with self.condition:
            self.closed = True
            self.data = b''


class Guest:
    def __init__(self, work, secret, disk, *, medium=None, tpm=True):
        self.work, self.secret = work, secret
        self.process = self.tpm = self.serial = self.qmp = None
        self.console = None
        self.buffer = b''
        self.last_diagnostic = None
        self.qmp_events = []
        self.observed_diagnostics = {}
        self.environment = {key: value for key, value in os.environ.items()
                            if key not in ('SSH_AUTH_SOCK', 'SSH_AGENT_PID')}
        self.environment['SSH_AUTH_SOCK'] = str(secret/'agent.sock')
        work.mkdir(mode=0o700)
        self.firmware = regular(Path('/usr/share/OVMF/OVMF_CODE_4M.secboot.fd'))
        variables = regular(Path('/usr/share/OVMF/OVMF_VARS_4M.fd'))
        run('virt-fw-vars', '--input', str(variables), '--output', str(work/'vars.fd'),
            '--enroll-cert', str(secret/'test.crt'), '--add-mok', OWNER, str(secret/'test.crt'), '--secure-boot')
        self.disk, self.medium, self.tpm_enabled = regular(disk), regular(medium) if medium else None, tpm

    @property
    def buffer(self):
        if self.console is None:
            return b''
        with self.console.condition:
            return self.console.data

    @buffer.setter
    def buffer(self, data):
        if self.console is not None:
            with self.console.condition:
                self.console.data = data

    def start(self):
        release.require(self.process is None or self.process.poll() is not None, 'Guest is already running.')
        self.qmp_events = []
        self.observed_diagnostics = {}
        for name in ('qmp.sock', 'serial.sock', 'tpm.sock'):
            (self.work/name).unlink(missing_ok=True)
        arguments = ['qemu-system-x86_64', '-machine', 'q35,smm=on,accel=tcg', '-cpu', 'max',
            '-smp', '2', '-m', '4096', '-nodefaults', '-display', 'none', '-no-reboot',
            '-global', 'driver=cfi.pflash01,property=secure,value=on',
            '-drive', 'if=pflash,format=raw,unit=0,readonly=on,file='+str(self.firmware),
            '-drive', 'if=pflash,format=raw,unit=1,file='+str(self.work/'vars.fd'),
            '-drive', 'if=none,id=installed,format=raw,file='+str(self.disk),
            '-device', 'virtio-blk-pci,drive=installed,serial=lanrith-qa-disk,bootindex=2',
            '-chardev', 'socket,id=serial,path='+str(self.work/'serial.sock')+',server=on,wait=off',
            '-serial', 'chardev:serial', '-qmp', 'unix:'+str(self.work/'qmp.sock')+',server=on,wait=off', '-S']
        if self.medium:
            arguments += ['-device', 'qemu-xhci', '-drive', 'if=none,id=medium,format=raw,file='+str(self.medium),
                          '-device', 'usb-storage,drive=medium,serial=lanrith-test-medium,bootindex=1']
        with socket.socket() as listener:
            listener.bind(('127.0.0.1', 0))
            self.port = listener.getsockname()[1]
        # Restricted Slirp and loopback forwarding only: no bridge, tap, host
        # device, physical NIC, or connection to another network.
        arguments += ['-netdev', 'user,id=wan,restrict=on', '-device',
            'virtio-net-pci,netdev=wan,mac=02:00:00:00:01:01', '-netdev',
            'user,id=lan,restrict=on,net=192.168.10.0/24,host=192.168.10.2,'+
            'hostfwd=tcp:127.0.0.1:'+str(self.port)+'-192.168.10.1:22',
            '-device', 'virtio-net-pci,netdev=lan,mac=02:00:00:00:01:02']
        if self.tpm_enabled:
            state = self.work/'tpm-state'
            state.mkdir(mode=0o700, exist_ok=True)
            self.tpm = subprocess.Popen(['swtpm', 'socket', '--tpm2', '--tpmstate', 'dir='+str(state)+',mode=0600',
                '--ctrl', 'type=unixio,path='+str(self.work/'tpm.sock')+',mode=0600', '--flags', 'not-need-init'],
                stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            deadline = time.monotonic()+30
            while not (self.work/'tpm.sock').exists() and time.monotonic() < deadline:
                release.require(self.tpm.poll() is None, 'Disposable TPM failed to start.')
                time.sleep(0.1)
            arguments += ['-chardev', 'socket,id=chrtpm,path='+str(self.work/'tpm.sock'),
                          '-tpmdev', 'emulator,id=tpm0,chardev=chrtpm', '-device', 'tpm-tis,tpmdev=tpm0']
        with (self.work/'qemu.stderr').open('ab') as errors:
            self.process = subprocess.Popen(arguments, stdin=subprocess.DEVNULL,
                                            stdout=subprocess.DEVNULL, stderr=errors)
        self.serial, self.qmp = connect(self.work/'serial.sock', self.process), connect(self.work/'qmp.sock', self.process)
        self.console = SerialReader(self.serial)
        self.qmp.recv(65536)
        self.control('qmp_capabilities')
        self.control('cont')

    def control(self, command):
        self.qmp.sendall(json.dumps({'execute': command}).encode()+b'\n')
        data, deadline = b'', time.monotonic()+15
        while time.monotonic() < deadline:
            try:
                data += self.qmp.recv(65536)
            except socket.timeout:
                continue
            for line in data.splitlines():
                value = json.loads(line)
                release.require('error' not in value, 'QEMU rejected a qualification command.')
                if 'return' in value:
                    return
        raise release.ReleaseError('QEMU control response timed out.')

    def expect(self, pattern, answer=None, timeout=600):
        self.expect_any([pattern], timeout=timeout)
        if answer is not None:
            self.serial.sendall(answer.encode()+b'\r')

    def expect_any(self, patterns, timeout=600):
        deadline = time.monotonic()+timeout
        expressions = [re.compile(pattern, re.IGNORECASE) for pattern in patterns]
        while time.monotonic() < deadline:
            with self.console.condition:
                for index, expression in enumerate(expressions):
                    match = expression.search(self.console.data)
                    if match:
                        self.last_diagnostic = self.diagnostic()
                        self.console.data = self.console.data[match.end():]
                        return index
                release.require(self.process.poll() is None, 'Guest stopped before the expected console event.')
                release.require(not self.console.closed, 'Guest console closed before the expected event.')
                self.console.condition.wait(timeout=min(1, max(0, deadline-time.monotonic())))
        raise release.ReleaseError('Guest console event timed out: '+self.diagnostic())

    def diagnostic(self):
        # Emit only fixed public error literals and identifiers, never console
        # lines: the buffer can contain a disposable recovery key.
        buffer = self.buffer
        flags = {name: marker.lower() in buffer.lower() for name, marker in (
            ('secure-boot-rejection', b'Security Violation'), ('kernel-started', b'Linux version'),
            ('emergency-mode', b'emergency mode'), ('recovery-prompt', b'RECOVERY-KEY-STORED'),
            ('bootloader-menu', b'Linux Boot Manager'), ('kernel-panic', b'Kernel panic'),
            ('guest-reboot', b'Rebooting'), ('guest-shutdown', b'systemd-shutdown'),
            ('pid1-freeze', b'Freezing execution'))}
        if self.qmp:
            while select.select([self.qmp], [], [], 0)[0]:
                data = self.qmp.recv(65536)
                if not data:
                    break
                for line in data.splitlines():
                    try:
                        event = json.loads(line)
                    except (ValueError, UnicodeError):
                        continue
                    if event.get('event') in ('SHUTDOWN', 'RESET', 'STOP', 'GUEST_PANICKED'):
                        reason = event.get('data', {}).get('reason', '')
                        self.qmp_events.append({'event': event['event'],
                            'reason': reason if re.fullmatch(r'[a-z-]{0,64}', reason) else 'unknown'})
        literals = set()
        for message in ('Factory installation failed closed.', 'Runtime operation failed.'):
            if message.encode() in buffer:
                literals.add(message)
        for executable in ('bootctl', 'cryptsetup', 'dd', 'dmsetup', 'findmnt', 'ip', 'lsblk',
                           'mount', 'sfdisk', 'sync', 'systemctl', 'systemd-repart', 'systemd-sysupdate',
                           'udevadm', 'umount'):
            for prefix in ('Update command failed: ', 'Update command could not start: '):
                message = prefix+executable
                if message.encode() in buffer:
                    literals.add(message)
        for module in ('factory', 'update', 'release', 'runtime'):
            tree = ast.parse((PROJECT/'lanrith'/(module+'.py')).read_text())
            for node in ast.walk(tree):
                if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == 'require' and len(node.args)>1:
                    message = node.args[1]
                    if isinstance(message, ast.Constant) and isinstance(message.value, str) and message.value.encode() in buffer:
                        literals.add(message.value)
        clean = re.sub(rb'\x1b\[[0-9;?]*[ -/]*[@-~]', b'', buffer)
        units = set()
        for line in clean.splitlines():
            if b'fail' in line.lower() or b'timed out' in line.lower():
                units.update(match.decode() for match in re.findall(
                    rb'[A-Za-z0-9_@.\\-]+\.(?:service|mount|target|device|socket)', line))
        # Prompts consume the raw buffer, including initrd messages preceding
        # recovery enrollment. Keep only bounded, public diagnostic categories
        # across those prompts so a later failure retains its original cause.
        previous = self.observed_diagnostics
        flags = {name: present or previous.get('flags', {}).get(name, False)
                 for name, present in flags.items()}
        literals.update(previous.get('literal_errors', []))
        units.update(previous.get('failed_units', []))
        self.observed_diagnostics = {'flags': flags, 'literal_errors': sorted(literals)[:32],
                                     'failed_units': sorted(units)[:32]}
        return json.dumps({'flags':flags,'qmp_events':self.qmp_events[-16:], 'literal_errors':sorted(literals)[:32],
            'failed_units':sorted(units)[:32],'console_sha256':hashlib.sha256(buffer).hexdigest()},sort_keys=True)

    def ssh_arguments(self, command, *, agent=True, user='admin'):
        return ['ssh', '-F', '/dev/null']+(['-A'] if agent else [])+[
            '-i', str(self.secret/'ssh'), '-o', 'IdentitiesOnly=yes', '-o', 'BatchMode=yes',
            '-o', 'ConnectTimeout=5', '-o', 'StrictHostKeyChecking=accept-new',
            '-o', 'HostKeyAlias=lanrith-qualification',
            '-o', 'UserKnownHostsFile='+str(self.secret/'known-hosts'),
            '-p', str(self.port), user+'@127.0.0.1', command]

    def wait_shutdown(self, timeout=180):
        deadline = time.monotonic()+timeout
        while time.monotonic()<deadline and self.process.poll() is None:
            time.sleep(0.1)
        release.require(self.process.poll() is not None, 'Guest did not power off: '+self.diagnostic())

    def poweroff(self):
        request = self.ssh('sudo systemctl poweroff --no-block', success=False)
        release.require(request.returncode in (0, 255), 'Guest refused the orderly shutdown request.')
        self.wait_shutdown()
        self.close()

    def ssh(self, command, *, success=True, timeout=180, agent=True, user='admin'):
        result = subprocess.run(self.ssh_arguments(command, agent=agent, user=user), stdin=subprocess.DEVNULL,
                                capture_output=True, env=self.environment, timeout=timeout)
        if success:
            release.require(result.returncode == 0, 'Guest SSH operation failed: '+
                            result.stderr[-2048:].decode(errors='replace'))
        return result

    def ready(self, *, healthy=True, root_access=True):
        deadline = time.monotonic()+600
        while time.monotonic() < deadline:
            release.require(self.process.poll() is None, 'Guest exited before SSH became ready (status '+
                            str(self.process.returncode)+'): '+self.diagnostic())
            release.require(not re.search(rb'(?:You are in|Entering) emergency mode', self.buffer, re.IGNORECASE),
                            'Installed boot entered emergency mode: '+self.diagnostic())
            if healthy and root_access:
                command = 'sudo sh -c '+shlex.quote(
                    'test -s /run/lanrith/boot.json && lanrith-runtime health >/dev/null')
            elif healthy:
                command = 'test -s /run/lanrith/boot.json && lanrith-runtime status >/dev/null'
            else:
                command = 'sudo id -u' if root_access else 'id -u'
            try:
                if self.ssh(command, success=False, timeout=min(120, max(1, deadline-time.monotonic()))).returncode == 0:
                    return
            except subprocess.TimeoutExpired:
                # A first boot can finish recovery enrollment before sshd and
                # PAM are ready. Retry within the overall bounded boot window.
                pass
            time.sleep(2)
        raise release.ReleaseError('Guest did not pass its native health check over SSH: '+self.diagnostic())

    def close(self):
        stop(self.process)
        self.process = None
        if self.console:
            self.console.close()
        for client in (self.serial, self.qmp):
            if client:
                client.close()
        stop(self.tpm)
        self.tpm = None
        self.buffer = b''


def image(value, base, initrd, work, secret, sequence):
    assembly = work/('image-'+str(sequence))
    identity = build.assembly(value, base, assembly, version='0.1.0', sequence=sequence,
        certificate=secret/'test.crt', private_key=secret/'test.key',
        serial_hash=secret/'serial.hash' if value['administration']['serial']['enabled'] else None,
        initrd_base=initrd)
    build.run(assembly)
    update = work/('update-'+str(sequence))
    build.update_payload(assembly, identity, update)
    release.sign(update, secret/'test.key')
    release.verify(update, secret/'test.crt', purpose='update', image_id='lanrith')
    return assembly, identity, update


def factory_medium(assembly, identity, update, work, secret):
    output = work/'factory'
    manifest = build.factory_payload(assembly, identity, update, output)
    release.sign(output, secret/'test.key')
    release.verify(output, secret/'test.crt', purpose='factory', image_id='lanrith')
    source = output/next(item['name'] for item in manifest['artifacts'] if item['role'] == 'disk')
    target = work/'factory-medium.raw'
    shutil.copyfile(source, target)
    before = json.loads(run('sfdisk', '--json', str(source)))['partitiontable']
    payload_mib = (sum(path.stat().st_size for path in output.iterdir())+1024**2-1)//1024**2+256
    with target.open('r+b') as stream:
        stream.truncate(source.stat().st_size+(payload_mib+64)*1024**2)
    run('sfdisk', '--relocate', 'gpt-bak-std', str(target))
    definitions = work/'media-definitions'
    definitions.mkdir()
    (definitions/'90-payload.conf').write_text('[Partition]\nType=linux-generic\nLabel=lanrith-factory-media\n'+
        f'Format=ext4\nCopyFiles={output}:/release\nSizeMinBytes={payload_mib}M\nSizeMaxBytes={payload_mib}M\n')
    run('systemd-repart', '--empty=refuse', '--dry-run=no', '--offline=yes',
        '--definitions='+str(definitions), str(target), timeout=600)
    after = json.loads(run('sfdisk', '--json', str(target)))['partitiontable']
    parts, _ = media.partitions(before, after)
    with source.open('rb') as expected, target.open('rb') as observed:
        for part in parts:
            release.require(media.digest_range(expected, part['start']*512, part['size']*512) ==
                            media.digest_range(observed, part['start']*512, part['size']*512),
                            'Disposable factory media changed signed partition bytes.')
    return target


def upload(guest, directory):
    target = '/var/tmp/lanrith-update/'+directory.name
    guest.ssh('mkdir -m 0700 '+shlex.quote(target))
    with tempfile.TemporaryFile() as stream:
        with tarfile.open(fileobj=stream, mode='w') as archive:
            for path in sorted(directory.iterdir()):
                archive.add(path, arcname=path.name, recursive=False)
        stream.seek(0)
        result = subprocess.run(guest.ssh_arguments('tar -xf - -C '+shlex.quote(target), agent=False),
            stdin=stream, capture_output=True, env=guest.environment, timeout=600)
        release.require(result.returncode == 0, 'Qualification upload failed.')
    return target


def lease_snapshot(filename):
    """Read logical IPv4 leases in Kea's completed/previous/input/current order."""
    import csv
    import ipaddress
    from pathlib import Path
    import time

    path = Path(filename)
    completed, previous, pending = [Path(str(path)+suffix) for suffix in ('.completed', '.2', '.1')]
    paths = (completed, previous, pending, path)
    required = {'address', 'hwaddr', 'client_id', 'valid_lifetime', 'expire', 'subnet_id',
                'fqdn_fwd', 'fqdn_rev', 'hostname', 'state', 'user_context'}
    numeric = ('valid_lifetime', 'expire', 'subnet_id', 'fqdn_fwd', 'fqdn_rev', 'state', 'pool_id')

    def fingerprint():
        result = []
        for item in paths:
            if item.is_symlink():
                raise ValueError('Lease snapshot contains a linked file.')
            try:
                info = item.stat()
            except FileNotFoundError:
                continue
            result.append((item.name, info.st_ino, info.st_size, info.st_mtime_ns))
        return result

    # Cleanup atomically rotates these files. Compare only a stable generation.
    for attempt in range(20):
        before = fingerprint()
        leases = {}
        selected = [completed] if completed.exists() else [previous, pending]
        try:
            for item in [*selected, path]:
                if item != path and not item.exists():
                    continue
                with item.open(newline='') as stream:
                    rows = csv.DictReader(stream)
                    fields = rows.fieldnames or []
                    if len(fields) != len(set(fields)) or not required <= set(fields) or \
                            set(fields)-required-{'pool_id'}:
                        raise ValueError('Lease snapshot has an unsupported CSV header.')
                    for row in rows:
                        if None in row or any(value is None for value in row.values()):
                            raise ValueError('Lease snapshot has an incomplete row.')
                        row.setdefault('pool_id', '0')
                        row['address'] = str(ipaddress.IPv4Address(row['address']))
                        for field in numeric:
                            number = int(row[field])
                            if not 0 <= number <= 2**32-1:
                                raise ValueError('Lease snapshot has an invalid numeric field.')
                            row[field] = str(number)
                        if row['valid_lifetime'] == '0':
                            leases.pop(row['address'], None)
                        else:
                            leases[row['address']] = row
        except FileNotFoundError:
            pass
        else:
            if before == fingerprint():
                return leases
        time.sleep(0.1)
    raise ValueError('Lease files did not stabilize for persistence verification.')


STATE = '''set -eu
test "$(cat /etc/machine-id)" = 0123456789abcdef0123456789abcdef
test "$(findmnt -n -o FSTYPE /)" = erofs
findmnt -n -o OPTIONS / | tr , '\\n' | grep -qx ro
cryptsetup status "$(findmnt -n -o SOURCE /var)" | grep -q 'type:.*LUKS2'
sha256sum /var/lib/lanrith/ssh-host-keys/ssh_host_ed25519_key.pub \
  /var/lib/lanrith/qualification-state/credentials /var/lib/lanrith/qualification-state/enrollment
''' + "python3 - <<'PY'\n" + inspect.getsource(lease_snapshot) + '''
import json
print(json.dumps(lease_snapshot('/var/lib/kea/kea-leases4.csv'), sort_keys=True, separators=(',', ':')))
PY
journalctl --quiet --no-pager -t lanrith-qualification | grep -q synthetic-persistent-state
'''


def root(guest, script, **kwargs):
    return guest.ssh('sudo sh -c '+shlex.quote(script), **kwargs)


UNPRIVILEGED_PROBE = '''set -eu
deny() {
    if "$@" >/dev/null 2>&1; then
        exit 77
    fi
}
test "$(id -u)" -ne 0
awk '$1 == "CapEff:" && $2 ~ /^0+$/' /proc/self/status >/dev/null
deny sudo -k -n true
deny nft add table inet lanrith_unprivileged_probe
deny ip route add blackhole 198.18.0.0/15 table 500
deny sysctl -w kernel.kptr_restrict=0
probe=/var/tmp/lanrith-unprivileged-$(id -u)
mkdir -m 0700 "$probe"
deny mount -t tmpfs tmpfs "$probe"
rmdir "$probe"
deny systemctl --no-ask-password stop kea-dhcp4-server.service
deny systemd-run --quiet --wait /usr/bin/true
deny sh -c 'printf probe > /etc/lanrith-unprivileged-probe'
deny sh -c 'printf probe > /var/lib/lanrith/unprivileged-probe'
deny sh -c 'printf probe > /boot/lanrith-unprivileged-probe'
deny dd if=/dev/zero of=/dev/vda bs=1 count=0 status=none
deny lanrith-runtime accept 9
deny head -c 1 /etc/shadow
deny kill -TERM 1
'''


def unprivileged_control_boundary(guest):
    """Prove root-only control paths stay unavailable before elevation.

    This is intentionally not a claim that UID 0 is constrained after a
    successful administrative PAM/sudo transition. The VM is disposable; a
    surprising success fails qualification and the postconditions identify
    any partial mutation.
    """
    release.require(guest.ssh('id -u', user='root', agent=False, success=False).returncode != 0,
                    'Direct root SSH login succeeded.')
    administrator = guest.ssh('sh -c '+shlex.quote(UNPRIVILEGED_PROBE), agent=False, success=False)
    service_probe = '''set -eu
probe=%s
tested=0
for account in $(awk -F: '$3 != 0 && $1 != "admin" {print $1}' /etc/passwd); do
    uid=$(id -u "$account")
    gid=$(id -g "$account")
    setpriv --reuid "$uid" --regid "$gid" --clear-groups sh -c "$probe"
    tested=$((tested + 1))
done
test "$tested" -gt 0
''' % shlex.quote(UNPRIVILEGED_PROBE.replace('deny sudo -k -n true\n', ''))
    services = root(guest, service_probe, success=False)
    postconditions = root(guest, '''set -eu
test "$(sshd -T | awk '$1 == "permitrootlogin" {print $2}')" = no
test "$(sysctl -n kernel.kptr_restrict)" = 2
! nft list table inet lanrith_unprivileged_probe >/dev/null 2>&1
! ip route show table 500 | grep -q 198.18.0.0/15
! findmnt --list --noheadings --output TARGET | grep -q '^/var/tmp/lanrith-unprivileged-'
test ! -e /etc/lanrith-unprivileged-probe
test ! -e /var/lib/lanrith/unprivileged-probe
test ! -e /boot/lanrith-unprivileged-probe
systemctl is-active --quiet kea-dhcp4-server.service
python3 - <<'PY'
from pathlib import Path
import subprocess

# A compromised non-root process must not already hold capabilities that can
# administer policy, mount filesystems, bypass discretionary access, ptrace
# peers, change identity, load code into the kernel, or use privileged BPF.
# systemd-networkd is a declared network-control TCB identity rather than an
# unprivileged daemon. Its constrained process may hold only the capabilities
# required by the packaged unit, and must retain no-new-privileges and seccomp.
forbidden = sum(1 << bit for bit in (1, 2, 3, 6, 7, 12, 16, 17, 19, 21, 38, 39, 40))
networkd = int(subprocess.check_output(
    ['systemctl', 'show', '--property', 'MainPID', '--value', 'systemd-networkd.service'], text=True))
if networkd <= 0:
    raise SystemExit('The declared network-control TCB process is absent.')
properties = subprocess.check_output(['systemctl', 'show', '--property', 'NoNewPrivileges',
    '--property', 'SystemCallFilter', 'systemd-networkd.service'], text=True).splitlines()
if 'NoNewPrivileges=yes' not in properties or not any(line.startswith('SystemCallFilter=') and
                                                       line != 'SystemCallFilter=' for line in properties):
    raise SystemExit('The network-control TCB lost its execution restrictions.')
networkd_allowed = sum(1 << bit for bit in (10, 11, 12, 13, 21, 39))
allowed = {networkd: networkd_allowed}
seen = set()
for status in Path('/proc').glob('[0-9]*/status'):
    try:
        fields = {line.split(':', 1)[0]: line.split(':', 1)[1].strip()
                  for line in status.read_text().splitlines() if ':' in line}
        uid = int(fields['Uid'].split()[1])
        effective = int(fields['CapEff'], 16)
    except (FileNotFoundError, KeyError, ValueError, PermissionError):
        continue
    if uid != 0:
        seen.add(uid)
        permitted = allowed.get(int(status.parent.name), 0)
        if effective & forbidden & ~permitted or effective & ~permitted and permitted:
            raise SystemExit('A non-root process holds a root-equivalent capability.')
if not seen:
    raise SystemExit('No non-root process context was observed.')
PY
''', success=False)
    release.require(administrator.returncode == 0 and services.returncode == 0 and postconditions.returncode == 0,
                    'A non-root identity reached a root-only control path or changed its postcondition.')


def check_state(guest, expected, message):
    observed = root(guest, STATE).stdout
    labels = ('ssh-identity', 'credentials', 'enrollment', 'dhcp-leases')
    before, after = expected.splitlines(), observed.splitlines()
    changed = [label for index, label in enumerate(labels) if
               index >= len(before) or index >= len(after) or before[index] != after[index]]
    release.require(observed == expected, message+' Changed categories: '+', '.join(changed))


def boot(guest, *, manual=False, first=False, root_access=True):
    guest.start()
    def expect(pattern, answer):
        event = guest.expect_any([pattern, rb'(?:You are in|Entering) emergency mode'])
        release.require(event == 0, 'Installed initrd entered emergency mode: '+guest.last_diagnostic)
        guest.serial.sendall(answer.encode()+b'\r')
    if manual:
        if first:
            expect(rb'State encryption passphrase .*: ', PASSPHRASE)
            expect(rb'Repeat state encryption passphrase: ', PASSPHRASE)
        else:
            expect(rb'(?:Please enter passphrase|Please enter password|Password:).*', PASSPHRASE)
    if first:
        if manual:
            # Creating the LUKS volume and unlocking it for the root system
            # are separate operations. Recovery enrollment can ask again.
            for _ in range(8):
                event = guest.expect_any([rb'Type RECOVERY-KEY-STORED[^\r\n]*: ',
                    rb'Please enter (?:current )?(?:passphrase|password)[^\r\n]*: ?',
                    rb'(?:You are in|Entering) emergency mode'])
                release.require(event != 2, 'Installed initrd entered emergency mode: '+guest.last_diagnostic)
                if event == 0:
                    guest.serial.sendall(b'RECOVERY-KEY-STORED\r')
                    break
                guest.serial.sendall(PASSPHRASE.encode()+b'\r')
            else:
                raise release.ReleaseError('Manual state boot repeated too many unlock prompts.')
        else:
            expect(rb'Type RECOVERY-KEY-STORED.*: ', 'RECOVERY-KEY-STORED')
    guest.ready(root_access=root_access)


def network_hardening():
    """Check kernel policy independently of the generated sysctl assignments."""
    for family, options in (
        ('ipv4', {'accept_source_route': 0, 'accept_redirects': 0, 'secure_redirects': 0, 'send_redirects': 0}),
        ('ipv6', {'accept_source_route': -1, 'accept_redirects': 0}),
    ):
        for scope in (Path('/proc/sys/net')/family/'conf').iterdir():
            for option, expected in options.items():
                if (scope/option).read_text().strip() != str(expected):
                    raise AssertionError('Network hardening is not effective on every current/default interface.')
    for key, expected in {'ipv4/ip_forward': 1, 'ipv6/conf/all/forwarding': 1,
                          'ipv4/tcp_syncookies': 1, 'ipv4/icmp_echo_ignore_broadcasts': 1,
                          'ipv4/icmp_ignore_bogus_error_responses': 1}.items():
        if (Path('/proc/sys/net')/key).read_text().strip() != str(expected):
            raise AssertionError('Global routing hardening is not effective.')


def firewall_failure(guest):
    """Core listeners stop with nftables and cannot start if its activation fails."""
    # A transient unit survives the SSH listener it deliberately stops. Every
    # write is under /run in this disposable guest; restore before reconnecting.
    script = inspect.getsource(network_hardening)+'\n'+inspect.cleandoc('''
        import json
        from pathlib import Path
        import subprocess
        import time

        listeners = ['ssh.service', 'unbound.service', 'kea-dhcp4-server.service']
        override = Path('/run/systemd/system/nftables.service.d/90-qualification-failure.conf')
        receipt = Path('/run/lanrith/firewall-failure-qualification.json')

        def command(*arguments, check=True):
            return subprocess.run(['systemctl', *arguments], check=check,
                                  capture_output=True, timeout=40)

        def inactive():
            for unit in listeners:
                if command('is-active', '--quiet', unit, check=False).returncode == 0:
                    raise RuntimeError('A listener survived a missing firewall.')

        time.sleep(3)
        record = {'result': 'fail'}
        try:
            network_hardening()
            record['effective_kernel_hardening'] = True
            for unit in listeners:
                if command('is-active', '--quiet', unit, check=False).returncode != 0:
                    raise RuntimeError('A selected listener was inactive before the probe.')
            command('stop', 'nftables.service')
            inactive()
            record['stopped_with_firewall'] = True
            override.parent.mkdir(exist_ok=True)
            override.write_text('[Service]\\nExecStart=\\nExecStart=/usr/bin/false\\n')
            command('daemon-reload')
            if command('start', *listeners, check=False).returncode == 0:
                raise RuntimeError('Listener activation succeeded with a failing firewall.')
            if command('is-failed', '--quiet', 'nftables.service', check=False).returncode != 0:
                raise RuntimeError('The injected firewall failure did not occur.')
            inactive()
            record.update(result='pass', blocked_on_firewall_failure=True)
        finally:
            override.unlink(missing_ok=True)
            command('daemon-reload')
            command('reset-failed', check=False)
            command('start', 'nftables.service')
            command('start', *listeners)
            receipt.write_text(json.dumps(record, sort_keys=True)+'\\n')
        ''')
    print('Native VM: verifying listener shutdown and firewall-failure admission.', flush=True)
    root(guest, 'systemd-run --unit=lanrith-firewall-qualification --service-type=oneshot '+
         '--property=TimeoutStartSec=180 /usr/bin/python3 -c '+shlex.quote(script))
    deadline = time.monotonic()+240
    while time.monotonic() < deadline:
        result = guest.ssh('cat /run/lanrith/firewall-failure-qualification.json', success=False, timeout=15)
        if result.returncode == 0:
            record = json.loads(result.stdout)
            release.require(record == {'result': 'pass', 'stopped_with_firewall': True,
                                       'blocked_on_firewall_failure': True, 'effective_kernel_hardening': True},
                            'Core listeners did not enforce the firewall activation boundary.')
            guest.ready()
            return
        time.sleep(2)
    raise release.ReleaseError('Firewall-failure qualification did not restore healthy administration.')


def provisioning_failure(value, base, initrd, work, secret):
    """An error after creating valid encrypted state must remain in the initrd."""
    work.mkdir(mode=0o700)
    assembly = work/'image'
    build.assembly(value, base, assembly, version='0.1.0', sequence=12,
        certificate=secret/'test.crt', private_key=secret/'test.key',
        serial_hash=secret/'serial.hash', initrd_base=initrd)
    unit = assembly/'mkosi.images/initrd/mkosi.extra/usr/lib/systemd/system/lanrith-factory.service'
    with unit.open('a') as stream:
        stream.write('ExecStartPost=/usr/bin/false\n')
    build.run(assembly)
    disk = work/'installed.raw'
    shutil.copyfile(assembly/'output/lanrith_12.raw', disk)
    with disk.open('r+b') as stream:
        stream.truncate(40*1024**3)
    guest = Guest(work/'guest', secret, disk, tpm=True)
    print('Native VM: verifying a provisioning failure prevents switch-root.', flush=True)
    try:
        guest.start()
        event = guest.expect_any([rb'(?:You are in|Entering) emergency mode',
                                 rb'Type RECOVERY-KEY-STORED[^\r\n]*: '])
        release.require(event == 0, 'Failed provisioning reached root recovery enrollment.')
        # A failed target alone previously let the distribution's switch-root
        # service proceed. Observe beyond normal root startup, including sshd,
        # without authenticating or recording console payloads.
        deadline = time.monotonic()+180
        while time.monotonic() < deadline:
            release.require(guest.process.poll() is None and not guest.console.closed,
                            'Provisioning failure reset or stopped the guest.')
            release.require(b'RECOVERY-KEY-STORED' not in guest.buffer,
                            'Failed provisioning continued into the installed root.')
            try:
                with socket.create_connection(('127.0.0.1', guest.port), timeout=0.5) as client:
                    client.settimeout(0.5)
                    release.require(not client.recv(255).startswith(b'SSH-'),
                                    'Failed provisioning exposed installed SSH administration.')
            except OSError:
                pass
            time.sleep(1)
    finally:
        guest.close()
    table = json.loads(run('sfdisk', '--json', str(disk)))['partitiontable']
    state = [part for part in table['partitions'] if part['type'].lower() ==
             '4d21b016-b534-45c2-a9fb-5c16e091fd2d']
    release.require(len(table['partitions']) == 8 and len(state) == 1 and table['sectorsize'] == 512,
                    'The injected failure did not follow completed slot and state provisioning.')
    with disk.open('rb') as stream:
        stream.seek(state[0]['start']*512)
        release.require(stream.read(6) == b'LUKS\xba\xbe', 'The failure probe did not create encrypted state.')
    shutil.rmtree(work)
    print('Native VM: completed provisioning failed closed before switch-root.', flush=True)


def qualify(value, base, initrd, work, secret, *, manual=False):
    value['hardware']['boot']['tpm'] = 'disabled' if manual else 'required'
    assembly, identity, first = image(value, base, initrd, work, secret, 9)
    disk = work/'installed.raw'
    if manual:
        shutil.copyfile(assembly/'output/lanrith_9.raw', disk)
    else:
        with disk.open('xb'):
            pass
    with disk.open('r+b') as stream:
            stream.truncate(40*1024**3)
    medium = None if manual else factory_medium(assembly, identity, first, work, secret)
    guest = Guest(work/'guest', secret, disk, medium=medium, tpm=not manual)
    try:
        if medium:
            print('Native VM: booting the disposable factory installation medium.',flush=True)
            guest.start()
            event = guest.expect_any([rb'Type ERASE-AND-INSTALL .* to continue: ',
                                     rb'(?:You are in|Entering) emergency mode'])
            release.require(event == 0, 'Factory initrd entered emergency mode: '+guest.last_diagnostic)
            print('Native VM: confirmed the disposable installation target.',flush=True)
            guest.serial.sendall(b'ERASE-AND-INSTALL /dev/disk/by-id/virtio-lanrith-qa-disk\r')
            guest.expect(rb'Installation read-back passed')
            print('Native VM: signed factory installation read-back passed.',flush=True)
            guest.wait_shutdown()
            guest.close()
            guest.medium = None
        print('Native VM: booting the installed '+('manual' if manual else 'TPM2')+' state profile.',flush=True)
        boot(guest, manual=manual, first=True)
        if medium:
            medium.unlink()
            shutil.rmtree(work/'factory')
        shutil.rmtree(assembly)
        release.require(guest.ssh('sudo id -u', agent=False, success=False).returncode != 0,
                        'Root administration succeeded without the forwarded test agent.')
        guest.ssh('sudo lanrith-runtime accept 9')
        unprivileged_control_boundary(guest)
        root(guest, '''set -eu
mkdir -p /var/lib/lanrith/qualification-state /var/lib/kea
systemctl stop kea-dhcp4-server.service
printf 'address,hwaddr,client_id,valid_lifetime,expire,subnet_id,fqdn_fwd,fqdn_rev,hostname,state,user_context\\n192.168.10.123,02:00:00:00:02:01,,3600,4102444800,1,0,0,synthetic,0,\\n' > /var/lib/kea/kea-leases4.csv
printf synthetic-credential > /var/lib/lanrith/qualification-state/credentials
printf synthetic-enrollment > /var/lib/lanrith/qualification-state/enrollment
chmod 0600 /var/lib/lanrith/qualification-state/*
logger -t lanrith-qualification synthetic-persistent-state
journalctl --sync
systemctl start kea-dhcp4-server.service
''')
        guest.ready()
        state = root(guest, STATE).stdout
        leases = json.loads(state.splitlines()[3])
        release.require(leases == {'192.168.10.123': {
            'address': '192.168.10.123', 'hwaddr': '02:00:00:00:02:01', 'client_id': '',
            'valid_lifetime': '3600', 'expire': '4102444800', 'subnet_id': '1',
            'fqdn_fwd': '0', 'fqdn_rev': '0', 'hostname': 'synthetic', 'state': '0',
            'user_context': '', 'pool_id': '0'}},
            'Qualification did not seed the expected persistent DHCP lease.')
        print('Native VM: installed boot accepted and populated state verified.', flush=True)
        root(guest, '''for unit in frr.service freeradius.service suricata.service snmpd.service alloy.service \
chrony.service chronyd-restricted.service chrony-wait.service \
discovery-bridge.service discovery-bridge-collector.service discovery-bridge-publisher.service \
discovery-bridge-dns.service dpdk.service lanrith-policy-reader.service lanrith-policy-helper.service \
systemd-sysupdate.service systemd-sysupdate.timer systemd-sysupdate-reboot.service systemd-sysupdate-reboot.timer \
lanrith-policy-helper-requests.socket lanrith-policy-helper-status.socket lanrith-radius-runtime.service \
lanrith-vpp-service-attachment.service lanrith-nat64.service lanrith-nat64-internal.service lanrith-nat46.service; do
! systemctl is-active --quiet "$unit" || exit 1
done''')
        if manual:
            guest.poweroff()
            boot(guest, manual=True)
            check_state(guest, state, 'Manual encryption boot changed persistent state.')
            return {'profile': 'manual-encryption', 'result': 'pass', 'checks': [
                'secure-boot', 'dm-verity', 'manual-state-encryption', 'recovery-enrollment',
                'ssh-pam-administration', 'automatic-boot-observation',
                'persistent-state-reboot', 'optional-services-inactive', 'unprivileged-control-boundary']}
        firewall_failure(guest)
        second_assembly, _, second = image(value, base, initrd, work, secret, 10)
        shutil.rmtree(second_assembly)
        # This signed candidate keeps administration reachable but cannot pass
        # health: its additional required physical NIC does not exist in QEMU.
        failed_value = json.loads(json.dumps(value))
        failed_value['hardware']['interfaces']['absent'] = {'match': {'mac': '02:00:00:00:09:09'}}
        failed_value['networks']['absent'] = {'interface': 'absent', 'addresses': ['192.0.2.1/24'],
                                            'ra': False, 'dns': False}
        third_assembly, _, third = image(failed_value, base, initrd, work, secret, 11)
        shutil.rmtree(third_assembly)
        second_path, third_path = upload(guest, second), upload(guest, third)
        guest.ssh('sudo lanrith-runtime promote '+second_path, timeout=900)
        guest.close()
        boot(guest)
        release.require(json.loads(guest.ssh('lanrith-runtime status').stdout)['deployment_sequence'] == 10,
                        'One-shot update did not boot the new deployment.')
        check_state(guest, state, 'Update changed populated state or host identity.')
        rejected = guest.ssh('sudo lanrith-runtime promote '+third_path, success=False, timeout=900)
        release.require(rejected.returncode != 0 and b'Accept the running boot as default' in rejected.stderr,
                        'An unaccepted update could overwrite the last accepted fallback.')
        guest.close()
        boot(guest)
        release.require(json.loads(guest.ssh('lanrith-runtime status').stdout)['deployment_sequence'] == 9,
                        'Unaccepted one-shot boot replaced the accepted default.')
        guest.ssh('sudo bootctl set-oneshot lanrith_10.efi')
        guest.close()
        boot(guest)
        guest.ssh('sudo lanrith-runtime accept 10')
        replay = upload(guest, first)
        release.require(guest.ssh('sudo lanrith-runtime promote '+replay, success=False).returncode != 0,
                        'The installed updater accepted a replay.')
        root(guest, 'printf tampered >> '+third_path+'/release.json')
        release.require(guest.ssh('sudo lanrith-runtime promote '+third_path, success=False).returncode != 0,
                        'The installed updater accepted a tampered manifest.')
        guest.ssh('rm -rf -- '+third_path)
        third_path = upload(guest, third)
        # The admitted store must survive the earlier power cycles. Keep the
        # authorized foreground SSH session alive until the actual disk fault.
        root(guest, 'test -d /var/lib/lanrith/update-inbox/11')
        process = subprocess.Popen(guest.ssh_arguments(
            'sudo lanrith-runtime stage /var/lib/lanrith/update-inbox/11'),
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            env=guest.environment)
        deadline, interrupted = time.monotonic()+90, False
        try:
            while time.monotonic() < deadline:
                if process.poll() is not None:
                    _, errors = process.communicate(timeout=5)
                    raise release.ReleaseError('Staging exited before the inactive-slot fault: '+
                                               errors[-2048:].decode(errors='replace'))
                table = json.loads(root(guest, 'sfdisk --json /dev/vda').stdout)['partitiontable']['partitions']
                if any(part.get('name') == '_empty' for part in table):
                    # Discard guest RAM and stop every writer at the observed
                    # inactive-slot transaction, then boot the accepted image.
                    guest.close()
                    interrupted = True
                    break
                time.sleep(0.1)
        finally:
            stop(process)
        release.require(interrupted, 'Did not observe the inactive-slot write before interruption.')
        boot(guest)
        release.require(json.loads(guest.ssh('lanrith-runtime status').stdout)['deployment_sequence'] == 10,
                        'Accepted update did not persist.')
        check_state(guest, state, 'Interrupted staging changed populated state.')
        guest.ssh('sudo lanrith-runtime promote '+third_path, timeout=900)
        guest.close()
        guest.start()
        guest.ready(healthy=False)
        release.require(guest.ssh('sudo lanrith-runtime health', success=False).returncode != 0 and
                        not (json.loads(guest.ssh('lanrith-runtime status').stdout).get('boot') or {}).get('accepted'),
                        'A failed-health candidate was accepted.')
        guest.close()
        boot(guest)
        release.require(json.loads(guest.ssh('lanrith-runtime status').stdout)['deployment_sequence'] == 10,
                        'Failed candidate did not fall back to the accepted deployment.')
        check_state(guest, state, 'Failed candidate fallback changed populated state.')
        guest.close()
        # The accepted synthetic disk is no longer needed. Reclaim it before
        # constructing the independent provisioning-failure probe.
        disk.unlink()
        provisioning_failure(value, base, initrd, work/'provisioning-failure', secret)
        return {'profile': 'tpm2-ab', 'result': 'pass', 'checks': ['factory-install-readback',
            'secure-boot', 'dm-verity', 'tpm2-state-encryption', 'recovery-enrollment', 'ssh-pam-administration',
            'automatic-boot-observation',
            'optional-services-inactive', 'one-shot-upgrade', 'fallback-protection', 'unaccepted-reboot-fallback',
            'explicit-acceptance', 'replay-rejection', 'tamper-rejection', 'interrupted-staging',
            'failed-health-fallback', 'populated-state-upgrade-and-rollback',
            'initrd-provisioning-failure-boundary', 'firewall-listener-failure-boundary',
            'unprivileged-control-boundary']}
    finally:
        guest.close()


def qualify_rootless(value, base, initrd, work, secret):
    """Boot the actual no-root image and prove every general elevation route is absent."""
    value = json.loads(json.dumps(value))
    value['hardware']['boot']['tpm'] = 'required'
    value['administration']['root_access'] = 'disabled'
    value['administration']['serial'] = {'enabled': False}
    assembly, _, _ = image(value, base, initrd, work, secret, 20)
    disk = work/'installed.raw'
    shutil.copyfile(assembly/'output/lanrith_20.raw', disk)
    with disk.open('r+b') as stream:
        stream.truncate(40*1024**3)
    guest = Guest(work/'guest', secret, disk, tpm=True)
    try:
        print('Native VM: booting the rootless-administration profile.', flush=True)
        boot(guest, first=True, root_access=False)
        release.require(guest.ssh('id -u', user='root', agent=False, success=False).returncode != 0,
                        'Rootless image accepted direct root SSH login.')
        probe = r'''set -eu
test "$(id -u)" -ne 0
! id -nG | tr ' ' '\n' | grep -qx sudo
test "$(awk -F: '$1 == "root" {print $7}' /etc/passwd)" = /usr/sbin/nologin
for path in /usr/bin/sudo /usr/bin/sudoedit /usr/bin/su /bin/su /etc/sudoers /etc/sudoers.d \
  /etc/pam.d/sudo /etc/pam.d/sudo-i /etc/pam.d/su /etc/pam.d/su-l \
  /etc/security/authorized_keys /etc/security/admin.serial-passphrase.hash /root/.ssh; do
    test ! -e "$path" && test ! -L "$path"
done
test ! -S "${SSH_AUTH_SOCK:-/nonexistent}"
grep -qx 'AllowAgentForwarding no' /etc/ssh/sshd_config.d/00-lanrith.conf
! find /usr /bin /sbin -xdev -type f -perm /6000 -print -quit | grep -q .
python3 - <<'PY'
import os
from pathlib import Path
for root in ('/usr', '/bin', '/sbin'):
    for path in Path(root).rglob('*'):
        if path.is_file() and not path.is_symlink() and \
                'security.capability' in os.listxattr(path, follow_symlinks=False):
            raise SystemExit('file capability remains: '+str(path))
PY
for command in 'sudo -n id' 'sudoedit /etc/hostname' 'su -c id' \
  'systemd-run --quiet --wait /usr/bin/id' 'systemctl restart ssh.service' \
  'lanrith-runtime accept 20'; do
    if sh -c "$command" >/dev/null 2>&1; then exit 77; fi
done
test ! -e /etc/lanrith/config.yaml
! find /usr/share/lanrith /usr/lib/lanrith -type f \( -name '*.yaml' -o -name '*.yml' \) -print -quit | grep -q .
lanrith-runtime status >/dev/null
mkdir -m 0700 /var/tmp/lanrith-update/rootless-upload-probe
rmdir /var/tmp/lanrith-update/rootless-upload-probe
'''
        result = guest.ssh('sh -c '+shlex.quote(probe), success=False)
        release.require(result.returncode == 0,
                        'Rootless administration retained a login or elevation path: '+
                        result.stderr[-2048:].decode(errors='replace'))
        print('Native VM: no-root login, sudo, su, privileged-file or source-YAML path remains.', flush=True)
        return {'profile': 'rootless-administration', 'result': 'pass', 'checks': [
            'secure-boot', 'dm-verity', 'tpm2-state-encryption', 'recovery-enrollment',
            'automatic-boot-observation', 'unprivileged-ssh-administration', 'root-login-absent',
            'elevation-tools-absent', 'privileged-file-paths-absent', 'source-configuration-absent',
            'unprivileged-upload-staging']}
    finally:
        guest.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--base', type=Path, required=True)
    parser.add_argument('--initrd-base', type=Path, required=True)
    parser.add_argument('--work', type=Path, required=True)
    parser.add_argument('--result', type=Path, required=True)
    args = parser.parse_args()
    base, initrd, work = regular(args.base), regular(args.initrd_base), args.work
    release.require(work.is_absolute() and work.parent.resolve() == work.parent and not work.exists(),
                    'VM qualification requires a new workspace; existing disks are never adopted.')
    work.mkdir(mode=0o700)
    value = config.load(PROJECT/'examples/minimal.yaml')
    value['hardware']['storage'] = {'root_mib': 6144, 'state_mib': 16384, 'esp_mib': 512,
                                   'target': '/dev/disk/by-id/virtio-lanrith-qa-disk'}
    value['hardware']['boot'] = {'secure_boot': True, 'console': 'ttyS0,115200n8', 'recovery_console': 'ttyS0'}
    value['administration']['serial'] = {'enabled': True, 'tty': 'ttyS0'}
    report = {'schema': 1, 'result': 'fail', 'test': 'x86-64-uefi-factory-ab', 'profiles': [],
        'filesystem_sha256': release.file_record(base)['sha256'], 'initrd_sha256': release.file_record(initrd)['sha256'],
        'source_sha256': release.file_record(Path(__file__))['sha256']}
    try:
        with ExitStack() as resources:
            secret = Path(resources.enter_context(tempfile.TemporaryDirectory(prefix='lanrith-vm-authority.', dir='/dev/shm')))
            run('openssl', 'req', '-x509', '-newkey', 'rsa:3072', '-nodes', '-days', '1',
                '-subj', '/CN=Lanrith Disposable VM Qualification Authority',
                '-keyout', str(secret/'test.key'), '-out', str(secret/'test.crt'))
            (secret/'test.key').chmod(0o600)
            run('ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-f', str(secret/'ssh'))
            value['administration']['authorized_keys'] = [(secret/'ssh.pub').read_text().strip()]
            salt = os.urandom(16)
            hashed = hashlib.scrypt(b'disposable-qualification-serial-passphrase', salt=salt,
                                    n=32768, r=8, p=1, dklen=32, maxmem=64*1024*1024)
            (secret/'serial.hash').write_text('scrypt:32768:8:1:'+salt.hex()+':'+hashed.hex()+'\n')
            (secret/'serial.hash').chmod(0o600)
            agent = subprocess.Popen(['ssh-agent', '-D', '-a', str(secret/'agent.sock')],
                stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            resources.callback(stop, agent)
            deadline = time.monotonic()+15
            while not (secret/'agent.sock').exists() and time.monotonic() < deadline:
                time.sleep(0.1)
            run('ssh-add', str(secret/'ssh'), env={**os.environ, 'SSH_AUTH_SOCK': str(secret/'agent.sock')})
            for name, manual in (('tpm2', False), ('manual', True)):
                profile = work/name
                profile.mkdir(mode=0o700)
                (secret/'known-hosts').unlink(missing_ok=True)
                report['profiles'].append(qualify(value, base, initrd, profile, secret, manual=manual))
                print('Native VM profile '+name+' passed.', flush=True)
                shutil.rmtree(profile)
            profile = work/'rootless'
            profile.mkdir(mode=0o700)
            (secret/'known-hosts').unlink(missing_ok=True)
            report['profiles'].append(qualify_rootless(value, base, initrd, profile, secret))
            print('Native VM profile rootless passed.', flush=True)
            shutil.rmtree(profile)
        report['result'] = 'pass'
    finally:
        report['assessed_at'] = datetime.datetime.now(datetime.timezone.utc).isoformat()
        args.result.write_bytes(release.canonical(report))
    print('Real UEFI factory, encrypted-state and A/B qualification passed.')


if __name__ == '__main__':
    main()
