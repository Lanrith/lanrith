#!/usr/bin/env python3
"""Qualify real UEFI boots and A/B updates using disposable regular-file disks."""

import argparse
import ast
from contextlib import ExitStack
import datetime
import hashlib
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

    def ssh_arguments(self, command, *, agent=True):
        return ['ssh', '-F', '/dev/null']+(['-A'] if agent else [])+[
            '-i', str(self.secret/'ssh'), '-o', 'IdentitiesOnly=yes', '-o', 'BatchMode=yes',
            '-o', 'ConnectTimeout=5', '-o', 'StrictHostKeyChecking=accept-new',
            '-o', 'HostKeyAlias=lanrith-qualification',
            '-o', 'UserKnownHostsFile='+str(self.secret/'known-hosts'),
            '-p', str(self.port), 'admin@127.0.0.1', command]

    def wait_shutdown(self, timeout=180):
        deadline = time.monotonic()+timeout
        while time.monotonic()<deadline and self.process.poll() is None:
            time.sleep(0.1)
        release.require(self.process.poll() is not None, 'Factory VM did not power off: '+self.diagnostic())

    def ssh(self, command, *, success=True, timeout=180, agent=True):
        result = subprocess.run(self.ssh_arguments(command, agent=agent), stdin=subprocess.DEVNULL,
                                capture_output=True, env=self.environment, timeout=timeout)
        if success:
            release.require(result.returncode == 0, 'Guest SSH operation failed: '+
                            result.stderr[-2048:].decode(errors='replace'))
        return result

    def ready(self, *, healthy=True):
        deadline = time.monotonic()+600
        while time.monotonic() < deadline:
            release.require(self.process.poll() is None, 'Guest exited before SSH became ready (status '+
                            str(self.process.returncode)+'): '+self.diagnostic())
            release.require(not re.search(rb'(?:You are in|Entering) emergency mode', self.buffer, re.IGNORECASE),
                            'Installed boot entered emergency mode: '+self.diagnostic())
            command = ('sudo sh -c '+shlex.quote(
                'test -s /run/lanrith/boot.json && lanrith-runtime health >/dev/null')
                if healthy else 'sudo id -u')
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
        certificate=secret/'test.crt', private_key=secret/'test.key', serial_hash=secret/'serial.hash', initrd_base=initrd)
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


STATE = '''set -eu
test "$(cat /etc/machine-id)" = 0123456789abcdef0123456789abcdef
test "$(findmnt -n -o FSTYPE /)" = erofs
findmnt -n -o OPTIONS / | tr , '\\n' | grep -qx ro
cryptsetup status "$(findmnt -n -o SOURCE /var)" | grep -q 'type:.*LUKS2'
sha256sum /var/lib/lanrith/ssh-host-keys/ssh_host_ed25519_key.pub /var/lib/kea/kea-leases4.csv \
  /var/lib/lanrith/qualification-state/credentials /var/lib/lanrith/qualification-state/enrollment
journalctl --quiet --no-pager -t lanrith-qualification | grep -q synthetic-persistent-state
'''


def root(guest, script, **kwargs):
    return guest.ssh('sudo sh -c '+shlex.quote(script), **kwargs)


def boot(guest, *, manual=False, first=False):
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
    guest.ready()


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
        root(guest, '''set -eu
mkdir -p /var/lib/lanrith/qualification-state /var/lib/kea
printf 'address,hwaddr,client_id,valid_lifetime,expire,subnet_id,fqdn_fwd,fqdn_rev,hostname,state,user_context\\n192.168.10.123,02:00:00:00:02:01,,3600,4102444800,1,0,0,synthetic,0,\\n' > /var/lib/kea/kea-leases4.csv
printf synthetic-credential > /var/lib/lanrith/qualification-state/credentials
printf synthetic-enrollment > /var/lib/lanrith/qualification-state/enrollment
chmod 0600 /var/lib/lanrith/qualification-state/*
logger -t lanrith-qualification synthetic-persistent-state
journalctl --sync
''')
        state = root(guest, STATE).stdout
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
            guest.close()
            boot(guest, manual=True)
            release.require(root(guest, STATE).stdout == state, 'Manual encryption boot changed persistent state.')
            return {'profile': 'manual-encryption', 'result': 'pass', 'checks': [
                'secure-boot', 'dm-verity', 'manual-state-encryption', 'recovery-enrollment',
                'ssh-pam-administration', 'automatic-boot-observation',
                'persistent-state-reboot', 'optional-services-inactive']}
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
        release.require(root(guest, STATE).stdout == state, 'Update changed populated state or host identity.')
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
        # A previously authenticated root-owned inbox was retained after the
        # unaccepted-slot rejection. Interrupt the actual sysupdate write after
        # it relabels an inactive partition, rather than killing an upload copy.
        process = int(root(guest, 'setsid lanrith-runtime stage /var/lib/lanrith/update-inbox/11 '
            '>/var/tmp/lanrith-qualification-stage.log 2>&1 </dev/null & echo $!').stdout)
        release.require(process > 1, 'Invalid disposable update process.')
        deadline, interrupted = time.monotonic()+90, False
        while time.monotonic() < deadline:
            table = json.loads(root(guest, 'sfdisk --json /dev/vda').stdout)['partitiontable']['partitions']
            if any(part.get('name') == '_empty' for part in table):
                root(guest, 'kill -KILL -- -'+str(process))
                interrupted = True
                break
            time.sleep(0.1)
        release.require(interrupted, 'Did not observe the inactive-slot write before interruption.')
        guest.close()
        boot(guest)
        release.require(json.loads(guest.ssh('lanrith-runtime status').stdout)['deployment_sequence'] == 10 and
                        root(guest, STATE).stdout == state, 'Accepted update or populated state did not persist.')
        guest.ssh('sudo lanrith-runtime promote '+third_path, timeout=900)
        guest.close()
        guest.start()
        guest.ready(healthy=False)
        release.require(guest.ssh('sudo lanrith-runtime health', success=False).returncode != 0 and
                        not (json.loads(guest.ssh('lanrith-runtime status').stdout).get('boot') or {}).get('accepted'),
                        'A failed-health candidate was accepted.')
        guest.close()
        boot(guest)
        release.require(json.loads(guest.ssh('lanrith-runtime status').stdout)['deployment_sequence'] == 10 and
                        root(guest, STATE).stdout == state, 'Failed candidate did not fall back with populated state intact.')
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
            'initrd-provisioning-failure-boundary']}
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
        report['result'] = 'pass'
    finally:
        report['assessed_at'] = datetime.datetime.now(datetime.timezone.utc).isoformat()
        args.result.write_bytes(release.canonical(report))
    print('Real UEFI factory, encrypted-state and A/B qualification passed.')


if __name__ == '__main__':
    main()
