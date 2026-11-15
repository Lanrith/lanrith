#!/usr/bin/env python3
"""Test real VGA keyboard and UART provisioning without disks, networking or keys.

This direct-kernel drill qualifies terminal behavior, not Secure Boot or storage.
The signed factory/A/B profiles in vm.py cover those separate boundaries.
"""

import argparse
import copy
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import tarfile
import tempfile
import time

from lanrith.release import canonical, file_record, require


PROJECT = Path(__file__).resolve().parents[1]
PROBE = r'''
import getpass,json,os,sys,termios
from pathlib import Path
sys.path.insert(0,'/usr/lib/lanrith')
from lanrith.factory_console import Consoles, require_physical_input
installed={'boot':{'console':'tty0','recovery_console':'ttyS0'}}
report=open('/dev/ttyS1','w',buffering=1)
def note(**value):
    report.write('LANRITH-CONSOLE-QA '+json.dumps(value)+'\n')
def private():
    require_physical_input(installed)
    print('SYNTHETIC-PRIVATE-MATERIAL',flush=True)
    assert getpass.getpass('Private input: ') == 'synthetic-passphrase'
try:
    with Consoles(installed) as console:
        console.write('VM-DISK-CHOICES synthetic-disk\n')
        assert b'VM-DISK-CHOICES' in Path('/dev/vcs1').read_bytes()
        note(stage='choices',monitor_visible=True)
        selected=console.input('Select synthetic disk: ')
        assert selected == 'synthetic-disk'
        assert console.input('Confirm synthetic disk: ') == 'confirm-synthetic'
        console.private(private)
        owner=console.devices[console.owner][0]
        visible=b'SYNTHETIC-PRIVATE-MATERIAL' in Path('/dev/vcs1').read_bytes()
        assert visible == (owner == '/dev/tty1')
        console.write('VM-PUBLIC-COMPLETE\n')
        note(result='pass',owner=owner,private_monitor_visible=visible)
except BaseException as error:
    trace=error.__traceback__
    while trace.tb_next:
        trace=trace.tb_next
    note(result='fail',category=type(error).__name__,file=Path(trace.tb_frame.f_code.co_filename).name,
         line=trace.tb_lineno)
'''


def prepare(base, initrd, work):
    root = work/'root'
    root.mkdir()
    # Convert the admitted base's absolute symlinks to equivalent in-tree
    # relative links before using Python's traversal-safe extraction filter.
    def confined(member, destination):
        member = copy.copy(member)
        if member.issym() and member.linkname.startswith('/'):
            parent = root/Path(member.name).parent
            member.linkname = os.path.relpath(root/member.linkname.lstrip('/'), parent)
        return tarfile.data_filter(member, destination)
    with tarfile.open(initrd) as archive:
        archive.extractall(root, filter=confined)
    with tarfile.open(base) as archive:
        kernels = [item for item in archive.getmembers()
                   if item.isfile() and item.name.startswith('./usr/lib/modules/') and item.name.endswith('/vmlinuz')]
        require(len(kernels) == 1, 'Expected one kernel in the admitted base.')
        (work/'vmlinuz').write_bytes(archive.extractfile(kernels[0]).read())
        modules = [item for item in archive.getmembers() if item.name.startswith('./usr/lib/modules/')]
        archive.extractall(root, members=modules, filter=confined)
    library = root/'usr/lib/lanrith/lanrith'
    library.mkdir(parents=True)
    for name in ('__init__.py', 'factory_console.py', 'release.py'):
        shutil.copyfile(PROJECT/'lanrith'/name, library/name)
    (root/'probe.py').write_text(PROBE)
    (root/'qa-init').write_text('#!/bin/sh\n'
        'mount -t proc proc /proc\nmount -t sysfs sysfs /sys\nmount -t devtmpfs devtmpfs /dev\n'
        'mkdir -p /dev/pts /run\nmount -t devpts devpts /dev/pts\n'
        'modprobe atkbd\nmodprobe i8042\n'
        'python3 /probe.py\npoweroff -f\n')
    (root/'qa-init').chmod(0o755)
    names = [b'.']+[os.fsencode(str(path.relative_to(root))) for path in root.rglob('*')]
    with (work/'initrd').open('wb') as output:
        subprocess.run(['cpio', '--null', '-o', '--format=newc', '--quiet', '--owner=0:0'], cwd=root,
                       input=b'\0'.join(names)+b'\0', stdout=output, check=True)
    shutil.rmtree(root)


def connect(path, process):
    deadline = time.monotonic()+20
    while time.monotonic() < deadline:
        client = socket.socket(socket.AF_UNIX)
        try:
            client.connect(os.path.relpath(path))
            client.settimeout(0.5)
            return client
        except OSError:
            client.close()
            require(process.poll() is None, 'Console VM stopped during startup.')
            time.sleep(0.1)
    raise RuntimeError('Console VM socket did not appear.')


def run_profile(work, owner):
    profile = work/owner
    profile.mkdir()
    args = ['qemu-system-x86_64', '-accel', 'tcg', '-m', '1024', '-smp', '2', '-display', 'none', '-nic', 'none',
            '-no-reboot', '-kernel', str((work/'vmlinuz').resolve()), '-initrd', str((work/'initrd').resolve()),
            '-append', 'rdinit=/qa-init console=tty0 quiet panic=-1',
            '-qmp', 'unix:qmp,server=on,wait=off',
            '-serial', 'unix:serial,server=on,wait=off',
            '-serial', 'unix:report,server=on,wait=off']
    with (profile/'qemu.stderr').open('wb') as errors:
        process = subprocess.Popen(args, cwd=profile, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=errors)
    sockets = []
    qmp_file = None
    try:
        qmp, serial, report = [connect(profile/name, process) for name in ('qmp', 'serial', 'report')]
        sockets += [qmp, serial, report]
        qmp_file = qmp.makefile('rb')
        qmp.settimeout(10)
        json.loads(qmp_file.readline())
        def control(command, arguments=None):
            qmp.sendall(json.dumps({'execute': command, 'arguments': arguments or {}}).encode()+b'\n')
            while True:
                result = json.loads(qmp_file.readline())
                require('error' not in result, 'QEMU console control failed.')
                if 'return' in result:
                    return
        control('qmp_capabilities')
        buffers = {serial: b'', report: b''}
        readers = set(buffers)
        def expect(client, marker, timeout=120):
            deadline = time.monotonic()+timeout
            while marker not in buffers[client] and time.monotonic() < deadline:
                import select
                for source in select.select(list(readers), [], [], 0.2)[0]:
                    data = source.recv(65536)
                    if data:
                        buffers[source] += data
                    else:
                        readers.remove(source)
                if marker in buffers[client]:
                    return
                require(readers and process.poll() is None,
                        'Console VM exited before the expected event. Report: '+buffers[report].decode(errors='replace'))
            require(marker in buffers[client], 'Console VM event timed out: '+marker.decode())
        def enter(text):
            if owner == 'serial':
                serial.sendall(text.encode()+b'\r')
            else:
                for character in text+'\n':
                    key = {'-': 'minus', '\n': 'ret'}.get(character, character)
                    control('human-monitor-command', {'command-line': 'sendkey '+key+' 10'})
                    time.sleep(0.025)
        expect(report, b'"monitor_visible": true')
        expect(serial, b'Select synthetic disk: ')
        enter('synthetic-disk')
        expect(serial, b'Confirm synthetic disk: ')
        enter('confirm-synthetic')
        expect(serial, b'Private provisioning continues only')
        if owner == 'serial':
            expect(serial, b'Private input: ')
        else:
            # The VGA private prompt is deliberately absent from serial output.
            time.sleep(1)
        enter('synthetic-passphrase')
        expected = '/dev/ttyS0' if owner == 'serial' else '/dev/tty1'
        expect(report, json.dumps({'result': 'pass', 'owner': expected,
                                  'private_monitor_visible': owner == 'monitor'}).encode())
        require(json.dumps(expected).encode() in buffers[report], 'The wrong physical console owned provisioning.')
        require((b'SYNTHETIC-PRIVATE-MATERIAL' in buffers[serial]) == (owner == 'serial'),
                'Private output crossed physical consoles.')
        require(b'synthetic-passphrase' not in buffers[serial], 'Secret input was echoed.')
        qmp_file.close()
        return {'owner': owner, 'result': 'pass', 'choices_visible_on_monitor_and_serial': True,
                'private_output_on_selected_console_only': True}
    finally:
        if qmp_file is not None:
            qmp_file.close()
        for client in sockets:
            client.close()
        if process.poll() is None:
            process.terminate()
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--base', type=Path, required=True)
    parser.add_argument('--initrd-base', type=Path, required=True)
    parser.add_argument('--work-parent', type=Path, required=True)
    parser.add_argument('--result', type=Path, required=True)
    args = parser.parse_args()
    record = {'schema': 1, 'scope': 'physical-console-drivers-only', 'result': 'fail', 'profiles': [],
              'source_sha256': file_record(PROJECT/'lanrith/factory_console.py')['sha256']}
    try:
        with tempfile.TemporaryDirectory(prefix='console-vm-', dir=args.work_parent) as directory:
            work = Path(directory)
            prepare(args.base, args.initrd_base, work)
            for owner in ('serial', 'monitor'):
                record['profiles'].append(run_profile(work, owner))
                print('Real VGA/UART '+owner+' console qualification passed.', flush=True)
        record['result'] = 'pass'
    finally:
        args.result.write_bytes(canonical(record))


if __name__ == '__main__':
    main()
