"""Interrupt an ESP write in a systemd guest using a temporary loop-backed GPT."""

import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from lanrith import image_operation as operation, release, runtime, update


def run(*args, **kwargs):
    return subprocess.run(args, check=True, text=True, capture_output=True, **kwargs).stdout.strip()


def worker(root, action):
    value = operation.policy(root/'installed.json')
    esp = Path(value['esp'])
    stable = esp/'EFI/Linux'/value['uki_name']
    disk = (root/'device').read_text()
    variable = root/'oneshot'
    actual_command = update.command

    def command(args, **options):
        if args == ['bootctl', '--print-stub-path']:
            return str(stable)
        if args == ['bootctl', '--json=short', 'list']:
            return json.dumps([{'type': 'type2', 'source': 'esp', 'path': str(stable), 'id': stable.name}])
        if args == ['bootctl', 'set-oneshot', stable.name]:
            variable.write_bytes(bytes(4) + (stable.name+'\0').encode('utf-16-le'))
            return ''
        return actual_command(args, **options)

    def verified_disk():
        observed = run('losetup', '--noheadings', '--output', 'BACK-FILE', disk)
        assert Path(observed) == root/'disk.raw'
        return disk, {2}

    with patch.object(update, 'root_disk', verified_disk), patch.object(update, 'command', command), \
            patch.object(operation, 'command', command), patch.object(runtime, 'BOOT_OBSERVATION', root/'boot.json'), \
            patch.object(operation, 'require_default', lambda entry: update.require_default(entry, root/'default')), \
            patch.object(operation, 'select_boot_once', lambda entry: update.select_boot_once(entry, variable=variable)):
        if action == 'cancel':
            operation.cancel_request(root/'installed.json')
            return
        with operation.admission_lock(root/'installed.json'):
            candidate = operation.identity({**value, 'deployment_sequence': 11, 'uki_name': 'lanrith_11.efi'})
            operation.save(value, {'schema': 1, 'phase': 'staging', 'executor_id': os.environ['INVOCATION_ID'],
                                  'digest': 'f'*64, 'candidate': candidate, 'fallback': operation.identity(value),
                                  'error': None})
            with update.writable_esp(value):
                (root/'worker-writable').touch()
                signal.pause()


def exercise():
    assert os.getuid() == 0 and run('systemd-detect-virt', '--vm') in ('qemu', 'kvm')
    with tempfile.TemporaryDirectory(dir='/run') as temporary:
        root = Path(temporary)
        raw = root/'disk.raw'
        with raw.open('xb') as stream:
            stream.truncate(64*1024**2)
        run('sfdisk', str(raw), input='label: gpt\nsize=32MiB,type=U\ntype=L\n')
        run('modprobe', 'loop')
        disk = run('losetup', '--find', '--show', '--partscan', str(raw))
        esp = root/'esp'
        esp.mkdir()
        try:
            run('udevadm', 'settle')
            partitions = update.geometry(disk)
            first, = [row for row in partitions if row['number'] == 1 and
                      row['type'] == 'c12a7328-f81f-11d2-ba4b-00a0c93ec93b']
            (root/'device').write_text(disk)
            run('mkfs.vfat', first['device'])
            run('mount', '-o', 'nodev,nosuid,noexec,umask=0077', first['device'], str(esp))
            try:
                tree = esp/'EFI/Linux'
                tree.mkdir(parents=True)
                stable = tree/'lanrith_10.efi'
                stable.write_bytes(b'synthetic predecessor')
                run('mount', '-o', 'remount,ro,nodev,nosuid,noexec', str(esp))
                value = {'image_id': 'lanrith', 'update_image_id': 'lanrith', 'deployment_sequence': 10,
                         'uki_name': stable.name, 'configuration_sha256': 'a'*64, 'platform_version': '0.1.0',
                         'esp': str(esp), 'state_directory': str(root/'state'), 'operator': 'operator'}
                (root/'installed.json').write_bytes(release.canonical(value))
                operation.save_accepted(value)
                with patch.object(runtime, 'BOOT_OBSERVATION', root/'boot.json'):
                    runtime.publish_boot(value, stable, accepted=True)
                (root/'default').write_bytes(bytes(4) + (stable.name+'\0').encode('utf-16-le'))
                run('systemd-tmpfiles', '--create', '-', input='d /run/lanrith-image-locks 0700 root root -\n')
                script = str(Path(__file__).resolve())
                for ending in ('KILL', 'TERM'):
                    (root/'worker-writable').unlink(missing_ok=True)
                    (root/'oneshot').write_bytes(bytes(4) + ('lanrith_11.efi\0').encode('utf-16-le'))
                    unit = 'lanrith-esp-interruption-'+ending.lower()+'.service'
                    command = '/usr/bin/python3 '+script+' '+str(root)
                    run('systemd-run', '--unit='+unit, '--property=Type=exec',
                        '--property=ExecStopPost='+command+' cancel', '/usr/bin/python3', script, str(root), 'stage')
                    deadline = time.monotonic()+20
                    while not (root/'worker-writable').exists() and time.monotonic() < deadline:
                        time.sleep(0.1)
                    assert (root/'worker-writable').exists(), run('journalctl', '-u', unit, '--no-pager')
                    def flags():
                        return set(run('findmnt', '--noheadings', '--output', 'OPTIONS', '--target', str(tree)).split(','))
                    assert {'rw', 'nodev', 'nosuid', 'noexec'} <= flags()
                    pending = operation.load(value)
                    assert pending['phase'] == 'staging'
                    try:
                        with operation.operation_lock():
                            raise AssertionError('Staging did not own the admission lock')
                    except release.ReleaseError as error:
                        assert 'already running' in str(error)
                    if ending == 'KILL':
                        run('systemctl', 'kill', '--kill-whom=main', '--signal=KILL', unit)
                    else:
                        run('systemctl', 'stop', unit)
                    deadline = time.monotonic()+30
                    while operation.load(value)['phase'] == 'staging' and time.monotonic() < deadline:
                        time.sleep(0.1)
                    result = operation.load(value)
                    assert result == {**pending, 'phase': 'failed', 'error': 'admission-or-staging-failed'}, run(
                        'journalctl', '-u', unit, '--no-pager')
                    assert {'ro', 'nodev', 'nosuid', 'noexec'} <= flags()
                    assert (root/'oneshot').read_bytes() == (root/'default').read_bytes()
                    with patch.object(runtime, 'BOOT_OBSERVATION', root/'boot.json'), operation.admission_lock(root/'installed.json'):
                        assert update.boot_esp(value, disk=disk) == esp
                    print(ending, 'stopped staging 11 from accepted 10, restored', first['device'], 'GPT', first['uuid'],
                          'read-only. Accepted default and one-shot match, next admission acquired the lock.')
            finally:
                run('umount', str(esp))
        finally:
            run('losetup', '--detach', disk)


if __name__ == '__main__':
    if sys.argv[1:] == ['--systemd']:
        exercise()
    elif len(sys.argv) == 3 and sys.argv[2] in ('stage', 'cancel'):
        worker(Path(sys.argv[1]), sys.argv[2])
    else:
        raise SystemExit('Use --systemd in the disposable qualification guest.')
