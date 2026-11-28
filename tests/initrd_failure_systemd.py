"""Exercise initrd verification deadlines across real systemd service processes in a disposable guest."""
from contextlib import ExitStack
import hashlib
import json
import os
from pathlib import Path
import select
import subprocess
import sys
import tempfile
import time
from unittest.mock import patch

from lanrith import early_failure, factory, recovery_console, recovery_failure_console, release, repair, tpm_migration


def child(directory, action):
    factory.ATTEMPT_DIRECTORY = directory
    factory.FAILURE_IDENTITY = directory/'identity.json'
    early_failure.EFI_VARIABLES = directory
    if action == 'media':
        recovery_console.POLICY = directory/'media-policy'
        recovery_console.CREDENTIAL = directory/'media-hash'
        with patch.object(factory, 'secure_boot'), patch.object(factory, 'verified_root'):
            return recovery_console.main()
    mode = (directory/'mode').read_text()

    def inspect(_):
        with (directory/'inspections').open('a') as stream:
            stream.write(f'{os.getpid()}\n')
        # Model slow interruptible storage at the first expensive read.
        if mode in ('timeout', 'killed'):
            time.sleep(30)
        return {'sequence': 1, 'authorized_to_boot': False}

    def reboot(args):
        assert args == ['systemctl', '--force', 'reboot']
        (directory/'request').touch(exist_ok=False)

    def check_state(_):
        if mode == 'denied':
            raise release.ReleaseError('Synthetic incompatible state.')
        return {'authorized_to_boot': False}

    with patch.object(early_failure, 'inspect_bound_fallback', side_effect=inspect), \
            patch.object(early_failure, 'observe_rollback_compatibility', side_effect=check_state), \
            patch.object(early_failure, 'command', side_effect=reboot):
        if action == 'failed':
            return factory.main(['failed'])
        start = time.monotonic()
        completed = recovery_failure_console.automatic_fallback()
        (directory/'serial-result').write_text(json.dumps([completed, time.monotonic()-start]))
    return 0


def setup(directory, mode):
    (directory/'mode').write_text(mode)
    for variable, value in (('LoaderEntrySelected', 'lanrith_2.efi'), ('LoaderEntryDefault', 'lanrith_1.efi')):
        (directory/(variable+early_failure.LOADER_VENDOR)).write_bytes(bytes(4)+(value+'\0').encode('utf-16-le'))
    contract = {'schema': 1, 'machine_id': 'a'*32, 'state': {'service': {'writes': 'v1', 'reads': ['v1']}},
                'trust': {'generation': 1, 'transition': 'steady',
                          'authorities': {'secure_boot': '1'*64, 'manifest': '1'*64, 'verity': '1'*64,
                                          'pcr_policy': None}}}
    partitions = {role: {'label': 'l_1_'+role.replace('-', '_'),
                         'uuid': f'12345678-1234-1234-1234-{index:012d}', 'size': 512, 'sha256': 'b'*64}
                  for index, role in enumerate(('root', 'verity', 'verity-sig'), 1)}
    value = {'image_id': 'lanrith', 'deployment_sequence': 2, 'uki_name': 'lanrith_2.efi',
             'fallback_timeout_seconds': 1 if mode == 'timeout' else 20,
             'steady_state': {'image_contract': contract, 'fallback_contract': contract, 'tpm_policy': None,
                              'state_directory': '/var/lib/lanrith'},
             'fallback_binding': {'disk_by_id': '/dev/disk/by-id/synthetic',
                                  'esp_uuid': 'abcdefab-1234-1234-1234-123456789abc',
                                  'release': {'sequence': 1, 'uki_name': 'lanrith_1.efi', 'uki_sha256': 'a'*64,
                                              'partitions': partitions}}}
    (directory/'identity.json').write_bytes(release.canonical(early_failure.failure_identity(value)))


def exercise(directory, mode):
    setup(directory, mode)
    serial = 'lanrith-test-serial-'+directory.name+'.service'
    unit = Path('/run/systemd/system')/serial
    script = Path(__file__).resolve()
    bind = 'BindReadOnlyPaths=/etc/os-release:/etc/initrd-release'
    unit.write_text('[Unit]\nDescription=Fixture emergency entry\n[Service]\nType=oneshot\n'+bind+'\n'
                    'Environment=PYTHONPATH=/source\nExecStart=/usr/bin/python3 '+str(script)+' '+str(directory)+' serial\n')
    try:
        subprocess.run(['systemctl', 'daemon-reload'], check=True)
        if mode == 'direct':
            subprocess.run(['systemctl', 'start', serial], check=True)
        else:
            failure = 'lanrith-test-failed-'+directory.name+'.service'
            args = ['systemd-run', '--quiet', '--wait', '--collect', '--unit='+failure, '--service-type=oneshot',
                    '--property='+bind, '--property=OnFailure='+serial, '--property=TimeoutStartSec=40',
                    '--setenv=PYTHONPATH=/source', '/usr/bin/python3', str(script), str(directory), 'failed']
            with subprocess.Popen(args) as process:
                if mode == 'killed':
                    deadline = time.monotonic()+10
                    while not (directory/'inspections').exists() and time.monotonic() < deadline:
                        time.sleep(0.1)
                    assert (directory/'inspections').exists()
                    # A concurrent emergency request must also honor the active reservation.
                    subprocess.run(['systemctl', 'start', serial], check=True)
                    assert json.loads((directory/'serial-result').read_text())[0] is False
                    (directory/'serial-result').unlink()
                    subprocess.run(['systemctl', 'kill', '--signal=KILL', failure], check=True)
                assert process.wait(timeout=45) != 0
        deadline = time.monotonic()+15
        while not (directory/'serial-result').exists() and time.monotonic() < deadline:
            time.sleep(0.1)
        completed, duration = json.loads((directory/'serial-result').read_text())
        assert completed == (mode == 'direct')
        assert (directory/'request').exists() == completed
        assert len((directory/'inspections').read_text().splitlines()) == (2 if completed else 1)
        marks = list(directory.glob('lanrith-fallback-*'))
        assert len(marks) == 1 and marks[0].stat().st_mode & 0o777 == 0o600
        assert duration < 3, f'{mode}: emergency entry took {duration}s'
        print(f'{mode} emergency entry {duration:.3f}s, reboot requests {int(completed)}', flush=True)
    finally:
        unit.unlink()
        subprocess.run(['systemctl', 'daemon-reload'], check=True)


def media_terminal(directory):
    (directory/'media-policy').write_text(json.dumps({'schema': 1, 'tty': 'ttyS0', 'image_id': 'lanrith',
                                                    'disk_by_id': '/dev/disk/by-id/fixture'}))
    secret = b'synthetic-test-passphrase'
    salt = bytes(16)
    digest = hashlib.scrypt(secret, salt=salt, n=32768, r=8, p=1, dklen=32, maxmem=64*1024*1024)
    credential = directory/'media-hash'
    credential.write_text('scrypt:32768:8:1:'+salt.hex()+':'+digest.hex())
    credential.chmod(0o600)
    with ExitStack() as resources:
        master, tty = os.openpty()
        wrong_master, wrong_tty = os.openpty()
        for fd in (master, tty, wrong_master, wrong_tty):
            resources.callback(os.close, fd)
        args = ['systemd-run', '--quiet', '--wait', '--collect', '--service-type=exec', '--property=RuntimeMaxSec=40',
                '--property=BindReadOnlyPaths=/etc/os-release:/etc/initrd-release',
                '--property=BindPaths='+os.ttyname(tty)+':/dev/ttyS0', '--property=StandardInput=tty-force',
                '--property=StandardOutput=tty', '--property=StandardError=journal', '--setenv=PYTHONPATH=/source']
        def launch(terminal):
            return subprocess.Popen(args+['--property=TTYPath='+os.ttyname(terminal), '/usr/bin/python3',
                                          str(Path(__file__).resolve()), str(directory), 'media'])
        with launch(wrong_tty) as process:
            assert process.wait(timeout=15) != 0
            assert not select.select([wrong_master], [], [], 0)[0]
        def expect(pattern):
            data = b''
            deadline = time.monotonic()+20
            while pattern not in data:
                wait = deadline-time.monotonic()
                assert wait > 0 and select.select([master], [], [], wait)[0], 'Synthetic terminal prompt timed out'
                data += os.read(master, 1024)
            assert secret not in data
        with launch(tty) as process:
            expect(b'Recovery passphrase: ')
            os.write(master, secret+b'\n')
            expect(b'recovery> ')
            os.write(master, b'exit\n')
            assert process.wait(timeout=15) == 0
        print('Dedicated media authenticated on the bound terminal. The other terminal received no prompt.', flush=True)


def measure_reads():
    # Measure the three digest passes on part of the immutable fixture image.
    assert 'rdinit=/fixture-init' in Path('/proc/cmdline').read_text().split()
    source = subprocess.check_output(['findmnt', '--noheadings', '--output', 'SOURCE',
                                      '--mountpoint', '/opt/fixture-platform'], text=True).strip()
    assert source == '/dev/vdb' and Path('/sys/class/block/vdb/ro').read_text().strip() == '1'
    started = time.monotonic()
    size = 128*1024*1024
    digests = [digest(source, size) for digest in
               (repair.partition_digest, tpm_migration.partition_digest, repair.partition_digest)]
    assert len(set(digests)) == 1
    print(f'128 MiB read-only virtual disk sample, three digest passes in {time.monotonic()-started:.2f}s', flush=True)


if __name__ == '__main__':
    if len(sys.argv) == 3 and sys.argv[2] in ('failed', 'serial', 'media'):
        sys.exit(child(Path(sys.argv[1]), sys.argv[2]))
    if sys.argv[1:] != ['--systemd'] or not Path('/opt/fixture-platform/usr/lib/os-release').is_file():
        raise SystemExit('Run with --systemd in the disposable fixture guest.')
    for scenario in ('timeout', 'killed', 'denied', 'direct'):
        with tempfile.TemporaryDirectory(dir='/run', prefix='initrd-budget-') as scratch:
            exercise(Path(scratch), scenario)
    with tempfile.TemporaryDirectory(dir='/run', prefix='initrd-media-') as scratch:
        media_terminal(Path(scratch))
    measure_reads()
