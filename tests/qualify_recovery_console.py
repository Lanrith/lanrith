#!/usr/bin/env python3
"""Exercise the experimental signed recovery initrd on a disposable VM only."""

import argparse
import datetime
import hashlib
import json
import os
import re
import shutil
import sys
from pathlib import Path
import subprocess
import tempfile
import time

from vm import Guest, PROJECT, regular, run
from qualify_bound_observation_vm import require_matching_base
from lanrith import build, config, recovery_backup_files, recovery_build, release


def encrypted_target(work, prepared=None, supplied_key=None, *, synthetic_key=False):
    """Create a disposable LUKS partition with no filesystem on a regular file."""
    partition = work/'synthetic-luks-partition'
    if prepared is not None:
        release.require(prepared.is_file() and prepared.stat().st_size == 128*1024*1024,
                        'Synthetic prepared partition has an unexpected size.')
        shutil.copyfile(prepared, partition)
        recovery_key = supplied_key
    else:
        with partition.open('xb') as stream:
            stream.truncate(128*1024*1024)
    if prepared is None:
        result = subprocess.run(['cryptsetup', 'luksFormat', '--batch-mode', '--type=luks2',
                                 '--pbkdf=pbkdf2', '--pbkdf-force-iterations=1000', '--key-file=-', str(partition)],
                                input=b'synthetic-state-key', capture_output=True, timeout=120)
        release.require(result.returncode == 0, 'Synthetic encrypted fixture formatting failed.')
        if synthetic_key:
            recovery_key = bytearray(b'synthetic-state-key')
        else:
            enrollment = subprocess.run(['systemd-cryptenroll', '--unlock-key-file=/proc/self/fd/0',
                                         '--recovery-key', str(partition)], input=b'synthetic-state-key',
                                        capture_output=True, timeout=120,
                                        env=dict(os.environ, SYSTEMD_COLORS='0', TERM='dumb'))
            release.require(enrollment.returncode == 0, 'Synthetic recovery-key enrollment failed.')
            recovery_key = bytearray(enrollment.stdout.strip())
    release.require(recovery_key is not None and (synthetic_key or
                    re.fullmatch(rb'(?:[a-z]{8}-){7}[a-z]{8}', recovery_key) is not None),
                    'Synthetic recovery-key input has an unexpected format.')
    check = subprocess.run(['cryptsetup', 'open', '--test-passphrase', '--key-file=-', str(partition)],
                           input=recovery_key, capture_output=True, timeout=120)
    release.require(check.returncode == 0, 'Synthetic recovery key does not unlock the fixture.')
    uuid = run('cryptsetup', 'luksUUID', str(partition)).decode('ascii').strip().lower()
    target = work/'synthetic-encrypted-target.raw'
    with target.open('xb') as stream:
        stream.truncate(160*1024*1024)
    definition = (b'label: gpt\nunit: sectors\n\n'
                  b'start=2048,size=262144,type=4d21b016-b534-45c2-a9fb-5c16e091fd2d,name="var"\n')
    result = subprocess.run(['sfdisk', '--no-reread', str(target)], input=definition,
                            capture_output=True, timeout=30)
    release.require(result.returncode == 0, 'Synthetic recovery GPT creation failed.')
    # The target must not be automatically discovered/mounted by the initrd.
    run('sfdisk', '--part-attrs', str(target), '1', 'GUID:59')
    with partition.open('rb') as source, target.open('r+b') as destination:
        destination.seek(2048*512)
        while data := source.read(4*1024*1024):
            destination.write(data)
        destination.flush()
        os.fsync(destination.fileno())
    partition.unlink()
    return target, uuid, recovery_key


def state_result(guest):
    labels = ('key or volume', 'read-only filesystem mount', 'target disk', 'target state', 'state identity',
              'target geometry', 'read-only backing', 'read-only mapping', 'read-only device check',
              'read-only device missing', 'read-only device denied', 'read-only device unavailable',
              'encrypted metadata', 'device discovery', 'recovery boot root')
    patterns = [rb'State inspection failed \('+label.encode()+rb'\)\.' for label in labels]
    patterns.append(rb'State inspection failed\.')
    index = guest.expect_any(patterns)
    return labels[index] if index < len(labels) else 'unspecified'


def fixture_initializer(state_uuid, *, enroll_systemd=False, exercise_header=False):
    """Synthetic-only initializer; it is never part of the recovery image."""
    return '''#!/usr/bin/python3 -I
import hashlib,json,os,re,subprocess,sys,tempfile,time
from pathlib import Path
sys.path.insert(0,"/usr/lib/lanrith")
from lanrith import factory,recovery_console,release,repair,update
try:
    disk=Path('/dev/disk/by-id/virtio-lanrith-state-test').resolve(strict=True)
    boot,_=factory.verified_root('/sysroot')
    release.require(str(disk)=='/dev/vdb' and str(disk)!=boot, 'Synthetic target identity differs.')
    layout=repair.disk_layout(str(disk))
    rows=update.geometry(str(disk))
    matches=[r for r in rows if r['type']==factory.VAR_GUID and r['label']=='var']
    release.require(len(matches)==1 and matches[0]['device']=='/dev/vdb1' and
                    matches[0]['size']==128*1024*1024 and not matches[0]['mounted'] and
                    len(layout['extents'])==1, 'Synthetic target layout differs.')
    device=matches[0]['device']
    release.require(update.command(['cryptsetup','luksUUID',device]).strip().lower()=='''+repr(state_uuid)+''',
                    'Synthetic target volume differs.')
    secret=recovery_console.secret_from_tty(sys.stdin.buffer,sys.stdout,prompt='Offline recovery key: ')
    try:
        recovered=None
        if '''+repr(enroll_systemd)+''':
            result=subprocess.run(['systemd-cryptenroll','--unlock-key-file=/proc/self/fd/0',
                                   '--recovery-key',device],input=secret,capture_output=True,timeout=120,
                                  env=dict(os.environ,SYSTEMD_COLORS='0',TERM='dumb'))
            candidates=re.findall(rb'(?:[a-z]{8}-){7}[a-z]{8}',result.stdout)
            release.require(result.returncode==0 and len(candidates)==1,'Synthetic recovery enrollment failed.')
            recovered=bytearray(candidates[0])
        result=subprocess.run(['cryptsetup','open','--type=luks2','--disable-external-tokens',
                               '--key-file=-',device,'lanrith-fixture-state'],input=secret,
                              capture_output=True,timeout=120)
        release.require(result.returncode==0,'Synthetic fixture unlock failed.')
    finally:
        for i in range(len(secret)): secret[i]=0
    # The fixture needs an ext4 filesystem. This initializer is generated only
    # for a disposable, explicitly identified VM disk, never for repair media.
    update.command(['dmsetup','mknodes','lanrith-fixture-state'])
    update.command(['mkfs.ext4','-F','/dev/mapper/lanrith-fixture-state'],timeout=180)
    point=Path(tempfile.mkdtemp(prefix='fixture-state.',dir='/run'))
    try:
        update.command(['mount','-t','ext4','-o','nodev,nosuid,noexec','--',
                        '/dev/mapper/lanrith-fixture-state',str(point)])
        marker=point/'synthetic-fixture.txt'
        with marker.open('xb') as stream:
            stream.write(b'synthetic persisted state\\n');stream.flush();os.fsync(stream.fileno())
        directory=point/'lib/lanrith'
        directory.mkdir(parents=True,mode=0o700)
        inventory={'schema':1,'machine_id':'1'*32,'state':{'dns':{'writes':'dns-v1','reads':['dns-v1']}},
                   'trust':{'generation':1,'transition':'steady','authorities':
                            {'manifest':'2'*64,'secure_boot':'3'*64,'verity':'4'*64,'pcr_policy':'5'*64}}}
        contract=directory/'state-contract.json'
        contract.write_text(json.dumps(inventory));contract.chmod(0o600)
        update.command(['sync'])
    finally:
        if point.is_mount(): update.command(['umount',str(point)])
        update.command(['cryptsetup','close','lanrith-fixture-state'])
        point.rmdir()
    if '''+repr(exercise_header)+''':
        release.require(recovered is not None,'Synthetic header test requires an enrolled key.')
        header=Path('/run/synthetic-luks-header')
        update.command(['cryptsetup','luksHeaderBackup',device,'--header-backup-file',str(header)])
        length=header.stat().st_size
        release.require(0<length<=32*1024*1024 and length<128*1024*1024,
                        'Synthetic header backup size differs.')
        def payload_digest():
            digest=hashlib.sha256()
            with open(device,'rb',buffering=0) as stream:
                stream.seek(length)
                remaining=128*1024*1024-length
                while remaining:
                    data=stream.read(min(1024*1024,remaining))
                    release.require(data,'Synthetic encrypted payload is truncated.')
                    digest.update(data);remaining-=len(data)
            return digest.digest()
        before=payload_digest()
        with open(device,'r+b',buffering=0) as stream:
            remaining=length
            while remaining:
                block=b'\\0'*min(1024*1024,remaining)
                stream.write(block);remaining-=len(block)
            os.fsync(stream.fileno())
        damaged=subprocess.run(['cryptsetup','isLuks',device],capture_output=True,timeout=30)
        release.require(damaged.returncode!=0,'Synthetic damaged header remained valid.')
        update.command(['cryptsetup','luksHeaderRestore','--batch-mode',device,'--header-backup-file',str(header)],
                       timeout=120)
        release.require(update.command(['cryptsetup','luksUUID',device]).strip().lower()=='''+repr(state_uuid)+''',
                        'Synthetic restored volume identity differs.')
        tested=subprocess.run(['cryptsetup','open','--test-passphrase','--key-file=-',device],input=recovered,
                              capture_output=True,timeout=120)
        release.require(tested.returncode==0 and payload_digest()==before,
                        'Synthetic header restore did not preserve the recovery key or encrypted payload.')
        header.unlink()
    update.command(['sync'])
    print('Synthetic encrypted filesystem prepared.',flush=True)
    if recovered is not None:
        sys.stdout.buffer.write(b'SYNTHETIC_RECOVERY_KEY:'+recovered+b'\\n');sys.stdout.flush()
        for i in range(len(recovered)): recovered[i]=0
except Exception:
    print('Synthetic fixture preparation failed.',flush=True)
while True: time.sleep(60)
'''


def prepare_target_filesystem(value, base, initrd, work, secret, target, state_uuid, credential, recovery_key,
                              *, enroll_systemd=False, exercise_header=False):
    """Boot a separate non-exportable initializer; only its synthetic target is writable."""
    assembly = work/'fixture-assembly'
    build.assembly(value, base, assembly, version='0.1.0', sequence=30,
                   certificate=secret/'test.crt', private_key=secret/'test.key', initrd_base=initrd)
    recovery_build.prepare(assembly, disk_by_id='/dev/disk/by-id/virtio-lanrith-state-test',
                           credential=credential, state_uuid=state_uuid)
    initrd_overlay = assembly/'mkosi.images/initrd/mkosi.extra'
    program = initrd_overlay/'usr/bin/lanrith-synthetic-fixture'
    program.write_text(fixture_initializer(state_uuid, enroll_systemd=enroll_systemd,
                                           exercise_header=exercise_header))
    program.chmod(0o755)
    unit = initrd_overlay/'usr/lib/systemd/system/lanrith-factory.service'
    original = unit.read_text()
    release.require(original.count('ExecStart=/usr/bin/lanrith-recovery\n') == 1,
                    'Synthetic initializer unit differs.')
    unit.write_text(original.replace('ExecStart=/usr/bin/lanrith-recovery\n',
                                     'ExecStart=/usr/bin/lanrith-synthetic-fixture\n'))
    build.run(assembly)
    guest = Guest(work/'fixture-guest', secret, assembly/'output/lanrith_30.raw',
                  tpm=False, disk_readonly=True, extra_disk=target)
    try:
        print('Recovery VM: preparing a separate disposable encrypted filesystem.', flush=True)
        guest.start()
        event = guest.expect_any([rb'Offline recovery key: ', rb'Synthetic fixture preparation failed\.'])
        release.require(event == 0, 'Synthetic fixture preparation failed before key entry.')
        guest.serial.sendall(recovery_key + b'\r')
        event = guest.expect_any([rb'Synthetic encrypted filesystem prepared\.',
                                  rb'Synthetic fixture preparation failed\.'])
        release.require(event == 0, 'Synthetic encrypted filesystem preparation failed.')
        if enroll_systemd:
            deadline = time.monotonic()+120
            pattern = re.compile(rb'SYNTHETIC_RECOVERY_KEY:((?:[a-z]{8}-){7}[a-z]{8})\r?\n')
            while time.monotonic() < deadline:
                with guest.console.condition:
                    match = pattern.search(guest.console.data)
                    if match:
                        enrolled = bytearray(match.group(1))
                        guest.console.data = guest.console.data[match.end():]
                        break
                    release.require(guest.process.poll() is None and not guest.console.closed,
                                    'Synthetic enrollment guest stopped.')
                    guest.console.condition.wait(timeout=1)
            else:
                raise release.ReleaseError('Synthetic recovery enrollment output was absent.')
            return enrolled
    finally:
        guest.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--base', type=Path, required=True)
    parser.add_argument('--initrd-base', type=Path, required=True)
    parser.add_argument('--work', type=Path, required=True)
    parser.add_argument('--result', type=Path, required=True)
    parser.add_argument('--prepared-partition', type=Path)
    parser.add_argument('--synthetic-key', action='store_true', help='use a synthetic LUKS passphrase fixture')
    parser.add_argument('--systemd-in-vm', action='store_true', help='enroll synthetic recovery key inside VM')
    parser.add_argument('--exercise-header', action='store_true', help='test synthetic LUKS header restoration')
    parser.add_argument('--exercise-backup', action='store_true', help='test regular-file authenticated backup')
    args = parser.parse_args()
    base, initrd, work = regular(args.base), regular(args.initrd_base), args.work
    matched = require_matching_base(base)
    release.require(work.is_absolute() and work.parent.resolve() == work.parent and not work.exists(),
                    'Recovery qualification requires a new disposable workspace.')
    work.mkdir(mode=0o700)
    report = {'schema': 1, 'result': 'fail', 'scope': 'synthetic-recovery-initrd-only',
              'physical_homelab_qualified': False, 'independent_repair_media_admitted': False,
              'branch_overlay_files_matched': matched,
              'synthetic_luks_passphrase': args.synthetic_key and not args.systemd_in_vm,
              'synthetic_systemd_recovery_key': args.systemd_in_vm,
              'synthetic_luks_header_restore': args.exercise_header,
              'synthetic_authenticated_backup': args.exercise_backup,
              'filesystem_sha256': release.file_record(base)['sha256'],
              'initrd_sha256': release.file_record(initrd)['sha256'],
              'test_sha256': release.file_record(Path(__file__))['sha256']}
    target = None
    target_before = None
    recovery_key = None
    try:
        with tempfile.TemporaryDirectory(prefix='lanrith-recovery-authority.', dir='/dev/shm') as private:
            secret = Path(private)
            run('openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
                '-subj', '/CN=Lanrith Disposable Recovery Authority',
                '-keyout', str(secret/'test.key'), '-out', str(secret/'test.crt'))
            (secret/'test.key').chmod(0o600)
            salt = os.urandom(16)
            digest = hashlib.scrypt(b'synthetic-recovery-passphrase', salt=salt, n=32768, r=8, p=1,
                                    dklen=32, maxmem=64*1024*1024)
            credential = secret/'recovery.hash'
            credential.write_text('scrypt:32768:8:1:'+salt.hex()+':'+digest.hex()+'\n')
            credential.chmod(0o600)
            if args.prepared_partition is not None:
                recovery_key = bytearray(sys.stdin.buffer.readline(128).rstrip(b'\r\n'))
            release.require(not (args.synthetic_key and args.prepared_partition), 'Fixture options are exclusive.')
            release.require(not args.systemd_in_vm or args.synthetic_key,
                            'VM enrollment requires a synthetic initial passphrase.')
            release.require(not args.exercise_header or args.systemd_in_vm,
                            'Synthetic header restoration requires VM recovery-key enrollment.')
            release.require(not args.exercise_backup or args.systemd_in_vm,
                            'Synthetic backup test requires VM recovery-key enrollment.')
            target, state_uuid, recovery_key = encrypted_target(work, args.prepared_partition, recovery_key,
                                                                 synthetic_key=args.synthetic_key)
            value = config.load(PROJECT/'examples/minimal.yaml')
            value['hardware']['storage'] = {'root_mib': 6144, 'state_mib': 16384, 'esp_mib': 512,
                                           'target': '/dev/disk/by-id/virtio-unattached-target'}
            value['hardware']['boot'] = {'secure_boot': True, 'console': 'ttyS0,115200n8', 'recovery_console': 'ttyS0'}
            value['administration']['root_access'] = 'disabled'
            enrolled = prepare_target_filesystem(value, base, initrd, work, secret, target, state_uuid, credential,
                                                 recovery_key, enroll_systemd=args.systemd_in_vm,
                                                 exercise_header=args.exercise_header)
            if args.systemd_in_vm:
                for index in range(len(recovery_key)): recovery_key[index] = 0
                recovery_key = enrolled
            target_before = release.file_record(target)['sha256']
            if args.exercise_backup:
                # Extract the already prepared synthetic partition to an ordinary
                # file. This fixture deliberately does not accept block devices.
                partition = work/'synthetic-luks-for-backup'
                with target.open('rb') as source, partition.open('xb') as destination:
                    source.seek(2048*512)
                    remaining = 128*1024*1024
                    while remaining:
                        chunk = source.read(min(1024*1024, remaining))
                        release.require(chunk, 'Synthetic backup fixture is truncated.')
                        destination.write(chunk)
                        remaining -= len(chunk)
                    destination.flush(); os.fsync(destination.fileno())
                directory = work/'synthetic-backup-directory'
                directory.mkdir(mode=0o700)
                binding = {'image_id': 'lanrith', 'volume_uuid': state_uuid}
                name = recovery_backup_files.create(directory, partition, recovery_key, **binding)
                observation = recovery_backup_files.inspect(directory, name, recovery_key, **binding)
                release.require(observation.get('authorized_to_restore') is False,
                                'Synthetic backup inspection granted restore authority.')
                try:
                    recovery_backup_files.inspect(directory, name, bytearray(b'wrong-synthetic-key'), **binding)
                except release.ReleaseError:
                    pass
                else:
                    raise release.ReleaseError('Synthetic backup accepted the wrong recovery key.')
                payload = directory/name/'payload'
                with payload.open('r+b') as stream:
                    stream.seek(32*1024*1024)
                    original = stream.read(1)
                    release.require(len(original) == 1, 'Synthetic backup payload is truncated.')
                    stream.seek(32*1024*1024); stream.write(bytes([original[0]^1])); stream.flush(); os.fsync(stream.fileno())
                try:
                    recovery_backup_files.inspect(directory, name, recovery_key, **binding)
                except release.ReleaseError:
                    pass
                else:
                    raise release.ReleaseError('Synthetic backup accepted altered encrypted data.')
                release.require(release.file_record(target)['sha256'] == target_before,
                                'Synthetic backup altered its source target.')
            assembly = work/'assembly'
            build.assembly(value, base, assembly, version='0.1.0', sequence=31,
                           certificate=secret/'test.crt', private_key=secret/'test.key', initrd_base=initrd)
            recovery_build.prepare(assembly, disk_by_id='/dev/disk/by-id/virtio-lanrith-state-test',
                                   credential=credential, state_uuid=state_uuid)
            build.run(assembly)
            disk = assembly/'output/lanrith_31.raw'
            before = release.file_record(disk)['sha256']
            guest = Guest(work/'guest', secret, disk, tpm=False, disk_readonly=True,
                          extra_disk=target, extra_disk_readonly=True)
            try:
                print('Recovery VM: booting signed read-only recovery image without TPM.', flush=True)
                guest.start()
                event = guest.expect_any([rb'Recovery passphrase: ', rb'Recovery environment unavailable',
                                          rb'Recovery console unavailable'])
                release.require(event == 0, 'Experimental recovery console did not start.')
                guest.serial.sendall(b'synthetic-wrong-passphrase\r')
                guest.expect(rb'Authentication failed\.')
                guest.expect(rb'Recovery passphrase: ', 'synthetic-recovery-passphrase')
                guest.expect(rb'Recovery console: status, inspect, inspect-state, exit')
                guest.serial.sendall(b'status\r')
                guest.expect(rb'Slot selection and repair are not available\.')
                guest.serial.sendall(b'inspect\r')
                guest.expect(rb'Slot inspection failed\.')
                guest.serial.sendall(b'inspect-state\r')
                guest.expect(rb'Offline recovery key: ', 'synthetic-wrong-state-key')
                stage = state_result(guest)
                release.require(stage == 'key or volume', 'Wrong-key test failed at '+stage+'.')
                guest.serial.sendall(b'inspect-state\r')
                guest.expect(rb'Offline recovery key: ')
                guest.serial.sendall(recovery_key + b'\r')
                event = guest.expect_any([rb'Encrypted state opened read-only\. Retained inventory available\.',
                                          rb'State inspection failed(?: \([a-z -]+\))?\.'])
                release.require(event == 0, 'Valid-key read-only state mount failed.')
                guest.serial.sendall(b'exit\r')
                guest.expect(rb'Recovery session ended\.')
                guest.serial.sendall(b'id\r')
                time.sleep(2)
                release.require(b'uid=0' not in guest.buffer and guest.process.poll() is None,
                                'Recovery exit exposed a shell or unexpectedly stopped the guest.')
                guest.close()
                release.require(release.file_record(disk)['sha256'] == before,
                                'Read-only recovery media changed during boot.')
                release.require(release.file_record(target)['sha256'] == target_before,
                                'Synthetic encrypted target changed during read-only inspection.')
            finally:
                guest.close()
            # The same signed image must not ask for any secret when firmware
            # starts it in setup mode with Secure Boot disabled. This is an
            # independently booted disposable VM, not a firmware mutation.
            insecure = Guest(work/'insecure-guest', secret, disk, tpm=False, disk_readonly=True,
                             extra_disk=target, extra_disk_readonly=True, secure_boot=False)
            try:
                print('Recovery VM: checking disabled Secure Boot refuses credential prompts.', flush=True)
                insecure.start()
                event = insecure.expect_any([rb'Recovery unavailable: Secure Boot is disabled\.', rb'Recovery passphrase: ',
                                             rb'Offline recovery key: ', rb'Recovery environment unavailable'])
                release.require(event == 0, 'Insecure recovery boot did not fail before credential entry.')
                release.require(insecure.process.poll() is None, 'Insecure recovery guest unexpectedly stopped.')
            finally:
                insecure.close()
            release.require(release.file_record(disk)['sha256'] == before and
                            release.file_record(target)['sha256'] == target_before,
                            'A recovery VM changed read-only media or target.')
            report.update(result='pass', checks=['signed-recovery-image-boot', 'no-installed-router-root',
                'no-tpm', 'recovery-media-read-only', 'wrong-passphrase-denied', 'authenticated-fixed-menu',
                'missing-offline-input-denied', 'wrong-state-key-denied',
                ('synthetic-luks-key-readonly-ext4-mount' if args.synthetic_key and not args.systemd_in_vm else
                 'systemd-recovery-key-readonly-ext4-mount'), 'retained-inventory-readonly-mount',
                'secure-boot-disabled-no-secret-prompt',
                'encrypted-target-unchanged', 'no-shell-after-exit'])
            if args.exercise_header:
                report['checks'].append('synthetic-luks-header-corruption-and-restoration')
            if args.exercise_backup:
                report['checks'].append('synthetic-systemd-key-authenticated-regular-file-backup')
    finally:
        if recovery_key is not None:
            for index in range(len(recovery_key)):
                recovery_key[index] = 0
        if target is not None and target_before is not None and target.is_file():
            report['synthetic_target_unchanged'] = release.file_record(target)['sha256'] == target_before
        report['assessed_at'] = datetime.datetime.now(datetime.timezone.utc).isoformat()
        args.result.write_bytes(release.canonical(report))
    print('Experimental signed recovery initrd passed its limited synthetic VM test.', flush=True)


if __name__ == '__main__':
    main()
