#!/usr/bin/env python3
"""Observe a damaged synthetic LUKS target without granting restore authority."""
import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

from lanrith import build, config, recovery_build, release
from qualify_bound_observation_vm import require_matching_base
from qualify_recovery_console import encrypted_target
from vm import Guest, PROJECT, regular, run


BACKUP_UUID = '12345678-1234-1234-1234-123456789abe'


def backup_target(work, *, partition_mib=256, prepopulate=False):
    """Create an independent synthetic ext4 partition on a disposable disk."""
    partition, disk = work/'synthetic-backup-partition', work/'synthetic-backup.raw'
    with partition.open('xb') as stream:
        stream.truncate(partition_mib*1024*1024)
    if prepopulate:
        initial = work/'synthetic-backup-initial'
        initial.mkdir(mode=0o700)
        (initial/'lanrith-backups').mkdir(mode=0o700)
        run('mkfs.ext4', '-q', '-F', '-d', str(initial), str(partition))
    else:
        run('mkfs.ext4', '-q', '-F', str(partition))
    with disk.open('xb') as stream:
        stream.truncate((partition_mib+64)*1024*1024)
    table = ('label: gpt\nunit: sectors\n\n'
             f'start=2048,size={partition_mib*2048},type=0fc63daf-8483-4772-8e79-3d69d8477de4,'
             'uuid=12345678-1234-1234-1234-123456789abe,name="lanrith-backup"\n').encode()
    result = subprocess.run(['sfdisk', '--no-reread', str(disk)], input=table,
                            capture_output=True, timeout=30)
    release.require(result.returncode == 0, 'Synthetic backup GPT creation failed.')
    with partition.open('rb') as source, disk.open('r+b') as target:
        target.seek(2048*512)
        shutil.copyfileobj(source, target, 1024*1024)
        target.flush(); os.fsync(target.fileno())
    partition.unlink()
    return disk


def hook(value):
    return '''#!/usr/bin/python3 -I
import sys,time
sys.path.insert(0,"/usr/lib/lanrith")
from lanrith import recovery_backup_preflight as preflight,release
value='''+repr(value)+'''
try:
    observed=preflight.inspect_restore(value)
    release.require(observed.get('authorized_to_write') is False and
                    observed.get('authorized_to_restore') is False and
                    observed.get('header_authenticated') is False and
                    observed.get('backup_authenticated') is False,'Unexpected observation.')
    for changed in ({'state_partuuid':'12345678-1234-1234-1234-123456789abc'},
                    {'backup_disk_by_id':'/dev/disk/by-id/virtio-lanrith-qa-disk'},
                    {'backup_disk_by_id':value['target_disk_by_id']},
                    {'backup_partuuid':'12345678-1234-1234-1234-123456789abf'}):
        try: preflight.inspect_restore({**value,**changed})
        except (release.ReleaseError,OSError,ValueError): pass
        else: raise release.ReleaseError('Unsafe preflight was accepted.')
    print('Synthetic restore preflight passed.',flush=True)
except Exception:
    print('Synthetic restore preflight failed.',flush=True)
while True: time.sleep(60)
'''


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--base', type=Path, required=True)
    parser.add_argument('--initrd-base', type=Path, required=True)
    parser.add_argument('--work', type=Path, required=True)
    parser.add_argument('--result', type=Path, required=True)
    args = parser.parse_args()
    base, initrd, work = regular(args.base), regular(args.initrd_base), args.work
    matched = require_matching_base(base)
    release.require(work.is_absolute() and work.parent.resolve() == work.parent and not work.exists(),
                    'Qualification requires a new disposable workspace.')
    work.mkdir(mode=0o700)
    report = {'schema': 1, 'scope': 'synthetic-damaged-header-restore-preflight-only', 'result': 'fail',
              'branch_overlay_files_matched': matched, 'physical_homelab_qualified': False,
              'backup_or_restore_authorized': False, 'independent_repair_media_admitted': False,
              'filesystem_sha256': release.file_record(base)['sha256'],
              'initrd_sha256': release.file_record(initrd)['sha256'],
              'test_sha256': release.file_record(Path(__file__))['sha256']}
    key = None
    try:
        with tempfile.TemporaryDirectory(prefix='lanrith-backup-preflight.', dir='/dev/shm') as private:
            secret = Path(private)
            run('openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
                '-subj', '/CN=Lanrith Disposable Backup Preflight', '-keyout', str(secret/'test.key'),
                '-out', str(secret/'test.crt'))
            (secret/'test.key').chmod(0o600)
            salt = os.urandom(16)
            digest = hashlib.scrypt(b'synthetic-passphrase', salt=salt, n=32768, r=8, p=1,
                                    dklen=32, maxmem=64*1024*1024)
            credential = secret/'recovery.hash'
            credential.write_text('scrypt:32768:8:1:'+salt.hex()+':'+digest.hex()+'\n'); credential.chmod(0o600)
            target, state_uuid, key = encrypted_target(work, synthetic_key=True)
            table = json.loads(run('sfdisk', '--json', str(target)))['partitiontable']
            release.require(len(table['partitions']) == 1, 'Synthetic state GPT is ambiguous.')
            state_partuuid = table['partitions'][0]['uuid'].lower()
            backup = backup_target(work)
            # Corrupt only the new synthetic partition, after binding its GPT.
            # This deliberately damages both LUKS2 metadata copies.
            release.require(target == work/'synthetic-encrypted-target.raw' and target.is_file() and not target.is_symlink(),
                            'Synthetic restore target is unsafe.')
            with target.open('r+b') as stream:
                stream.seek(2048*512)
                stream.write(bytes(16*1024*1024))
                stream.flush(); os.fsync(stream.fileno())
            header = work/'synthetic-damaged-header'
            with target.open('rb') as stream:
                stream.seek(2048*512)
                header.write_bytes(stream.read(16*1024*1024))
            probe = subprocess.run(['cryptsetup', 'isLuks', str(header)], capture_output=True, timeout=30)
            release.require(probe.returncode != 0, 'Synthetic LUKS header was not damaged.')
            header.unlink()
            target_hash, backup_hash = release.file_record(target)['sha256'], release.file_record(backup)['sha256']
            value = config.load(PROJECT/'examples/minimal.yaml')
            value['hardware']['storage'] = {'root_mib': 6144, 'state_mib': 16384, 'esp_mib': 512,
                                           'target': '/dev/disk/by-id/virtio-unused-target'}
            value['hardware']['boot'] = {'secure_boot': True, 'console': 'ttyS0,115200n8', 'recovery_console': 'ttyS0'}
            value['administration']['root_access'] = 'disabled'
            assembly = work/'assembly'
            build.assembly(value, base, assembly, version='0.1.0', sequence=32,
                           certificate=secret/'test.crt', private_key=secret/'test.key', initrd_base=initrd)
            recovery_build.prepare(assembly, disk_by_id='/dev/disk/by-id/virtio-lanrith-state-test',
                                   credential=credential)
            initrd_root = assembly/'mkosi.images/initrd/mkosi.extra'
            library = initrd_root/'usr/lib/lanrith/lanrith'
            shutil.copyfile(PROJECT/'lanrith/recovery_backup_preflight.py', library/'recovery_backup_preflight.py')
            binding = {'schema': 1, 'target_disk_by_id': '/dev/disk/by-id/virtio-lanrith-state-test',
                       'state_partuuid': state_partuuid, 'state_uuid': state_uuid,
                       'backup_disk_by_id': '/dev/disk/by-id/virtio-lanrith-backup-test',
                       'backup_partuuid': BACKUP_UUID}
            binary = initrd_root/'usr/bin/lanrith-synthetic-backup-preflight'
            binary.write_text(hook(binding)); binary.chmod(0o755)
            unit = initrd_root/'usr/lib/systemd/system/lanrith-factory.service'
            original = unit.read_text()
            release.require(original.count('ExecStart=/usr/bin/lanrith-recovery\n') == 1,
                            'Synthetic recovery unit differs.')
            unit.write_text(original.replace('ExecStart=/usr/bin/lanrith-recovery\n',
                                             'ExecStart=/usr/bin/lanrith-synthetic-backup-preflight\n'))
            build.run(assembly)
            recovery = assembly/'output/lanrith_32.raw'
            recovery_hash = release.file_record(recovery)['sha256']
            guest = Guest(work/'guest', secret, recovery, tpm=False, disk_readonly=True,
                          extra_disk=target, extra_disk_readonly=True, backup_disk=backup)
            try:
                print('Restore preflight VM: checking damaged synthetic state and independent media.', flush=True)
                guest.start()
                event = guest.expect_any([rb'Synthetic restore preflight passed\.',
                                          rb'Synthetic restore preflight failed\.'])
                release.require(event == 0, 'Synthetic restore preflight failed.')
            finally:
                guest.close()
            release.require(release.file_record(target)['sha256'] == target_hash and
                            release.file_record(backup)['sha256'] == backup_hash and
                            release.file_record(recovery)['sha256'] == recovery_hash,
                            'Synthetic preflight changed a read-only disk.')
            report.update(result='pass', checks=['secure-boot-recovery-root','independent-bound-disks',
                'damaged-luks-header','bound-gpt-and-ext4-observation','wrong-partuuid-denied','disk-alias-denied',
                'wrong-partition-denied','read-only-disks-unchanged','no-write-or-restore-authorization'])
    finally:
        if key is not None:
            for index in range(len(key)):
                key[index] = 0
        report['assessed_at'] = datetime.datetime.now(datetime.timezone.utc).isoformat()
        args.result.write_bytes(release.canonical(report))
    print('Synthetic restore preflight passed.')


if __name__ == '__main__':
    main()
