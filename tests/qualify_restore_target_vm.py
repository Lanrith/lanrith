#!/usr/bin/env python3
"""Exercise the gated target claim on independent disposable VM disks."""
import argparse
import datetime
import hashlib
import json
import os
import re
from pathlib import Path
import shutil
import subprocess
import tempfile

from lanrith import build, config, recovery_build, release
from qualify_bound_observation_vm import require_matching_base
from qualify_recovery_console import encrypted_target
from vm import Guest, PROJECT, regular, run


BACKUP_UUID = '12345678-1234-1234-1234-123456789abe'


SUCCESS = 'Synthetic exclusive target claim passed.'
FAILURE = 'Synthetic exclusive target claim failed.'

def backup_target(work, *, partition_mib=256, prepopulate=False):
    """Create an independent synthetic ext4 partition on a disposable disk."""
    partition, disk = work/'synthetic-backup-partition', work/'synthetic-backup.raw'
    with partition.open('xb') as stream:
        stream.truncate(partition_mib*1024*1024)
    if prepopulate:
        initial = work/'synthetic-backup-initial'
        initial.mkdir(mode=0o700)
        (initial/'lanrith-backups').mkdir(mode=0o700)
        run('mkfs.ext4', '-q', '-F', '-O', 'verity', '-d', str(initial), str(partition))
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
import errno,os,re,sys,time
from pathlib import Path
print('Synthetic target claim stage: entry',flush=True)
sys.path.insert(0,"/usr/lib/lanrith")
try:
    from lanrith import recovery_restore_target as target,recovery_inputs,release
except ImportError:
    print('Synthetic target claim stage: import-failed',flush=True)
    print('''+repr(FAILURE)+''',flush=True)
    raise SystemExit(1)
value='''+repr(value)+'''
stage='binding'
print('Synthetic target claim stage: binding',flush=True)
try:
    release.require(Path(value['target_disk_by_id']).resolve(strict=True)==Path('/dev/vdb') and
                    Path(value['backup_disk_by_id']).resolve(strict=True)==Path('/dev/vdc'),
                    'Unexpected synthetic disk.')
    rows=recovery_inputs.disk_snapshot('/dev/vdb')[1]
    state=recovery_inputs.partition(rows,'/dev/vdb',value['state_partuuid'],target.factory.VAR_GUID,label='var')
    size=next(row['size'] for row in rows if row['device']==state)
    stage='readonly'
    print('Synthetic target claim stage: readonly',flush=True)
    target.update.command(['blockdev','--setro','/dev/vdb'])
    target.update.command(['blockdev','--setro',state])
    target.update.command(['blockdev','--setrw',state])
    disk_ro=target.update.command(['blockdev','--getro','/dev/vdb']).strip()
    state_ro=target.update.command(['blockdev','--getro',state]).strip()
    release.require(disk_ro in ('0','1') and state_ro in ('0','1'),'Unexpected readonly observation.')
    print('Synthetic target readonly observation: disk='+disk_ro+' partition='+state_ro,flush=True)
    target.update.command(['blockdev','--setrw','/dev/vdb'])
    target.update.command(['blockdev','--setrw',state])
    stage='gate'
    print('Synthetic target claim stage: gate',flush=True)
    try:
        with target.claim(value,expected_size=size): pass
    except release.ReleaseError: pass
    else: raise release.ReleaseError('Production target gate was bypassed.')
    target.TARGET_CLAIM_QUALIFIED=True # test-only signed initrd, not an owner option
    for bad in ({**value,'state_partuuid':'12345678-1234-1234-1234-123456789abc'},
                {**value,'backup_disk_by_id':value['target_disk_by_id']}):
        try:
            with target.claim(bad,expected_size=size): pass
        except (release.ReleaseError,OSError): pass
        else: raise release.ReleaseError('Unsafe target binding was accepted.')
    try:
        with target.claim(value,expected_size=size+512): pass
    except release.ReleaseError: pass
    else: raise release.ReleaseError('Incorrect target size was accepted.')
    stage='claim'
    print('Synthetic target claim stage: claim',flush=True)
    with target.claim(value,expected_size=size) as (fd,revalidate):
        revalidate()
        try: other=os.open(state,os.O_RDWR|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC)
        except OSError as error:
            release.require(error.errno == errno.EBUSY,'Unexpected exclusive-open error.')
        else:
            os.close(other)
            raise release.ReleaseError('Concurrent exclusive target claim was accepted.')
        revalidate()
    print('''+repr(SUCCESS)+''',flush=True)
except Exception as error:
    category='release' if isinstance(error,release.ReleaseError) else ('os' if isinstance(error,OSError) else 'other')
    allowed={'recovery_restore_target.py','recovery_restore_transaction.py','recovery_inputs.py',
             'recovery_backup_preflight.py','factory.py','update.py'}
    location='unknown'
    trace=error.__traceback__
    while trace is not None:
        code=trace.tb_frame.f_code
        module=Path(code.co_filename).name
        if module in allowed and re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]{0,63}',code.co_name):
            location=module+':'+code.co_name+':'+str(trace.tb_lineno)
        trace=trace.tb_next
    number=error.errno if isinstance(error,OSError) and type(error.errno) is int and 1<=error.errno<=4095 else 0
    print('Synthetic target claim diagnostic: '+stage+' '+category+' '+location+' errno='+str(number),flush=True)
    print('''+repr(FAILURE)+''',flush=True)
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
    report = {'schema': 1, 'scope': 'synthetic-exclusive-restore-target-claim-only', 'result': 'fail',
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
            for name in ('recovery_backup_preflight.py','recovery_backup_auth.py','recovery_backup_verity.py','recovery_restore_layout.py',
                         'recovery_restore_transaction.py','recovery_restore_target.py'):
                shutil.copyfile(PROJECT/'lanrith'/name, library/name)
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
                          extra_disk=target, extra_disk_readonly=False, backup_disk=backup, backup_disk_readonly=True)
            try:
                print('Target claim VM: checking independent virtual disks.', flush=True)
                guest.start()
                event = guest.expect_any([re.escape(SUCCESS.encode()), re.escape(FAILURE.encode())])
                report['diagnostic'] = json.loads(guest.last_diagnostic)
                release.require(event == 0, 'Synthetic exclusive target claim failed.')
            finally:
                guest.close()
            release.require(release.file_record(target)['sha256'] == target_hash and
                            release.file_record(backup)['sha256'] == backup_hash and
                            release.file_record(recovery)['sha256'] == recovery_hash,
                            'Synthetic preflight changed a read-only disk.')
            report.update(result='pass', checks=['secure-boot-recovery-root','independent-bound-disks',
                'test-only-claim-gate','wrong-partition-denied','disk-alias-denied','wrong-size-denied',
                'concurrent-exclusive-claim-denied','virtual-disks-unchanged','no-restore-authorization'])
    finally:
        if key is not None:
            for index in range(len(key)):
                key[index] = 0
        report['assessed_at'] = datetime.datetime.now(datetime.timezone.utc).isoformat()
        args.result.write_bytes(release.canonical(report))
    print('Synthetic exclusive target claim passed.')


if __name__ == '__main__':
    main()
