#!/usr/bin/env python3
"""Exercise a synthetic backup fixture on separate virtual media only.

The writable operation is a test-only initrd hook with fixed disposable VM
devices. It is not a recovery command and does not authorize production writes.
"""
import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import shutil
import tempfile

from lanrith import build, config, recovery_build, release
from qualify_backup_preflight_vm import BACKUP_UUID, backup_target
from qualify_bound_observation_vm import require_matching_base
from qualify_recovery_console import encrypted_target
from vm import Guest, PROJECT, regular, run


def hook(value, write_mode):
    return '''#!/usr/bin/python3 -I
import hashlib,json,os,shutil,sys,tempfile,time
from pathlib import Path
sys.path.insert(0,"/usr/lib/lanrith")
from lanrith import recovery_backup_files as files,recovery_backup_preflight as preflight,release,update
value='''+repr(value)+'''
write_mode='''+repr(write_mode)+'''
point=None
secret=bytearray(b'synthetic-state-key')
try:
    observation=preflight.inspect(value)
    release.require(observation.get('authorized_to_write') is False and
                    observation.get('authorized_to_restore') is False,'Unexpected preflight authority.')
    target=Path(value['target_disk_by_id']).resolve(strict=True)
    destination=Path(value['backup_disk_by_id']).resolve(strict=True)
    release.require(str(target)=='/dev/vdb' and str(destination)=='/dev/vdc',
                    'Synthetic test disk identities differ.')
    state='/dev/vdb1'; media='/dev/vdc1'
    release.require(update.command(['blockdev','--getro',str(target)]).strip()=='1' and
                    update.command(['blockdev','--getro',state]).strip()=='1',
                    'Synthetic state is not read-only.')
    point=Path(tempfile.mkdtemp(prefix='synthetic-backup-media.',dir='/run'))
    options=('rw' if write_mode else 'ro,noload')+',nodev,nosuid,noexec'
    update.command(['mount','-t','ext4','-o',options,'--',media,str(point)])
    release.require(point.is_mount(),'Synthetic backup medium did not mount.')
    observed=json.loads(update.command(['findmnt','--uniq','--json','--target',str(point),
                                        '--output','SOURCE,FSTYPE,TARGET,OPTIONS']))['filesystems']
    release.require(len(observed)==1 and observed[0]['target']==str(point) and observed[0]['fstype']=='ext4' and
                    Path(observed[0]['source']).resolve()==Path(media) and
                    ({'nodev','nosuid','noexec','rw' if write_mode else 'ro'} <=
                     set(observed[0]['options'].split(','))), 'Synthetic backup mount differs.')
    directory=point/'synthetic-backups'
    binding={'image_id':'lanrith','volume_uuid':value['state_uuid']}
    if write_mode:
        directory.mkdir(mode=0o700)
        source=Path('/run/synthetic-encrypted-state-copy')
        with open(state,'rb',buffering=0) as src,source.open('xb') as dst:
            shutil.copyfileobj(src,dst,1024*1024);dst.flush();os.fsync(dst.fileno())
        release.require(source.stat().st_size==observation['state_size'],'Synthetic state copy size differs.')
        good=files.create(directory,source,secret,**binding)
        bad=files.create(directory,source,secret,**binding)
        release.require(not files.inspect(directory,good,secret,**binding)['authorized_to_restore'],
                        'Synthetic backup granted restore authority.')
        with (directory/bad/'payload').open('r+b') as stream:
            stream.seek(32*1024*1024);original=stream.read(1)
            release.require(len(original)==1,'Synthetic backup is truncated.')
            stream.seek(32*1024*1024);stream.write(bytes([original[0]^1]));stream.flush();os.fsync(stream.fileno())
        source.unlink()
    else:
        names=sorted(path.name for path in directory.iterdir())
        release.require(len(names)==2,'Synthetic backup count differs.')
        good=[];rejected=[]
        for name in names:
            try: result=files.inspect(directory,name,secret,**binding)
            except release.ReleaseError: rejected.append(name)
            else:
                release.require(result['authorized_to_restore'] is False,'Unexpected restore authority.')
                good.append(name)
        release.require(len(good)==len(rejected)==1,'Synthetic tamper check differs.')
        try: files.inspect(directory,good[0],bytearray(b'wrong-synthetic-key'),**binding)
        except release.ReleaseError: pass
        else: raise release.ReleaseError('Synthetic backup accepted a wrong key.')
        def digest(path):
            value=hashlib.sha256()
            with open(path,'rb',buffering=0) as stream:
                while chunk:=stream.read(1024*1024): value.update(chunk)
            return value.digest()
        release.require(digest(state)==digest(directory/good[0]/'payload'),
                        'Synthetic backup differs from the encrypted state.')
    update.command(['umount','--',str(point)]);release.require(not point.is_mount(),'Synthetic backup remains mounted.')
    point.rmdir();point=None
    print('Synthetic backup media '+('write' if write_mode else 'verify')+' passed.',flush=True)
except Exception:
    print('Synthetic backup media '+('write' if write_mode else 'verify')+' failed.',flush=True)
finally:
    for index in range(len(secret)): secret[index]=0
    if point is not None and point.is_mount():
        try: update.command(['umount','--',str(point)])
        except Exception: pass
while True: time.sleep(60)
'''


def assembly(value, base, initrd, work, secret, credential, binding, sequence, *, write_mode):
    workspace = work/('assembly-'+str(sequence))
    build.assembly(value, base, workspace, version='0.1.0', sequence=sequence,
                   certificate=secret/'test.crt', private_key=secret/'test.key', initrd_base=initrd)
    recovery_build.prepare(workspace, disk_by_id='/dev/disk/by-id/virtio-lanrith-state-test', credential=credential)
    initrd_root = workspace/'mkosi.images/initrd/mkosi.extra'
    library = initrd_root/'usr/lib/lanrith/lanrith'
    for name in ('recovery_backup_preflight.py', 'recovery_backup_auth.py', 'recovery_backup_files.py'):
        shutil.copyfile(PROJECT/'lanrith'/name, library/name)
    binary = initrd_root/'usr/bin/lanrith-synthetic-backup-media'
    binary.write_text(hook(binding, write_mode)); binary.chmod(0o755)
    unit = initrd_root/'usr/lib/systemd/system/lanrith-factory.service'
    original = unit.read_text()
    release.require(original.count('ExecStart=/usr/bin/lanrith-recovery\n') == 1,
                    'Synthetic recovery unit differs.')
    unit.write_text(original.replace('ExecStart=/usr/bin/lanrith-recovery\n',
                                     'ExecStart=/usr/bin/lanrith-synthetic-backup-media\n'))
    build.run(workspace)
    return workspace/'output'/f'lanrith_{sequence}.raw'


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
    report = {'schema': 1, 'scope': 'synthetic-backup-media-fixture-only', 'result': 'fail',
              'branch_overlay_files_matched': matched, 'physical_homelab_qualified': False,
              'production_backup_authorized': False, 'restore_authorized': False,
              'independent_repair_media_admitted': False,
              'filesystem_sha256': release.file_record(base)['sha256'],
              'initrd_sha256': release.file_record(initrd)['sha256'],
              'test_sha256': release.file_record(Path(__file__))['sha256']}
    key = None
    try:
        with tempfile.TemporaryDirectory(prefix='lanrith-backup-media.', dir='/dev/shm') as private:
            secret = Path(private)
            run('openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
                '-subj', '/CN=Lanrith Disposable Backup Media', '-keyout', str(secret/'test.key'),
                '-out', str(secret/'test.crt'))
            (secret/'test.key').chmod(0o600)
            salt = os.urandom(16)
            digest = hashlib.scrypt(b'synthetic-passphrase', salt=salt, n=32768, r=8, p=1,
                                    dklen=32, maxmem=64*1024*1024)
            credential = secret/'recovery.hash'
            credential.write_text('scrypt:32768:8:1:'+salt.hex()+':'+digest.hex()+'\n');credential.chmod(0o600)
            target, state_uuid, key = encrypted_target(work, synthetic_key=True)
            table = json.loads(run('sfdisk', '--json', str(target)))['partitiontable']
            release.require(len(table['partitions']) == 1, 'Synthetic state GPT is ambiguous.')
            backup = backup_target(work, partition_mib=512)
            target_hash, empty_hash = release.file_record(target)['sha256'], release.file_record(backup)['sha256']
            binding = {'schema': 1, 'target_disk_by_id': '/dev/disk/by-id/virtio-lanrith-state-test',
                       'state_partuuid': table['partitions'][0]['uuid'].lower(), 'state_uuid': state_uuid,
                       'backup_disk_by_id': '/dev/disk/by-id/virtio-lanrith-backup-test',
                       'backup_partuuid': BACKUP_UUID}
            value = config.load(PROJECT/'examples/minimal.yaml')
            value['hardware']['storage'] = {'root_mib': 6144, 'state_mib': 16384, 'esp_mib': 512,
                                           'target': '/dev/disk/by-id/virtio-unused-target'}
            value['hardware']['boot'] = {'secure_boot': True, 'console': 'ttyS0,115200n8', 'recovery_console': 'ttyS0'}
            value['administration']['root_access'] = 'disabled'
            for write_mode, sequence in ((True, 32), (False, 33)):
                image = assembly(value, base, initrd, work, secret, credential, binding, sequence, write_mode=write_mode)
                image_hash = release.file_record(image)['sha256']
                before = release.file_record(backup)['sha256']
                guest = Guest(work/('guest-write' if write_mode else 'guest-verify'), secret, image,
                              tpm=False, disk_readonly=True, extra_disk=target, extra_disk_readonly=True,
                              backup_disk=backup, backup_disk_readonly=not write_mode)
                try:
                    print('Backup media VM: '+('writing' if write_mode else 'verifying')+' the synthetic fixture.', flush=True)
                    guest.start()
                    event = guest.expect_any([rb'Synthetic backup media (?:write|verify) passed\.',
                                              rb'Synthetic backup media (?:write|verify) failed\.'])
                    release.require(event == 0, 'Synthetic backup media fixture failed.')
                finally:
                    guest.close()
                after = release.file_record(backup)['sha256']
                release.require(release.file_record(target)['sha256'] == target_hash and
                                release.file_record(image)['sha256'] == image_hash and
                                (after != before if write_mode else after == before),
                                'Synthetic backup media changed unexpectedly.')
                if write_mode:
                    release.require(after != empty_hash, 'Synthetic backup media remained empty.')
            report.update(result='pass', checks=['test-only-separate-virtual-backup-media',
                'read-only-encrypted-source','authenticated-synthetic-copy','wrong-key-rejected',
                'tampered-copy-rejected','independent-read-only-verification','source-unchanged',
                'verification-media-unchanged','no-production-backup-or-restore-authority'])
    finally:
        if key is not None:
            for index in range(len(key)): key[index] = 0
        report['assessed_at'] = datetime.datetime.now(datetime.timezone.utc).isoformat()
        args.result.write_bytes(release.canonical(report))
    print('Synthetic backup media fixture passed.')


if __name__ == '__main__':
    main()
