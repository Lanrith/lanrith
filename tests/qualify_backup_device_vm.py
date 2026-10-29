#!/usr/bin/env python3
"""Exercise the gated backup candidate only on disposable virtual disks.

The qualification hook temporarily enables the candidate in its own signed,
non-exportable test initrd. No production configuration can enable it.
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
from qualify_recovery_console import encrypted_target, prepare_target_filesystem
from vm import Guest, PROJECT, regular, run


def hook(value, write_mode):
    return '''#!/usr/bin/python3 -I
import hashlib,re,sys,time
from pathlib import Path
sys.path.insert(0,"/usr/lib/lanrith")
from lanrith import (recovery_backup_device as device,recovery_backup_files as files,
                     recovery_backup_preflight as preflight,recovery_console,recovery_inputs,release)
value='''+repr(value)+'''
write_mode='''+repr(write_mode)+'''
secret=None
stage='binding'
try:
    release.require(str(Path(value['target_disk_by_id']).resolve(strict=True))=='/dev/vdb' and
                    str(Path(value['backup_disk_by_id']).resolve(strict=True))=='/dev/vdc',
                    'Synthetic test disk identities differ.')
    stage='credential'
    secret=recovery_console.secret_from_tty(sys.stdin.buffer,sys.stdout,prompt='Offline recovery key: ')
    binding={'image_id':'lanrith','volume_uuid':value['state_uuid']}
    if write_mode:
        def digest(path):
            result=hashlib.sha256()
            with open(path,'rb',buffering=0) as stream:
                while chunk:=stream.read(1024*1024): result.update(chunk)
            return result.digest()
        before=digest('/dev/vdc')
        device.BACKUP_WRITE_QUALIFIED=True # synthetic VM only; never a build or owner option
        stage='wrong-image'
        try: device.create(value,secret,image_id='other')
        except release.ReleaseError: pass
        else: raise release.ReleaseError('Synthetic wrong image was accepted.')
        release.require(digest('/dev/vdc')==before,'Synthetic wrong image changed backup media.')
        stage='wrong-key'
        wrong=bytearray(b'aaaaaaaa-bbbbbbbb-cccccccc-dddddddd-eeeeeeee-ffffffff-gggggggg-hhhhhhhh')
        try:
            try: device.create(value,wrong,image_id='lanrith')
            except release.ReleaseError: pass
            else: raise release.ReleaseError('Synthetic wrong key was accepted.')
        finally:
            for index in range(len(wrong)): wrong[index]=0
        release.require(digest('/dev/vdc')==before,'Synthetic wrong key changed backup media.')
        stage='publish'
        result=device.create(value,secret,image_id='lanrith')
        release.require(result.get('authorized_to_restore') is False,'Unexpected restore authority.')
    else:
        stage='verify'
        result=preflight.inspect(value)
        release.require(result.get('authorized_to_write') is False,'Unexpected preflight authority.')
        with recovery_inputs.mounted('/dev/vdc1','ext4') as point:
            directory=point/'lanrith-backups'
            names=[path.name for path in directory.iterdir()]
            release.require(len(names)==1,'Synthetic backup count differs.')
            from lanrith import recovery_restore_layout as layout
            with files.open_authenticated(directory,names[0],secret,**binding) as (payload,result):
                release.require(result.get('authorized_to_restore') is False,'Unexpected restore authority.')
                header=layout.inspect_pinned(payload,expected_uuid=value['state_uuid'],
                                             expected_measurement=bytes.fromhex(result['measurement_sha256']))
                release.require(header.get('authorized_to_restore') is False and
                                header.get('header_authenticated') is False and header.get('data_offset')>0,
                                'Unexpected header observation.')
                checked=layout.verify_recovery_key_pinned(payload,secret,expected_uuid=value['state_uuid'],
                                                          expected_measurement=bytes.fromhex(result['measurement_sha256']))
                release.require(checked.get('key_verified') is True and checked.get('authorized_to_restore') is False,
                                'Unexpected recovery-key observation.')
                wrong=bytearray(b'aaaaaaaa-bbbbbbbb-cccccccc-dddddddd-eeeeeeee-ffffffff-gggggggg-hhhhhhhh')
                try:
                    try: layout.verify_recovery_key_pinned(payload,wrong,expected_uuid=value['state_uuid'],
                                                          expected_measurement=bytes.fromhex(result['measurement_sha256']))
                    except release.ReleaseError: pass
                    else: raise release.ReleaseError('Synthetic wrong recovery key was accepted.')
                finally:
                    for index in range(len(wrong)): wrong[index]=0
            def digest(path):
                value=hashlib.sha256()
                with open(path,'rb',buffering=0) as stream:
                    while chunk:=stream.read(1024*1024): value.update(chunk)
                return value.digest()
            release.require(digest('/dev/vdb1')==digest(directory/names[0]/'payload'),
                            'Synthetic backup differs from the encrypted source.')
    print('Synthetic device backup '+('write' if write_mode else 'verify')+' passed.',flush=True)
except Exception as error:
    category='release' if isinstance(error,release.ReleaseError) else ('os' if isinstance(error,OSError) else 'other')
    allowed={'recovery_backup_device.py','recovery_backup_preflight.py','recovery_backup_files.py',
             'recovery_backup_verity.py','recovery_backup_auth.py','recovery_restore_layout.py','recovery_inputs.py','factory.py','update.py'}
    location='unknown'
    trace=error.__traceback__
    while trace is not None:
        code=trace.tb_frame.f_code
        module=Path(code.co_filename).name
        if module in allowed and re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]{0,63}',code.co_name):
            location=module+':'+code.co_name+':'+str(trace.tb_lineno)
        trace=trace.tb_next
    cause=error
    errno_code=0
    for _ in range(4):
        if isinstance(cause,OSError) and type(cause.errno) is int and 1 <= cause.errno <= 4095:
            errno_code=cause.errno
            break
        cause=cause.__context__
        if cause is None: break
    print('Synthetic device backup diagnostic: '+stage+' '+category+' '+location+' errno='+str(errno_code),flush=True)
    print('Synthetic device backup '+('write' if write_mode else 'verify')+' failed.',flush=True)
finally:
    if isinstance(secret,bytearray):
        for index in range(len(secret)): secret[index]=0
while True: time.sleep(60)
'''


def assembly(value, base, initrd, work, secret, credential, binding, sequence, *, write_mode):
    workspace = work/('assembly-'+str(sequence))
    build.assembly(value, base, workspace, version='0.1.0', sequence=sequence,
                   certificate=secret/'test.crt', private_key=secret/'test.key', initrd_base=initrd)
    recovery_build.prepare(workspace, disk_by_id='/dev/disk/by-id/virtio-lanrith-state-test', credential=credential)
    initrd_root = workspace/'mkosi.images/initrd/mkosi.extra'
    library = initrd_root/'usr/lib/lanrith/lanrith'
    for name in ('recovery_backup_preflight.py', 'recovery_backup_auth.py', 'recovery_backup_files.py',
                 'recovery_backup_device.py', 'recovery_backup_verity.py', 'recovery_restore_layout.py'):
        shutil.copyfile(PROJECT/'lanrith'/name, library/name)
    binary = initrd_root/'usr/bin/lanrith-synthetic-device-backup'
    binary.write_text(hook(binding, write_mode)); binary.chmod(0o755)
    unit = initrd_root/'usr/lib/systemd/system/lanrith-factory.service'
    original = unit.read_text()
    release.require(original.count('ExecStart=/usr/bin/lanrith-recovery\n') == 1,
                    'Synthetic recovery unit differs.')
    unit.write_text(original.replace('ExecStart=/usr/bin/lanrith-recovery\n',
                                     'ExecStart=/usr/bin/lanrith-synthetic-device-backup\n'))
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
    report = {'schema': 1, 'scope': 'synthetic-gated-device-backup-only', 'result': 'fail',
              'branch_overlay_files_matched': matched, 'physical_homelab_qualified': False,
              'production_backup_authorized': False, 'restore_authorized': False,
              'independent_repair_media_admitted': False,
              'filesystem_sha256': release.file_record(base)['sha256'],
              'initrd_sha256': release.file_record(initrd)['sha256'],
              'test_sha256': release.file_record(Path(__file__))['sha256']}
    key = None
    try:
        with tempfile.TemporaryDirectory(prefix='lanrith-device-backup.', dir='/dev/shm') as private:
            secret = Path(private)
            run('openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
                '-subj', '/CN=Lanrith Disposable Device Backup', '-keyout', str(secret/'test.key'),
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
            backup = backup_target(work, partition_mib=512, prepopulate=True)
            binding = {'schema': 1, 'target_disk_by_id': '/dev/disk/by-id/virtio-lanrith-state-test',
                       'state_partuuid': table['partitions'][0]['uuid'].lower(), 'state_uuid': state_uuid,
                       'backup_disk_by_id': '/dev/disk/by-id/virtio-lanrith-backup-test',
                       'backup_partuuid': BACKUP_UUID}
            value = config.load(PROJECT/'examples/minimal.yaml')
            value['hardware']['storage'] = {'root_mib': 6144, 'state_mib': 16384, 'esp_mib': 512,
                                           'target': '/dev/disk/by-id/virtio-unused-target'}
            value['hardware']['boot'] = {'secure_boot': True, 'console': 'ttyS0,115200n8', 'recovery_console': 'ttyS0'}
            value['administration']['root_access'] = 'disabled'
            enrolled = prepare_target_filesystem(value, base, initrd, work, secret, target, state_uuid,
                                                 credential, key, enroll_systemd=True)
            for index in range(len(key)): key[index] = 0
            key = enrolled
            target_hash = release.file_record(target)['sha256']
            for write_mode, sequence in ((True, 32), (False, 33)):
                image = assembly(value, base, initrd, work, secret, credential, binding, sequence, write_mode=write_mode)
                image_hash, before = release.file_record(image)['sha256'], release.file_record(backup)['sha256']
                guest = Guest(work/('guest-write' if write_mode else 'guest-verify'), secret, image,
                              tpm=False, disk_readonly=True, extra_disk=target, extra_disk_readonly=True,
                              backup_disk=backup, backup_disk_readonly=not write_mode)
                try:
                    print('Device backup VM: '+('writing' if write_mode else 'verifying')+' the synthetic fixture.', flush=True)
                    guest.start()
                    event = guest.expect_any([rb'Offline recovery key: ', rb'Synthetic device backup (?:write|verify) failed\.'])
                    release.require(event == 0, 'Synthetic device backup failed before key prompt.')
                    guest.serial.sendall(key+b'\r')
                    event = guest.expect_any([rb'Synthetic device backup (?:write|verify) passed\.',
                                              rb'Synthetic device backup (?:write|verify) failed\.'])
                    if event != 0:
                        report['diagnostic'] = json.loads(guest.last_diagnostic)
                    release.require(event == 0, 'Synthetic device backup fixture failed.')
                finally:
                    guest.close()
                after = release.file_record(backup)['sha256']
                release.require(release.file_record(target)['sha256'] == target_hash and
                                release.file_record(image)['sha256'] == image_hash and
                                (after != before if write_mode else after == before),
                                'Synthetic device backup changed a protected disk.')
            report.update(result='pass', checks=['test-only-gate-override','independent-bound-virtual-disks',
                'read-only-encrypted-source','systemd-recovery-keyslot-validated','wrong-image-no-media-write','wrong-key-no-media-write',
                'authenticated-direct-device-copy','immutable-payload','sealed-header-observation','enrolled-recovery-key-observation','independent-read-only-verification','source-unchanged',
                'verification-media-unchanged','no-production-backup-or-restore-authority'])
    finally:
        if key is not None:
            for index in range(len(key)): key[index] = 0
        report['assessed_at'] = datetime.datetime.now(datetime.timezone.utc).isoformat()
        args.result.write_bytes(release.canonical(report))
    print('Synthetic gated device backup passed.')


if __name__ == '__main__':
    main()
