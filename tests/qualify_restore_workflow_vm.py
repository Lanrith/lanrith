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
import re
from pathlib import Path
import shutil
import subprocess
import tempfile
import time

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


def assembly(value, base, initrd, work, secret, credential, binding, sequence, *, write_mode, console_backup=False):
    workspace = work/('assembly-'+str(sequence))
    build.assembly(value, base, workspace, version='0.1.0', sequence=sequence,
                   certificate=secret/'test.crt', private_key=secret/'test.key', initrd_base=initrd)
    if console_backup:
        release.require(write_mode, 'Synthetic console backup requires write mode.')
        recovery_build.RESTORE_RECOVERY_BUILD_QUALIFIED = True # disposable build only
        try:
            recovery_build.prepare(workspace, disk_by_id=binding['target_disk_by_id'], credential=credential,
                                   state_uuid=binding['state_uuid'], offline_backup=binding)
        finally:
            recovery_build.RESTORE_RECOVERY_BUILD_QUALIFIED = False
    else:
        recovery_build.prepare(workspace, disk_by_id='/dev/disk/by-id/virtio-lanrith-state-test', credential=credential)
    initrd_root = workspace/'mkosi.images/initrd/mkosi.extra'
    library = initrd_root/'usr/lib/lanrith/lanrith'
    if console_backup:
        preflight_module = library/'recovery_backup_preflight.py'
        preflight_source = preflight_module.read_text()
        release.require(preflight_source.count('READONLY_PREPARATION_QUALIFIED = False') == 1,
                        'Synthetic disk protection gate differs.')
        preflight_module.write_text(preflight_source.replace('READONLY_PREPARATION_QUALIFIED = False',
                                                              'READONLY_PREPARATION_QUALIFIED = True'))
        module = library/'recovery_backup_device.py'
        source = module.read_text()
        release.require(source.count('BACKUP_WRITE_QUALIFIED = False') == 1, 'Synthetic backup gate differs.')
        module.write_text(source.replace('BACKUP_WRITE_QUALIFIED = False', 'BACKUP_WRITE_QUALIFIED = True'))
        binary = initrd_root/'usr/bin/lanrith-recovery'
        binary.write_text('''#!/usr/bin/python3 -I
import sys
sys.path.insert(0,"/usr/lib/lanrith")
from lanrith import recovery_console,release,update
release.require(all(update.command(["blockdev","--getro",p]).strip()=="0" for p in ("/dev/vdb","/dev/vdb1")),
                "Synthetic target was not initially writable.")
print("Synthetic initially writable target observed.",flush=True)
sys.exit(recovery_console.main())
''')
        binary.chmod(0o755)
        build.run(workspace)
        return workspace/'output'/f'lanrith_{sequence}.raw'
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



RESTORE_SUCCESS = 'Synthetic offline restore passed.'
RESTORE_FAILURE = 'Synthetic offline restore failed.'
RESTORE_INTERRUPT = 'Synthetic restore interruption checkpoint.'

def restore_hook(binding, *, interrupt=False):
    return '''#!/usr/bin/python3 -I
import hashlib,os,re,sys,time
from pathlib import Path
sys.path.insert(0,"/usr/lib/lanrith")
from lanrith import recovery_restore as workflow,recovery_restore_target as target,recovery_restore_transaction as transaction
from lanrith import recovery_console,release,update
value='''+repr(binding)+'''
interrupt='''+repr(interrupt)+'''
secret=None
stage='binding'
try:
    release.require(Path(value['target_disk_by_id']).resolve(strict=True)==Path('/dev/vdb') and
                    Path(value['backup_disk_by_id']).resolve(strict=True)==Path('/dev/vdc'), 'Synthetic disks differ.')
    update.command(['blockdev','--setro','/dev/vdb'])
    update.command(['blockdev','--setro','/dev/vdb1'])
    stage='credential'
    secret=recovery_console.secret_from_tty(sys.stdin.buffer,sys.stdout,prompt='Offline recovery key: ')
    def digest(path):
        result=hashlib.sha256()
        with open(path,'rb',buffering=0) as stream:
            while chunk:=stream.read(1024*1024): result.update(chunk)
        return result.digest()
    before=digest('/dev/vdb')
    workflow.RESTORE_WORKFLOW_QUALIFIED=True # synthetic test only
    workflow.BACKUP_FRESHNESS_QUALIFIED=True # no production freshness proof
    target.TARGET_CLAIM_QUALIFIED=True # synthetic test only
    transaction.RESTORE_WRITE_QUALIFIED=True # synthetic test only
    names=[]
    from lanrith import recovery_inputs
    with recovery_inputs.mounted('/dev/vdc1','ext4') as point:
        names=[p.name for p in (point/'lanrith-backups').iterdir()]
    release.require(len(names)==1,'Synthetic backup count differs.')
    stage='wrong-key'
    wrong=bytearray(b'aaaaaaaa-bbbbbbbb-cccccccc-dddddddd-eeeeeeee-ffffffff-gggggggg-hhhhhhhh')
    try:
        try: workflow.restore(value,names[0],wrong,image_id='lanrith',confirm=lambda name,measurement:name)
        except release.ReleaseError: pass
        else: raise release.ReleaseError('Synthetic wrong key was accepted.')
    finally:
        for i in range(len(wrong)): wrong[i]=0
    release.require(digest('/dev/vdb')==before,'Wrong key changed synthetic target.')
    stage='restore'
    original_copy=transaction.restore_pinned
    def check_other_partition(*args,**kwargs):
        release.require(update.command(['blockdev','--getro','/dev/vdb2']).strip()=='1',
                        'Synthetic non-target partition is not read-only.')
        return original_copy(*args,**kwargs)
    transaction.restore_pinned=check_other_partition
    if interrupt:
        def interrupted_body(source,destination,start,end):
            data=os.pread(source,4096,start)
            release.require(len(data)==4096 and os.pwrite(destination,data,start)==4096,
                            'Synthetic interruption setup failed.')
            os.fsync(destination)
            print('''+repr(RESTORE_INTERRUPT)+''',flush=True)
            while True: time.sleep(60)
        transaction._copy_and_verify=interrupted_body
    result=workflow.restore(value,names[0],secret,image_id='lanrith',confirm=lambda name,measurement:name)
    release.require(result.get('authorized_to_boot') is False and
                    update.command(['blockdev','--getro','/dev/vdb1']).strip()=='1',
                    'Synthetic restore returned unexpected authority or write state.')
    print('''+repr(RESTORE_SUCCESS)+''',flush=True)
except Exception as error:
    category='release' if isinstance(error,release.ReleaseError) else ('os' if isinstance(error,OSError) else 'other')
    allowed={'recovery_restore.py','recovery_restore_target.py','recovery_restore_transaction.py',
             'recovery_restore_layout.py','recovery_backup_preflight.py','recovery_backup_files.py',
             'recovery_backup_verity.py','recovery_backup_auth.py','recovery_inputs.py','factory.py','update.py'}
    location='unknown'
    trace=error.__traceback__
    while trace is not None:
        code=trace.tb_frame.f_code
        module=Path(code.co_filename).name
        if module in allowed and re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]{0,63}',code.co_name):
            location=module+':'+code.co_name+':'+str(trace.tb_lineno)
        trace=trace.tb_next
    number=error.errno if isinstance(error,OSError) and type(error.errno) is int and 1<=error.errno<=4095 else 0
    print('Synthetic offline restore diagnostic: '+stage+' '+category+' '+location+' errno='+str(number),flush=True)
    print('''+repr(RESTORE_FAILURE)+''',flush=True)
finally:
    if isinstance(secret,bytearray):
        for i in range(len(secret)): secret[i]=0
while True: time.sleep(60)
'''


def restore_assembly(value, base, initrd, work, secret, credential, binding, *, interrupt=False, sequence=34,
                     console_mode=False):
    workspace=work/('assembly-'+str(sequence))
    build.assembly(value,base,workspace,version='0.1.0',sequence=sequence,
                   certificate=secret/'test.crt',private_key=secret/'test.key',initrd_base=initrd)
    if console_mode:
        recovery_build.RESTORE_RECOVERY_BUILD_QUALIFIED = True # disposable build only
        try:
            recovery_build.prepare(workspace, disk_by_id=binding['target_disk_by_id'], credential=credential,
                                   state_uuid=binding['state_uuid'], offline_backup=binding)
        finally:
            recovery_build.RESTORE_RECOVERY_BUILD_QUALIFIED = False
    else:
        recovery_build.prepare(workspace,disk_by_id='/dev/disk/by-id/virtio-lanrith-state-test',credential=credential)
    root=workspace/'mkosi.images/initrd/mkosi.extra'
    library=root/'usr/lib/lanrith/lanrith'
    if console_mode:
        # The builder supplies these modules. Open gates only inside this signed,
        # non-exportable synthetic initrd; production source remains unchanged.
        replacements = {'recovery_backup_preflight.py': ('READONLY_PREPARATION_QUALIFIED',),
                        'recovery_restore.py': ('RESTORE_WORKFLOW_QUALIFIED', 'BACKUP_FRESHNESS_QUALIFIED'),
                        'recovery_restore_target.py': ('TARGET_CLAIM_QUALIFIED',),
                        'recovery_restore_transaction.py': ('RESTORE_WRITE_QUALIFIED',)}
        for name, constants in replacements.items():
            module=library/name
            source=module.read_text()
            for constant in constants:
                old=constant+' = False'
                release.require(source.count(old)==1,'Synthetic restore gate differs.')
                source=source.replace(old,constant+' = True')
            module.write_text(source)
        binary=root/'usr/bin/lanrith-recovery'
        binary.write_text('''#!/usr/bin/python3 -I
import sys
sys.path.insert(0,"/usr/lib/lanrith")
from lanrith import recovery_console,recovery_inputs,release,update
release.require(all(update.command(["blockdev","--getro",p]).strip()=="0" for p in ("/dev/vdb","/dev/vdb1")),
                "Synthetic target was not initially writable.")
print("Synthetic initially writable target observed.",flush=True)
with recovery_inputs.mounted("/dev/vdc1","ext4") as point:
    names=[p.name for p in (point/"lanrith-backups").iterdir()]
release.require(len(names)==1,"Synthetic backup count differs.")
print("Synthetic backup ID: "+names[0],flush=True)
sys.exit(recovery_console.main())
''')
        binary.chmod(0o755)
        build.run(workspace)
        return workspace/'output'/f'lanrith_{sequence}.raw'
    for name in ('recovery_backup_preflight.py','recovery_backup_auth.py','recovery_backup_files.py',
                 'recovery_backup_verity.py','recovery_restore_layout.py','recovery_restore_target.py',
                 'recovery_restore_transaction.py','recovery_restore.py'):
        shutil.copyfile(PROJECT/'lanrith'/name,library/name)
    binary=root/'usr/bin/lanrith-synthetic-offline-restore'
    binary.write_text(restore_hook(binding, interrupt=interrupt));binary.chmod(0o755)
    unit=root/'usr/lib/systemd/system/lanrith-factory.service';original=unit.read_text()
    release.require(original.count('ExecStart=/usr/bin/lanrith-recovery\n')==1,'Synthetic recovery unit differs.')
    unit.write_text(original.replace('ExecStart=/usr/bin/lanrith-recovery\n',
                                     'ExecStart=/usr/bin/lanrith-synthetic-offline-restore\n'))
    build.run(workspace)
    return workspace/'output'/f'lanrith_{sequence}.raw'

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--base', type=Path, required=True)
    parser.add_argument('--initrd-base', type=Path, required=True)
    parser.add_argument('--work', type=Path, required=True)
    parser.add_argument('--result', type=Path, required=True)
    parser.add_argument('--interrupt-body', action='store_true',
                        help='kill only the disposable guest during the encrypted body copy')
    parser.add_argument('--console-restore', action='store_true',
                        help='exercise the assembled console with test-only restore gates')
    parser.add_argument('--console-backup', action='store_true',
                        help='exercise the assembled console with a test-only backup gate')
    args = parser.parse_args()
    release.require(not (args.console_restore and args.interrupt_body), 'Synthetic test modes are exclusive.')
    release.require(not args.console_backup or args.console_restore,
                    'Synthetic console backup requires the console restore scenario.')
    base, initrd, work = regular(args.base), regular(args.initrd_base), args.work
    matched = require_matching_base(base)
    release.require(work.is_absolute() and work.parent.resolve() == work.parent and not work.exists(),
                    'Qualification requires a new disposable workspace.')
    release.require(shutil.disk_usage(work.parent).free >= 16*1024**3,
                    'Synthetic restore qualification requires at least 16 GiB free.')
    work.mkdir(mode=0o700)
    report = {'schema': 1, 'scope': 'synthetic-gated-offline-restore-only', 'result': 'fail',
              'branch_overlay_files_matched': matched, 'physical_homelab_qualified': False,
              'production_backup_authorized': False, 'restore_authorized': False,
              'independent_repair_media_admitted': False,
              'simulated_interruption': args.interrupt_body,
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
            # These are disposable initializer artifacts, no longer used after
            # its guest has closed. Keep the target and evidence, not image copies.
            shutil.rmtree(work/'fixture-assembly')
            shutil.rmtree(work/'fixture-guest')
            # A second independent partition verifies that restore protects
            # non-target partitions while the parent disk is writable.
            added = subprocess.run(['sfdisk','--no-reread','--append',str(target)],
                input=b'start=266240,size=32768,type=0fc63daf-8483-4772-8e79-3d69d8477de4,name="synthetic-other"\n',
                capture_output=True,timeout=30)
            release.require(added.returncode == 0, 'Synthetic second partition creation failed.')
            run('sfdisk','--part-attrs',str(target),'2','GUID:59')
            with target.open('r+b',buffering=0) as stream:
                stream.seek(266240*512);stream.write(b'SYNTHETIC-OTHER-PARTITION');stream.flush();os.fsync(stream.fileno())
            table = json.loads(run('sfdisk', '--json', str(target)))['partitiontable']
            release.require(len(table['partitions']) == 2 and table['partitions'][0].get('name') == 'var' and
                            table['partitions'][1].get('name') == 'synthetic-other',
                            'Synthetic state GPT is ambiguous.')
            release.require(table['partitions'][0]['uuid'].lower() == binding['state_partuuid'],
                            'Synthetic state partition identity changed.')
            target_hash = release.file_record(target)['sha256']
            for write_mode, sequence in ((True, 32), (False, 33)):
                release.require(shutil.disk_usage(work).free >= 8*1024**3,
                                'Synthetic restore qualification is low on workspace space.')
                image = assembly(value, base, initrd, work, secret, credential, binding, sequence,
                                 write_mode=write_mode, console_backup=args.console_backup and write_mode)
                image_hash, before = release.file_record(image)['sha256'], release.file_record(backup)['sha256']
                guest = Guest(work/('guest-write' if write_mode else 'guest-verify'), secret, image,
                              tpm=False, disk_readonly=True, extra_disk=target,
                              extra_disk_readonly=not (args.console_backup and write_mode),
                              backup_disk=backup, backup_disk_readonly=not write_mode)
                try:
                    print('Device backup VM: '+('writing' if write_mode else 'verifying')+' the synthetic fixture.', flush=True)
                    guest.start()
                    if args.console_backup and write_mode:
                        guest.expect(rb'Synthetic initially writable target observed\.')
                        guest.expect(rb'Recovery passphrase: ')
                        guest.serial.sendall(b'synthetic-passphrase\r')
                        guest.expect(rb'Recovery console: .*backup')
                        guest.expect(rb'recovery> ')
                        guest.serial.sendall(b'backup\r')
                        guest.expect(rb'Type BACKUP to confirm: ')
                        guest.expect(rb'recovery> ')
                        guest.serial.sendall(b'cancel\r')
                        guest.expect(rb'Backup cancelled\.')
                        release.require(release.file_record(backup)['sha256']==before,
                                        'Declined backup changed synthetic media.')
                        guest.expect(rb'recovery> ')
                        guest.serial.sendall(b'backup\r')
                        guest.expect(rb'Type BACKUP to confirm: ')
                        guest.expect(rb'recovery> ')
                        guest.serial.sendall(b'BACKUP\r')
                        guest.expect(rb'Offline recovery key: ')
                        guest.serial.sendall(b'aaaaaaaa-bbbbbbbb-cccccccc-dddddddd-eeeeeeee-ffffffff-gggggggg-hhhhhhhh\r')
                        guest.expect(rb'Backup failed\.')
                        release.require(release.file_record(backup)['sha256']==before,
                                        'Wrong recovery key changed synthetic backup media.')
                        guest.expect(rb'recovery> ')
                        guest.serial.sendall(b'backup\r')
                        guest.expect(rb'Type BACKUP to confirm: ')
                        guest.expect(rb'recovery> ')
                        guest.serial.sendall(b'BACKUP\r')
                        guest.expect(rb'Offline recovery key: ')
                        guest.serial.sendall(key+b'\r')
                        guest.expect(rb'Backup created: backup-[0-9a-f]{32}\. Restore and freshness are not established\.')
                        guest.expect(rb'recovery> ')
                        guest.serial.sendall(b'exit\r')
                    else:
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
                shutil.rmtree(work/('assembly-'+str(sequence)))
                shutil.rmtree(work/('guest-write' if write_mode else 'guest-verify'))
            # Corrupt only the disposable target's LUKS headers after preserving
            # its authenticated independent backup and original whole-disk hash.
            offset=table['partitions'][0]['start']*table['sectorsize']
            with target.open('r+b',buffering=0) as stream:
                stream.seek(offset); header=stream.read(16)
                release.require(header[:8]==b'LUKS\xba\xbe\x00\x02','Synthetic LUKS header differs.')
                metadata_size=int.from_bytes(header[8:16],'big')
                release.require(metadata_size in (16384,32768,65536,131072,262144,524288,1048576,2097152,4194304),
                                'Synthetic metadata geometry differs.')
                for position in (offset,offset+metadata_size):
                    stream.seek(position);stream.write(bytes(4096))
                # Damage one encrypted payload byte too, so recovery must
                # restore both metadata and data rather than only headers.
                stream.seek(offset+32*1024*1024); byte=stream.read(1)
                release.require(len(byte)==1, 'Synthetic encrypted payload is truncated.')
                stream.seek(offset+32*1024*1024);stream.write(bytes([byte[0]^1]))
                stream.flush();os.fsync(stream.fileno())
            release.require(release.file_record(target)['sha256'] != target_hash,'Synthetic damage was not applied.')
            damaged_hash=release.file_record(target)['sha256']
            release.require(shutil.disk_usage(work).free >= 8*1024**3,
                            'Synthetic restore qualification is low on workspace space.')
            image=restore_assembly(value,base,initrd,work,secret,credential,binding,interrupt=args.interrupt_body,
                                   console_mode=args.console_restore)
            image_hash, backup_hash=release.file_record(image)['sha256'],release.file_record(backup)['sha256']
            guest=Guest(work/'guest-restore',secret,image,tpm=False,disk_readonly=True,
                        extra_disk=target,extra_disk_readonly=False,backup_disk=backup,backup_disk_readonly=True)
            try:
                print('Restore VM: recovering a deliberately damaged synthetic target.',flush=True)
                guest.start()
                if args.console_restore:
                    guest.expect(rb'Synthetic initially writable target observed\.')
                    guest.expect(rb'Synthetic backup ID: ')
                    deadline=time.monotonic()+60
                    found=None
                    while time.monotonic()<deadline:
                        found=re.search(rb'backup-[0-9a-f]{32}',guest.buffer)
                        if found is not None:
                            break
                        time.sleep(0.1)
                    release.require(found is not None,'Synthetic backup identifier was not observed.')
                    name=found.group(0)
                    guest.expect(re.escape(name))
                    guest.expect(rb'Recovery passphrase: ')
                    guest.serial.sendall(b'wrong-passphrase\r')
                    guest.expect(rb'Authentication failed\.')
                    guest.expect(rb'Recovery passphrase: ')
                    guest.serial.sendall(b'synthetic-passphrase\r')
                    guest.expect(rb'Recovery console: .*restore')
                    guest.expect(rb'recovery> ')
                    guest.serial.sendall(b'restore\r')
                    guest.expect(rb'Enter backup ID: ')
                    guest.expect(rb'recovery> ')
                    guest.serial.sendall(name+b'\r')
                    guest.expect(rb'Offline recovery key: ')
                    guest.serial.sendall(b'aaaaaaaa-bbbbbbbb-cccccccc-dddddddd-eeeeeeee-ffffffff-gggggggg-hhhhhhhh\r')
                    guest.expect(rb'Restore failed\.')
                    release.require(release.file_record(target)['sha256']==damaged_hash,
                                    'Wrong recovery key changed synthetic target.')
                    guest.expect(rb'recovery> ')
                    guest.serial.sendall(b'restore\r')
                    guest.expect(rb'Enter backup ID: ')
                    guest.expect(rb'recovery> ')
                    guest.serial.sendall(name+b'\r')
                    guest.expect(rb'Offline recovery key: ')
                    guest.serial.sendall(key+b'\r')
                    guest.expect(rb'Type the backup ID to confirm: ')
                    guest.expect(rb'recovery> ')
                    guest.serial.sendall(b'cancel\r')
                    guest.expect(rb'Restore failed\.')
                    release.require(release.file_record(target)['sha256']==damaged_hash,
                                    'Declined confirmation changed synthetic target.')
                    guest.expect(rb'recovery> ')
                    guest.serial.sendall(b'restore\r')
                    guest.expect(rb'Enter backup ID: ')
                    guest.expect(rb'recovery> ')
                    guest.serial.sendall(name+b'\r')
                    guest.expect(rb'Offline recovery key: ')
                    guest.serial.sendall(key+b'\r')
                    guest.expect(rb'Type the backup ID to confirm: ')
                    guest.expect(rb'recovery> ')
                    guest.serial.sendall(name+b'\r')
                    guest.expect(rb'Restore completed\. Boot compatibility is not established\.')
                    guest.expect(rb'recovery> ')
                    guest.serial.sendall(b'exit\r')
                else:
                    event=guest.expect_any([rb'Offline recovery key: ',re.escape(RESTORE_FAILURE.encode())])
                    release.require(event==0,'Synthetic restore failed before key prompt.')
                    guest.serial.sendall(key+b'\r')
                    if args.interrupt_body:
                        event=guest.expect_any([re.escape(RESTORE_INTERRUPT.encode()),re.escape(RESTORE_FAILURE.encode())])
                        if event!=0: report['diagnostic']=json.loads(guest.last_diagnostic)
                        release.require(event==0,'Synthetic restore did not reach the interruption checkpoint.')
                        guest.process.kill()
                        guest.process.wait(timeout=30)
                    else:
                        event=guest.expect_any([re.escape(RESTORE_SUCCESS.encode()),re.escape(RESTORE_FAILURE.encode())])
                        if event!=0: report['diagnostic']=json.loads(guest.last_diagnostic)
                        release.require(event==0,'Synthetic offline restore failed.')
            finally:
                guest.close()
            if args.interrupt_body:
                with target.open('rb',buffering=0) as stream:
                    stream.seek(offset); primary=stream.read(4096)
                    stream.seek(offset+metadata_size); secondary=stream.read(4096)
                release.require(primary==bytes(4096) and secondary==bytes(4096) and
                                release.file_record(target)['sha256']!=target_hash and
                                release.file_record(backup)['sha256']==backup_hash and
                                release.file_record(image)['sha256']==image_hash,
                                'Synthetic interrupted restore safety observation failed.')
                # The same target and independent backup must remain usable
                # by a fresh recovery boot after the abrupt interruption.
                shutil.rmtree(work/'assembly-34')
                shutil.rmtree(work/'guest-restore')
                release.require(shutil.disk_usage(work).free >= 8*1024**3,
                                'Synthetic retry qualification is low on workspace space.')
                retry_image=restore_assembly(value,base,initrd,work,secret,credential,binding,sequence=35)
                retry_hash=release.file_record(retry_image)['sha256']
                retry=Guest(work/'guest-retry',secret,retry_image,tpm=False,disk_readonly=True,
                            extra_disk=target,extra_disk_readonly=False,backup_disk=backup,backup_disk_readonly=True)
                try:
                    print('Restore VM: retrying after synthetic interruption.',flush=True)
                    retry.start()
                    event=retry.expect_any([rb'Offline recovery key: ',re.escape(RESTORE_FAILURE.encode())])
                    release.require(event==0,'Synthetic restore retry failed before key prompt.')
                    retry.serial.sendall(key+b'\r')
                    event=retry.expect_any([re.escape(RESTORE_SUCCESS.encode()),re.escape(RESTORE_FAILURE.encode())])
                    if event!=0: report['diagnostic']=json.loads(retry.last_diagnostic)
                    release.require(event==0,'Synthetic restore retry failed.')
                finally:
                    retry.close()
                release.require(release.file_record(target)['sha256']==target_hash and
                                release.file_record(backup)['sha256']==backup_hash and
                                release.file_record(retry_image)['sha256']==retry_hash,
                                'Synthetic retry did not recover exact original bytes.')
                report.update(result='pass', scope='synthetic-restore-interruption-and-retry',
                              checks=['test-only-gate-override','wrong-key-denied-before-write',
                                      'non-target-partition-readonly','guest-killed-during-body-copy',
                                      'both-luks-headers-invalid','backup-unchanged',
                                      'fresh-recovery-retry-restored-exact-target',
                                      'no-production-backup-or-restore-authority'])
                return
            release.require(release.file_record(target)['sha256']==target_hash and
                            release.file_record(backup)['sha256']==backup_hash and
                            release.file_record(image)['sha256']==image_hash,
                            'Synthetic restore did not recover exact original target bytes.')
            if args.console_restore:
                report.update(result='pass', scope='synthetic-assembled-console-restore',
                              checks=['test-only-gate-override','assembled-console-policy-and-modules',
                                      'wrong-console-password-denied','wrong-recovery-key-denied',
                                      'declined-confirmation-denied','explicit-backup-id-confirmed','exact-target-byte-recovery',
                                      'backup-unchanged','no-production-backup-or-restore-authority'])
                if args.console_backup:
                    report['checks'].extend(['assembled-console-backup','declined-backup-no-write',
                                             'wrong-backup-key-no-write','confirmed-backup-verified-independently',
                                             'initially-writable-kernel-target-observed','console-protects-writable-target'])
                return
            report.update(result='pass', checks=['test-only-gate-override','independent-bound-virtual-disks',
                'read-only-encrypted-source','systemd-recovery-keyslot-validated','wrong-image-no-media-write','wrong-key-no-media-write',
                'authenticated-direct-device-copy','immutable-payload','sealed-header-observation','enrolled-recovery-key-observation','independent-read-only-verification','source-unchanged',
                'verification-media-unchanged','non-target-partition-readonly','damaged-header-restored','wrong-key-denied-before-write','exact-target-byte-recovery','backup-unchanged','no-production-backup-or-restore-authority'])
    finally:
        if key is not None:
            for index in range(len(key)): key[index] = 0
        report['assessed_at'] = datetime.datetime.now(datetime.timezone.utc).isoformat()
        args.result.write_bytes(release.canonical(report))
    print('Synthetic gated offline restore passed.')


if __name__ == '__main__':
    main()
