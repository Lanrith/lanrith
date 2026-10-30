#!/usr/bin/env python3
"""Exercise fs-verity only on a newly created disposable virtual filesystem."""

import argparse
import datetime
import hashlib
import json
from pathlib import Path
import shutil
import tempfile

from lanrith import build, config, recovery_build, release
from qualify_backup_preflight_vm import backup_target
from qualify_bound_observation_vm import require_matching_base
from vm import Guest, PROJECT, regular, run


HOOK = '''#!/usr/bin/python3 -I
import os,sys,time
from pathlib import Path
sys.path.insert(0,"/usr/lib/lanrith")
from lanrith import factory,recovery_backup_verity as verity,release,update
point=Path('/run/synthetic-fsverity')
mounted=False
fd=None
try:
    factory.secure_boot()
    recovery_disk,_=factory.verified_root('/sysroot')
    target=Path('/dev/disk/by-id/virtio-lanrith-state-test').resolve(strict=True)
    release.require(str(target)=='/dev/vdb' and str(target)!=recovery_disk,'Synthetic disk identity differs.')
    point.mkdir(mode=0o700)
    update.command(['mount','-t','ext4','-o','rw,nodev,nosuid,noexec','--','/dev/vdb1',str(point)])
    mounted=True
    payload=point/'lanrith-backups'/'synthetic-payload'
    with payload.open('xb') as stream:
        stream.write(b'synthetic encrypted fixture')
        stream.flush(); os.fsync(stream.fileno())
    payload.chmod(0o600)
    fd=os.open(payload,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:
        measurement=verity.enable(fd)
    except release.ReleaseError as error:
        cause=error.__context__
        number=cause.errno if isinstance(cause,OSError) and type(cause.errno) is int and 1<=cause.errno<=4095 else 0
        print('Synthetic fsverity errno: '+str(number),flush=True)
        raise
    release.require(len(measurement)==32 and verity.measure(fd)==measurement,
                    'Synthetic fsverity measurement differs.')
    try: writable=os.open(payload,os.O_WRONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
    except OSError: pass
    else:
        os.close(writable)
        raise release.ReleaseError('Synthetic verity payload remained writable.')
    os.close(fd); fd=None
    update.command(['umount','--',str(point)])
    mounted=False
    point.rmdir()
    print('Synthetic fsverity passed.',flush=True)
except Exception:
    print('Synthetic fsverity failed.',flush=True)
finally:
    if fd is not None: os.close(fd)
    if mounted:
        try: update.command(['umount','--',str(point)])
        except Exception: pass
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
    report = {'schema': 1, 'scope': 'synthetic-fsverity-filesystem-only', 'result': 'fail',
              'branch_overlay_files_matched': matched, 'physical_homelab_qualified': False,
              'backup_or_restore_authorized': False, 'independent_repair_media_admitted': False,
              'filesystem_sha256': release.file_record(base)['sha256'],
              'initrd_sha256': release.file_record(initrd)['sha256'],
              'test_sha256': release.file_record(Path(__file__))['sha256']}
    try:
        with tempfile.TemporaryDirectory(prefix='lanrith-fsverity.', dir='/dev/shm') as private:
            secret = Path(private)
            run('openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
                '-subj', '/CN=Lanrith Disposable Verity Fixture', '-keyout', str(secret/'test.key'),
                '-out', str(secret/'test.crt'))
            (secret/'test.key').chmod(0o600)
            salt = bytes.fromhex('42'*16)
            digest = hashlib.scrypt(b'synthetic-passphrase', salt=salt, n=32768, r=8, p=1,
                                    dklen=32, maxmem=64*1024*1024)
            credential = secret/'recovery.hash'
            credential.write_text('scrypt:32768:8:1:'+salt.hex()+':'+digest.hex()+'\n')
            credential.chmod(0o600)
            disk = backup_target(work, partition_mib=256, prepopulate=True)
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
            root = assembly/'mkosi.images/initrd/mkosi.extra'
            library = root/'usr/lib/lanrith/lanrith'
            for name in ('recovery_backup_auth.py', 'recovery_backup_verity.py'):
                shutil.copyfile(PROJECT/'lanrith'/name, library/name)
            binary = root/'usr/bin/lanrith-synthetic-fsverity'
            binary.write_text(HOOK); binary.chmod(0o755)
            unit = root/'usr/lib/systemd/system/lanrith-factory.service'
            original = unit.read_text()
            release.require(original.count('ExecStart=/usr/bin/lanrith-recovery\n') == 1,
                            'Synthetic recovery unit differs.')
            unit.write_text(original.replace('ExecStart=/usr/bin/lanrith-recovery\n',
                                             'ExecStart=/usr/bin/lanrith-synthetic-fsverity\n'))
            build.run(assembly)
            image = assembly/'output/lanrith_32.raw'
            image_hash = release.file_record(image)['sha256']
            guest = Guest(work/'guest', secret, image, tpm=False, disk_readonly=True,
                          extra_disk=disk, extra_disk_readonly=False)
            try:
                print('fs-verity VM: checking the disposable filesystem.', flush=True)
                guest.start()
                event = guest.expect_any([rb'Synthetic fsverity passed\.', rb'Synthetic fsverity failed\.'])
                if event != 0:
                    report['diagnostic'] = json.loads(guest.last_diagnostic)
                release.require(event == 0, 'Synthetic fs-verity filesystem test failed.')
            finally:
                guest.close()
            release.require(release.file_record(image)['sha256'] == image_hash,
                            'Synthetic recovery image changed.')
            report.update(result='pass', checks=['secure-boot-recovery-root', 'disposable-ext4-verity',
                'enable-and-measure', 'write-rejected', 'recovery-image-unchanged', 'no-restore-authority'])
    finally:
        report['assessed_at'] = datetime.datetime.now(datetime.timezone.utc).isoformat()
        args.result.write_bytes(release.canonical(report))
    print('Synthetic fs-verity filesystem test passed.')


if __name__ == '__main__':
    main()
