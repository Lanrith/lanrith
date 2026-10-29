#!/usr/bin/env python3
"""Exercise compiled backup/restore admission and the independently kept receipt."""

import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import tempfile
import time

from lanrith import build, config, recovery_build, release
from qualify_backup_preflight_vm import BACKUP_UUID, backup_target
from qualify_bound_observation_vm import require_matching_base
from qualify_recovery_console import encrypted_target, prepare_target_filesystem
from vm import Guest, PROJECT, regular, run


def command(guest, text):
    guest.expect(rb'recovery> ')
    guest.serial.sendall(text+b'\r')


def observed(guest, pattern, timeout=600):
    """Read a public receipt without persisting any raw serial transcript."""
    deadline = time.monotonic()+timeout
    while time.monotonic() < deadline:
        match = re.search(pattern, guest.buffer)
        if match:
            value = match.group(1)
            guest.expect(pattern)
            return value
        release.require(guest.process.poll() is None, 'Disposable recovery guest stopped.')
        time.sleep(0.2)
    raise release.ReleaseError('Disposable recovery receipt was not observed: '+guest.diagnostic())


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('base', 'initrd-base', 'work', 'result'):
        parser.add_argument('--'+name, type=Path, required=True)
    args = parser.parse_args()
    base, initrd, work = regular(args.base), regular(args.initrd_base), args.work
    require_matching_base(base)
    release.require(work.is_absolute() and work.parent.resolve() == work.parent and not work.exists() and
                    not args.result.exists() and shutil.disk_usage(work.parent).free > 12*1024**3,
                    'Use a fresh disposable qualification workspace.')
    work.mkdir(mode=0o700)
    report = {'schema': 1, 'scope': 'compiled-recovery-backup-and-receipt-restore', 'result': 'fail',
              'qualification_gates_overridden': False, 'physical_hardware_qualified': False, 'checks': []}
    guest = key = None
    try:
        with tempfile.TemporaryDirectory(prefix='lanrith-backup-qa.', dir='/dev/shm') as temporary:
            secret = Path(temporary)
            run('openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
                '-subj', '/CN=Disposable admitted backup test', '-keyout', str(secret/'test.key'),
                '-out', str(secret/'test.crt'))
            (secret/'test.key').chmod(0o600)
            salt = os.urandom(16)
            digest = hashlib.scrypt(b'disposable-recovery-passphrase', salt=salt, n=32768, r=8, p=1,
                                    dklen=32, maxmem=64*1024*1024)
            credential = secret/'recovery.hash'
            credential.write_text('scrypt:32768:8:1:'+salt.hex()+':'+digest.hex()+'\n')
            credential.chmod(0o600)
            target, state_uuid, key = encrypted_target(work, synthetic_key=True)
            value = config.load(PROJECT/'examples/minimal.yaml')
            value['hardware']['storage'] = {'root_mib': 3072, 'state_mib': 4096, 'esp_mib': 512,
                                           'target': '/dev/disk/by-id/virtio-unused-target'}
            value['hardware']['boot'] = {'secure_boot': True, 'tpm': 'disabled',
                                        'console': 'ttyS0,115200n8', 'recovery_console': 'ttyS0'}
            value['administration']['root_access'] = 'disabled'
            enrolled = prepare_target_filesystem(value, base, initrd, work, secret, target, state_uuid,
                                                 credential, key, enroll_systemd=True)
            for index in range(len(key)): key[index] = 0
            key = enrolled
            shutil.rmtree(work/'fixture-assembly')
            table = json.loads(run('sfdisk', '--json', str(target)))['partitiontable']
            backup = backup_target(work, partition_mib=512, prepopulate=True)
            binding = {'schema': 1, 'target_disk_by_id': '/dev/disk/by-id/virtio-lanrith-state-test',
                       'state_partuuid': table['partitions'][0]['uuid'].lower(), 'state_uuid': state_uuid,
                       'backup_disk_by_id': '/dev/disk/by-id/virtio-lanrith-backup-test',
                       'backup_partuuid': BACKUP_UUID}
            assembly = work/'recovery-assembly'
            build.assembly(value, base, assembly, version='0.1.0', sequence=40,
                           certificate=secret/'test.crt', private_key=secret/'test.key', initrd_base=initrd)
            recovery_build.prepare(assembly, disk_by_id=binding['target_disk_by_id'], credential=credential,
                                   state_uuid=state_uuid, offline_backup=binding, operations=['backup', 'restore'])
            build.run(assembly)
            image = assembly/'output/lanrith_40.raw'
            original = release.file_record(target)['sha256']
            guest = Guest(work/'backup-guest', secret, image, tpm=False, disk_readonly=True,
                          extra_disk=target, extra_disk_readonly=False, backup_disk=backup,
                          backup_disk_readonly=False)
            print('Admitted recovery VM: creating an authenticated backup through the standard menu.', flush=True)
            guest.start()
            guest.expect(rb'Recovery passphrase: ')
            guest.serial.sendall(b'disposable-recovery-passphrase\r')
            command(guest, b'backup')
            guest.expect(rb'Type BACKUP to confirm: '); command(guest, b'BACKUP')
            guest.expect(rb'Offline recovery key: '); guest.serial.sendall(key+b'\r')
            name = observed(guest, rb'Backup created: (backup-[0-9a-f]{32})\.')
            receipt = observed(guest, rb'Keep this receipt separately from the backup media\. SHA-256: ([0-9a-f]{64})')
            guest.close()
            release.require(release.file_record(target)['sha256'] == original, 'Backup changed encrypted state.')
            backup_hash = release.file_record(backup)['sha256']
            offset = table['partitions'][0]['start']*table['sectorsize']
            with target.open('r+b', buffering=0) as stream:
                stream.seek(offset); header = stream.read(16)
                release.require(header[:8] == b'LUKS\xba\xbe\x00\x02', 'Disposable LUKS geometry differs.')
                metadata_size = int.from_bytes(header[8:16], 'big')
                release.require(16384 <= metadata_size <= 4*1024*1024, 'Disposable metadata size differs.')
                for position in (offset, offset+metadata_size):
                    stream.seek(position); stream.write(bytes(4096))
                stream.seek(offset+32*1024*1024); previous = stream.read(1)
                stream.seek(offset+32*1024*1024); stream.write(bytes([previous[0]^1]))
                stream.flush(); os.fsync(stream.fileno())
            damaged = release.file_record(target)['sha256']
            guest = Guest(work/'restore-guest', secret, image, tpm=False, disk_readonly=True,
                          extra_disk=target, extra_disk_readonly=False, backup_disk=backup,
                          backup_disk_readonly=True)
            print('Admitted recovery VM: checking receipt denial and exact encrypted-state restoration.', flush=True)
            guest.start()
            guest.expect(rb'Recovery passphrase: ')
            guest.serial.sendall(b'disposable-recovery-passphrase\r')
            for correct in (False, True):
                command(guest, b'restore')
                guest.expect(rb'Enter backup ID: '); command(guest, name)
                guest.expect(rb'Offline recovery key: '); guest.serial.sendall(key+b'\r')
                guest.expect(rb'Enter the SHA-256 from your separately stored backup receipt: ')
                command(guest, receipt if correct else b'0'*64)
                if not correct:
                    guest.expect(rb'Restore failed\.')
                    release.require(release.file_record(target)['sha256'] == damaged, 'Wrong receipt changed state.')
                else:
                    guest.expect(rb'Type the backup ID to confirm: '); command(guest, name)
                    guest.expect(rb'Restore completed\.', timeout=900)
            guest.close()
            release.require(release.file_record(target)['sha256'] == original and
                            release.file_record(backup)['sha256'] == backup_hash,
                            'Restore did not recover exact encrypted bytes or changed its backup.')
            report.update(result='pass', checks=['root-disabled-signed-recovery', 'compiled-backup-and-restore-policy',
                'no-gate-overrides', 'initially-writable-target-protected', 'encrypted-state-backup-with-receipt',
                'backup-source-unchanged', 'both-LUKS-headers-and-payload-damaged', 'wrong-receipt-denied-with-no-writes',
                'confirmed-restore-with-independent-receipt', 'exact-encrypted-state-bytes-restored', 'backup-unchanged'])
    finally:
        if guest is not None:
            if report['result'] != 'pass': report['diagnostic'] = json.loads(guest.diagnostic())
            guest.close()
        if key is not None:
            for index in range(len(key)): key[index] = 0
        report['assessed_at'] = datetime.datetime.now(datetime.timezone.utc).isoformat()
        args.result.write_bytes(release.canonical(report))


if __name__ == '__main__':
    main()
