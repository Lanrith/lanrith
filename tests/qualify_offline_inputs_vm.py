#!/usr/bin/env python3
"""Exercise authenticated serial inspection with bound read-only VM disks.

This uses nonbootable synthetic release artifacts and an experimental recovery
root. It does not admit repair media, select a slot, or qualify physical hardware.
"""

import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

from vm import Guest, PROJECT, regular, run
from qualify_bound_observation_vm import require_matching_base
from lanrith import build, config, media, recovery_build, release, update


SOURCE_UUID = 'abcdefab-1234-1234-1234-123456789abc'
ESP_UUID = 'fedcba98-1234-1234-1234-123456789abc'


def make_release(root, sequence, key):
    root.mkdir()
    files = {'uki': f'lanrith_{sequence}.efi'}
    for index, role in enumerate(update.PARTITION_ROLES, 1):
        uuid = f'12345678-1234-1234-1234-{index:012d}'
        files[role] = f'lanrith_{sequence}_{uuid}.{role}.raw'
    for role, name in files.items():
        (root/name).write_bytes(('synthetic-'+role+'-'+str(sequence)).encode())
    contract = {'schema': 1, 'machine_id': '1'*32,
                'state': {'dns': {'writes': 'dns-v1', 'reads': ['dns-v1']}},
                'trust': {'generation': 1, 'transition': 'steady', 'authorities':
                          {'manifest': '2'*64, 'secure_boot': '3'*64,
                           'verity': '4'*64, 'pcr_policy': '5'*64}}}
    manifest = release.unsigned_manifest(root, purpose='update', version='0.1.0', sequence=sequence,
                                         configuration_sha256='a'*64, files=files, image_contract=contract)
    (root/'release.json').write_bytes(release.canonical(manifest))
    release.sign(root, key)
    return files


def target_disk(work, fallback, files):
    target = work/'synthetic-target.raw'
    with target.open('xb') as stream: stream.truncate(160*1024*1024)
    lines = ['label: gpt', 'unit: sectors', '',
             'start=2048,size=131072,type=c12a7328-f81f-11d2-ba4b-00a0c93ec93b,'+
             'uuid='+ESP_UUID+',name="ESP"']
    offsets = {}
    for index, role in enumerate(update.PARTITION_ROLES, 1):
        uuid = f'12345678-1234-1234-1234-{index:012d}'
        offset = 135168+(index-1)*2048
        offsets[role] = offset*512
        lines.append(f'start={offset},size=2048,type={update.GUIDS[role]},uuid={uuid},name="l_30_{role.replace("-", "_")}"')
    result = subprocess.run(['sfdisk', '--no-reread', str(target)], input=('\n'.join(lines)+'\n').encode(),
                            capture_output=True, timeout=30)
    release.require(result.returncode == 0, 'Synthetic target GPT creation failed.')
    esp = work/'synthetic-esp.raw'
    with esp.open('xb') as stream: stream.truncate(64*1024*1024)
    run('mkfs.vfat', str(esp))
    run('mmd', '-i', str(esp), '::/EFI')
    run('mmd', '-i', str(esp), '::/EFI/Linux')
    run('mcopy', '-i', str(esp), str(fallback/files['uki']), '::/EFI/Linux/'+files['uki'])
    with target.open('r+b') as disk, esp.open('rb') as source:
        disk.seek(2048*512); shutil.copyfileobj(source, disk, 4*1024*1024)
        for role, offset in offsets.items():
            disk.seek(offset); disk.write((fallback/files[role]).read_bytes())
        disk.flush(); os.fsync(disk.fileno())
    esp.unlink()
    return target, offsets


def attach_release_input(work, disk, fallback):
    """Append a read-only input partition without changing signed partitions."""
    before = json.loads(run('sfdisk', '--json', str(disk)))['partitiontable']
    original = work/'signed-before.raw'
    shutil.copyfile(disk, original)
    content_bytes = sum(path.stat().st_size for path in fallback.iterdir() if path.is_file())
    payload_mib = max(64, (content_bytes*6//5+1024**2-1)//1024**2+256)
    with disk.open('r+b') as stream: stream.truncate(disk.stat().st_size+(payload_mib+64)*1024*1024)
    run('sfdisk', '--relocate', 'gpt-bak-std', str(disk))
    definitions = work/'input-definitions'; definitions.mkdir()
    (definitions/'90-recovery-input.conf').write_text(
        '[Partition]\nType=linux-generic\nLabel=lanrith-recovery-input\nUUID='+SOURCE_UUID+
        '\nFormat=ext4\nCopyFiles='+str(fallback)+':/release\nSizeMinBytes='+str(payload_mib)+
        'M\nSizeMaxBytes='+str(payload_mib)+'M\n')
    run('systemd-repart', '--empty=refuse', '--dry-run=no', '--offline=yes',
        '--definitions='+str(definitions), str(disk), timeout=600)
    after = json.loads(run('sfdisk', '--json', str(disk)))['partitiontable']
    fields = ('start', 'size', 'type', 'uuid', 'name', 'attrs', 'bootable')
    release.require(before.get('label') == after.get('label') == 'gpt' and
                    len(after['partitions']) == len(before['partitions'])+1 and all(
                        all(left.get(field) == right.get(field) for field in fields)
                        for left, right in zip(before['partitions'], after['partitions'])),
                    'Synthetic recovery input changed signed partition identities.')
    appended = after['partitions'][-1]
    release.require(appended.get('name') == 'lanrith-recovery-input' and
                    appended.get('uuid', '').lower() == SOURCE_UUID,
                    'Synthetic recovery input identity differs.')
    with original.open('rb') as expected, disk.open('rb') as actual:
        for part in before['partitions']:
            start, size = part['start']*512, part['size']*512
            release.require(media.digest_range(expected, start, size) == media.digest_range(actual, start, size),
                            'Synthetic recovery input changed signed partition bytes.')
    original.unlink()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--base', type=Path, required=True)
    parser.add_argument('--initrd-base', type=Path, required=True)
    parser.add_argument('--work', type=Path, required=True)
    parser.add_argument('--result', type=Path, required=True)
    parser.add_argument('--root-disabled', action='store_true', help='exercise root-disabled recovery image')
    parser.add_argument('--dedicated-export', action='store_true', help='verify the supported recovery release export and media read-back')
    args = parser.parse_args()
    base, initrd, work = regular(args.base), regular(args.initrd_base), args.work
    matched_files = require_matching_base(base)
    release.require(work.is_absolute() and work.parent.resolve() == work.parent and not work.exists(),
                    'Qualification requires a new disposable workspace.')
    work.mkdir(mode=0o700)
    report = {'schema': 1, 'scope': 'synthetic-offline-serial-inspection-only', 'result': 'fail',
              'independent_repair_media_admitted': False, 'physical_homelab_qualified': False,
              'root_disabled_qualified': False, 'root_disabled_recovery_serial_tested': False,
              'branch_overlay_files_matched': matched_files,
              'synthetic_release_artifacts_bootable': False,
              'filesystem_sha256': release.file_record(base)['sha256'],
              'initrd_sha256': release.file_record(initrd)['sha256'],
              'test_sha256': release.file_record(Path(__file__))['sha256']}
    try:
        with tempfile.TemporaryDirectory(prefix='lanrith-offline-authority.', dir='/dev/shm') as private:
            secret = Path(private)
            run('openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
                '-subj', '/CN=Lanrith Synthetic Offline Inspection', '-keyout', str(secret/'test.key'),
                '-out', str(secret/'test.crt'))
            (secret/'test.key').chmod(0o600)
            salt = os.urandom(16)
            digest = hashlib.scrypt(b'disposable-recovery-passphrase', salt=salt, n=32768, r=8, p=1,
                                    dklen=32, maxmem=64*1024*1024)
            credential = secret/'recovery.hash'
            credential.write_text('scrypt:32768:8:1:'+salt.hex()+':'+digest.hex()+'\n'); credential.chmod(0o600)
            fallback = work/'fallback'
            files = make_release(fallback, 30, secret/'test.key')
            target, offsets = target_disk(work, fallback, files)
            value = config.load(PROJECT/'examples/minimal.yaml')
            if args.root_disabled:
                value['administration']['root_access'] = 'disabled'
                value['administration']['serial'] = {'enabled': False}
            value['hardware']['storage'] = {'root_mib': 6144, 'state_mib': 16384, 'esp_mib': 512,
                                           'target': '/dev/disk/by-id/virtio-unused-target'}
            value['hardware']['boot'] = {'secure_boot': True, 'console': 'ttyS0,115200n8', 'recovery_console': 'ttyS0'}
            assembly = work/'assembly'
            identity = build.assembly(value, base, assembly, version='0.1.0', sequence=32,
                           certificate=secret/'test.crt', private_key=secret/'test.key', initrd_base=initrd)
            recovery_build.prepare(assembly, disk_by_id='/dev/disk/by-id/virtio-lanrith-state-test',
                credential=credential, offline_inputs={
                    'release_disk_by_id': '/dev/disk/by-id/virtio-lanrith-qa-disk',
                    'release_partition_uuid': SOURCE_UUID, 'target_esp_uuid': ESP_UUID})
            build.run(assembly)
            disk = assembly/'output/lanrith_32.raw'
            if args.dedicated_export:
                exported = work/'recovery-release'
                build.recovery_payload(assembly, identity, exported)
                release.sign(exported, secret/'test.key')
                manifest = release.verify(exported, secret/'test.crt', purpose='recovery', image_id='lanrith')
                try:
                    release.verify(exported, secret/'test.crt', purpose='update', image_id='lanrith')
                except release.ReleaseError:
                    pass
                else:
                    raise release.ReleaseError('Recovery image was accepted as an ordinary update.')
                media.verify_recovery(str(disk), exported, secret/'test.crt', manifest)
                report['dedicated_recovery_export_verified'] = True
                shutil.rmtree(exported)
            attach_release_input(work, disk, fallback)
            disk_hash = release.file_record(disk)['sha256']
            for tampered in (False, True):
                if tampered:
                    with target.open('r+b') as stream:
                        stream.seek(offsets['root']); original = stream.read(1)
                        release.require(len(original) == 1, 'Synthetic target is truncated.')
                        stream.seek(offsets['root']); stream.write(bytes([original[0]^1])); stream.flush(); os.fsync(stream.fileno())
                before = release.file_record(target)['sha256']
                guest = Guest(work/('guest-tampered' if tampered else 'guest-valid'), secret, disk,
                              tpm=False, disk_readonly=True, extra_disk=target, extra_disk_readonly=True)
                try:
                    print('Offline VM: inspecting '+('tampered' if tampered else 'valid')+' synthetic slot.', flush=True)
                    guest.start()
                    guest.expect(rb'Recovery passphrase: ')
                    if args.root_disabled and not tampered:
                        guest.serial.sendall(b'incorrect-synthetic-passphrase\r')
                        guest.expect(rb'Authentication failed\.')
                        guest.expect(rb'Recovery passphrase: ')
                    guest.serial.sendall(b'disposable-recovery-passphrase\r')
                    guest.expect(rb'recovery> ')
                    guest.serial.sendall(b'inspect\r')
                    event = guest.expect_any([rb'Signed slot inspection passed for deployment 30\.',
                                              rb'Slot inspection failed\.'])
                    release.require(event == (1 if tampered else 0), 'Synthetic inspection gave an unexpected result.')
                    guest.expect(rb'recovery> '); guest.serial.sendall(b'exit\r')
                    guest.expect(rb'Recovery session ended\. Restart verified recovery media\.')
                finally:
                    guest.close()
                release.require(release.file_record(target)['sha256'] == before and
                                release.file_record(disk)['sha256'] == disk_hash,
                                'Synthetic inspection changed a read-only disk.')
            if args.root_disabled and not args.dedicated_export:
                before = release.file_record(target)['sha256']
                guest = Guest(work/'guest-auth-limit', secret, disk, tpm=False, disk_readonly=True,
                              extra_disk=target, extra_disk_readonly=True)
                try:
                    print('Offline VM: checking the serial authentication attempt limit.', flush=True)
                    guest.start()
                    for _ in range(3):
                        guest.expect(rb'Recovery passphrase: ')
                        guest.serial.sendall(b'incorrect-synthetic-passphrase\r')
                        guest.expect(rb'Authentication failed\.')
                    guest.expect(rb'Recovery session closed\.')
                    guest.expect(rb'Recovery session ended\. Restart verified recovery media\.')
                finally:
                    guest.close()
                release.require(release.file_record(target)['sha256'] == before and
                                release.file_record(disk)['sha256'] == disk_hash,
                                'Synthetic authentication changed a read-only disk.')
            report.update(result='pass', checks=['signed-experimental-recovery-boot', 'authenticated-serial-menu',
                'bound-readonly-release-input', 'bound-readonly-target-esp', 'signed-slot-observation',
                'tampered-slot-denied', 'read-only-disks-unchanged', 'no-boot-authorization'])
            report['root_disabled_recovery_serial_tested'] = args.root_disabled
            if args.root_disabled:
                report['checks'].append('incorrect-serial-passphrase-rejected')
                if not args.dedicated_export:
                    report['checks'].append('serial-authentication-attempt-limit')
    finally:
        report['assessed_at'] = datetime.datetime.now(datetime.timezone.utc).isoformat()
        args.result.write_bytes(release.canonical(report))
    print('Synthetic offline serial inspection passed.')


if __name__ == '__main__':
    main()
