#!/usr/bin/env python3
"""Inspect a real signed synthetic router slot from an experimental recovery VM.

The recovery image is not admitted repair media. This uses disposable disks,
does not select a slot, and does not qualify root-disabled or physical systems.
"""

import argparse
from contextlib import ExitStack
import datetime
import hashlib
import json
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import tempfile
import time

from vm import Guest, PROJECT, boot, factory_medium, image, regular, root, run, stop
from qualify_bound_observation_vm import require_matching_base
from qualify_offline_inputs_vm import SOURCE_UUID, attach_release_input
from lanrith import build, config, recovery_build, release


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--base', type=Path, required=True)
    parser.add_argument('--initrd-base', type=Path, required=True)
    parser.add_argument('--work', type=Path, required=True)
    parser.add_argument('--result', type=Path, required=True)
    parser.add_argument('--root-disabled', action='store_true', help='exercise root-disabled recovery image')
    args = parser.parse_args()
    base, initrd, work = regular(args.base), regular(args.initrd_base), args.work
    matched = require_matching_base(base)
    release.require(work.is_absolute() and work.parent.resolve() == work.parent and not work.exists(),
                    'Qualification requires a new disposable workspace.')
    work.mkdir(mode=0o700)
    report = {'schema': 1, 'scope': 'synthetic-real-slot-serial-inspection-only', 'result': 'fail',
              'independent_repair_media_admitted': False, 'physical_homelab_qualified': False,
              'root_disabled_qualified': False, 'root_disabled_real_slot_tested': False,
              'branch_overlay_files_matched': matched,
              'filesystem_sha256': release.file_record(base)['sha256'],
              'initrd_sha256': release.file_record(initrd)['sha256'],
              'test_sha256': release.file_record(Path(__file__))['sha256']}
    try:
        with ExitStack() as resources:
            secret = Path(resources.enter_context(tempfile.TemporaryDirectory(prefix='lanrith-real-offline.', dir='/dev/shm')))
            run('openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
                '-subj', '/CN=Lanrith Disposable Offline Slot', '-keyout', str(secret/'test.key'),
                '-out', str(secret/'test.crt'))
            (secret/'test.key').chmod(0o600)
            run('ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-f', str(secret/'ssh'))
            salt = os.urandom(16)
            digest = hashlib.scrypt(b'disposable-recovery-passphrase', salt=salt, n=32768, r=8, p=1,
                                    dklen=32, maxmem=64*1024*1024)
            credential = secret/'serial.hash'
            credential.write_text('scrypt:32768:8:1:'+salt.hex()+':'+digest.hex()+'\n'); credential.chmod(0o600)
            agent = subprocess.Popen(['ssh-agent', '-D', '-a', str(secret/'agent.sock')],
                stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            resources.callback(stop, agent)
            deadline = time.monotonic()+15
            while not (secret/'agent.sock').exists() and time.monotonic() < deadline: time.sleep(0.1)
            run('ssh-add', str(secret/'ssh'), env={**os.environ, 'SSH_AUTH_SOCK': str(secret/'agent.sock')})
            value = config.load(PROJECT/'examples/minimal.yaml')
            value['hardware']['storage'] = {'root_mib': 6144, 'state_mib': 16384, 'esp_mib': 512,
                                           'target': '/dev/disk/by-id/virtio-lanrith-qa-disk'}
            value['hardware']['boot'] = {'secure_boot': True, 'console': 'ttyS0,115200n8', 'recovery_console': 'ttyS0'}
            value['administration']['serial'] = ({'enabled': False} if args.root_disabled else
                                                  {'enabled': True, 'tty': 'ttyS0'})
            if args.root_disabled:
                value['administration']['root_access'] = 'disabled'
            value['administration']['authorized_keys'] = [(secret/'ssh.pub').read_text().strip()]
            assembly, identity, first = image(value, base, initrd, work, secret, 9)
            target = work/'synthetic-target.raw'
            with target.open('xb') as stream: stream.truncate(40*1024**3)
            medium = factory_medium(assembly, identity, first, work, secret)
            guest = Guest(work/'router-guest', secret, target, medium=medium, tpm=True)
            try:
                print('Real-slot VM: installing the signed synthetic router.', flush=True)
                guest.start()
                event = guest.expect_any([rb'Type ERASE-AND-INSTALL .* to continue: ',
                                          rb'(?:You are in|Entering) emergency mode'])
                release.require(event == 0, 'Synthetic installer entered emergency mode.')
                guest.serial.sendall(b'ERASE-AND-INSTALL /dev/disk/by-id/virtio-lanrith-qa-disk\r')
                guest.expect(rb'Installation read-back passed')
                guest.wait_shutdown(); guest.close(); guest.medium = None
                boot(guest, first=True, root_access=not args.root_disabled)
                if args.root_disabled:
                    status = json.loads(guest.ssh('lanrith-image status', agent=False).stdout)
                    release.require((status.get('accepted') or {}).get('deployment_sequence') == 9,
                                    'Synthetic root-disabled image was not accepted.')
                    guest.control('system_powerdown')
                    guest.wait_shutdown(); guest.close()
                else:
                    guest.ssh('sudo lanrith-runtime accept 9')
                    guest.poweroff()
            finally:
                guest.close()
            table = json.loads(run('sfdisk', '--json', str(target)))['partitiontable']
            esps = [row for row in table['partitions'] if
                    row.get('type', '').lower() == 'c12a7328-f81f-11d2-ba4b-00a0c93ec93b']
            release.require(len(esps) == 1 and isinstance(esps[0].get('uuid'), str),
                            'Synthetic target ESP is ambiguous.')
            esp_uuid = esps[0]['uuid'].lower()
            # The accepted release is retained; installer output is no longer
            # needed and removing it leaves space for the independent image.
            medium.unlink(); shutil.rmtree(work/'factory'); shutil.rmtree(assembly)
            print('Real-slot VM: building the experimental recovery image.', flush=True)
            recovery = work/'recovery-assembly'
            build.assembly(value, base, recovery, version='0.1.0', sequence=32,
                           certificate=secret/'test.crt', private_key=secret/'test.key',
                           serial_hash=None if args.root_disabled else credential, initrd_base=initrd)
            recovery_build.prepare(recovery, disk_by_id='/dev/disk/by-id/virtio-lanrith-state-test',
                credential=credential, offline_inputs={
                    'release_disk_by_id': '/dev/disk/by-id/virtio-lanrith-qa-disk',
                    'release_partition_uuid': SOURCE_UUID, 'target_esp_uuid': esp_uuid})
            build.run(recovery)
            recovery_disk = recovery/'output/lanrith_32.raw'
            attach_release_input(work, recovery_disk, first)
            recovery_hash = release.file_record(recovery_disk)['sha256']
            manifest = release.verify(first, secret/'test.crt', purpose='update', image_id='lanrith')
            artifact = next(item for item in manifest['artifacts'] if item['role'] == 'root')
            table = json.loads(run('sfdisk', '--json', str(target)))['partitiontable']
            roots = [part for part in table['partitions'] if part.get('name') == 'l_9_root']
            expected_uuid = artifact['name'].removeprefix('lanrith_9_').removesuffix('.root.raw')
            release.require(table.get('sectorsize') == 512 and len(roots) == 1 and
                            roots[0].get('uuid', '').lower() == expected_uuid and
                            roots[0].get('type', '').lower() == '4f68bce3-e8cd-4db1-96e7-fbcaf984b709',
                            'Synthetic accepted root differs from its signed identity.')
            for tampered in (False, True):
                if tampered:
                    with (first/artifact['name']).open('rb') as signed:
                        signed.seek(1024); expected = signed.read(1)
                    with target.open('r+b') as disk:
                        offset = roots[0]['start']*512+1024
                        disk.seek(offset); actual = disk.read(1)
                        release.require(len(actual) == 1 and actual == expected,
                                        'Synthetic root byte differs before fault injection.')
                        disk.seek(offset); disk.write(bytes([actual[0]^1])); disk.flush(); os.fsync(disk.fileno())
                before = release.file_record(target)['sha256']
                guest = Guest(work/('recovery-tampered' if tampered else 'recovery-valid'), secret, recovery_disk,
                              tpm=False, disk_readonly=True, extra_disk=target, extra_disk_readonly=True)
                try:
                    print('Real-slot VM: inspecting '+('tampered' if tampered else 'valid')+' signed slot.', flush=True)
                    guest.start(); guest.expect(rb'Recovery passphrase: ')
                    guest.serial.sendall(b'disposable-recovery-passphrase\r')
                    guest.expect(rb'recovery> '); guest.serial.sendall(b'inspect\r')
                    event = guest.expect_any([rb'Signed slot inspection passed for deployment 9\.',
                                              rb'Slot inspection failed\.'])
                    release.require(event == (1 if tampered else 0), 'Synthetic real-slot inspection differed.')
                    guest.expect(rb'recovery> '); guest.serial.sendall(b'exit\r')
                    guest.expect(rb'Recovery session ended\. Restart verified recovery media\.')
                finally:
                    guest.close()
                release.require(release.file_record(target)['sha256'] == before and
                                release.file_record(recovery_disk)['sha256'] == recovery_hash,
                                'Synthetic inspection changed a read-only disk.')
            report.update(result='pass', checks=['signed-factory-install', 'signed-experimental-recovery-boot',
                'authenticated-serial-menu', 'full-signed-router-release', 'bound-readonly-release-and-target',
                'real-installed-slot-observation', 'tampered-slot-denied', 'read-only-disks-unchanged',
                'no-boot-authorization'])
            report['root_disabled_real_slot_tested'] = args.root_disabled
    finally:
        report['assessed_at'] = datetime.datetime.now(datetime.timezone.utc).isoformat()
        args.result.write_bytes(release.canonical(report))
    print('Synthetic real-slot serial inspection passed.')


if __name__ == '__main__':
    main()
