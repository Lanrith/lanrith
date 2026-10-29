#!/usr/bin/env python3
"""Repair a corrupted fresh installation through the supported recovery menu."""

from contextlib import ExitStack
import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import time

from lanrith import build, config, media, recovery_build, release
from qualify_bound_observation_vm import require_matching_base
from qualify_offline_inputs_vm import attach_release_input, SOURCE_UUID
from vm import Guest, PROJECT, boot, image, regular, root, run, stop


class KeyCapturingGuest(Guest):
    """Keep only this disposable guest's generated key in volatile test memory."""
    recovery_key = None

    def expect_any(self, patterns, timeout=600):
        if self.recovery_key is None and any(b'RECOVERY-KEY-STORED' in pattern for pattern in patterns):
            deadline = time.monotonic()+timeout
            while time.monotonic() < deadline:
                clean = re.sub(rb'\x1b\[[0-9;:?]*[A-Za-z]', b'', self.buffer)
                matches = set(re.findall(rb'\b(?:[a-z]{8}-){7}[a-z]{8}\b', clean))
                if matches:
                    release.require(len(matches) == 1, 'Disposable recovery key observation is ambiguous.')
                    self.recovery_key = bytearray(next(iter(matches)))
                    break
                release.require(self.process.poll() is None and b'Entering emergency mode' not in clean,
                                'Disposable install failed before recovery enrollment.')
                time.sleep(0.2)
            release.require(self.recovery_key is not None, 'Disposable recovery key was not observed.')
        return super().expect_any(patterns, timeout=timeout)


def partition_hashes(disk, rows):
    with disk.open('rb', buffering=0) as stream:
        return {part['uuid']: media.digest_range(stream, part['start']*512, part['size']*512).hex() for part in rows}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('base', 'initrd-base', 'work', 'disk-directory', 'result'):
        parser.add_argument('--'+name, type=Path, required=True)
    args = parser.parse_args()
    base, initrd, work = regular(args.base), regular(args.initrd_base), args.work
    require_matching_base(base)
    release.require(work.is_absolute() and work.parent.resolve() == work.parent and not work.exists() and
                    args.disk_directory.is_dir() and args.disk_directory.resolve() == args.disk_directory and
                    not args.result.exists(), 'Use fresh disposable repair qualification paths.')
    work.mkdir(mode=0o700)
    report = {'schema': 1, 'scope': 'authenticated-state-preserving-OS-slot-repair', 'result': 'fail',
              'qualification_gates_overridden': False, 'physical_hardware_qualified': False, 'checks': []}
    original = recovery = None
    try:
        with ExitStack() as resources:
            secret = Path(resources.enter_context(tempfile.TemporaryDirectory(prefix='lanrith-slot-qa.', dir='/dev/shm')))
            run('openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
                '-subj', '/CN=Disposable OS repair test', '-keyout', str(secret/'test.key'), '-out', str(secret/'test.crt'))
            (secret/'test.key').chmod(0o600)
            run('ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-f', str(secret/'ssh'))
            agent = subprocess.Popen(['ssh-agent', '-D', '-a', str(secret/'agent.sock')],
                stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            resources.callback(stop, agent)
            deadline = time.monotonic()+15
            while not (secret/'agent.sock').exists() and time.monotonic() < deadline:
                time.sleep(0.1)
            run('ssh-add', str(secret/'ssh'), env={**os.environ, 'SSH_AUTH_SOCK': str(secret/'agent.sock')})
            salt = os.urandom(16)
            digest = hashlib.scrypt(b'disposable-recovery-passphrase', salt=salt, n=32768, r=8, p=1, dklen=32,
                                    maxmem=64*1024*1024)
            credential = secret/'recovery.hash'
            credential.write_text('scrypt:32768:8:1:'+salt.hex()+':'+digest.hex()+'\n'); credential.chmod(0o600)
            value = config.load(PROJECT/'examples/minimal.yaml')
            value['hardware']['storage'] = {'root_mib': 3072, 'state_mib': 4096, 'esp_mib': 512,
                                           'target': '/dev/disk/by-id/virtio-lanrith-qa-disk'}
            value['hardware']['boot'] = {'secure_boot': True, 'tpm': 'required',
                                         'console': 'ttyS0,115200n8', 'recovery_console': 'ttyS0'}
            value['administration']['authorized_keys'] = [(secret/'ssh.pub').read_text().strip()]
            assembly, _, first = image(value, base, initrd, work, secret, 9)
            disk = args.disk_directory/'slot-repair-qualification.raw'
            release.require(not disk.exists() and not disk.is_symlink(), 'Disposable target already exists.')
            shutil.copyfile(assembly/'output/lanrith_9.raw', disk)
            with disk.open('r+b') as stream: stream.truncate(12*1024**3)
            shutil.rmtree(assembly)
            original = KeyCapturingGuest(work/'original-guest', secret, disk, tpm=True)
            print('Slot repair VM: creating and accepting the disposable measured installation.', flush=True)
            boot(original, first=True)
            original.ssh('sudo lanrith-runtime accept 9')
            root(original, 'printf preserved-state > /var/lib/lanrith/slot-repair-probe')
            logical_before = root(original, 'sha256sum /var/lib/lanrith/slot-repair-probe; cat /etc/machine-id').stdout
            program = ('import sys,json;sys.path.insert(0,"/usr/lib/lanrith");from lanrith import factory;'
                'v=json.load(open("/usr/share/lanrith/installed.json"));d,s,l=factory.state_metadata(v);'
                'from lanrith.update import command;print(command(["cryptsetup","luksUUID",s]).strip())')
            state_uuid = root(original, 'python3 -I -c '+__import__('shlex').quote(program)).stdout.decode().strip()
            original.poweroff()
            rows = json.loads(run('sfdisk', '--json', str(disk)))['partitiontable']['partitions']
            esps = [part for part in rows if part.get('type', '').lower() == 'c12a7328-f81f-11d2-ba4b-00a0c93ec93b']
            roots = [part for part in rows if part.get('name') == 'l_9_root']
            release.require(len(esps) == len(roots) == 1, 'Disposable installed partitions are ambiguous.')
            root_offset = roots[0]['start']*512+1024
            with disk.open('r+b') as stream:
                stream.seek(root_offset); previous = stream.read(1)
                stream.seek(root_offset); stream.write(bytes([previous[0]^1])); stream.flush(); os.fsync(stream.fileno())
            damaged = partition_hashes(disk, rows)
            repair_value = json.loads(json.dumps(value))
            repair_value['administration']['root_access'] = 'disabled'
            repair_value['administration']['serial'] = {'enabled': False}
            recovery_work = work/'recovery-assembly'
            identity = build.assembly(repair_value, base, recovery_work, version='0.1.0', sequence=99,
                certificate=secret/'test.crt', private_key=secret/'test.key', initrd_base=initrd)
            recovery_build.prepare(recovery_work, disk_by_id='/dev/disk/by-id/virtio-lanrith-state-test',
                credential=credential, state_uuid=state_uuid, operations=['repair'], offline_inputs={
                    'release_disk_by_id': '/dev/disk/by-id/virtio-lanrith-qa-disk',
                    'release_partition_uuid': SOURCE_UUID, 'target_esp_uuid': esps[0]['uuid'].lower()})
            build.run(recovery_work)
            exported = work/'recovery-release'
            build.recovery_payload(recovery_work, identity, exported)
            release.sign(exported, secret/'test.key')
            release.verify(exported, secret/'test.crt', purpose='recovery', image_id='lanrith')
            shutil.rmtree(exported)
            recovery_disk = recovery_work/'output/lanrith_99.raw'
            attach_release_input(work, recovery_disk, first)
            recovery = Guest(work/'recovery-guest', secret, recovery_disk, tpm=True, disk_readonly=True,
                             extra_disk=disk, extra_disk_readonly=False)
            shutil.copyfile(original.work/'vars.fd', recovery.work/'vars.fd')
            shutil.copytree(original.work/'tpm-state', recovery.work/'tpm-state')
            print('Slot repair VM: authenticating to the independent recovery image.', flush=True)
            recovery.start()
            recovery.expect(rb'Recovery passphrase: '); recovery.serial.sendall(b'disposable-recovery-passphrase\r')
            recovery.expect(rb'recovery> '); recovery.serial.sendall(b'repair\r')
            recovery.expect(rb'Offline recovery key: '); recovery.serial.sendall(b'incorrect-offline-key\r')
            recovery.expect(rb'OS slot repair failed\.', timeout=900)
            release.require(partition_hashes(disk, rows) == damaged, 'Incorrect key changed the target.')
            recovery.expect(rb'recovery> '); recovery.serial.sendall(b'repair\r')
            recovery.expect(rb'Offline recovery key: '); recovery.serial.sendall(original.recovery_key+b'\r')
            recovery.expect(rb'Type the deployment number: ', timeout=900); recovery.serial.sendall(b'9\r')
            recovery.expect(rb'OS slot repaired\.', timeout=1200)
            recovery.close()
            restored = partition_hashes(disk, rows)
            selected = {part['uuid'] for part in rows if part.get('type', '').lower() == 'c12a7328-f81f-11d2-ba4b-00a0c93ec93b' or part.get('name') in ('l_9_root', 'l_9_verity', 'l_9_verity_sig')}
            release.require(all(restored[part['uuid']] == damaged[part['uuid']] for part in rows if part['uuid'] not in selected),
                            'OS repair changed encrypted state or the other slot.')
            release.require(json.loads(run('sfdisk', '--json', str(disk)))['partitiontable']['partitions'] == rows,
                            'OS repair changed GPT.')
            for name in ('vars.fd',): shutil.copyfile(recovery.work/name, original.work/name)
            shutil.rmtree(original.work/'tpm-state'); shutil.copytree(recovery.work/'tpm-state', original.work/'tpm-state')
            boot(original)
            release.require(root(original, 'sha256sum /var/lib/lanrith/slot-repair-probe; cat /etc/machine-id').stdout == logical_before,
                            'Repaired boot lost persistent state or identity.')
            original.poweroff()
            report.update(result='pass', checks=['fresh-PCR-7-11-15-installation', 'one-OS-slot-corrupted',
                'root-disabled-independent-recovery', 'incorrect-state-key-denied-with-no-writes',
                'confirmed-signed-slot-repair', 'GPT-and-encrypted-state-unchanged', 'other-slot-unchanged',
                'repaired-image-booted-with-retained-state-and-identity'])
    finally:
        for guest in (original, recovery):
            if guest is not None:
                if report['result'] != 'pass': report['diagnostic'] = json.loads(guest.diagnostic())
                guest.close()
        if original is not None and original.recovery_key is not None:
            for index in range(len(original.recovery_key)): original.recovery_key[index] = 0
        report['assessed_at'] = datetime.datetime.now(datetime.timezone.utc).isoformat()
        args.result.write_bytes(release.canonical(report))


if __name__ == '__main__':
    main()
