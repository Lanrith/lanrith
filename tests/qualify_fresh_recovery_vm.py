#!/usr/bin/env python3
"""Exercise fresh measured boot and a real authenticated fallback without gate overrides."""

import argparse
from contextlib import ExitStack
import datetime
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import time

from lanrith import build, config, release
from qualify_bound_observation_vm import require_matching_base
from vm import Guest, PROJECT, boot, image, regular, root, run, stop, upload


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--base', type=Path, required=True)
    parser.add_argument('--initrd-base', type=Path, required=True)
    parser.add_argument('--work', type=Path, required=True)
    parser.add_argument('--result', type=Path, required=True)
    parser.add_argument('--disk-directory', type=Path, required=True,
                        help='Bounded scratch filesystem for the disposable virtual disk')
    args = parser.parse_args()
    base, initrd, work = regular(args.base), regular(args.initrd_base), args.work
    require_matching_base(base)
    release.require(work.is_absolute() and not work.exists() and work.parent.resolve() == work.parent and
                    shutil.disk_usage(work.parent).free > 12*1024**3 and not args.result.exists() and
                    args.disk_directory.is_absolute() and args.disk_directory.resolve() == args.disk_directory and
                    args.disk_directory.is_dir() and shutil.disk_usage(args.disk_directory).free > 32*1024**3,
                    'Qualification requires fresh bounded VM storage and evidence.')
    work.mkdir(mode=0o700)
    report = {'schema': 1, 'scope': 'fresh-install-measured-boot-recovery', 'result': 'fail',
              'qualification_gates_overridden': False, 'state_compatibility_stubbed': False,
              'physical_hardware_qualified': False, 'checks': [],
              'filesystem_sha256': release.file_record(base)['sha256'],
              'initrd_sha256': release.file_record(initrd)['sha256']}
    guest = None
    try:
        with ExitStack() as resources:
            secret = Path(resources.enter_context(tempfile.TemporaryDirectory(prefix='lanrith-fresh-qa.', dir='/dev/shm')))
            run('openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
                '-subj', '/CN=Disposable fresh recovery test', '-keyout', str(secret/'test.key'),
                '-out', str(secret/'test.crt'))
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
            digest = hashlib.scrypt(b'disposable-recovery-passphrase', salt=salt, n=32768, r=8, p=1,
                                    dklen=32, maxmem=64*1024*1024)
            (secret/'serial.hash').write_text('scrypt:32768:8:1:'+salt.hex()+':'+digest.hex()+'\n')
            (secret/'serial.hash').chmod(0o600)
            value = config.load(PROJECT/'examples/minimal.yaml')
            value['hardware']['storage'] = {'root_mib': 3072, 'state_mib': 4096, 'esp_mib': 512,
                                           'target': '/dev/disk/by-id/virtio-lanrith-qa-disk'}
            value['hardware']['boot'] = {'secure_boot': True, 'tpm': 'required',
                'console': 'ttyS0,115200n8', 'recovery_console': 'ttyS0'}
            value['administration']['authorized_keys'] = [(secret/'ssh.pub').read_text().strip()]
            first_assembly, _, first = image(value, base, initrd, work, secret, 9)
            disk = args.disk_directory/'fresh-recovery-qualification.raw'
            release.require(not disk.exists() and not disk.is_symlink(), 'Disposable disk already exists.')
            shutil.copyfile(first_assembly/'output/lanrith_9.raw', disk)
            with disk.open('r+b') as stream:
                stream.truncate(12*1024**3)
            shutil.rmtree(first_assembly)
            guest = Guest(work/'guest', secret, disk, tpm=True)
            print('Fresh recovery VM: starting the signed installed image.', flush=True)
            boot(guest, first=True)
            guest.ssh('sudo lanrith-runtime accept 9')
            root(guest, 'printf synthetic-persistent-state > /var/lib/lanrith/fresh-recovery-probe')
            before = root(guest, 'sha256sum /var/lib/lanrith/fresh-recovery-probe; cat /etc/machine-id').stdout
            program = ('import sys,json;sys.path.insert(0,"/usr/lib/lanrith");'
                'from lanrith import update,early_unlock;'
                'v=json.load(open("/usr/share/lanrith/installed.json"));'
                'assert v["tpm_policy"]["direct_pcrs"]==[7,15];'
                'assert v["tpm_policy"]["signed_pcrs"]==[11];'
                'assert early_unlock.observation(v)["late_unseal_denied"] is True;'
                'print(json.dumps(update.geometry("/dev/vda")))')
            rows = json.loads(root(guest, 'python3 -I -c '+__import__('shlex').quote(program)).stdout)
            esp = [row for row in rows if row.get('type') == 'c12a7328-f81f-11d2-ba4b-00a0c93ec93b']
            release.require(len(esp) == 1, 'Synthetic boot ESP is ambiguous.')
            report['checks'].append('fresh-PCR-7-11-15-boot-and-late-unseal-denial')
            second = work/'image-10'
            candidate = build.assembly(value, base, second, version='0.1.0', sequence=10,
                certificate=secret/'test.crt', private_key=secret/'test.key', initrd_base=initrd,
                recovery_hash=secret/'serial.hash', fallback_release=first,
                fallback_disk_by_id='/dev/disk/by-id/virtio-lanrith-qa-disk', fallback_esp_uuid=esp[0]['uuid'])
            unit = second/'mkosi.images/initrd/mkosi.extra/usr/lib/systemd/system/lanrith-factory.service'
            with unit.open('a') as stream:
                stream.write('ExecStartPre=/usr/bin/false\n')
            build.run(second)
            update = work/'update-10'
            build.update_payload(second, candidate, update)
            release.sign(update, secret/'test.key')
            uploaded = upload(guest, update)
            guest.ssh('sudo lanrith-runtime promote '+uploaded, timeout=900)
            guest.poweroff()
            shutil.rmtree(second)
            shutil.rmtree(update)
            print('Fresh recovery VM: starting the signed candidate with an injected initrd failure.', flush=True)
            guest.start()
            deadline = time.monotonic()+600
            while guest.process.poll() is None and time.monotonic() < deadline:
                if b'Recovery passphrase: ' in guest.buffer or b'Automatic fallback unavailable' in guest.buffer:
                    raise release.ReleaseError('Candidate held instead of returning to the verified fallback.')
                time.sleep(0.5)
            release.require(guest.process.poll() is not None, 'Failed candidate did not request a bounded reboot.')
            report['diagnostic'] = json.loads(guest.diagnostic())
            release.require(any(item.get('reason') == 'guest-reset' for item in report['diagnostic']['qmp_events']),
                            'Candidate stopped without a guest reset.')
            guest.close()
            boot(guest)
            status = json.loads(guest.ssh('sudo lanrith-runtime status').stdout)
            release.require(status['deployment_sequence'] == 9, 'Fallback booted another image.')
            after = root(guest, 'sha256sum /var/lib/lanrith/fresh-recovery-probe; cat /etc/machine-id').stdout
            release.require(after == before, 'Fallback changed persistent state or identity.')
            guest.poweroff()
            report['checks'] += ['normal-build-path-with-bound-fallback', 'injected-initrd-failure',
                'authenticated-fallback-and-real-state-contract', 'accepted-prior-image-reboot', 'persistent-state-retained']
            report['result'] = 'pass'
    finally:
        if guest is not None:
            if report['result'] != 'pass':
                report['diagnostic'] = json.loads(guest.diagnostic())
            guest.close()
        report['assessed_at'] = datetime.datetime.now(datetime.timezone.utc).isoformat()
        args.result.write_bytes(release.canonical(report))


if __name__ == '__main__':
    main()
