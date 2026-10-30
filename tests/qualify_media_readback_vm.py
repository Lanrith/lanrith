#!/usr/bin/env python3
"""Exercise factory-media readback on a disposable read-only virtual device.

This tests the media verifier, not independent repair media, a physical USB,
or permission to install. Only synthetic signing material and disks are used.
"""

import argparse
from contextlib import ExitStack
import datetime
import hashlib
import json
import os
from pathlib import Path
import shlex
import subprocess
import tempfile
import time

from vm import Guest, PROJECT, boot, factory_medium, image, regular, root, run, stop
from lanrith import config, release
from qualify_bound_observation_vm import require_matching_base


CHECK = '''import importlib.util,json,os,re,subprocess,sys,tempfile
from pathlib import Path
sys.path.insert(0,"/usr/lib/lanrith")
from lanrith import release
spec = importlib.util.spec_from_file_location("lanrith.media", "/run/lanrith-media-qualification.py")
media = importlib.util.module_from_spec(spec)
spec.loader.exec_module(media)
target = Path("/dev/disk/by-id/virtio-lanrith-readback").resolve(strict=True)
if target.parent != Path("/dev") or not re.fullmatch(r"[A-Za-z0-9_.-]+", target.name):
    raise RuntimeError("Synthetic media device is unsafe")
listing = json.loads(subprocess.run(["lsblk","--json","--paths","--output","NAME,TYPE,PARTLABEL",str(target)],
    check=True,capture_output=True,timeout=30).stdout)
pending = list(listing["blockdevices"])
matches = []
while pending:
    item = pending.pop()
    pending.extend(item.get("children", []))
    if item.get("type") == "part" and item.get("partlabel") == "lanrith-factory-media":
        matches.append(item["name"])
if len(matches) != 1:
    raise RuntimeError("Synthetic payload device is ambiguous")
point = Path(tempfile.mkdtemp(prefix="lanrith-test-release.", dir="/run"))
try:
    subprocess.run(["mount","-t","ext4","-o","ro,noload,nodev,nosuid,noexec","--",matches[0],str(point)],
        check=True,capture_output=True,timeout=30)
    if not point.is_mount():
        raise RuntimeError("Synthetic payload is not mounted")
    certificate = Path("/usr/share/lanrith/owner.crt")
    manifest = release.verify(point/"release", certificate, purpose="factory", image_id="lanrith")
    media.verify(str(target), point/"release", certificate, manifest)
finally:
    if point.is_mount():
        subprocess.run(["umount","--",str(point)],check=True,capture_output=True,timeout=30)
        if point.is_mount(): raise RuntimeError("Synthetic payload remains mounted")
    point.rmdir()
print("Synthetic media readback passed.")
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
    report = {'schema': 1, 'scope': 'synthetic-factory-media-readback-only', 'result': 'fail',
              'independent_repair_media_qualified': False, 'physical_homelab_qualified': False,
              'branch_overlay_files_matched': matched,
              'filesystem_sha256': release.file_record(base)['sha256'],
              'initrd_sha256': release.file_record(initrd)['sha256'],
              'test_sha256': release.file_record(Path(__file__))['sha256']}
    try:
        with ExitStack() as resources:
            secret = Path(resources.enter_context(tempfile.TemporaryDirectory(prefix='lanrith-media-vm.', dir='/dev/shm')))
            run('openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
                '-subj', '/CN=Lanrith Disposable Media VM', '-keyout', str(secret/'test.key'),
                '-out', str(secret/'test.crt'))
            (secret/'test.key').chmod(0o600)
            run('ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-f', str(secret/'ssh'))
            salt = os.urandom(16)
            digest = hashlib.scrypt(b'disposable-passphrase', salt=salt, n=32768, r=8, p=1,
                                    dklen=32, maxmem=64*1024*1024)
            (secret/'serial.hash').write_text('scrypt:32768:8:1:'+salt.hex()+':'+digest.hex()+'\n')
            (secret/'serial.hash').chmod(0o600)
            agent = subprocess.Popen(['ssh-agent', '-D', '-a', str(secret/'agent.sock')],
                stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            resources.callback(stop, agent)
            deadline = time.monotonic()+15
            while not (secret/'agent.sock').exists() and time.monotonic() < deadline:
                time.sleep(0.1)
            run('ssh-add', str(secret/'ssh'), env={**os.environ, 'SSH_AUTH_SOCK': str(secret/'agent.sock')})
            value = config.load(PROJECT/'examples/minimal.yaml')
            value['hardware']['storage'] = {'root_mib': 6144, 'state_mib': 16384, 'esp_mib': 512,
                                           'target': '/dev/disk/by-id/virtio-lanrith-qa-disk'}
            value['hardware']['boot'] = {'secure_boot': True, 'console': 'ttyS0,115200n8', 'recovery_console': 'ttyS0'}
            value['administration']['serial'] = {'enabled': True, 'tty': 'ttyS0'}
            value['administration']['authorized_keys'] = [(secret/'ssh.pub').read_text().strip()]
            assembly, identity, first = image(value, base, initrd, work, secret, 9)
            disk = work/'installed.raw'
            with disk.open('xb') as stream: stream.truncate(40*1024**3)
            medium = factory_medium(assembly, identity, first, work, secret)
            before = release.file_record(medium)['sha256']
            guest = Guest(work/'guest', secret, disk, medium=medium, tpm=True, hotplug_port=True)
            try:
                print('Media VM: installing synthetic accepted image.', flush=True)
                guest.start()
                event = guest.expect_any([rb'Type ERASE-AND-INSTALL .* to continue: ',
                                          rb'(?:You are in|Entering) emergency mode'])
                release.require(event == 0, 'Synthetic installer entered emergency mode.')
                guest.serial.sendall(b'ERASE-AND-INSTALL /dev/disk/by-id/virtio-lanrith-qa-disk\r')
                guest.expect(rb'Installation read-back passed')
                guest.wait_shutdown(); guest.close(); guest.medium = None
                boot(guest, first=True)
                # Attach the same synthetic medium only after boot to avoid
                # duplicate PARTUUIDs during root discovery. QEMU enforces RO.
                guest.control('blockdev-add', {'node-name': 'lanrith-media-file', 'driver': 'file',
                                              'filename': str(medium), 'read-only': True})
                guest.control('blockdev-add', {'node-name': 'lanrith-media-raw', 'driver': 'raw',
                                              'file': 'lanrith-media-file', 'read-only': True})
                guest.control('device_add', {'driver': 'virtio-blk-pci', 'id': 'lanrith-readback-device',
                                             'drive': 'lanrith-media-raw', 'serial': 'lanrith-readback',
                                             'bus': 'lanrith-hotplug-port'})
                root(guest, 'udevadm settle --timeout=30')
                module = (PROJECT/'lanrith/media.py').read_bytes()
                upload_command = 'sudo sh -c '+shlex.quote('umask 077; cat > /run/lanrith-media-qualification.py')
                sent = subprocess.run(guest.ssh_arguments(upload_command),
                                      input=module, capture_output=True, env=guest.environment, timeout=60)
                release.require(sent.returncode == 0, 'Synthetic verifier upload failed.')
                uploaded_hash = root(guest, 'sha256sum /run/lanrith-media-qualification.py').stdout.split()[0]
                release.require(uploaded_hash == hashlib.sha256(module).hexdigest().encode('ascii'),
                                'Synthetic verifier changed during upload.')
                print('Media VM: verifying the read-only virtual medium.', flush=True)
                result = root(guest, 'python3 -I -c '+shlex.quote(CHECK), timeout=900)
                release.require(b'Synthetic media readback passed.' in result.stdout,
                                'Synthetic media verifier did not complete.')
                guest.poweroff()
                release.require(release.file_record(medium)['sha256'] == before,
                                'Synthetic read-only media bytes changed.')
                report.update(result='pass', checks=['signed-factory-install', 'post-boot-read-only-hotplug',
                    'signed-factory-release', 'real-block-device-readback', 'restricted-payload-mount',
                    'media-bytes-unchanged'])
            finally:
                guest.close()
    finally:
        report['assessed_at'] = datetime.datetime.now(datetime.timezone.utc).isoformat()
        args.result.write_bytes(release.canonical(report))
    print('Synthetic factory-media readback VM passed.')


if __name__ == '__main__':
    main()
