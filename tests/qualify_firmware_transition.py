#!/usr/bin/env python3
"""Cold-boot isolated signed fixture UKIs with disposable OVMF variables, disks and TPM2."""

import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time
import uuid


PROJECT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT))
from lanrith import build, early_unlock, factory, release


OWNER = '33777b74-9386-42fb-822a-f4e381ff3aa1'
INIT = '''#!/bin/sh
set -eu
export PATH=/usr/sbin:/usr/bin:/sbin:/bin
mount -t proc proc /proc
mount -t sysfs sys /sys
mount -t devtmpfs dev /dev
mkdir -p /sys/firmware/efi/efivars /run/systemd /sysroot /mnt
mount -t efivarfs efivarfs /sys/firmware/efi/efivars
for module in virtio_pci virtio_blk tpm_crb dm_mod dm_verity dm_crypt ext4; do modprobe "$module"; done
/usr/lib/systemd/systemd-udevd --daemon
udevadm trigger --action=add
udevadm settle --timeout=30
python3 /fixture/guest.py || true
sync
echo o > /proc/sysrq-trigger
while :; do sleep 1; done
'''


def run(*args, **kwargs):
    return subprocess.run(args, check=True, **kwargs)


def disk(path, mib, table):
    with path.open('xb') as stream:
        stream.truncate(mib*1024**2)
    run('sfdisk', path, input='label: gpt\n'+table, text=True, stdout=subprocess.DEVNULL)


def certificate(root, name):
    crt, key = root/(name+'.crt'), root/(name+'.key')
    run('openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1', '-subj', '/CN=Test '+name,
        '-keyout', key, '-out', crt, capture_output=True)
    return crt, key


def build_uki(root, kernel, initrd, mode, cfg, public, key, cert):
    supplement = root/'supplement'
    supplement.mkdir(exist_ok=True)
    library = supplement/'fixture/lanrith'
    library.mkdir(parents=True, exist_ok=True)
    for source in (PROJECT/'lanrith').glob('*.py'):
        shutil.copyfile(source, library/source.name)
    shutil.copyfile(PROJECT/'tests/firmware_transition_guest.py', supplement/'fixture/guest.py')
    (supplement/'test-config.json').write_bytes(release.canonical({'mode': mode, 'uuid': cfg['state_uuid']}))
    (supplement/'firmware-test-init').write_text(INIT)
    (supplement/'firmware-test-init').chmod(0o755)
    if mode == 'recover':
        dest = supplement/'usr/share/lanrith/recovery-console.json'
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(release.canonical(cfg))
    archive = root/'supplement.cpio'
    with archive.open('wb') as out:
        names = [str(p.relative_to(supplement)).encode() for p in supplement.rglob('*')]
        run('cpio', '--null', '--quiet', '-o', '-H', 'newc', '--owner=0:0', cwd=supplement,
            input=b'\x00'.join(names)+b'\x00', stdout=out)
    result = root/(mode+'.efi')
    cmdline = 'console=ttyS0 rdinit=/firmware-test-init loglevel=3 panic=-1 qa_roothash='+(
        root/'roothash').read_text().strip()
    run('ukify', 'build', '--linux='+str(kernel), '--initrd='+str(initrd), '--initrd='+str(archive),
        '--cmdline='+cmdline, '--os-release=@/etc/os-release', '--uname='+mode,
        '--secureboot-private-key='+str(key), '--secureboot-certificate='+str(cert),
        '--pcr-private-key='+str(key), '--pcr-public-key='+str(public), '--pcr-banks=sha256',
        '--phases=enter-initrd', '--output='+str(result))
    return result


def boot(root, variables, label, *, negative=False):
    print('Cold boot '+label, flush=True)
    sock = root/'tpm.sock'
    sock.unlink(missing_ok=True)
    state = root/'tpm'
    state.mkdir(exist_ok=True)
    tpm = subprocess.Popen(['swtpm', 'socket', '--tpm2', '--tpmstate', 'dir='+str(state),
                            '--ctrl', 'type=unixio,path='+str(sock)])
    try:
        for _ in range(100):
            if sock.exists():
                break
            time.sleep(.03)
        assert sock.exists()
        args = ['qemu-system-x86_64', '-nodefaults', '-no-user-config', '-no-reboot', '-display', 'none',
                '-nic', 'none', '-serial', 'stdio', '-monitor', 'none', '-machine', 'q35,smm=on,accel=tcg',
                '-cpu', 'max', '-smp', '2', '-m', '1536', '-global', 'driver=cfi.pflash01,property=secure,value=on',
                '-drive', 'if=pflash,format=raw,unit=0,readonly=on,file=/usr/share/OVMF/OVMF_CODE_4M.secboot.fd',
                '-drive', 'if=pflash,format=raw,unit=1,file='+str(variables),
                '-chardev', 'socket,id=tpm,path='+str(sock), '-tpmdev', 'emulator,id=t,chardev=tpm',
                '-device', 'tpm-crb,tpmdev=t']
        for index, name in enumerate(('vda', 'vdb'), 1):
            args += ['-drive', 'if=none,format=raw,id='+name+',file='+str(root/name),
                     '-device', 'virtio-blk-pci,drive='+name+',serial=transition-'+name+',bootindex='+str(index)]
        log = root/(label+'.log')
        with log.open('wb') as out:
            vm = subprocess.Popen(args, stdin=subprocess.DEVNULL, stdout=out, stderr=subprocess.STDOUT)
            try:
                deadline = time.monotonic() + 160
                while vm.poll() is None and time.monotonic() < deadline:
                    data = log.read_bytes()
                    if b'Access Denied' in data or b'Security Violation' in data:
                        if not negative:
                            break
                        assert b'FIRMWARE-TEST' not in data
                        return
                    if b'Kernel panic' in data or b'Traceback (most recent call last)' in data:
                        time.sleep(1)
                        break
                    time.sleep(.25)
            finally:
                if vm.poll() is None:
                    vm.terminate()
                vm.wait(timeout=10)
        data = log.read_text(errors='replace')
        for line in data.splitlines():
            if line.startswith('FIRMWARE-TEST ') and not negative:
                return json.loads(line.split(' ', 1)[1])
        raise RuntimeError(label+' failed\n'+data[-4500:])
    finally:
        tpm.terminate()
        tpm.wait(timeout=10)


def qualify(root, kernel, initrd):
    cert, key = certificate(root, 'owner')
    new_db, _ = certificate(root, 'db-change')
    public = root/'pcr.pub'
    run('openssl', 'pkey', '-in', key, '-pubout', '-out', public)
    cfg = {'schema': 1, 'image_id': 'firmware-test', 'tty': 'ttyS0', 'disk_by_id': '/dev/disk/by-id/virtio-transition-vdb',
           'state_uuid': str(uuid.uuid4())}
    part = str(uuid.uuid4())
    disk(root/'vdb', 80, 'start=2048,size=131072,type='+factory.VAR_GUID+',name=var,uuid='+part+'\nstart=133120,size=8192,type=L,name=spare\n')
    disk(root/'vda', 230, 'start=2048,size=409600,type=U\nstart=411648,size=16384,type=L\nstart=428032,size=8192,type=L\n')
    esp = str(root/'vda')+'@@1048576'
    run('mformat', '-F', '-i', esp, '-T', '409600', '::')
    for name in ('EFI', 'EFI/BOOT', 'EFI/Linux', 'EFI/systemd', 'loader'):
        run('mmd', '-i', esp, '::/'+name)
    (root/'loader.conf').write_text('timeout 0\neditor no\n')
    run('mcopy', '-i', esp, root/'loader.conf', '::/loader/loader.conf')
    fs = root/'fs'
    (fs/'usr/lib/systemd').mkdir(parents=True)
    (fs/'usr/share/lanrith').mkdir(parents=True)
    shutil.copyfile(public, fs/'usr/lib/systemd/tpm2-pcr-public-key.pem')
    (fs/'usr/share/lanrith/installed.json').write_bytes(release.canonical({'tpm_policy': early_unlock.policy(public.read_bytes())}))
    run('mkfs.ext4', '-q', '-b', '4096', '-d', fs, '-F', root/'root.ext4', '8192k')
    with (root/'verity').open('wb') as out:
        out.truncate(4*1024**2)
    run('veritysetup', 'format', '--root-hash-file', root/'roothash', root/'root.ext4', root/'verity', capture_output=True)
    with (root/'vda').open('r+b') as out:
        for offset, name in ((411648, 'root.ext4'), (428032, 'verity')):
            out.seek(offset*512)
            with (root/name).open('rb') as inp:
                shutil.copyfileobj(inp, out)
    loader = root/'loader.efi'
    run('sbsign', '--key', key, '--cert', cert, '--output', loader, '/usr/lib/systemd/boot/efi/systemd-bootx64.efi')
    removable = '::/EFI/BOOT/BOOTX64.EFI'
    for entry in (removable, '::/EFI/systemd/systemd-bootx64.efi'):
        run('mcopy', '-i', esp, loader, entry)
    variables = root/'vars.fd'
    template = '/usr/share/OVMF/OVMF_VARS_4M.fd'
    def vars_for(dest, *extra):
        run('virt-fw-vars', '-i', template, '-o', dest, '--enroll-cert', cert, '--no-microsoft',
            '--microsoft-kek=none', '--add-db', OWNER, cert, '--secure-boot', *extra)
    vars_for(variables)
    installed = build_uki(root, kernel, initrd, 'installed', cfg, public, key, cert)
    entry = '::/EFI/Linux/firmware-test.efi'
    run('mcopy', '-i', esp, installed, entry)
    scratch = root/'scratch.efi'
    shutil.copyfile(installed, scratch)
    build.verify_efi_entries(esp, cert, {}, scratch)
    other_crt, other_key = certificate(root, 'unrelated')
    other = root/'unrelated.efi'
    run('sbsign', '--key', other_key, '--cert', other_crt, '--output', other, '/usr/lib/systemd/boot/efi/systemd-bootx64.efi')
    run('mcopy', '-o', '-i', esp, other, removable)
    boot(root, variables, 'unapproved-removable', negative=True)
    run('mcopy', '-o', '-i', esp, loader, removable)
    from virt.firmware.efi import efijson, efivar
    dbx = efivar.EfiVarList()
    dbx.add_cert('dbx', OWNER, str(cert))
    revoked = root/'revoked.json'
    revoked.write_text(json.dumps(dbx, cls=efijson.EfiJSONEncoder))
    vars_for(variables, '--set-json', revoked)
    boot(root, variables, 'revoked-removable', negative=True)
    vars_for(variables)
    first = boot(root, variables, 'owner-removable')
    assert first['result'] == 'unlocked-then-denied'
    vars_for(variables, '--add-db', OWNER, new_db)
    denied = boot(root, variables, 'changed-firmware')
    assert denied['result'] == 'denied-offline-access' and denied['pcr7'] != first['pcr7']
    fallback = build_uki(root, kernel, initrd, 'fallback', cfg, public, key, cert)
    binding = {k: first[k] for k in ('inventory', 'old_token', 'old_slot')}
    cfg.update(operations=['reenroll-tpm'], firmware_transition={**binding, 'pcr7_sha256': denied['pcr7'], 'state_partuuid': part})
    recovery = build_uki(root, kernel, initrd, 'recover', cfg, public, key, cert)
    run('mcopy', '-o', '-i', esp, recovery, entry)
    other_vars = root/'unapproved-destination.fd'
    vars_for(other_vars)
    assert boot(root, other_vars, 'unapproved-destination')['result'] == 'destination-refused'
    assert boot(root, variables, 'interrupted-transition')['result'] == 'interrupted-retirement'
    assert boot(root, variables, 'resumed-transition')['result'] == 'recovered'
    for label, uki in (('retained-cold-boot-one', installed), ('retained-cold-boot-two-fallback', fallback)):
        run('mcopy', '-o', '-i', esp, uki, entry)
        result = boot(root, variables, label)
        assert result['result'] == 'unlocked-then-denied' and result['pcr7'] == denied['pcr7']
        assert result['old_token'] != first['old_token'] and result['old_slot'] != first['old_slot']
    # Remove the removable entry to force the declared installed device path.
    run('mdel', '-i', esp, removable)
    vars_for(variables, '--add-db', OWNER, new_db, '--append-boot-filepath', r'\EFI\systemd\systemd-bootx64.efi')
    assert boot(root, variables, 'direct-systemd-boot')['result'] == 'unlocked-then-denied'
    # Qualify an explicit Debian shim profile with its own firmware authorities.
    shim = Path('/usr/lib/shim/shimx64.efi.signed')
    pin = hashlib.sha256(shim.read_bytes()).hexdigest()
    run('mcopy', '-i', esp, shim, removable)
    run('mcopy', '-i', esp, '/usr/lib/shim/mmx64.efi.signed', '::/EFI/BOOT/mmx64.efi')
    run('mcopy', '-i', esp, loader, '::/EFI/BOOT/grubx64.efi')
    shutil.copyfile(fallback, scratch)
    build.verify_efi_entries(esp, cert, {'removable_shim_sha256': pin}, scratch)
    run('virt-fw-vars', '-i', template, '-o', variables, '--enroll-cert', cert,
        '--add-mok', OWNER, cert, '--secure-boot')
    assert boot(root, variables, 'explicit-vendor-shim')['result'] == 'denied-offline-access'
    print('PASS owner-only removable and installed entries, dbx and unrelated signer refusal, pinned vendor shim, '
          'offline recovery and two cold boots including a second signed fallback.')


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--kernel', required=True, type=Path)
    parser.add_argument('--initrd', required=True, type=Path)
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix='firmware-qualification.') as temporary:
        qualify(Path(temporary), args.kernel, args.initrd)
