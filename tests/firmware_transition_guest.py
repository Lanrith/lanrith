"""Initrd workload for qualify_firmware_transition.py, using only its signed fixture disks."""

import json
from pathlib import Path
import shutil
import subprocess
import sys
import traceback
from unittest.mock import patch

sys.path.insert(0, '/fixture')
from lanrith import early_unlock, factory, firmware_recovery, recovery_enrollment as enrollment
from lanrith import recovery_authority, recovery_state, release, update


def run(*args):
    subprocess.run(args, check=True)


def main():
    cfg = json.loads(Path('/test-config.json').read_bytes())
    cmdline = Path('/proc/cmdline').read_text().split()
    assert 'rdinit=/firmware-test-init' in cmdline
    factory.secure_boot()
    for node in ('vda', 'vdb'):
        assert (Path('/sys/block')/node/'serial').read_text().strip() == 'transition-'+node
    target = '/dev/vdb1'
    alias = Path('/dev/disk/by-id/virtio-transition-vdb')
    alias.parent.mkdir(parents=True, exist_ok=True)
    if not alias.exists():
        alias.symlink_to('/dev/vdb')
    assert str(alias.resolve()) == '/dev/vdb'
    roothash = next(arg.split('=')[1] for arg in cmdline if arg.startswith('qa_roothash='))
    run('veritysetup', 'open', '/dev/vda2', 'fixture-root', '/dev/vda3', roothash)
    run('dmsetup', 'mknodes', 'fixture-root')
    run('mount', '-t', 'ext4', '-o', 'ro,noload', '/dev/mapper/fixture-root', '/sysroot')
    assert factory.verified_root('/sysroot')[0] == '/dev/vda'
    public = firmware_recovery.PUBLIC
    policy = early_unlock.policy(public.read_bytes())
    shutil.copyfile('/.extra/tpm2-pcr-signature.json', firmware_recovery.SIGNATURE)
    run('/usr/lib/systemd/systemd-pcrextend', '--bank=sha256', '--pcr=11', 'enter-initrd')
    early_unlock.in_initrd()
    pcr7 = early_unlock.kernel_text(Path('/sys/class/tpm/tpm0/pcr-sha256/7'), 256).lower()
    secret = bytearray(b'-'.join([b'vvvvvvvv']*8))
    if cfg['mode'] == 'recover':
        profile = json.loads(Path('/usr/share/lanrith/recovery-console.json').read_bytes())
        assert recovery_authority.permits('reenroll-tpm', profile)
        before = enrollment.header(target)
        if pcr7 != profile['firmware_transition']['pcr7_sha256']:
            try:
                firmware_recovery.reenroll(profile, secret)
            except release.ReleaseError as error:
                assert 'destination PCR 7' in str(error)
            else:
                raise AssertionError('Unapproved destination was accepted.')
            assert before == enrollment.header(target)
            return {'result': 'destination-refused'}
        try:
            firmware_recovery.reenroll(profile, bytearray(b'-'.join([b'bbbbbbbb']*8)))
        except release.ReleaseError:
            pass
        else:
            raise AssertionError('Wrong recovery key was accepted.')
        assert before == enrollment.header(target)
        old = profile['firmware_transition']['old_token']
        if old in before['tokens']:
            native_command = update.command
            def interrupt_before_barrier(args, **kwargs):
                if args[0] == '/usr/lib/systemd/systemd-pcrextend':
                    raise InterruptedError('fixture interruption after replacement enrollment')
                return native_command(args, **kwargs)
            with patch.object(update, 'command', side_effect=interrupt_before_barrier):
                try:
                    firmware_recovery.reenroll(profile, secret)
                except InterruptedError:
                    pass
                else:
                    raise AssertionError('Expected fixture interruption.')
            pending = enrollment.header(target)
            assert len(early_unlock.tpm_tokens(pending)) == 2 and enrollment.matches(target, '0', secret)
            native_private = enrollment.run_private
            def interrupt_retirement(args, credential):
                if args[0] == 'luksKillSlot':
                    raise InterruptedError('fixture power loss between predecessor token and keyslot writes')
                return native_private(args, credential)
            with patch.object(enrollment, 'run_private', side_effect=interrupt_retirement):
                try:
                    firmware_recovery.reenroll(profile, secret)
                except InterruptedError:
                    pass
                else:
                    raise AssertionError('Expected retirement interruption.')
            pending = enrollment.header(target)
            assert old not in pending['tokens'] and len(pending['keyslots']) == 3
            assert early_unlock.pcr15() == early_unlock.CLOSED
            assert enrollment.matches(target, '0', secret) and before['keyslots']['0'] == pending['keyslots']['0']
            return {'result': 'interrupted-retirement'}
        firmware_recovery.reenroll(profile, secret)
        after = enrollment.header(target)
        assert before['keyslots']['0'] == after['keyslots']['0'] and enrollment.matches(target, '0', secret)
        assert update.command(['blockdev', '--getro', '/dev/vdb']).strip() == '1'
        return {'result': 'recovered', 'pcr7': pcr7}
    if subprocess.run(['cryptsetup', 'isLuks', target]).returncode:
        assert cfg['mode'] == 'installed'
        assert enrollment.run_private(['luksFormat', '--batch-mode', '--type=luks2', '--uuid', cfg['uuid'],
            '--pbkdf=pbkdf2', '--pbkdf-force-iterations=1000', '--key-file=-', target], secret)
        assert enrollment.run_private(['token', 'import', '--token-id', '0', '--json-file=-', target],
                                      release.canonical(enrollment.recovery_token('0')))
        args = ['systemd-cryptenroll', '--unlock-key-file=/proc/self/fd/0', '--tpm2-device=/dev/tpmrm0',
                '--tpm2-pcrs=7:sha256+15:sha256='+early_unlock.ZERO, '--tpm2-pcrlock=',
                '--tpm2-public-key='+str(public), '--tpm2-public-key-pcrs=11',
                '--tpm2-signature='+firmware_recovery.SIGNATURE, target]
        subprocess.run(args, input=secret, check=True)
        assert enrollment.run_private(['open', '--key-file=-', target, 'fixture-state'], secret)
        run('dmsetup', 'mknodes', 'fixture-state')
        run('mkfs.ext4', '-q', '/dev/mapper/fixture-state')
        run('mount', '-t', 'ext4', '/dev/mapper/fixture-state', '/mnt')
        Path('/mnt/retained').write_text('independent retained data')
        run('umount', '/mnt')
        run('cryptsetup', 'close', 'fixture-state')
    luks = enrollment.header(target)
    factory.enrollment_tokens(luks, tpm_required=True, policy=policy)
    ids = early_unlock.tpm_tokens(luks)
    assert len(ids) == 1
    if not early_unlock.token_test(target, ids[0]):
        # Read the bound state using the offline key, through the production read-only recovery path.
        with recovery_state.open_readonly('/dev/vdb', cfg['uuid'], secret) as point:
            assert (point/'retained').read_text() == 'independent retained data'
        return {'result': 'denied-offline-access', 'pcr7': pcr7}
    run('cryptsetup', 'open', '--token-only', '--token-type=systemd-tpm2', '--token-id', ids[0], target, 'var')
    run('dmsetup', 'mknodes', 'var')
    run('mount', '-t', 'ext4', '-o', 'ro,noload', '/dev/mapper/var', '/mnt')
    assert Path('/mnt/retained').read_text() == 'independent retained data'
    run('umount', '/mnt')
    run('cryptsetup', 'close', 'var')
    run('/usr/lib/systemd/systemd-pcrextend', '--bank=sha256', '--pcr=15', early_unlock.BARRIER)
    assert early_unlock.pcr15() == early_unlock.CLOSED and not early_unlock.token_test(target, ids[0])
    return {'result': 'unlocked-then-denied', 'pcr7': pcr7, 'inventory': enrollment.inventory(luks),
            'old_token': ids[0], 'old_slot': luks['tokens'][ids[0]]['keyslots'][0]}


if __name__ == '__main__':
    try:
        print('FIRMWARE-TEST '+json.dumps(main(), separators=(',', ':')), flush=True)
    except BaseException:
        traceback.print_exc()
        subprocess.run(['sh', '-c', 'dmesg | tail -18'])
        sys.exit(1)
