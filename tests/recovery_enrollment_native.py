#!/usr/bin/env python3
"""Exercise recovery enrollment on disposable LUKS2 files; print only results."""

import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from lanrith import recovery_enrollment as enrollment
from lanrith.release import ReleaseError, require


def must_stop(action):
    try:
        action()
    except ReleaseError:
        return
    raise AssertionError('Invalid synthetic recovery operation succeeded.')


def main():
    installed = {'boot': {'tpm': 'disabled'}}
    manual = bytearray(b'synthetic ordinary manual method')
    old = bytearray(b'-'.join([b'cccccccc']*8))
    new = bytearray(b'-'.join([b'dddddddd']*8))
    with tempfile.TemporaryDirectory() as temp:
        root = Path(temp)
        device = str(root/'luks2')
        with open(device, 'wb') as stream:
            stream.truncate(48*1024**2)
        require(enrollment.run_private(['luksFormat', '--batch-mode', '--type=luks2', '--pbkdf=pbkdf2',
                                        '--pbkdf-force-iterations=1000', '--key-file=-', device], manual),
                'Could not create disposable encrypted file.')
        uuid = enrollment.volume_id(device)
        original = enrollment.inventory(enrollment.header(device))['keyslots']['0']
        with patch.object(enrollment, 'private_input', return_value=manual.copy()):
            enrollment.add_slot(device, enrollment.header(device), '1', old, False)
        require(enrollment.run_private(['token', 'import', '--token-id', '0', '--json-file=-', device],
                                       json.dumps(enrollment.recovery_token('1')).encode()), 'Fixture token failed.')
        (root/enrollment.LEGACY).touch(mode=0o600)
        with patch.object(enrollment, 'recorded_key', return_value=new.copy()):
            must_stop(lambda: enrollment.enroll(installed, device, root))
        assert not (root/enrollment.MARKER).exists() and not (root/enrollment.INTENT).exists()
        prior = enrollment.header(device)
        with patch.object(enrollment, 'recorded_key', return_value=old.copy()):
            enrollment.enroll(installed, device, root, verification_only=True)
        assert enrollment.verified(root, device, enrollment.header(device)) and enrollment.header(device) == prior
        (root/enrollment.MARKER).unlink()
        # Stop after the fsynced intent. Restart with the durable record at each metadata boundary.
        class Interrupted(Exception):
            pass
        try:
            with patch.object(enrollment, 'recorded_key', return_value=None), patch.object(enrollment, 'fresh_key', return_value=new.copy()), \
                    patch.object(enrollment, 'step', side_effect=Interrupted):
                enrollment.enroll(installed, device, root)
        except Interrupted:
            pass
        assert (root/enrollment.INTENT).is_file() and not (root/enrollment.MARKER).exists()
        for phase in ('prior', 'added', 'tagged', 'untagged', 'retired'):
            intent = enrollment.load(root/enrollment.INTENT)
            authority = enrollment.journal_key(root)
            current = enrollment.header(device)
            assert enrollment.classify(intent, uuid, current, authority) == phase
            assert current['keyslots']['0'] == prior['keyslots']['0'] and enrollment.matches(device, '0', manual)
            forged = {**intent, 'body': {**intent['body'], 'uuid': 'modified'}}
            must_stop(lambda: enrollment.step(device, forged, uuid, current, new, authority, tpm=False))
            changed_prior = {**current, 'keyslots': {**current['keyslots'], '0': {}}}
            must_stop(lambda: enrollment.step(device, intent, uuid, changed_prior, new, authority, tpm=False))
            if phase == 'tagged':
                # A committed but subsequently lost copy may be replaced on an explicit choice.
                # Retire both superseded recovery methods only after validating the third copy.
                with tempfile.TemporaryDirectory() as branch:
                    state = Path(branch)
                    other = str(state/'luks2')
                    shutil.copyfile(device, other)
                    for name in (enrollment.INTENT, enrollment.AUTHORITY):
                        shutil.copy2(root/name, state/name)
                    third = bytearray(b'-'.join([b'ffffffff']*8))
                    with patch.object(enrollment, 'recorded_key', return_value=None), \
                            patch.object(enrollment, 'fresh_key', return_value=third.copy()), \
                            patch.object(enrollment, 'private_input', side_effect=lambda _: manual.copy()):
                        enrollment.enroll(installed, other, state)
                    result = enrollment.header(other)
                    assert set(result['keyslots']) == {'0', '3'} and enrollment.matches(other, '0', manual)
                    assert enrollment.matches(other, '3', third) and enrollment.verified(state, other, result)
            if phase != 'retired':
                assert enrollment.matches(device, '1', old)
            must_stop(lambda: enrollment.step(device, intent, uuid, current, old, authority, tpm=False))
            wrong_uuid = '00000000-0000-0000-0000-000000000001'
            must_stop(lambda: enrollment.step(device, intent, wrong_uuid, current, new, authority, tpm=False))
            changed = {**current, 'keyslots': {**current['keyslots'], '31': current['keyslots']['0']}}
            must_stop(lambda: enrollment.step(device, intent, uuid, changed, new, authority, tpm=False))
            assert enrollment.header(device) == current and not (root/enrollment.MARKER).exists()
            if phase == 'retired':
                break
            with patch.object(enrollment, 'private_input', return_value=manual.copy()):
                done = enrollment.step(device, intent, uuid, current, new, authority, tpm=False,
                                       directory=root, repair_only=phase in ('added', 'untagged'))
            assert not done
        with patch.object(enrollment, 'recorded_key', return_value=new.copy()):
            enrollment.enroll(installed, device, root)
        final = enrollment.header(device)
        assert enrollment.verified(root, device, final) and not (root/enrollment.INTENT).exists()
        assert enrollment.inventory(final)['keyslots']['0'] == original
        assert enrollment.matches(device, '0', manual) and not enrollment.matches(device, '2', old)
        assert set(final['keyslots']) == {'0','2'} and enrollment.recovery_slots(final) == {'1':'2'}
        assert enrollment.matches(device, '2', new)
        for path in root.iterdir():
            if path.name != 'luks2':
                assert new not in path.read_bytes() and old not in path.read_bytes()
    print(subprocess.check_output(['cryptsetup', '--version'], text=True).strip())
    print('PASS manual unlock, legacy verification, wrong copy, replacement, four command boundaries and slot-specific retry')


def tpm_retry():
    """Requires a disposable VM with its own vTPM, loop driver and mount namespace."""
    import contextlib
    from lanrith import early_unlock, factory
    require('rdinit=/fixture-init' in Path('/proc/cmdline').read_text(), 'Requires the disposable fixture guest.')
    subprocess.run(['modprobe', 'loop'], check=True)
    subprocess.run(['modprobe', 'dm-crypt'], check=True)
    subprocess.run(['modprobe', 'tpm_crb'], check=True)
    subprocess.run(['tpm2_pcrextend', '-T', 'device:/dev/tpmrm0', '7:sha256='+('42'*32)], check=True)
    installed = {'boot': {'tpm': 'required'}, 'state_directory': '/var/lib/lanrith'}
    manual = b'disposable-provisioning-credential'
    key = bytearray(b'-'.join([b'bbbbbbbb']*8))
    with tempfile.TemporaryDirectory() as temp:
        root = Path(temp)
        device = str(root/'encrypted')
        with open(device, 'wb') as stream:
            stream.truncate(48*1024**2)
        require(enrollment.run_private(['luksFormat', '--batch-mode', '--type=luks2', '--pbkdf=pbkdf2',
                                        '--pbkdf-force-iterations=1000', '--key-file=-', device], manual),
                'Could not create the synthetic TPM fixture.')
        enrolled = subprocess.run(['systemd-cryptenroll', '--unlock-key-file=/proc/self/fd/0', '--tpm2-device=auto', '--tpm2-pcrs=7:sha256',
                                   '--tpm2-pcrlock=', '--tpm2-public-key-pcrs=', device], input=manual, stdout=subprocess.DEVNULL)
        require(enrolled.returncode == 0, 'Could not enroll the synthetic TPM.')
        ids = early_unlock.tpm_tokens(enrollment.header(device))
        assert len(ids) == 1
        if not early_unlock.token_test(device, ids[0]):
            sample = enrollment.header(device)['tokens'][ids[0]]
            print('Test token direct PCRs', sample.get('tpm2-pcrs'), 'signed PCRs', sample.get('tpm2_pubkey_pcrs'),
                  'bank', sample.get('tpm2-pcr-bank'), flush=True)
            raise AssertionError('Initial software TPM probe failed.')
        enrollment.command(['cryptsetup', 'luksKillSlot', '--batch-mode', device, '0'])
        name = 'test-recovery-native'
        mapper = '/dev/mapper/'+name
        point = root/'state'
        point.mkdir()
        def open_fixture():
            enrollment.command(['cryptsetup', 'open', '--token-only', '--token-type=systemd-tpm2',
                                '--token-id='+ids[0], device, name])
        open_fixture()
        enrollment.command(['mkfs.ext4', '-q', mapper])
        enrollment.command(['mount', '-t', 'ext4', mapper, str(point)])
        directory = point/'lib/lanrith'
        directory.mkdir(parents=True, mode=0o700)
        uuid, prior = enrollment.volume_id(device), enrollment.header(device)
        authority = enrollment.journal_key(directory, create=True)
        intent = enrollment.create_intent(uuid, prior, key, [], authority)
        enrollment.save(directory/enrollment.INTENT, intent)
        enrollment.step(device, intent, uuid, prior, key, authority, tpm=True, directory=directory)
        partial = enrollment.header(device)
        assert enrollment.classify(intent, uuid, partial, authority) == 'added'
        enrollment.command(['umount', str(point)])
        enrollment.command(['cryptsetup', 'close', name])
        class Console(contextlib.AbstractContextManager):
            def __exit__(self, *args):
                pass
            def write(self, status):
                pass
            def private(self, operation):
                operation()
        with patch.object(factory, 'Consoles', return_value=Console()), patch.object(factory, 'require_physical_input'):
            with patch.object(enrollment, 'recorded_key', return_value=bytearray(b'incorrect')):
                must_stop(lambda: enrollment.repair_partial(installed, device, partial))
            assert enrollment.header(device) == partial and not Path('/dev/mapper/lanrith-recovery-inspect').exists()
            with patch.object(enrollment, 'recorded_key', return_value=key.copy()):
                enrollment.repair_partial(installed, device, partial)
        completed = enrollment.header(device)
        assert factory.state_tokens(installed, completed) and early_unlock.token_test(device, ids[0])
        open_fixture()
        enrollment.command(['mount', '-t', 'ext4', mapper, str(point)])
        with patch.object(enrollment, 'recorded_key', return_value=key.copy()):
            enrollment.enroll(installed, device, directory)
        assert enrollment.verified(directory, device, enrollment.header(device))
        enrollment.command(['umount', str(point)])
        enrollment.command(['cryptsetup', 'close', name])
        print('PASS software TPM, restricted ext4 intent inspection, wrong copy refusal, repair, offline key and unchanged TPM')


if __name__ == '__main__':
    main()
    if sys.argv[1:] == ['--disposable-tpm']:
        tpm_retry()
