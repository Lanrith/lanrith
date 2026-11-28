"""Real A/B geometry and host job deadlines on a loop disk in a disposable TPM guest."""

from contextlib import ExitStack
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import time
from types import SimpleNamespace
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from lanrith import boot_policy, factory, image_operation, release, runtime, slot_state, update

SYSROOT = Path('/sysroot')
UNIT = 'lanrith-slot-initialization.service'
FOLLOWER = 'slot-fixture-accept.service'


def run(*args, data=None):
    result = subprocess.run(args, input=data, capture_output=True, timeout=90)
    if result.returncode:
        raise RuntimeError(f'{args[0]} failed: ' + result.stderr.decode(errors='replace'))
    return result.stdout.decode().strip()


def worker(root):
    inspect = factory.inspect_state
    original = slot_state.sync_directory

    def sync(directory):
        time.sleep(float((root/'delay').read_text()))
        original(directory)

    # The guest manager runs on its own disk. Verify the mounted test root and
    # its real encrypted /var, then run the normal host CLI and publication.
    with patch.object(factory, 'inspect_state', lambda installed, _: inspect(installed, str(SYSROOT))), \
            patch.object(runtime, 'INSTALLED', root/'installed.json'), patch.object(slot_state, 'sync_directory', sync):
        return runtime.main(['initialize'])


def attach(root, size_mib, sector, stack):
    raw = root/f'fixture-{sector}.raw'
    with raw.open('xb') as stream:
        stream.truncate(size_mib * 1024**2)
    disk = run('losetup', '--find', '--show', '--sector-size', str(sector), '--partscan', str(raw))
    stack.callback(run, 'losetup', '--detach', disk)
    assert Path(run('losetup', '--noheadings', '--output', 'BACK-FILE', disk)) == raw
    return disk


def failed_completion(root, installed):
    # Feed the actual failed manager result into the promotion health boundary.
    # This guest has no signed predecessor or EFI selector to mutate.
    def gate():
        result = run('systemctl', 'show', UNIT, '-p', 'Result', '--value')
        release.require(result == 'success', 'Slot verification did not complete.')
        return installed

    policy = {**installed, 'operator': 'operator', 'uki_name': 'sample_10.efi'}
    previous = image_operation.identity({**policy, 'deployment_sequence': 9, 'uki_name': 'sample_9.efi'})
    lockdir = root/'locks'
    lockdir.mkdir(mode=0o700)
    for bound in (False, True):
        if bound:
            policy['image_contract'] = {'recovery': {'binding': {'release': {'sequence': 9, 'uki_name': 'sample_9.efi'}}}}
            policy['recovery_state'] = {}
            image_operation.save_accepted({**policy, **previous})
            image_operation.save(policy, {'schema': 1, 'phase': 'rebooting', 'digest': '1'*64, 'executor_id': '2'*32,
                'candidate': image_operation.identity(policy), 'fallback': previous, 'error': None})
        policy_path = root/'promotion.json'
        policy_path.write_bytes(release.canonical(policy))
        times = iter((0, 31))
        with patch.object(update, 'IMAGE_LOCK_DIR', lockdir), patch.object(runtime, 'health', gate), \
                patch.object(image_operation, 'time', SimpleNamespace(monotonic=lambda: next(times))), \
                patch('lanrith.credential_operation.wait_ready', return_value=True), \
                patch('lanrith.steady_recovery.runtime_fallback') as fallback:
            try:
                image_operation.complete(policy_path, deadline_seconds=30)
            except release.ReleaseError as error:
                assert 'readiness deadline expired' in str(error)
            else:
                raise AssertionError('Completion accepted a failed initialization')
            assert fallback.call_count == int(bound)
        if bound:
            assert image_operation.visible_accepted(policy) == previous
            assert image_operation.load(policy)['error'] == 'readiness-failed'
        else:
            assert image_operation.visible_accepted(policy) is None
    print('First boot stayed unaccepted. Bound candidate retained predecessor and requested authenticated fallback.',
          flush=True)


def exercise(root, stack, *, tpm):
    assert os.geteuid() == 0 and run('systemd-detect-virt', '--vm') in ('qemu', 'kvm')
    for module in ('loop', 'dm-verity', 'dm-crypt') + (('tpm_crb',) if tpm else ()):
        run('modprobe', module)
    four = attach(root, 24, 4096, stack)
    run('sfdisk', four, data=b'label: gpt\nsize=4MiB,type=L\n')
    run('udevadm', 'settle')
    row, = update.geometry(four)
    assert row['size'] == 4*1024**2 and row['start_bytes'] == 1024**2
    print('4Kn GPT and kernel byte start/size matched', flush=True)

    disk = attach(root, 128, 512, stack)
    labels = {role: 'l_10_'+role.replace('-', '_') for role in update.PARTITION_ROLES}
    sizes = {'root': '16MiB', 'verity': '2MiB', 'verity-sig': '16KiB'}
    lines = ['label: gpt']
    for is_active in (True, False):
        for role in update.PARTITION_ROLES:
            label = labels[role] if is_active else '_empty'
            lines.append(f'size={sizes[role]},type={update.GUIDS[role]},name={label}')
    lines.append('size=64MiB,type='+factory.VAR_GUID+',name=var')
    run('sfdisk', disk, data=('\n'.join(lines)+'\n').encode())
    run('udevadm', 'settle')
    rows = {row['number']: row for row in update.geometry(disk)}
    populated = root/'filesystem'
    (populated/'var').mkdir(parents=True)
    run('mkfs.ext4', '-q', '-b', '4096', '-d', str(populated), rows[3]['device'])
    verity = run('veritysetup', 'format', rows[3]['device'], rows[2]['device'])
    digest, = re.findall(r'^Root hash:\s+([0-9a-f]{64})$', verity, re.MULTILINE)
    run('veritysetup', 'open', rows[3]['device'], 'slot-fixture-root', rows[2]['device'], digest)
    stack.callback(run, 'veritysetup', 'close', 'slot-fixture-root')
    SYSROOT.mkdir(exist_ok=True)
    run('mount', '-t', 'ext4', '-o', 'ro,noload', '/dev/mapper/slot-fixture-root', str(SYSROOT))
    stack.callback(run, 'umount', str(SYSROOT))
    key = os.urandom(32)
    device = rows[7]['device']
    run('cryptsetup', 'luksFormat', '--batch-mode', '--pbkdf=pbkdf2', '--pbkdf-force-iterations=1000',
        '--key-file=-', device, data=key)
    if tpm:
        run('tpm2_pcrextend', '-T', 'device:/dev/tpmrm0', '7:sha256='+('42'*32))
        run('systemd-cryptenroll', '--unlock-key-file=/proc/self/fd/0', '--tpm2-device=auto',
            '--tpm2-pcrs=7:sha256', '--tpm2-pcrlock=', '--tpm2-public-key-pcrs=', device, data=key)
        run('cryptsetup', 'open', '--token-only', '--token-type=systemd-tpm2', device, 'slot-fixture-state')
    else:
        run('cryptsetup', 'open', '--key-file=-', device, 'slot-fixture-state', data=key)
    stack.callback(run, 'cryptsetup', 'close', 'slot-fixture-state')
    mapper = '/dev/mapper/slot-fixture-state'
    run('mkfs.ext4', '-q', mapper)
    run('mount', '-o', 'nodev,noexec,nosuid', mapper, str(SYSROOT/'var'))
    stack.callback(run, 'umount', str(SYSROOT/'var'))
    directory = SYSROOT/'var/lib/lanrith'
    installed = {'active_labels': labels, 'image_id': 'sample', 'deployment_sequence': 10,
                 'configuration_sha256': 'a'*64, 'state_directory': str(directory), 'boot': {'tpm': 'required' if tpm else 'disabled'},
                 'payload_limits': {'uki': 1024**2, **{role: rows[index]['size'] for index, role in
                                                        enumerate(update.PARTITION_ROLES, 1)}}}
    (root/'installed.json').write_bytes(release.canonical(installed))
    (root/'delay').write_text('0')
    if tpm:
        print('Mounted synthetic root:', run('findmnt', '-n', '-o', 'SOURCE,TARGET,FSTYPE,MAJ:MIN', str(SYSROOT)),
              'mapper resolves to:',
              Path('/dev/mapper/slot-fixture-root').resolve(), flush=True)
        assert worker(root) == 0 and slot_state.read_health(installed, max_age_seconds=60)['standby']['available']
        standby = rows[6]['device']
        run('dmsetup', 'create', 'slot-fixture-holder', '--table', '0 16 linear '+standby+' 0')
        try:
            assert worker(root) == 0 and slot_state.read_health(installed, max_age_seconds=60)['standby']['busy'] == ['root']
        finally:
            run('dmsetup', 'remove', 'slot-fixture-holder')
        print('Audited appliance verified live dm-verity, TPM2-opened LUKS2 state and degraded standby.', flush=True)
        return
    unit = boot_policy.slot_initialization_unit({'initialization_timeout_seconds': 8})
    assert 'TimeoutStartSec=120s' in boot_policy.slot_initialization_unit({})
    unit = unit.replace('var.mount', 'sysroot-var.mount').replace('/usr/bin/lanrith-runtime initialize',
        '/usr/bin/python3 '+str(Path(__file__).resolve())+' worker '+str(root))
    units = Path('/run/systemd/system')
    units.mkdir(parents=True, exist_ok=True)
    (units/UNIT).write_text(unit)
    (units/FOLLOWER).write_text('[Unit]\nRequires='+UNIT+'\nAfter='+UNIT+'\n'
        '[Service]\nType=oneshot\nExecStart=/usr/bin/touch '+str(root/'accepted')+'\n')
    run('systemctl', 'daemon-reload')

    def check():
        start = time.monotonic()
        try:
            run('systemctl', 'start', FOLLOWER)
        except RuntimeError:
            print(run('journalctl', '-u', UNIT, '-n', '12', '--no-pager'), flush=True)
            raise
        assert (root/'accepted').is_file()
        (root/'accepted').unlink()
        return round(time.monotonic()-start, 2), slot_state.read_health(installed, max_age_seconds=30)

    elapsed, report = check()
    assert report['standby']['available'] and not report['active_short']
    marker = directory/'slots-initialized'
    assert slot_state.marker(marker) == {'schema': 2, 'disk_uuid': rows[7]['disk_uuid'], 'state_partuuid': rows[7]['uuid']}
    print('Verified first boot, factory-empty standby and LUKS2 state, elapsed seconds', elapsed, flush=True)
    for index, role in enumerate(update.PARTITION_ROLES, 4):
        run('sfdisk', '--part-label', disk, str(index), 'l_9_'+role.replace('-', '_'))
    run('udevadm', 'settle')
    assert check()[1]['standby']['available']
    standby = rows[6]['device']
    run('mkfs.ext4', '-q', standby)
    scratch = root/'mount'
    scratch.mkdir()
    run('mount', '-o', 'ro', standby, str(scratch))
    try:
        assert check()[1]['standby']['busy'] == ['root']
    finally:
        run('umount', str(scratch))
    # The verifier has no view of this second namespace's mount table.
    ready = root/'private-mount-ready'
    ns = subprocess.Popen(['unshare', '--mount', '--propagation=private', '/bin/sh', '-ec',
        'mount -o ro "$1" "$2"; touch "$3"; exec sleep 60', 'fixture', standby, str(scratch), str(ready)])
    try:
        deadline = time.monotonic()+15
        while not ready.exists() and ns.poll() is None and time.monotonic() < deadline:
            time.sleep(0.1)
        assert ready.exists() and not scratch.is_mount() and update.claimed(standby)
        assert check()[1]['standby']['busy'] == ['root']
    finally:
        ns.terminate()
        ns.wait(timeout=5)
    run('dmsetup', 'create', 'slot-fixture-holder', '--table', '0 16 linear '+standby+' 0')
    try:
        assert check()[1]['standby']['busy'] == ['root']
    finally:
        run('dmsetup', 'remove', 'slot-fixture-holder')
    print('Retained standby, mounted root and unmounted kernel holder verified', flush=True)
    marker.unlink()
    (root/'delay').write_text('1')
    elapsed, _ = check()
    assert elapsed >= 2
    print('Delayed successful publication, elapsed seconds', elapsed, flush=True)
    marker.unlink()
    (root/'delay').write_text('12')
    start = time.monotonic()
    assert subprocess.run(['systemctl', 'start', FOLLOWER]).returncode != 0
    elapsed = round(time.monotonic()-start, 2)
    assert run('systemctl', 'show', UNIT, '-p', 'Result', '--value') == 'timeout'
    assert not (root/'accepted').exists() and not marker.exists()
    print('Over-budget storage flush, dependent action withheld, elapsed seconds', elapsed, flush=True)
    failed_completion(root, installed)
    (root/'delay').write_text('0')
    assert check()[1]['standby']['available'] and slot_state.marker(marker)['schema'] == 2
    print('Retry verified LUKS2, verity and the recovered initialization marker', flush=True)


if __name__ == '__main__':
    if sys.argv[1:] in (['--systemd'], ['--tpm']):
        with tempfile.TemporaryDirectory(dir='/run') as temporary, ExitStack() as stack:
            exercise(Path(temporary), stack, tpm=sys.argv[1] == '--tpm')
    elif len(sys.argv) == 3 and sys.argv[1] == 'worker':
        sys.exit(worker(Path(sys.argv[2])))
    else:
        raise SystemExit('Use --systemd in the manager guest or --tpm in the audited TPM guest.')
