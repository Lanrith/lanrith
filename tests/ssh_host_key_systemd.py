#!/usr/bin/env python3
"""Verify the encrypted-state SSH provisioning contract on a disposable guest."""

import json
import os
from pathlib import Path
import runpy
import shutil
import subprocess
import sys
from unittest.mock import patch

from ssh_listeners_systemd import CHECK, PORT, ROOT, UNIT, V4, V6, config, run, stage, write


STATE = Path('/var/lib/lanrith/ssh-host-keys')
HELPER = Path('/usr/lib/lanrith/ensure-ssh-host-key')
POLICY = Path('/usr/share/lanrith/administration.json')
SERVICE = 'lanrith-ssh-host-key.service'
KEY = STATE/'ssh_host_ed25519_key'
PUB = KEY.with_suffix('.pub')
CURRENT = STATE/'.host-key-identity'
PENDING = STATE/'.host-key-pending'
GEN1 = '1'*32
GEN2 = '2'*32
RECORD = Path('/root/ssh-fixture-record.json')


def policy(rotation='retain', pin=None):
    value = config.load(ROOT/'examples/minimal.yaml')
    value['administration'].update(ssh_port=PORT, root_access='disabled', host_key_rotation=rotation)
    if pin is not None:
        value['administration']['host_key_pin'] = pin
    files = config.render(value)
    write(POLICY, files[str(POLICY)[1:]])
    return files


def stage_guest():
    files = policy()
    stage(files, provision_key=False)
    image = Path('/opt/fixture-platform')
    shutil.copy2(image/'usr/bin/ssh-keyscan', '/usr/bin/ssh-keyscan')
    shutil.copy2(ROOT/'mkosi/base/mkosi.extra'/str(HELPER)[1:], HELPER)
    shutil.copy2(ROOT/'mkosi/base/mkosi.extra/usr/lib/systemd/system'/SERVICE, Path('/run/systemd/system')/SERVICE)
    write('/run/systemd/system/nftables.service', '[Service]\nType=oneshot\nRemainAfterExit=yes\nExecStart=/bin/true\n')
    prepare_network()


def prepare_network():
    run('systemctl', 'stop', 'ssh.socket', check=False)
    run('systemctl', 'mask', '--runtime', 'ssh.socket')
    run('ip', 'link', 'set', 'lo', 'up')
    run('ip', 'link', 'add', 'lan', 'type', 'dummy')
    run('ip', 'link', 'set', 'lan', 'up')
    run('ip', 'addr', 'add', V4+'/24', 'dev', 'lan')
    run('ip', '-6', 'addr', 'add', V6+'/64', 'dev', 'lan', 'nodad')
    run('systemctl', 'daemon-reload')


def fingerprint(path):
    return run('ssh-keygen', '-l', '-E', 'sha256', '-f', path).stdout.split()[1]


def start(expected=None):
    run('systemctl', 'stop', UNIT, check=False)
    run('systemctl', 'reset-failed', SERVICE, UNIT, check=False)
    result = run('systemctl', 'start', UNIT, check=False)
    if expected is False:
        assert result.returncode and run('systemctl', 'is-active', UNIT, check=False).returncode, result
        assert run('systemctl', 'show', '-P', 'Result', SERVICE).stdout.strip() == 'exit-code', (
            result, run('journalctl', '-b', '-u', UNIT, '-u', SERVICE).stdout)
        assert f'{V4}:{PORT}' not in run('ss', '-nlt').stdout
        return
    assert not result.returncode, run('journalctl', '-b', '-u', UNIT, '-u', SERVICE).stdout
    run(CHECK)
    keys = run('ssh-keyscan', '-T', '5', '-p', str(PORT), '-t', 'ed25519', V4).stdout
    assert len([line for line in keys.splitlines() if line and not line.startswith('#')]) == 1 and ' ssh-ed25519 ' in keys, keys
    wire = subprocess.run(['ssh-keygen', '-l', '-E', 'sha256', '-f', '-'], input=keys,
                          text=True, capture_output=True, check=True).stdout.split()[1]
    assert wire == fingerprint(PUB) and (expected is None or wire == expected), (wire, expected)
    return wire


def full_state(fp):
    for options, inode_limited in [('size=128k,nr_inodes=16', False), (f'size=1m,nr_inodes={1 + len(list(STATE.iterdir()))}', True)]:
        # Mount a disposable full state at the production pathname. Both a
        # historical pair and a committed pair must pass without an allocation.
        backup = [(p.name, p.read_bytes(), p.stat().st_mode & 0o777) for p in STATE.iterdir()]
        run('mount', '-t', 'tmpfs', '-o', options+',mode=0700', 'tmpfs', STATE)
        try:
            for name, data, mode in backup:
                target = STATE/name
                target.write_bytes(data)
                target.chmod(mode)
            if inode_limited:
                assert os.statvfs(STATE).f_favail == 0
            else:
                (STATE/'fill').write_bytes(bytes(os.statvfs(STATE).f_bavail * os.statvfs(STATE).f_frsize))
                assert os.statvfs(STATE).f_bavail == 0
            def snapshot():
                return [(p.stat().st_ino, p.stat().st_mtime_ns, p.stat().st_ctime_ns) for p in (STATE, KEY, PUB)]
            before = snapshot()
            start(fp)
            run('mount', '-o', 'remount,ro', STATE)
            start(fp)
            assert snapshot() == before
        finally:
            run('umount', STATE)


def interrupted(name):
    helper = runpy.run_path(str(HELPER))
    original = helper['publish']
    def cut(fd, path, data, mode):
        original(fd, path, data, mode)
        if path.name == name:
            raise InterruptedError('fixture stopped after durable publish')
    with patch.dict(helper['main'].__globals__, publish=cut):
        try:
            helper['main']()
        except InterruptedError:
            return
    raise AssertionError(f'missing interruption point {name}')


def qualification():
    stage_guest()
    fp = start()
    old = KEY.read_bytes()
    old_pub = PUB.read_bytes()
    full_state(fp)
    print('First boot, full blocks/inodes and read-only PID1 startup served the original wire identity.', flush=True)
    KEY.unlink()
    start(False)
    assert PUB.read_bytes() == old_pub
    PUB.unlink()
    start(False)
    KEY.write_bytes(old)
    KEY.chmod(0o600)
    start(fp)
    PUB.write_text('stale\n')
    start(fp)
    saved = Path('/root/ssh-fixture-sidecar')
    saved.write_text('untouched')
    PUB.unlink()
    PUB.symlink_to(saved)
    start(fp)
    assert saved.read_text() == 'untouched' and not PUB.is_symlink()
    KEY.chmod(0o644)
    start(False)
    KEY.chmod(0o600)
    KEY.rename(STATE/'backup')
    KEY.symlink_to(STATE/'backup')
    start(False)
    KEY.unlink()
    (STATE/'backup').rename(KEY)
    CURRENT.unlink()  # An ordinary pre-upgrade retained pair has no receipt.
    start(fp)
    KEY.unlink()
    start(False)
    assert PUB.read_bytes() == old_pub
    KEY.write_bytes(old)
    KEY.chmod(0o600)
    start(fp)
    print('Partial restores blocked the listener. Restoring the original key and repairing sidecars recovered its fingerprint.', flush=True)
    for i, cut in enumerate((PENDING.name, KEY.name, PUB.name, 'receipt', CURRENT.name), 1):
        gen = f'{i:032x}'
        policy(gen)
        interrupted('.rotation-'+gen if cut == 'receipt' else cut)
        transaction = json.loads(PENDING.read_bytes())
        pin = transaction['record']['identity']
        assert PENDING.stat().st_mode & 0o777 == 0o600
        policy()
        start(False)
        policy(gen)
        start(pin['fingerprint'])
        assert not PENDING.exists() and not (STATE/'.host-key-write').exists()
        start(pin['fingerprint'])
    fp_new = pin['fingerprint']
    assert fp_new != fp
    policy(f'{1:032x}')
    start(fp_new)  # Previously consumed generation on the other release.
    policy()
    start(fp_new)
    new = KEY.read_bytes()
    KEY.write_bytes(old)
    start(False)
    KEY.write_bytes(new)
    start(fp_new)
    print('All five durable rotation boundaries converged. Superseded generation and retain slots served the newest committed key.', flush=True)

    # Represent a consistent backup created by a historical rotation helper.
    for path in STATE.glob('.rotation-*'):
        path.unlink()
    CURRENT.unlink()
    marker = STATE/('.rotation-'+GEN1)
    marker.write_text(GEN1+'\n')
    marker.chmod(0o600)
    policy(GEN1)
    start(False)
    policy()
    start(False)
    legacy = marker.read_bytes()
    wrong = {'generation': GEN1, 'fingerprint': fp}
    policy(GEN1, wrong)
    start(False)
    assert marker.read_bytes() == legacy and KEY.read_bytes() == new
    right = {'generation': GEN1, 'fingerprint': fp_new}
    policy('retain', right)
    interrupted(PENDING.name)
    start(fp_new)
    assert json.loads(marker.read_bytes()) == right
    policy(GEN2)
    rotated = start()
    assert rotated != fp_new
    # An independently authorized current generation rejects a complete rollback.
    pin2 = {'generation': GEN2, 'fingerprint': rotated}
    policy('retain', pin2)
    start(rotated)
    for path in STATE.iterdir():
        path.unlink()
    KEY.write_bytes(new)
    KEY.chmod(0o600)
    marker.write_bytes(legacy)
    marker.chmod(0o600)
    start(False)
    print('Legacy adoption required the signed external pin. An older complete restore failed under the current pin.', flush=True)


def historical():
    stage_guest()
    original = Path('/opt/fixture-platform/usr/lib/lanrith/ensure-ssh-host-key')
    run(original)
    assert not CURRENT.exists()
    fp = fingerprint(PUB)
    # The historical contract admitted any group for the root-owned 0600
    # private file. Exercise that exact migration on state with no space.
    os.chown(KEY, 0, 1)
    full_state(fp)
    start(fp)
    old = KEY.read_bytes()
    retained = PUB.read_bytes()
    PUB.unlink()
    PUB.symlink_to('/dev/null')
    start(fp)
    assert PUB.read_bytes() == retained
    os.link(KEY, STATE/'extra-link')
    start(False)
    (STATE/'extra-link').unlink()
    policy(GEN1)
    interrupted(PENDING.name)
    transaction = PENDING.read_bytes()
    PENDING.chmod(0o644)
    start(False)
    PENDING.chmod(0o600)
    recorded = json.loads(transaction)
    recorded['private'] = old.decode('ascii')
    PENDING.write_text(json.dumps(recorded))
    start(False)
    assert KEY.read_bytes() == old
    PENDING.write_bytes(transaction)
    fp1 = json.loads(transaction)['record']['identity']['fingerprint']
    start(fp1)
    snapshot = {p.name: (p.read_bytes(), p.stat().st_mode & 0o777) for p in STATE.iterdir()}
    policy(GEN2)
    # Two callers must land on the same key and remove all private staging.
    jobs = [subprocess.Popen([HELPER]) for _ in range(2)]
    assert all(p.wait(timeout=30) == 0 for p in jobs)
    fp2 = start()
    assert fp1 != fp2 and not PENDING.exists()
    for name, (data, mode) in snapshot.items():
        (STATE/name).write_bytes(data)
        (STATE/name).chmod(mode)
    policy()
    start(False)  # The newer receipt survives a partial older-state restore.
    print('Historical image pair survived read-only/full state. Unsafe staging, hardlinks and mixed receipt histories blocked SSH. Concurrent rotation converged.', flush=True)


def powercycle():
    # The driver must retain its disposable guest disk across abrupt reboots.
    if not RECORD.exists():
        stage_guest()
        start()
        policy(GEN1)
        run('systemctl', 'stop', UNIT)
        # Finish installing the test OS and disable its AF_UNIX SSH generator
        # across reboot before cutting power during the identity transaction.
        generator = Path('/etc/systemd/system-generators/systemd-ssh-generator')
        generator.parent.mkdir(exist_ok=True)
        generator.symlink_to('/dev/null')
        os.sync()
        interrupted(KEY.name)
        identity = json.loads(PENDING.read_bytes())['record']['identity']
        write(RECORD, json.dumps({'phase': 1, 'pin': identity}))
        with RECORD.open() as stream:
            os.fsync(stream.fileno())
        parent = os.open(RECORD.parent, os.O_DIRECTORY)
        os.fsync(parent)
        os.close(parent)
        print('POWER_CUT after durable active private-key replacement', flush=True)
        Path('/proc/sysrq-trigger').write_text('b')
        raise AssertionError('reboot did not occur')
    record = json.loads(RECORD.read_text())
    # /run is fresh on each boot, while the guest keeps the key on ext4.
    shutil.copy2(ROOT/'mkosi/base/mkosi.extra/usr/lib/systemd/system'/SERVICE, Path('/run/systemd/system')/SERVICE)
    write('/run/systemd/system/nftables.service', '[Service]\nType=oneshot\nRemainAfterExit=yes\nExecStart=/bin/true\n')
    Path('/run/sshd').mkdir(exist_ok=True)
    prepare_network()
    pin = record['pin']
    if record['phase'] == 1:
        policy()
        start(False)
        policy(GEN1)
        start(pin['fingerprint'])
        assert not PENDING.exists()
        write(RECORD, json.dumps({'phase': 2, 'pin': pin}))
        os.sync()
        print('Second boot blocked the retain profile during recovery and committed the staged wire key on the rotation profile.', flush=True)
        Path('/proc/sysrq-trigger').write_text('b')
        raise AssertionError('reboot did not occur')
    policy()
    start(pin['fingerprint'])
    print('Third boot served the committed rotation from the fallback retain profile.', flush=True)


if __name__ == '__main__':
    assert os.geteuid() == 0 and 'rdinit=/fixture-init' in Path('/proc/cmdline').read_text()
    assert {row['ifname'] for row in json.loads(run('ip', '-j', 'link').stdout)} == {'lo'}
    if sys.argv[1:] == ['--powercycle']:
        powercycle()
    elif sys.argv[1:] == ['--historical']:
        historical()
    else:
        assert sys.argv[1:] == ['--disposable-systemd']
        qualification()
