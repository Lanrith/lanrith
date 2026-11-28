#!/usr/bin/python3
"""Run in a disposable no-NIC fixture VM. With --reboot re-enter on the same disk."""

import io
import json
import os
from pathlib import Path
import secrets
import shutil
import socket
import sys
import tarfile
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from lanrith import build, config, journal
from unbound_native import run, write

UNITS = Path('/etc/systemd/system')
STATE = Path('/journal-fixture')
DISK = STATE/'state.img'
KEY = STATE/'ephemeral'
RECEIVER = 'fixture-log-sink.service'
FLUSH = journal.FLUSH
POLICY = 'etc/systemd/journald.conf.d/syslog.conf'
RECEIVER_CONTENT = ('[Unit]\nDescription=Fixture local syslog sink\n[Service]\nType=exec\n'
                    'ExecStart=/usr/bin/python3 /source/tests/journal_systemd.py --receive\n')


def receive():
    assert int(os.environ['LISTEN_PID']) == os.getpid() and int(os.environ['LISTEN_FDS']) == 1
    with socket.socket(fileno=3) as sock:
        while True:
            data = sock.recv(65536)
            if b'journal-fixture-' in data:
                with Path('/run/fixture-syslog.log').open('ab') as stream:
                    stream.write(data+b'\n')


def systemctl(*args, check=True):
    return run('systemctl', *args, check=check)


def prop(unit, name):
    return systemctl('show', unit, '-p', name, '--value').stdout.strip()


def require_flush(success=True):
    result = systemctl('restart', FLUSH, check=False)
    status = prop(FLUSH, 'ActiveState')
    if (result.returncode == 0, status) != ((True, 'active') if success else (False, 'failed')):
        raise AssertionError(run('journalctl', '-b', '-u', FLUSH, '-n', '14', '-o', 'cat').stdout)


def stage(policy):
    value = config.load(ROOT/'examples/minimal.yaml')
    value.setdefault('observability', {})['journal'] = policy
    with tempfile.TemporaryDirectory(dir='/run') as tmp:
        temp = Path(tmp)
        base = temp/'base.tar'
        with tarfile.open(base, 'w') as tar:
            if policy.get('syslog_receiver_unit'):
                unit = tarfile.TarInfo('usr/lib/systemd/system/'+RECEIVER)
                unit.size = len(RECEIVER_CONTENT)
                tar.addfile(unit, io.BytesIO(RECEIVER_CONTENT.encode()))
                write('/usr/lib/systemd/system/'+RECEIVER, RECEIVER_CONTENT)
        build.assembly(value, base, temp/'image', version='0.1.0', sequence=1)
        overlay = temp/'image/mkosi.extra'
        policy_files = journal.render(value).keys()
        for name in [*policy_files, 'usr/lib/lanrith/verify-journal-flush']:
            dest = Path('/')/name
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(overlay/name, dest)
        plan = json.loads((overlay/'usr/share/lanrith/health.json').read_bytes())
        assert FLUSH in plan['units'] and (RECEIVER in plan['units']) == bool(policy.get('syslog_receiver_unit'))
    systemctl('daemon-reload')


def setup_volume():
    STATE.mkdir()
    KEY.write_bytes(secrets.token_bytes(32))
    KEY.chmod(0o600)
    with DISK.open('wb') as image:
        image.truncate(12*1024**3)
    for module in ('dm_crypt', 'loop'):
        run('modprobe', module)
    run('cryptsetup', 'luksFormat', '--batch-mode', '--type=luks2', '--pbkdf=pbkdf2',
        '--pbkdf-force-iterations=1000', '--key-file', KEY, DISK)
    unlock = ('/usr/sbin/cryptsetup', 'open', '--key-file', str(KEY), str(DISK), 'journalfixture')
    run(*unlock)
    run('mkfs.ext4', '-q', '-E', 'nodiscard,lazy_itable_init=1,lazy_journal_init=1', '/dev/mapper/journalfixture')
    write(UNITS/'fixture-journal-unlock.service', '[Unit]\nDefaultDependencies=no\nBefore=var.mount\n'
          '[Service]\nType=oneshot\nRemainAfterExit=yes\nExecStart=/usr/sbin/modprobe dm_crypt\n'
          'ExecStart=/usr/sbin/modprobe loop\nExecStart='+' '.join(unlock)+'\n')
    write(UNITS/'var.mount', '[Unit]\nRequires=fixture-journal-unlock.service\nAfter=fixture-journal-unlock.service\n'
          '[Mount]\nWhat=/dev/mapper/journalfixture\nWhere=/var\nType=ext4\nOptions=nodev,nosuid,noexec\n')
    # Re-open under the manager's ownership. No mounted filesystem yet uses it.
    run('cryptsetup', 'close', 'journalfixture')
    systemctl('daemon-reload')
    systemctl('start', 'var.mount')
    assert run('findmnt', '-nro', 'SOURCE', '/var').stdout.strip() == '/dev/mapper/journalfixture'
    run('cryptsetup', 'status', 'journalfixture')


def records(directory, boot, *fields):
    result = run('journalctl', '--quiet', '--directory', directory, '-o', 'json',
                 '_BOOT_ID='+boot, *fields, check=False)
    return [json.loads(row) for row in result.stdout.splitlines()]


def marker_rows(directory, boot):
    return records(directory, boot, 'SYSLOG_IDENTIFIER=lanrith-journal-flush', '_TRANSPORT=syslog', '_UID=0')


def write_marker(name):
    run('logger', '--socket-errors=on', '--socket=/dev/log', '-t', 'fixture-input', '--', name)
    run('journalctl', '--sync')


def effective_forward():
    text = run('systemd-analyze', 'cat-config', 'systemd/journald.conf').stdout
    result = dict(row.split('=', 1) for row in text.splitlines()
                  if row and not row.startswith(('#', ';', '[')) and '=' in row)
    assert result['MaxRetentionSec'] == '14day' and result['SystemMaxFileSize'] == '64M'
    assert result['RuntimeMaxUse'] == '256M' and result['RuntimeMaxFileSize'] == '32M'
    return result['ForwardToSyslog']


def qualify(reboot):
    assert os.geteuid() == 0 and Path('/proc/1/comm').read_text().strip() == 'systemd'
    assert run('systemd-detect-virt', '--vm').stdout.strip() and not Path('/usr/share/lanrith/installed.json').exists()
    assert {row['ifname'] for row in json.loads(run('ip', '-j', 'link').stdout)} == {'lo'}
    boot = Path('/proc/sys/kernel/random/boot_id').read_text().strip().replace('-', '')
    machine = Path('/etc/machine-id').read_text().strip()
    directory = Path('/var/log/journal', machine)
    run_directory = Path('/run/log/journal', machine)
    print('systemd', run('systemctl', '--version').stdout.splitlines()[0], 'boot', boot, flush=True)
    if (STATE/'prior').exists():
        old_boot, original = (STATE/'prior').read_text().split()
        assert boot != old_boot and original in [r['MESSAGE'] for r in marker_rows(directory, old_boot)]
        assert prop(FLUSH, 'ActiveState') == 'active' and marker_rows(directory, boot)
        assert effective_forward() == 'no' and not Path('/run/systemd/journal/syslog').exists()
        assert run('findmnt', '-nro', 'SOURCE', '/var').stdout.strip() == '/dev/mapper/journalfixture'
        assert int(prop('var.mount', 'ActiveEnterTimestampMonotonic')) <= int(prop(FLUSH, 'ExecMainStartTimestampMonotonic'))
        print('Previous-boot marker survived rotation, reboot, LUKS reopen and mount; current boot flush passed.', flush=True)
        return

    base_conf = 'etc/systemd/journald.conf.d/20-lanrith.conf'
    write('/'+base_conf, (ROOT/'mkosi/base/mkosi.extra'/base_conf).read_text())
    stage({})
    systemctl('stop', FLUSH)
    run('journalctl', '--relinquish-var')
    setup_volume()
    systemctl('restart', 'systemd-journald.service')
    # This regular file models an unavailable journal destination on the disposable ext4 volume.
    Path('/var/log').mkdir(exist_ok=True)
    Path('/var/log/journal').touch()
    assert 'var.mount' in prop(FLUSH, 'Requires').split() and 'var.mount' in prop(FLUSH, 'After').split()
    require_flush(False)
    assert run('journalctl', '--flush').returncode == 0
    runtime = marker_rows(run_directory, boot)
    assert runtime and not marker_rows(directory, boot)
    original = runtime[-1]['MESSAGE']
    pending = Path('/run/lanrith-journal-flush/pending')
    assert original == 'lanrith-journal-flush-'+pending.read_text()
    Path('/var/log/journal').rename('/var/log/journal.fixture-obstruction')
    run('journalctl', '--flush')
    run('journalctl', '--sync')
    run('journalctl', '--rotate')
    run('journalctl', '--sync')
    archived = [path for path in directory.glob('system@*.journal')
                if original == run('journalctl', '--quiet', '--file', path, '-n1', '-ocat',
                                   'MESSAGE='+original).stdout.strip()]
    assert len(archived) == 1
    saved = archived[0].rename(directory.parent/archived[0].name)
    require_flush(False)
    assert original not in [row['MESSAGE'] for row in marker_rows(directory, boot)]
    assert marker_rows(directory, boot) and pending.exists()
    saved.rename(archived[0])
    require_flush()
    assert not pending.exists()
    assert original in [row['MESSAGE'] for row in marker_rows(directory, boot)]
    def usage():
        return records(directory, boot, '_TRANSPORT=driver', 'JOURNAL_PATH='+str(directory))[-1]
    disk = os.statvfs(directory)
    page = os.sysconf('SC_PAGESIZE')
    reserve = min(((disk.f_blocks*disk.f_frsize//20 + page-1)//page)*page, 4*1024**3)
    assert int(usage()['DISK_KEEP_FREE']) == reserve and int(usage()['MAX_USE']) == 1024**3
    print('Obstructed flush exited 0, its unit failed, and retry recovered the original marker. Package reserve', reserve, flush=True)

    assert effective_forward() == 'no'
    assert not Path('/run/systemd/journal/syslog').exists()
    with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as listener:
        listener.bind('/run/systemd/journal/syslog')
        listener.settimeout(.4)
        write_marker('journal-fixture-local')
        assert records(directory, boot, 'MESSAGE=journal-fixture-local', '_TRANSPORT=syslog')
        try:
            listener.recv(65536)
        except TimeoutError:
            pass
        else:
            raise AssertionError('Undeclared receiver got forwarded output.')
    Path('/run/systemd/journal/syslog').unlink()

    # An existing retained volume may be smaller than today's signed layout.
    stage({'system_keep_free_mib': 16384})
    systemctl('restart', 'systemd-journald.service')
    require_flush(False)
    assert 'exceeds usable state capacity' in run('journalctl', '-b', '-u', FLUSH, '-n', '12', '-o', 'cat').stdout

    settings = {'system_keep_free_mib': 8192, 'system_max_use_mib': 1024, 'syslog_receiver_unit': RECEIVER}
    stage(settings)
    assert effective_forward() == 'yes'
    systemctl('restart', 'systemd-journald.service')
    require_flush()
    assert int(usage()['DISK_KEEP_FREE']) == 8192*1024**2 and int(usage()['MAX_USE']) == 1024**3
    write_marker('journal-fixture-delivered')
    assert records(directory, boot, 'MESSAGE=journal-fixture-delivered')
    for _ in range(40):
        path = Path('/run/fixture-syslog.log')
        if path.is_file() and b'journal-fixture-delivered' in path.read_bytes():
            break
        time.sleep(.1)
    else:
        raise AssertionError(systemctl('status', RECEIVER, 'syslog.socket', check=False).stdout)
    assert prop(RECEIVER, 'ActiveState') == 'active'
    print('8 GiB reserve, 1 GiB maximum, 12 GiB LUKS device. Same input stored locally and delivered to named socket peer.', flush=True)

    # Test the effective daemon, including mismatches from later-sorting settings.
    override = Path('/etc/systemd/journald.conf.d/z-fixture.conf')
    for mismatch in ('SystemKeepFree=1M', 'SystemMaxUse=512M'):
        write(override, '[Journal]\n'+mismatch+'\n')
        systemctl('restart', 'systemd-journald.service')
        require_flush(False)
    override.unlink()
    systemctl('restart', 'systemd-journald.service')
    require_flush()
    run('journalctl', '--rotate')
    run('journalctl', '--sync')
    assert original in [row['MESSAGE'] for row in marker_rows(directory, boot)]
    systemctl('stop', 'syslog.socket', RECEIVER)
    (Path('/usr/lib/systemd/system')/RECEIVER).unlink()
    systemctl('daemon-reload')
    assert systemctl('start', RECEIVER, check=False).returncode and prop(RECEIVER, 'ActiveState') != 'active'
    # Switch /etc fixtures to the next slot's default template before restarting.
    for name in ('syslog.socket.d/60-lanrith-receiver.conf', RECEIVER+'.d/60-lanrith-syslog.conf',
                 'systemd-journald.service.d/60-lanrith-syslog.conf'):
        (UNITS/name).unlink()
    stage({})
    if reboot:
        (STATE/'prior').write_text(boot+' '+original+'\n')
        run('sync')
        print('Restarting the disposable guest for prior-boot readback.', flush=True)
        systemctl('--no-block', 'reboot')
        time.sleep(90)
        raise AssertionError('Requested reboot did not occur.')


if __name__ == '__main__':
    if sys.argv[1:] == ['--receive']:
        receive()
    else:
        assert sys.argv[1:] in ([], ['--reboot'])
        qualify('--reboot' in sys.argv)
