#!/usr/bin/python3
"""Run the observation units in an offline, disposable PID 1 guest."""

import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from lanrith import boot_health, image_operation, runtime, update
from lanrith.release import canonical


WORK = Path('/run/observation-fixture')
UNITS = Path('/etc/systemd/system')
HEALTH = 'lanrith-health.service'
OBSERVER = 'lanrith-observation.service'
HEARTBEAT = 'lanrith-telemetry-heartbeat.service'
TARGET = 'boot-complete.target'
REQUIRED = ['fixture-required.service', 'fixture-core.service', 'fixture-network.service']
PLAN = {'schema': 1, 'units': REQUIRED, 'interfaces': [{'name': 'lo', 'addresses': ['127.0.0.1']}], 'probes': []}
BOOT = Path('/run/lanrith/boot.json')
RESULT = BOOT.with_name('health.json')
UNIT = '[Service]\nType=oneshot\nRemainAfterExit=yes\nExecStart=/bin/true\n'


def run(*args, ok=True):
    process = subprocess.run(args, capture_output=True, text=True, timeout=35)
    if ok and process.returncode:
        raise AssertionError((args, process.returncode, process.stdout, process.stderr))
    return process


def until(call, timeout=20):
    deadline = time.monotonic()+timeout
    while time.monotonic() < deadline:
        value = call()
        if value:
            return value
        time.sleep(.1)
    raise AssertionError('Fixture deadline expired')


def fixture_cli(arguments):
    def check(value):
        # Native tools guest has no signed root, ESP or TPM. Exercise actual
        # mandatory unit and interface checks inside the normal health attempt.
        with (WORK/'invocations').open('a') as stream:
            stream.write(str(os.getpid())+'\n')
        boot_health.check(PLAN)
        hold = os.environ.get('FIXTURE_HOLD') or ('service' if (WORK/'delay').exists() else None)
        if hold:
            (WORK/('entered-'+hold)).touch()
            until(lambda: (WORK/('release-'+hold)).exists(), timeout=25)

    runtime.check_health = check
    runtime.boot_esp = lambda value: WORK/'esp'
    default_entry = update.default_entry
    update.default_entry = lambda *args: default_entry(WORK/'default')
    return runtime.main(arguments)


def qualify():
    from lanrith import build, config
    from test_logs import declaration as logs_declaration
    assert os.geteuid() == 0 and Path('/proc/1/comm').read_text().strip() == 'systemd'
    assert 'rdinit=/fixture-init' in Path('/proc/cmdline').read_text().split()
    assert {i['ifname'] for i in json.loads(run('ip', '-j', 'link').stdout)} == {'lo'}
    assert not runtime.INSTALLED.exists()
    WORK.mkdir()
    base = WORK/'base.tar'
    base.write_bytes(b'synthetic base')
    minimal = config.load(ROOT/'examples/minimal.yaml')
    build.assembly(config.normalize(minimal), base, WORK/'assembly', version='0.1.32', sequence=1)
    overlay = WORK/'assembly/mkosi.extra'
    assert not (overlay/'usr/lib/systemd/system'/HEARTBEAT).exists()
    feature = config.render(logs_declaration())
    accounts = WORK/'accounts.conf'
    accounts.write_text('u alloy - "Synthetic heartbeat account" /\n')
    run('systemd-sysusers', str(accounts))
    timer = HEARTBEAT.replace('.service', '.timer')
    for name in (HEARTBEAT, timer):
        (UNITS/name).write_text(feature['usr/lib/systemd/system/'+name])
    shutil.copytree(overlay/'usr/share/lanrith', '/usr/share/lanrith', dirs_exist_ok=True)
    shutil.copytree(overlay/'usr/lib/lanrith', '/usr/lib/lanrith', dirs_exist_ok=True)
    shutil.copy2(overlay/'usr/bin/lanrith-runtime', '/usr/bin/lanrith-runtime')
    shutil.copy2(ROOT/'mkosi/base/mkosi.extra/usr/bin/lanrith-status', '/usr/bin/lanrith-status')
    Path('/usr/bin/lanrith-status').chmod(0o755)
    require_dir = UNITS/(TARGET+'.requires')
    require_dir.mkdir(exist_ok=True)
    (require_dir/HEALTH).symlink_to('../'+HEALTH)
    for name in (HEALTH, OBSERVER):
        (UNITS/name).write_text((overlay/'usr/lib/systemd/system'/name).read_text())
    required = next(line.split('=', 1)[1].split() for line in (UNITS/HEALTH).read_text().splitlines()
                    if line.startswith('Requires='))
    for unit in {*required, *REQUIRED, 'alloy.service'}:
        (UNITS/unit).write_text(UNIT)
    cli = ['/usr/bin/python3', str(Path(__file__).resolve()), 'cli']
    dropin = UNITS/(HEALTH+'.d')
    dropin.mkdir()
    (dropin/'fixture.conf').write_text('[Service]\nExecStart=\nExecStart='+' '.join(cli+['health'])+'\n')
    (UNITS/TARGET).write_text('[Unit]\nDescription=Offline boot-complete target\nDefaultDependencies=no\n')
    run('systemd-tmpfiles', '--create', str(overlay/'usr/lib/tmpfiles.d/80-lanrith-update.conf'),
        '--prefix=/run/lanrith', '--prefix=/run/lanrith-image-locks')
    installed = runtime.installed()
    state = Path(installed['state_directory'])
    state.mkdir(exist_ok=True, mode=0o700)
    state.chmod(0o700)
    entry = WORK/'esp/EFI/Linux'/installed['uki_name']
    entry.parent.mkdir(parents=True)
    entry.touch()
    # bootctl reads/writes a synthetic EFI variable only. All systemctl calls,
    # target ordering, timeouts, health receipts and promotion writes are real.
    Path('/usr/bin/bootctl').unlink(missing_ok=True)
    Path('/usr/bin/bootctl').write_text('#!/usr/bin/python3\nfrom pathlib import Path\nimport sys\n'
        +'root=Path('+repr(str(WORK))+')\nargs=sys.argv[1:]\n'
        +"if args==['--print-esp-path']: print(root/'esp')\n"
        +"elif args==['--print-stub-path']: print("+repr(str(entry))+")\n"
        +"elif args==['set-default',"+repr(entry.name)+"] and not (root/'refuse').exists():\n"
        +"    (root/'default').write_bytes(bytes(4)+(args[1]+chr(0)).encode('utf-16-le'))\n"
        +"else: sys.exit(1)\n")
    Path('/usr/bin/bootctl').chmod(0o755)
    run('systemctl', 'daemon-reload')
    run('systemctl', 'start', *REQUIRED)
    run('ip', 'link', 'set', 'lo', 'up')
    outsider = ['setpriv', '--reuid=nobody', '--regid=nogroup', '--clear-groups']
    def status():
        return json.loads(run(*outsider, '/usr/bin/lanrith-status').stdout)
    def count():
        return len((WORK/'invocations').read_text().splitlines())
    def elapsed(start):
        return round(time.monotonic()-start, 3)
    assert status()['health']['state'] == 'missing' and status()['boot'] is None
    assert run('/usr/bin/lanrith-runtime', 'health', ok=False).returncode
    assert status()['health']['result'] == 'failed' and status()['boot'] is None
    run('systemctl', 'start', timer, TARGET)
    target_at = int(run('systemctl', 'show', '-P', 'ActiveEnterTimestampMonotonic', TARGET).stdout) / 10**6
    first_count = count()
    run('systemctl', 'start', OBSERVER)
    published = elapsed(target_at)
    pending = status()
    assert not pending['boot']['accepted'] and pending['health']['result'] == 'passed'
    assert len(pending['boot']) == 8 and pending['boot_scope'] == 'historical'
    assert first_count == count(), (first_count, count())
    assert run(*outsider, '/usr/bin/lanrith-runtime', 'telemetry', ok=False).returncode
    (WORK/'refuse').touch()
    assert run(*cli, 'accept', '1', ok=False).returncode and not status()['boot']['accepted']
    (WORK/'refuse').unlink()
    run(*cli, 'accept', '1')
    accepted_at = time.monotonic()
    assert count() > first_count and status()['boot']['accepted']
    legacy = BOOT.read_bytes()
    def emitted():
        lines = run('journalctl', '-b', '-u', HEARTBEAT, '-o', 'json', '--no-pager').stdout.splitlines()
        for line in lines:
            row = json.loads(line)
            if '"event":"lanrith-heartbeat"' in row.get('MESSAGE', ''):
                return int(row['__MONOTONIC_TIMESTAMP']) / 10**6

    heartbeat_at = until(emitted, timeout=135)
    first_heartbeat = round(heartbeat_at-target_at, 3)
    after_commit = round(heartbeat_at-accepted_at, 3)
    assert first_heartbeat >= 0 and after_commit >= 0
    assert run(*outsider, 'cat', str(state/'accepted-image.json'), ok=False).returncode
    assert run(*outsider, 'test', '-w', str(RESULT), ok=False).returncode

    env = {**os.environ, 'FIXTURE_HOLD': 'old'}
    with subprocess.Popen(cli+['health'], env=env, stdout=subprocess.DEVNULL) as older:
        until(lambda: (WORK/'entered-old').exists())
        assert status()['health']['state'] == 'checking'
        run('systemctl', 'stop', REQUIRED[0])
        assert run(*cli, 'accept', '1', ok=False).returncode
        assert status()['health']['result'] == 'failed'
        latest = RESULT.read_bytes()
        (WORK/'release-old').touch()
        assert older.wait(timeout=10) == 0 and RESULT.read_bytes() == latest
    assert BOOT.read_bytes() == legacy and status()['boot']['accepted']
    run('systemctl', 'start', REQUIRED[0])
    (WORK/'delay').touch()
    run('systemctl', 'start', '--no-block', HEALTH)
    until(lambda: (WORK/'entered-service').exists())
    assert status()['health']['state'] == 'checking'
    run('systemctl', 'kill', '--kill-whom=main', '-s', 'SIGKILL', HEALTH)
    until(lambda: status()['health']['state'] == 'interrupted')
    assert status()['health']['result'] == 'unavailable' and BOOT.read_bytes() == legacy
    (WORK/'delay').unlink()
    run('systemctl', 'start', HEALTH)
    assert status()['health']['result'] == 'passed'

    # Hold only the observer's process once, past its real startup deadline.
    od = UNITS/(OBSERVER+'.d')
    od.mkdir()
    (od/'delay.conf').write_text('[Service]\nExecStartPre=/bin/sh -c "if test -e '+str(WORK/'slow')+
                                  '; then sleep 30; fi"\n')
    run('systemctl', 'daemon-reload')
    (WORK/'slow').touch()
    baseline = json.loads(RESULT.read_bytes())
    for mutation, expected in (({'boot_id': '00000000-0000-0000-0000-000000000000'}, 'invalid'),
                              ({'configuration_sha256': '0'*64}, 'invalid'),
                              ({'started_monotonic_ns': time.monotonic_ns()+10**12}, 'invalid'),
                              ({'started_monotonic_ns': 0, 'finished_monotonic_ns': 1}, 'stale')):
        RESULT.write_bytes(canonical({**baseline, **mutation}))
        health = status()['health']
        assert health['state'] == expected and health['result'] == 'unavailable', health
    RESULT.write_bytes(canonical({**baseline, 'private-test-field': 'fixture-private-detail'}))
    public = status()
    assert public['health']['result'] == 'unavailable' and 'fixture-private-detail' not in json.dumps(public)
    RESULT.unlink()
    with subprocess.Popen(cli+['health'], env={**os.environ, 'FIXTURE_HOLD': 'late'},
                          stdout=subprocess.DEVNULL) as late:
        until(lambda: (WORK/'entered-late').exists())
        slow = time.monotonic()
        assert run('systemctl', 'start', OBSERVER, ok=False).returncode
        deadline = elapsed(slow)
        assert run('systemctl', 'show', '-P', 'Result', OBSERVER).stdout.strip() == 'timeout'
        latest = status()['health']
        assert latest['state'] == 'checking' and latest['result'] == 'unavailable'
        (WORK/'slow').unlink()
        (WORK/'release-late').touch()
        assert late.wait(timeout=10) == 0
    recovered_start = count()
    until(lambda: run('systemctl', 'show', '-P', 'Result', OBSERVER).stdout.strip() == 'success' and
          run('systemctl', 'show', '-P', 'SubState', OBSERVER).stdout.strip() == 'dead')
    recovered = elapsed(slow)
    assert status()['health']['result'] == 'passed' and BOOT.read_bytes() == legacy
    assert count() == recovered_start
    assert run('systemctl', 'show', '-P', 'TimeoutStartUSec', OBSERVER).stdout.strip() == '5s'
    # A subsequent committed-identity change must withdraw unprivileged evidence.
    image_operation.save_accepted({**installed, 'deployment_sequence': 2, 'uki_name': installed['image_id']+'_2.efi'})
    assert status()['boot'] is None and run(*outsider, '/usr/bin/lanrith-runtime', 'telemetry', ok=False).returncode
    print(json.dumps({'systemd': run('systemctl', '--version').stdout.splitlines()[0], 'pending_seconds': published,
        'first_heartbeat_seconds_after_target': first_heartbeat, 'heartbeat_seconds_after_commit': after_commit,
        'observer_deadline_seconds': deadline, 'retry_completed_seconds': recovered}), flush=True)


if __name__ == '__main__':
    if sys.argv[1:2] == ['cli']:
        sys.exit(fixture_cli(sys.argv[2:]))
    qualify()
