#!/usr/bin/env python3
"""Check real Chrony IPC and health identities in disposable offline namespaces."""

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import pwd
import shutil
import stat
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT/'tests')]
from lanrith import config, ntp_health_runtime as runtime
from test_metrics import fixture


def run(*args, expected=0):
    result = subprocess.run(args, capture_output=True, timeout=15)
    assert result.returncode == expected, (args[0], result.returncode, result.stdout[-2048:], result.stderr[-2048:])
    return result.stdout


def role(user, groups=(), *, net_admin=False):
    account = pwd.getpwnam(user)
    return ['setpriv', '--reuid='+str(account.pw_uid), '--regid='+str(account.pw_gid),
            *(['--groups='+','.join(str(g) for g in groups)] if groups else ['--clear-groups']),
            '--bounding-set=-all'+(',+net_admin' if net_admin else ''), '--inh-caps=-all',
            '--ambient-caps=-all', '--no-new-privs']


def qualify(output, *, systemd=False):
    assert os.geteuid() == 0 and not Path('/usr/share/lanrith/installed.json').exists()
    assert {row['ifname'] for row in json.loads(run('ip', '-j', 'link'))} == {'lo'}
    if systemd:
        assert Path('/proc/1/comm').read_text().strip() == 'systemd'
        # Finish the unrelated package unit's runtime-directory cleanup before
        # starting our clock-disabled fixture daemon with that private path.
        run('systemctl', 'stop', 'chrony.service')
    assert output is None or not output.exists()
    if not systemd:
        # A hosted runner can have its own packaged Chrony socket. Hide that
        # runtime before checking our empty fixture; never stop its service or
        # alter its socket, directory permissions or clock.
        run('mount', '-t', 'tmpfs', '-o', 'mode=0755', 'tmpfs', '/run')
    else:
        assert Path('/proc/1/comm').read_text().strip() == 'systemd'
    assert not runtime.CONTROL.exists() and not runtime.OUTPUT.exists()
    account = pwd.getpwnam('_chrony')
    run('ip', 'netns', 'add', 'lanrith-services')
    namespace = ['nsenter', '--net=/run/netns/lanrith-services', '--']
    run(*namespace, 'ip', 'link', 'set', 'lo', 'up')
    runtime.CONTROL.parent.mkdir(mode=0o700, exist_ok=True)
    runtime.CONTROL.parent.chmod(0o700)
    os.chown(runtime.CONTROL.parent, account.pw_uid, account.pw_gid)
    runtime.OUTPUT.parent.mkdir(mode=0o750)
    os.chown(runtime.OUTPUT.parent, account.pw_uid, account.pw_gid)
    # Stage exact runtime bytes outside potentially private checkout parents.
    library = Path('/run/ntp-native/lanrith')
    library.mkdir(parents=True)
    for name in ('__init__.py', 'release.py', 'policy_runtime.py', 'router_metrics_runtime.py', 'ntp_health_runtime.py'):
        shutil.copyfile(ROOT/'lanrith'/name, library/name)
        (library/name).chmod(0o644)
    entry = library.parent/'observe.py'
    entry.write_text('import os,pathlib\nfrom lanrith.ntp_health_runtime import main\n'
        'status=dict(line.split(":",1) for line in pathlib.Path("/proc/self/status").read_text().splitlines())\n'
        'assert int(status["CapEff"],16)==int(status["CapBnd"],16)==0 and status["NoNewPrivs"].strip()=="1"\n'
        'raise SystemExit(main())\n')
    entry.chmod(0o644)
    reader = library.parent/'read.py'
    reader.write_text('import json,pathlib,sys\nfrom lanrith.ntp_health_runtime import read_observation\n'
        'status=dict(line.split(":",1) for line in pathlib.Path("/proc/self/status").read_text().splitlines())\n'
        'assert int(status["CapEff"],16)==int(status["CapBnd"],16)==0x1000\n'
        'assert status["NoNewPrivs"].strip()=="1"\n'
        'try: value=read_observation()\nexcept (OSError,ValueError):sys.exit(10)\n'
        'print(json.dumps(value))\n')
    reader.chmod(0o644)
    value = fixture()
    value['services']['ntp']['enabled'] = True
    files = config.render(value)
    if systemd:
        installed = Path('/usr/lib/lanrith/lanrith')
        installed.parent.mkdir(parents=True, exist_ok=True)
        shutil.copytree(library, installed)
        wrapper = installed.parent/'ntp-health'
        wrapper.write_text('#!/usr/bin/python3 -I\nimport sys\nsys.path.insert(0,"/usr/lib/lanrith")\n'
                           'from lanrith.ntp_health_runtime import main\nsys.exit(main())\n')
        wrapper.chmod(0o755)
        for name in ('lanrith-ntp-health.service', 'lanrith-ntp-health.timer'):
            Path('/run/systemd/system', name).write_text(files['usr/lib/systemd/system/'+name])
        # The fixture creates the network namespace; no substitute service runs
        # in place of the real observer. Dependency ordering is a full-image test.
        Path('/run/systemd/system/lanrith-services.service').write_text(
            '[Service]\nType=oneshot\nExecStart=/usr/bin/true\nRemainAfterExit=yes\n')
        dropin = Path('/run/systemd/system/lanrith-ntp-health.service.d')
        dropin.mkdir()
        proof = installed.parent/'ntp-role-proof.py'
        proof.write_text('import json,os,pathlib,sys\n'
            's=dict(line.split(":",1) for line in pathlib.Path("/proc/self/status").read_text().splitlines())\n'
            'pathlib.Path(sys.argv[1]).write_text(json.dumps({"uid":os.geteuid(),"gid":os.getegid(),'
            '"effective":int(s["CapEff"],16),"bounding":int(s["CapBnd"],16),'
            '"nnp":s["NoNewPrivs"].strip(),"namespace":os.stat("/proc/self/ns/net").st_ino}))\n')
        (dropin/'fixture.conf').write_text('[Service]\nInaccessiblePaths='+str(ROOT)+'\n'
            'ExecStartPre=/usr/bin/python3 /usr/lib/lanrith/ntp-role-proof.py /run/lanrith-ntp-health/role.json\n')
        Path('/run/systemd/system/lanrith-router-metrics.service').write_text(
            files['usr/lib/systemd/system/lanrith-router-metrics.service'])
        host_dropin = Path('/run/systemd/system/lanrith-router-metrics.service.d')
        host_dropin.mkdir()
        (host_dropin/'fixture.conf').write_text('[Service]\nInaccessiblePaths='+str(ROOT)+'\n'
            'ExecStartPre=/usr/bin/python3 /usr/lib/lanrith/ntp-role-proof.py '
            '/var/lib/node_exporter/textfile_collector/role.json\n')
        wrapper = installed.parent/'router-metrics'
        wrapper.write_text('#!/usr/bin/python3 -I\nimport sys\nsys.path.insert(0,"/usr/lib/lanrith")\n'
                           'from lanrith.router_metrics_runtime import main\nsys.exit(main())\n')
        wrapper.chmod(0o755)
        Path('/usr/share/lanrith').mkdir(parents=True, exist_ok=True)
        Path('/usr/share/lanrith/router-metrics.json').write_text(files['usr/share/lanrith/router-metrics.json'])
        Path('/var/lib/node_exporter/textfile_collector').mkdir(parents=True, exist_ok=True)
        run('systemctl', 'daemon-reload')
        run('systemctl', 'start', 'lanrith-ntp-health.timer')
        run('systemctl', 'is-active', 'lanrith-ntp-health.timer')
    def observe():
        if systemd:
            run('systemctl', 'start', 'lanrith-ntp-health.service')
            assert run('systemctl', 'show', '--value', '-p', 'Result', 'lanrith-ntp-health.service').strip() == b'success'
            for key, expected in (('User', '_chrony'), ('Group', '_chrony'), ('CapabilityBoundingSet', ''),
                                  ('NetworkNamespacePath', str(runtime.NAMESPACE)), ('NoNewPrivileges', 'yes')):
                assert run('systemctl', 'show', '--value', '-p', key, 'lanrith-ntp-health.service').decode().strip() == expected
        else:
            run(*namespace, *role('_chrony'), '/usr/bin/python3', str(entry))
        return json.loads(run(*role('root', (account.pw_gid,), net_admin=True), '/usr/bin/python3', str(reader)))
    checks = []
    daemon = None
    with tempfile.TemporaryDirectory(prefix='lanrith-ntp.', dir='/etc/chrony') as temporary:
        root = Path(temporary)
        root.chmod(0o755)
        policy = root/'chrony.conf'
        policy.write_text('pidfile /run/chrony/chronyd.pid\ndriftfile /run/chrony/chrony.drift\n'
                          'bindcmdaddress /run/chrony/chronyd.sock\nport 0\ncmdport 0\nlocal stratum 10\n')
        policy.chmod(0o644)
        try:
            for _ in range(2):
                daemon = subprocess.Popen([*namespace, *role('_chrony'), '/usr/sbin/chronyd',
                    '-n', '-x', '-U', '-u', '_chrony', '-f', str(policy)],
                    stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
                deadline = time.monotonic()+5
                while not runtime.CONTROL.exists():
                    assert daemon.poll() is None and time.monotonic() < deadline
                    time.sleep(.02)
                status = dict(line.split(':', 1) for line in Path('/proc/'+str(daemon.pid)+'/status').read_text().splitlines())
                assert int(status['CapEff'], 16) == int(status['CapBnd'], 16) == 0
                assert status['NoNewPrivs'].strip() == '1'
                assert int(status['Uid'].split()[1]) == account.pw_uid
                observed = observe()
                if systemd and not observed['query_success']:
                    # Synthetic failure diagnostics under the same sandbox;
                    # these cannot turn the original failed observation green.
                    debug = Path('/usr/lib/lanrith/ntp-debug.py')
                    debug.write_text('import os,pathlib,subprocess\n'
                        'for name in ("/run/chrony","/run/chrony/chronyd.sock"):\n'
                        ' print(name,os.stat(name),flush=True)\n'
                        'r=subprocess.run(["/usr/bin/chronyc","-h","/run/chrony/chronyd.sock","-n","-c","tracking"],'
                        'capture_output=True,timeout=3)\nprint(r.returncode,r.stdout,r.stderr,flush=True)\n')
                    (dropin/'debug.conf').write_text('[Service]\nExecStart=\nExecStart=/usr/bin/python3 /usr/lib/lanrith/ntp-debug.py\n')
                    run('systemctl', 'daemon-reload')
                    subprocess.run(['systemctl', 'start', 'lanrith-ntp-health.service'], capture_output=True, timeout=10)
                    sys.stderr.buffer.write(run('journalctl', '--no-pager', '-u', 'lanrith-ntp-health.service', '-n', '20'))
                assert observed['query_success'] and not observed['synchronised']
                if systemd:
                    proof = json.loads((runtime.OUTPUT.parent/'role.json').read_text())
                    assert proof['uid'] == account.pw_uid and proof['gid'] == account.pw_gid
                    assert proof['effective'] == proof['bounding'] == 0 and proof['nnp'] == '1'
                    assert proof['namespace'] == runtime.NAMESPACE.stat().st_ino
                    run('systemctl', '--job-mode=ignore-dependencies', 'start', 'lanrith-router-metrics.service')
                    host_output = Path('/var/lib/node_exporter/textfile_collector')
                    text = (host_output/'lanrith_router.prom').read_text()
                    assert 'lanrith_router_metrics_query_success{collector="chrony"} 1\n' in text
                    assert 'lanrith_router_chrony_synchronised 0\n' in text
                    assert ('lanrith_router_chrony_observation_timestamp_seconds '+
                            str(observed['observed_timestamp_seconds'])+'\n') in text
                    host_proof = json.loads((host_output/'role.json').read_text())
                    assert host_proof['uid'] == host_proof['gid'] == 0
                    assert host_proof['effective'] == host_proof['bounding'] == 0x1000 and host_proof['nnp'] == '1'
                    assert host_proof['namespace'] == os.stat('/proc/self/ns/net').st_ino != proof['namespace']
                assert observed['network_namespace_inode'] == runtime.NAMESPACE.stat().st_ino
                assert stat.S_IMODE(runtime.CONTROL.parent.stat().st_mode) == 0o700
                assert stat.S_IMODE(runtime.CONTROL.stat().st_mode) == 0o755
                # Host root's metrics capability and group permit only the
                # bounded health snapshot; they cannot reach raw control IPC.
                run(*namespace, *role('root', (account.pw_gid,), net_admin=True), '/usr/bin/chronyc',
                    '-h', str(runtime.CONTROL), '-n', '-c', 'tracking', expected=1)
                run(*role('root', net_admin=True), '/usr/bin/python3', str(reader), expected=10)
                run(*role('nobody'), '/usr/bin/test', '-r', str(runtime.OUTPUT), expected=1)
                run(*namespace, *role('nobody'), '/usr/bin/chronyc', '-h', str(runtime.CONTROL),
                    '-n', '-c', 'tracking', expected=1)
                checks.append('real-unsynchronised-query-and-host-read-without-raw-control')
                daemon.terminate()
                daemon.communicate(timeout=5)
                daemon = None
                assert not runtime.CONTROL.exists()
                failed = observe()
                assert not failed['query_success'] and not failed['synchronised']
                checks.append('daemon-unavailable-is-failed-query')
            observed['observed_monotonic_ns'] -= 91*10**9
            runtime.OUTPUT.write_text(json.dumps(observed))
            runtime.OUTPUT.chmod(0o640)
            run(*role('root', (account.pw_gid,), net_admin=True), '/usr/bin/python3', str(reader), expected=10)
            checks.append('stale-observation-rejected')
        finally:
            if daemon is not None:
                daemon.terminate()
                daemon.communicate(timeout=5)
            if systemd:
                run('systemctl', 'stop', 'lanrith-ntp-health.timer', 'lanrith-ntp-health.service')
            run('ip', 'netns', 'delete', 'lanrith-services')
    result = {'schema': 1, 'test': 'offline-chrony-health-identities', 'result': 'pass',
              'assessed_at': datetime.now(timezone.utc).isoformat(), 'checks': checks,
              'chrony_version': run('chronyd', '-v').decode().strip(),
              'full_generated_observer_sandbox': systemd, 'boot_dependency_order_qualified': False,
              'full_generated_host_collector_sandbox': systemd,
              'daemon_clock_adjustment': False, 'external_network': False, 'private_image_qualified': False,
              'production_changed': False, 'source_sha256': {name: hashlib.sha256((ROOT/name).read_bytes()).hexdigest()
              for name in ('lanrith/metrics.py', 'lanrith/build.py', 'lanrith/runtime_plan.py',
                           'lanrith/ntp_health_runtime.py', 'lanrith/router_metrics_runtime.py',
                           'lanrith/policy_runtime.py', 'tests/ntp_health_native.py')}}
    if output is not None:
        with output.open('x') as stream:
            json.dump(result, stream, sort_keys=True, indent=2)
            stream.write('\n')
    print('Native Chrony observer, host reader, age and ordinary-user boundaries passed.')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--isolated', action='store_true')
    parser.add_argument('--systemd', action='store_true')
    parser.add_argument('--result', type=Path)
    args = parser.parse_args()
    if args.isolated or args.systemd:
        qualify(args.result, systemd=args.systemd)
    else:
        sys.stdout.buffer.write(run('unshare', '--mount', '--net', '--fork', '--propagation', 'private', '--',
            sys.executable, str(Path(__file__).resolve()), '--isolated',
            *(['--result', str(args.result)] if args.result else [])))
