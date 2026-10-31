"""Exercise optional descriptor setup with real systemd and restricted root.

The helper executable is a descriptor-reporting fixture, not the policy engine.
This qualifies launcher ownership, descriptors and boot-failure isolation only.
"""

import hashlib
import json
import os
from pathlib import Path
import shutil
import socket
import stat
import subprocess
import time

from lanrith import policy_agent, policy_runtime
from lanrith.release import require
from test_extension_observations import OBSERVER, settings


ROOT = Path(__file__).resolve().parents[1]
HELPER = 'lanrith-policy-helper.service'
BOOTSTRAP = 'lanrith-policy-bootstrap.service'
BINDINGS = 'lanrith-policy-bindings.service'
READER = 'lanrith-policy-reader.service'
SOCKETS = ('lanrith-policy-helper-requests.socket', 'lanrith-policy-helper-status.socket')
GATE = 'systemd-boot-check-no-failures.service'
CORE = 'example-observer-core-failure.service'
REPORT = Path('/run/lanrith-policy/fixture-identity.json')


def command(*args, check=True):
    result = subprocess.run(args, capture_output=True, timeout=20)
    require(not check or result.returncode == 0,
            'Observer native fixture command failed: '+result.stderr.decode(errors='replace')[-2048:])
    return result


def observation():
    deadline = time.monotonic()+5
    while not REPORT.exists():
        require(time.monotonic() < deadline, 'Native helper descriptor report did not arrive.')
        time.sleep(.05)
    return json.loads(REPORT.read_bytes())


def qualify():
    require(os.geteuid() == 0 and Path('/proc/1/comm').read_text().strip() == 'systemd' and
            (Path('/run/.containerenv').exists() or Path('/.dockerenv').exists()) and
            not Path('/usr/share/lanrith/installed.json').exists(),
            'Observer fixture requires an uninitialized disposable systemd container.')
    require({entry['ifname'] for entry in json.loads(command('ip', '-json', 'link').stdout)} == {'lo'},
            'Observer fixture requires no external network.')
    units = Path('/run/systemd/system')
    names = (HELPER, BOOTSTRAP, BINDINGS, READER, *SOCKETS, CORE)
    executable = Path('/usr/bin/router-policy-helper')
    recovery = Path('/usr/bin/router-policy-recover')
    wrapper = Path('/usr/lib/lanrith/policy-runtime')
    require(not executable.exists() and not recovery.exists() and not wrapper.exists() and
            all(not (units/name).exists() for name in names) and not policy_runtime.CONFIG.exists() and
            not policy_runtime.OBSERVATIONS.parent.exists() and not REPORT.parent.exists(),
            'Observer fixture refuses existing runtime/executable state.')
    groups = ((1701, 'router-policy-reader'), (1702, 'router-policy-operator'), (1801, 'fixture-policy-observer'))
    for gid, name in groups:
        require(command('getent', 'group', str(gid), name, check=False).returncode != 0,
                'Observer fixture service group already exists.')
        command('groupadd', '--gid', str(gid), name)
    state = Path('/var/lib/lanrith/policy-agent')
    require(not state.exists(), 'Observer fixture policy state already exists.')
    state.mkdir(mode=0o700, parents=True)
    REPORT.parent.mkdir(mode=0o700)
    policy_runtime.CONFIG.mkdir(mode=0o700, parents=True)
    wrapper.parent.mkdir(parents=True, exist_ok=True)
    library = wrapper.parent/'lanrith'
    require(not library.exists(), 'Observer runtime library already exists.')
    library.mkdir()
    for module in ('__init__.py', 'release.py', 'policy_runtime.py'):
        shutil.copyfile(ROOT/'lanrith'/module, library/module)
    wrapper.write_text('#!/usr/bin/python3 -I\nimport sys\nsys.path.insert(0,"/usr/lib/lanrith")\n'
                       'from lanrith.policy_runtime import main\nsys.exit(main())\n')
    wrapper.chmod(0o755)
    executable.write_text('#!/usr/bin/python3 -I\nimport json,os,pathlib,socket,time\n'
        'names=os.environ["LISTEN_FDNAMES"].split(":")\n'
        'listeners={}\n'
        'for fd,name in enumerate(names,3):\n'
        ' s=socket.socket(fileno=fd)\n'
        ' assert s.family==socket.AF_UNIX and s.getsockopt(socket.SOL_SOCKET,socket.SO_ACCEPTCONN)==1\n'
        ' listeners[name]=s.getsockname();s.detach()\n'
        'assert os.environ["LISTEN_PID"]==str(os.getpid()) and int(os.environ["LISTEN_FDS"])==len(names)\n'
        'status=dict(line.split(":",1) for line in pathlib.Path("/proc/self/status").read_text().splitlines() if ":" in line)\n'
        'value={"pid":os.getpid(),"uid":os.getuid(),"gid":os.getgid(),"groups":os.getgroups(),'
        '"cap_eff":status["CapEff"].strip(),"listeners":listeners}\n'
        'pathlib.Path("/run/lanrith-policy/fixture-identity.json").write_text(json.dumps(value))\n'
        'while True:time.sleep(1)\n')
    executable.chmod(0o755)
    recovery.write_text('#!/bin/sh\nexit 0\n')
    recovery.chmod(0o755)
    files = policy_agent.render(settings(), observer=OBSERVER)
    contract = Path('/etc/router-policy-agent/runtime/runtime.json')
    require(not contract.exists(), 'Observer runtime contract already exists.')
    contract.parent.mkdir(parents=True, exist_ok=True)
    contract.write_text(files['etc/router-policy-agent/runtime/runtime.json'])
    contract.chmod(0o600)
    config = policy_runtime.CONFIG/'helper.json'
    config.write_text(json.dumps({'observer_uid': 1801,
                                 'observations_socket': str(policy_runtime.OBSERVATIONS)}))
    config.chmod(0o600)
    policy_runtime.prepare_observation_directory()
    (units/HELPER).write_text(files['usr/lib/systemd/system/'+HELPER])
    for name in (BOOTSTRAP,):
        (units/name).write_text('[Service]\nType=oneshot\nRemainAfterExit=yes\nExecStart=/usr/bin/true\n')
    for name in (BINDINGS, READER):
        (units/name).write_text('[Service]\nType=exec\nExecStart=/usr/bin/sleep 600\n')
    for name in SOCKETS:
        text = (ROOT/'mkosi/base/mkosi.extra/usr/lib/systemd/system'/name).read_text()
        (units/name).write_text(text)
    (units/CORE).write_text('[Service]\nType=oneshot\nExecStart=/usr/bin/false\n')
    observations = []
    try:
        command('systemctl', 'daemon-reload')
        command('systemd-analyze', 'verify', *(str(units/name) for name in names))
        for scenario in ('available', 'unsafe-path', 'missing-directory'):
            if scenario != 'available':
                command('systemctl', 'stop', HELPER)
                REPORT.unlink()
                policy_runtime.OBSERVATIONS.unlink()
                if scenario == 'unsafe-path':
                    target = REPORT.parent/'retained'
                    target.write_text('retained synthetic state')
                    policy_runtime.OBSERVATIONS.symlink_to(target)
                else:
                    policy_runtime.OBSERVATIONS.parent.rmdir()
            started = command('systemctl', 'start', HELPER, check=False)
            if started.returncode:
                status = command('systemctl', 'show', '--property=Id,FragmentPath,DropInPaths,Result,LoadState,ActiveState,SubState',
                                 HELPER, BOOTSTRAP, BINDINGS, *SOCKETS, check=False)
                journal = command('journalctl', '-b', '--no-pager', '-n', '30',
                                  '-u', HELPER, '-u', BOOTSTRAP, '-u', BINDINGS, '-u', SOCKETS[0], '-u', SOCKETS[1], check=False)
                raise ValueError('Observer fixture startup failed: '+
                                 (started.stderr+status.stdout+journal.stdout).decode(errors='replace')[-10000:])
            observed = observation()
            require(observed['uid'] == observed['gid'] == 0 and 1801 in observed['groups'] and
                    int(observed['cap_eff'], 16) == 1 << 12,
                    'Launcher/helper acquired extra capabilities or lost its group binding.')
            expected = {'requests': '/run/router-policy-ipc/requests.sock',
                        'status': '/run/router-policy-ipc/status.sock'}
            if scenario == 'available':
                expected['observations'] = str(policy_runtime.OBSERVATIONS)
                info = policy_runtime.OBSERVATIONS.stat()
                require((info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode)) == (0, 1801, 0o660),
                        'Observer socket permission projection differs.')
                client = socket.socket(socket.AF_UNIX)
                try:
                    client.connect(str(policy_runtime.OBSERVATIONS))
                finally:
                    client.close()
                client_code = ('import socket;client=socket.socket(socket.AF_UNIX);'
                               'client.connect("/run/lanrith-policy-observations/observations.sock");client.close()')
                for uid, allowed in ((1801, True), (1802, False)):
                    client = subprocess.run(['/usr/bin/python3', '-I', '-c', client_code], user=uid, group=uid,
                                            extra_groups=[], capture_output=True, timeout=3)
                    require((client.returncode == 0) == allowed, 'Native observer socket group boundary differs.')
            elif scenario == 'unsafe-path':
                require(target.read_text() == 'retained synthetic state' and
                        policy_runtime.OBSERVATIONS.is_symlink(), 'Unsafe path was replaced.')
            else:
                require(not policy_runtime.OBSERVATIONS.parent.exists(), 'Missing observer directory was recreated.')
            require(observed['listeners'] == expected, 'Mandatory/optional helper descriptors differ.')
            command('systemctl', 'is-active', '--quiet', HELPER, *SOCKETS)
            command('systemctl', 'stop', GATE)
            command('systemctl', 'start', GATE)
            observations.append({'scenario': scenario, **observed})
        require(command('systemctl', 'start', CORE, check=False).returncode != 0,
                'Synthetic core failure did not fail.')
        command('systemctl', 'stop', GATE)
        require(command('systemctl', 'start', GATE, check=False).returncode != 0,
                'Mandatory core failure escaped native boot gate.')
    finally:
        command('systemctl', 'stop', *names, GATE, check=False)
        command('systemctl', 'reset-failed', *names, GATE, check=False)
        for name in names:
            (units/name).unlink(missing_ok=True)
        for path in (executable, recovery, wrapper, contract):
            path.unlink(missing_ok=True)
        shutil.rmtree(library)
        shutil.rmtree(policy_runtime.ROOT)
        if policy_runtime.OBSERVATIONS.parent.exists():
            shutil.rmtree(policy_runtime.OBSERVATIONS.parent)
        shutil.rmtree(state)
        for _, name in reversed(groups):
            command('groupdel', name)
        command('systemctl', 'daemon-reload')
    return {'result': 'pass', 'test': 'offline-systemd-policy-observer-launch',
            'checks': ['exact-generated-unit', 'two-required-sockets-preserved',
                       'optional-third-descriptor', 'root-owned-group-scoped-socket',
                       'no-extra-capabilities', 'unprivileged-socket-group-boundary',
                       'unsafe-path-denied-with-core-running', 'missing-directory-keeps-core-running',
                       'optional-unavailability-keeps-native-boot-gate-healthy',
                       'mandatory-core-failure-still-blocks-acceptance'],
            'observations': observations, 'private_image_qualified': False,
            'actual_policy_engine_qualified': False,
            'limits': ['descriptor-reporting helper fixture; actual component IPC still requires qualification',
                       'no full signed image, persistent state or private console acceptance'],
            'source_sha256': {name: hashlib.sha256((ROOT/name).read_bytes()).hexdigest() for name in
                ('lanrith/extension_observations.py', 'lanrith/extensions.py', 'lanrith/policy_agent.py',
                 'lanrith/policy_runtime.py', 'tests/test_extension_observations.py',
                 'tests/policy_observer_native.py')}}
