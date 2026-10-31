#!/usr/bin/env python3
"""Exercise generated provisioning units in a disposable offline systemd guest.

This checks the real socket, sandbox and generated dependency path. Consumers
are synthetic; this is not full-image, encryption, SSH or backend acceptance.
"""

import argparse
import base64
import datetime
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import tempfile
import time

from lanrith import build, config, release
from test_intent import minimal


def run(*args, **kwargs):
    result = subprocess.run(args, capture_output=True, timeout=30, **kwargs)
    assert result.returncode == 0, 'Synthetic native credential operation failed: '+args[0]
    return result.stdout


def wait(predicate):
    deadline = time.monotonic()+20
    while not predicate():
        assert time.monotonic() < deadline, 'Synthetic native credential deadline expired.'
        time.sleep(.1)


def active(unit):
    return subprocess.run(['systemctl', 'is-active', '--quiet', unit], timeout=5).returncode == 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--result', type=Path, required=True)
    args = parser.parse_args()
    assert os.geteuid() == 0 and Path('/proc/1/comm').read_text().strip() == 'systemd'
    assert {row['ifname'] for row in json.loads(run('ip', '-j', 'link'))} == {'lo'}
    assert not Path('/usr/share/lanrith/installed.json').exists(), 'Refusing initialized router state.'
    # Podman's explicit /run tmpfs is private. systemd v257 prepares credential
    # mounts in a child mount namespace and needs propagation back to /run.
    # The container's outer mount namespace remains isolated from the host.
    run('mount', '--make-shared', '/run')
    value = minimal()
    value['administration'].update(username='fixture-operator', root_access='disabled')
    value['observability'] = {'logs': {'enabled': True, 'endpoint': 'https://192.168.10.31/otlp',
        'tls_server_name': 'logs.example.test', 'username': 'fixture', 'credential': 'ingest'}}
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        base = root/'base.tar'
        base.write_bytes(b'synthetic assembly input')
        build.assembly(value, base, root/'assembly', version='0.1.0', sequence=12)
        run('useradd', '--uid', '1701', '--no-create-home', '--shell', '/bin/sh', 'fixture-operator')
        run('useradd', '--uid', '1702', '--no-create-home', '--shell', '/bin/sh', 'fixture-other')
        tree = root/'assembly/mkosi.extra'
        shutil.copytree(tree/'usr/lib/lanrith', '/usr/lib/lanrith', dirs_exist_ok=True)
        shutil.copytree(tree/'usr/share/lanrith', '/usr/share/lanrith', dirs_exist_ok=True)
        shutil.copyfile(tree/'usr/bin/lanrith-credentials', '/usr/bin/lanrith-credentials')
        Path('/usr/bin/lanrith-credentials').chmod(0o755)
        units = Path('/run/systemd/system')
        units.mkdir(parents=True, exist_ok=True)
        for path in (tree/'usr/lib/systemd/system').glob('lanrith-credential*'):
            if path.is_file():
                shutil.copyfile(path, units/path.name)
        dropin = units/'alloy.service.d'
        dropin.mkdir()
        shutil.copyfile(tree/'etc/systemd/system/alloy.service.d/50-lanrith-credentials.conf', dropin/'50-credentials.conf')
        Path('/usr/lib/lanrith/fixture-consumer.py').write_text(
            'import hashlib,os,pathlib\n'
            'raw=(pathlib.Path(os.environ["CREDENTIALS_DIRECTORY"])/"ingest").read_bytes()\n'
            'pathlib.Path("/run/fixture-consumer.sha").write_text(hashlib.sha256(raw).hexdigest())\n')
        (units/'alloy.service').write_text('[Service]\nType=oneshot\nRemainAfterExit=yes\n'
            'LoadCredential=ingest:/var/lib/lanrith/credentials/ingest\n'
            'ExecStart=/usr/bin/python3 /usr/lib/lanrith/fixture-consumer.py\n')
        (units/'lanrith-image-completion.service').write_text('[Service]\nType=exec\n'
            'ExecStart=/usr/bin/sleep 600\nExecStopPost=/usr/bin/touch /run/fixture-completion-stopped\n')
        for unit in ('lanrith-health.service', 'lanrith-observation.service'):
            (units/unit).write_text('[Service]\nType=oneshot\nRemainAfterExit=yes\nExecStart=/usr/bin/true\n')
        (units/'boot-complete.target').write_text('[Unit]\nRequires=lanrith-health.service\nAfter=lanrith-health.service\n')
        run('systemctl', 'daemon-reload')
        run('systemd-analyze', 'verify', '--man=no', '--recursive-errors=no',
            *[str(units/name) for name in ('lanrith-credentials.socket', 'lanrith-credentials@.service',
                                         'lanrith-credential-setup.service', 'lanrith-credential-ready.service')])
        run('systemctl', 'start', 'lanrith-credentials.socket', 'lanrith-image-completion.service')
        run('systemctl', 'start', '--no-block', 'alloy.service')
        wait(lambda: Path('/run/lanrith-credentials.sock').exists())
        assert not active('alloy.service') and active('lanrith-image-completion.service')
        info = Path('/run/lanrith-credentials.sock').stat()
        assert info.st_uid == 1701 and stat.S_IMODE(info.st_mode) == 0o600
        for command in (['/usr/bin/lanrith-credentials', 'status'],
                        ['runuser', '-u', 'fixture-other', '--', '/usr/bin/lanrith-credentials', 'status']):
            denied = subprocess.run(command, capture_output=True, timeout=20)
            assert denied.returncode != 0 and not denied.stdout, 'Unauthorized identity reached credential status.'
        assert not Path('/var/lib/lanrith/credentials/ingest').exists()
        wait(lambda: not run('systemctl', 'list-units', '--failed', '--no-pager', '--no-legend',
                             'lanrith-credentials@*').strip())
        pid = run('systemctl', 'show', '--property=MainPID', '--value', 'lanrith-image-completion.service').strip()
        installed = json.loads((tree/'usr/share/lanrith/installed.json').read_bytes())
        raw = b'synthetic-native-credential'
        payload = release.canonical({'ingest': base64.b64encode(raw).decode()})
        staged = json.loads(run('runuser', '-u', 'fixture-operator', '--', '/usr/bin/lanrith-credentials',
            'stage', installed['configuration_sha256'], input=payload))
        assert staged['phase'] == 'prepared'
        wait(lambda: active('alloy.service'))
        assert Path('/run/fixture-consumer.sha').read_text() == hashlib.sha256(raw).hexdigest()
        invocation = run('systemctl', 'show', '--property=InvocationID', '--value', 'alloy.service')
        invalid = subprocess.run(['runuser', '-u', 'fixture-operator', '--', '/usr/bin/lanrith-credentials',
            'stage', installed['configuration_sha256']],
            input=release.canonical({'ingest': base64.b64encode(b'invalid\nvalue').decode()}),
            capture_output=True, timeout=20)
        assert invalid.returncode != 0 and not invalid.stdout
        assert active('alloy.service') and invocation == run('systemctl', 'show', '--property=InvocationID', '--value', 'alloy.service')
        assert Path('/run/fixture-consumer.sha').read_text() == hashlib.sha256(raw).hexdigest()
        # Apply exactly the generated executor sandbox to a disposable probe;
        # no request can select this probe or its command.
        probe = Path('/usr/lib/lanrith/fixture-sandbox.py')
        probe.write_text('import json,pathlib,socket\n'
            'value={}\n'
            'for key in ("CapEff", "NoNewPrivs"):\n'
            ' value[key]=next(x.split(":",1)[1].strip() for x in pathlib.Path("/proc/self/status").read_text().splitlines() if x.startswith(key+":"))\n'
            'try: socket.socket(socket.AF_INET,socket.SOCK_STREAM); value["inet_denied"]=False\n'
            'except OSError: value["inet_denied"]=True\n'
            'try: pathlib.Path("/etc/fixture-escape").write_text("bad"); value["outside_write_denied"]=False\n'
            'except OSError: value["outside_write_denied"]=True\n'
            'pathlib.Path("/var/lib/lanrith/credential-provisioning/fixture-sandbox.json").write_text(json.dumps(value))\n')
        generated = (units/'lanrith-credentials@.service').read_text()
        probe_unit = generated.replace('ExecStart=/usr/bin/lanrith-credentials serve',
                                       'ExecStart=/usr/bin/python3 '+str(probe)).replace('StandardInput=socket', 'StandardInput=null')
        (units/'fixture-credential-sandbox.service').write_text(probe_unit)
        run('systemctl', 'daemon-reload')
        run('systemctl', 'start', 'fixture-credential-sandbox.service')
        wait(lambda: Path('/var/lib/lanrith/credential-provisioning/fixture-sandbox.json').exists())
        observed = json.loads(Path('/var/lib/lanrith/credential-provisioning/fixture-sandbox.json').read_bytes())
        assert int(observed['CapEff'], 16) == 0 and observed['NoNewPrivs'] == '1'
        assert observed['inet_denied'] and observed['outside_write_denied']
        confirmed = json.loads(run('runuser', '-u', 'fixture-operator', '--', '/usr/bin/lanrith-credentials',
                                  'commit', staged['transaction_id']))
        assert confirmed['phase'] == 'committed'
        assert pid == run('systemctl', 'show', '--property=MainPID', '--value', 'lanrith-image-completion.service').strip()
        assert not Path('/run/fixture-completion-stopped').exists()
        assert active('alloy.service')
        result = {'schema': 1, 'result': 'pass', 'test': 'offline-systemd-credential-provisioning',
            'assessed_at': datetime.datetime.now(datetime.timezone.utc).isoformat(),
            'source_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
            'implementation_sha256': {name: hashlib.sha256((Path(__file__).parents[1]/name).read_bytes()).hexdigest()
                for name in ('lanrith/credential_operation.py', 'lanrith/credential_config.py',
                             'lanrith/credential_store.py', 'lanrith/credential_values.py', 'lanrith/build.py',
                             'lanrith/runtime.py', 'lanrith/image_operation.py', 'lanrith/config.py',
                             'tests/test_intent.py', 'scripts/qualify-credentials.py',
                             'mkosi/base/mkosi.extra/usr/lib/lanrith/snmp_credentials.py',
                             'mkosi/base/mkosi.extra/usr/lib/lanrith/snmp_service.py',
                             'mkosi/base/mkosi.extra/usr/lib/lanrith/credential_runtime.py',
                             'mkosi/base/mkosi.extra/usr/lib/lanrith/systemd_service.py')},
            'systemd_version': run('systemctl', '--version').decode().splitlines()[0],
            'external_network': False, 'private_image_qualified': False,
            'checks': ['generated-unit-verification', 'operator-uid-socket-stage-and-commit',
                       'unauthorized-uid-and-root-denied', 'malformed-input-preserves-consumers',
                       'failed-requests-collected',
                       'consumer-waits-for-complete-staged-set', 'native-loadcredential-bytes',
                       'capability-empty-no-new-privileges', 'inet-and-outside-write-denial',
                       'active-completion-observer-not-stopped'],
            'limits': ['synthetic-consumers', 'no-ssh-or-encryption-acceptance', 'no-full-image-or-backend-qualification']}
        args.result.parent.mkdir(parents=True, exist_ok=True)
        args.result.write_bytes(release.canonical(result))
        print(json.dumps(result, sort_keys=True))


if __name__ == '__main__':
    main()
