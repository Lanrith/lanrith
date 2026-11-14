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
import tarfile
import tempfile
import time

from lanrith import build, config, extension_observations, logs, release
from test_systemd_credential import CredentialACLTests
from test_intent import minimal
import extension_credentials_native as extension_fixture


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


def generated_log_staging(tree, units, raw, value):
    """Exercise the real generated pre-start path with a nonroot consumer."""
    run('systemctl', 'stop', 'alloy.service')
    accounts = Path('/run/log-staging-accounts.conf')
    accounts.write_text('u alloy - "Synthetic log exporter" /nonexistent\n')
    run('systemd-sysusers', str(accounts))
    dropin = units/'alloy.service.d'
    import pwd
    other = pwd.getpwnam('fixture-other')
    identities = {'users': [{'name': 'fixture-other', 'uid': other.pw_uid, 'gid': other.pw_gid}],
                  'groups': [{'name': 'fixture-other', 'gid': other.pw_gid}]}
    selected = extension_observations.declarations([{'service': 'logs', 'user': 'fixture-other'}], identities)
    observer = extension_observations.resolve(config.normalize(value), [selected], service='logs')
    files = logs.render(config.normalize(value), observer=observer)
    Path('/usr/share/lanrith/logs.json').write_text(files['usr/share/lanrith/logs.json'])
    (dropin/'60-lanrith.conf').write_text(files['etc/systemd/system/alloy.service.d/60-lanrith.conf'])
    for name in ('lanrith-services.service', 'nftables.service'):
        (units/name).write_text('[Service]\nType=oneshot\nRemainAfterExit=yes\nExecStart=/usr/bin/true\n')
    # Only the daemon command and unavailable fixture namespace are replaced.
    # Credential source, generated root staging command and filesystem sandbox
    # are the real compiled contract. No protected store read is substituted.
    (dropin/'90-staging-fixture.conf').write_text('[Unit]\nRequires=\nAfter=\nBindsTo=\n'
        '[Service]\nType=oneshot\nNotifyAccess=none\nWatchdogSec=0\nRestart=no\nNetworkNamespacePath=\n'
        'ExecStart=\nExecStart=/usr/bin/python3 /usr/lib/lanrith/fixture-log-staging.py\n')
    proof = Path('/usr/lib/lanrith/fixture-log-staging.py')
    proof.write_text('import hashlib,json,os,pathlib,stat\n'
        'p=pathlib.Path("/run/lanrith-logs/password");s=p.stat()\n'
        'assert os.geteuid()!=0 and s.st_uid==os.geteuid() and stat.S_IMODE(s.st_mode)==0o400 and s.st_nlink==1\n'
        'status=dict(line.split(":",1) for line in pathlib.Path("/proc/self/status").read_text().splitlines())\n'
        'assert int(status["CapEff"],16)==0 and status["NoNewPrivs"].strip()=="1"\n'
        'try:pathlib.Path("/var/lib/lanrith/credentials/ingest").read_bytes()\n'
        'except PermissionError:pass\n'
        'else:raise AssertionError("consumer can read protected credential store")\n'
        'd=pathlib.Path("/run/lanrith-log-observations");assert stat.S_IMODE(d.stat().st_mode)==0o2750\n'
        'pathlib.Path("/run/lanrith-log-observations/events.jsonl").write_text("fixture metadata only\\n")\n'
        'pathlib.Path("/run/lanrith-logs/staging-proof.json").write_text(json.dumps({'
        '"uid":os.geteuid(),"sha256":hashlib.sha256(p.read_bytes()).hexdigest()}))\n')
    run('systemctl', 'daemon-reload')
    try:
        run('systemctl', 'start', 'alloy.service')
    except AssertionError:
        diagnostic = subprocess.run(['journalctl', '-b', '-u', 'alloy.service', '--no-pager', '-n', '30'],
                                    capture_output=True, timeout=10)
        print(diagnostic.stdout[-12000:].decode(errors='replace'), flush=True)
        raise
    result = json.loads(Path('/run/lanrith-logs/staging-proof.json').read_bytes())
    assert result['uid'] != 0 and result['sha256'] == hashlib.sha256(raw).hexdigest()
    assert Path('/run/lanrith-log-observations').stat().st_gid == other.pw_gid
    probe = ('from pathlib import Path; assert Path("/run/lanrith-log-observations/events.jsonl").read_text(); '
             '\ntry: Path("/run/lanrith-logs/password").read_bytes()'
             '\nexcept PermissionError: pass'
             '\nelse: raise AssertionError("observer can read log credential")')
    run('runuser', '-u', 'fixture-other', '--', 'python3', '-c', probe)
    denied = subprocess.run(['runuser', '-u', 'fixture-other', '--', '/usr/lib/lanrith/logs-runtime', 'stage'],
                            capture_output=True, timeout=10)
    assert denied.returncode != 0, 'Another user can invoke privileged log staging.'


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
        with tarfile.open(base, 'w') as archive:
            for name in ('etc/passwd', 'etc/group'):
                archive.add('/'+name, arcname=name, recursive=False)
        selected = extension_fixture.prepare(root)
        value['extensions'] = list(selected)
        build.assembly(value, base, root/'assembly', version='0.1.0', sequence=12, integrations=selected)
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
        extension_checks = extension_fixture.exercise(installed, tree, units, run, wait, active)
        generated_log_staging(tree, units, raw, value)
        acl_case = CredentialACLTests('test_kernel_named_user_read_does_not_grant_even_the_owning_group')
        acl_case.test_kernel_named_user_read_does_not_grant_even_the_owning_group()
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
                             'mkosi/base/mkosi.extra/usr/lib/lanrith/systemd_service.py',
                             'lanrith/logs.py', 'lanrith/logs_runtime.py', 'lanrith/systemd_credential.py', 'tests/test_systemd_credential.py', 'lanrith/policy_runtime.py', 'lanrith/extension_observations.py',
                             *extension_fixture.IMPLEMENTATION)},
            'systemd_version': run('systemctl', '--version').decode().splitlines()[0],
            'external_network': False, 'private_image_qualified': False,
            'checks': ['generated-unit-verification', 'operator-uid-socket-stage-and-commit',
                       'unauthorized-uid-and-root-denied', 'malformed-input-preserves-consumers',
                       'failed-requests-collected',
                       'consumer-waits-for-complete-staged-set', 'native-loadcredential-bytes',
                       'capability-empty-no-new-privileges', 'inet-and-outside-write-denial',
                       'active-completion-observer-not-stopped', 'generated-log-credential-staging',
                       'pid1-named-user-acl-and-owning-group-denial', *extension_checks],
            'limits': ['synthetic-consumers', 'synthetic-core-boot-acceptance-products',
                       'no-ssh-or-encryption-acceptance', 'no-full-image-or-backend-qualification']}
        args.result.parent.mkdir(parents=True, exist_ok=True)
        args.result.write_bytes(release.canonical(result))
        print(json.dumps(result, sort_keys=True))


if __name__ == '__main__':
    main()
