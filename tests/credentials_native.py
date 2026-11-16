#!/usr/bin/env python3
"""Exercise image-owned credentials in a disposable offline systemd guest.

This checks the real LoadCredential, permissions and generated readiness path. Consumers
are synthetic; this is not full-image, encryption, SSH or backend acceptance.
"""

import argparse
import base64
import copy
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
from test_credential_image import fixture
from lanrith import credential_config, credential_image, credential_operation
from test_authoritative import declaration as dns_declaration
from test_radius import declaration as radius_declaration
import extension_credentials_native as extension_fixture


IMPLEMENTATION = {
    'lanrith/authoritative.py',
    'lanrith/bindings.py',
    'lanrith/build.py',
    'lanrith/config.py',
    'lanrith/credential_config.py',
    'lanrith/credential_image.py',
    'lanrith/credential_operation.py',
    'lanrith/credential_store.py',
    'lanrith/credential_values.py',
    'lanrith/extension_credential_config.py',
    'lanrith/extension_credential_operation.py',
    'lanrith/extension_credential_values.py',
    'lanrith/extension_observations.py',
    'lanrith/extensions.py',
    'lanrith/image_operation.py',
    'lanrith/integrations.py',
    'lanrith/local.py',
    'lanrith/logs.py',
    'lanrith/logs_runtime.py',
    'lanrith/policy_agent.py',
    'lanrith/policy_runtime.py',
    'lanrith/radius.py',
    'lanrith/radius_runtime.py',
    'lanrith/runtime.py',
    'lanrith/runtime_plan.py',
    'lanrith/snmp.py',
    'lanrith/systemd_credential.py',
    'mkosi/base/mkosi.extra/usr/lib/lanrith/credential_runtime.py',
    'mkosi/base/mkosi.extra/usr/lib/lanrith/snmp_credentials.py',
    'mkosi/base/mkosi.extra/usr/lib/lanrith/snmp_service.py',
    'mkosi/base/mkosi.extra/usr/lib/lanrith/systemd_service.py',
    'scripts/assemble-offline.py',
    'scripts/consumer.py',
    'scripts/qualify-credentials.py',
    'tests/extension_credentials_native.py',
    'tests/test_authoritative.py',
    'tests/test_credential_catalog.py',
    'tests/test_credential_image.py',
    'tests/test_extension_credential_operation.py',
    'tests/test_intent.py',
    'tests/test_local.py',
    'tests/test_logs.py',
    'tests/test_logs_runtime.py',
    'tests/test_radius.py',
    'tests/test_routing.py',
    'tests/test_systemd_credential.py',
}

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
        'try:pathlib.Path("/usr/lib/lanrith/credentials/core/ingest").read_bytes()\n'
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

    # Select no client authentication while the log service stays enabled.
    run('systemctl', 'stop', 'alloy.service')
    no_auth = copy.deepcopy(value)
    settings = no_auth['observability']['logs']
    settings.pop('username'); settings.pop('credential')
    settings['authentication'] = 'none'
    files = logs.render(config.normalize(no_auth), observer=observer)
    Path('/usr/share/lanrith/logs.json').write_text(files['usr/share/lanrith/logs.json'])
    (dropin/'60-lanrith.conf').write_text(files['etc/systemd/system/alloy.service.d/60-lanrith.conf'])
    (dropin/'50-credentials.conf').unlink()
    proof.write_text('import os,pathlib\n'
        'assert os.geteuid()!=0 and not os.environ.get("CREDENTIALS_DIRECTORY")\n'
        'assert not pathlib.Path("/run/lanrith-logs/password").exists()\n'
        'pathlib.Path("/run/lanrith-logs/no-auth-proof").write_text("passed")\n')
    run('systemctl', 'daemon-reload')
    run('systemctl', 'start', 'alloy.service')
    assert Path('/run/lanrith-logs/no-auth-proof').read_text() == 'passed'


def native_service_authentication(root):
    """Enabled native services do not imply unrelated authentication integrations."""
    value = dns_declaration()
    authority = value['services']['dns']['authoritative']
    authority.pop('writers')
    authority['zones'].pop('example.test')
    files = config.render(value)
    assert 'usr/share/lanrith/credentials.json' not in files
    for name, text in files.items():
        if name.startswith('usr/share/lanrith/zones/'):
            path = Path('/')/name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text)
    named = root/'named.conf'; named.write_text(files['etc/bind/named.conf'])
    run('named-checkconf', '-z', str(named))

    value = radius_declaration()
    value['identity'] = {'radius': value['identity']['radius']}
    value['identity']['radius']['admission'] = {'network': 'devices'}
    value['access']['rules'] = []
    files = config.render(value)
    assert 'directory_bind' not in files['usr/share/lanrith/credentials.json']
    assert not any(name.startswith('etc/router-policy-agent/') for name in files)
    for name, text in files.items():
        if name.startswith('etc/freeradius/3.0/'):
            path = Path('/')/name
            path.parent.mkdir(parents=True, exist_ok=True)
            # Distribution module links may point to files in mods-available.
            path.write_text(text)
    from lanrith import radius_runtime
    policy = json.loads(files['usr/share/lanrith/radius.json'])
    references = {item['reference'] for item in credential_config.catalog(config.normalize(value))['credentials']}
    secrets = {name: 'A'*32 for name in references}
    Path('/etc/freeradius/3.0/clients.conf').write_text(radius_runtime.clients_configuration(policy, secrets))
    Path('/etc/freeradius/3.0/proxy.conf').write_text(radius_runtime.proxy_configuration(policy, secrets))
    run('freeradius', '-Cx', '-lstdout')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--result', type=Path, required=True)
    args = parser.parse_args()
    assert os.geteuid() == 0 and Path('/proc/1/comm').read_text().strip() == 'systemd'
    assert {row['ifname'] for row in json.loads(run('ip', '-j', 'link'))} == {'lo'}
    assert not Path('/usr/share/lanrith/installed.json').exists(), 'Refusing initialized router state.'
    run('mount', '--make-shared', '/run')
    for number, name in enumerate(('fixture-operator', 'fixture-other', 'fixture-app', 'fixture-critical'), 1701):
        run('useradd', '--uid', str(number), '--no-create-home', '--shell', '/usr/sbin/nologin', name)
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        value = fixture(root)
        value['administration'].update(username='fixture-operator', root_access='disabled')
        selected = extension_fixture.prepare(root)
        value['extensions'] = list(selected)
        for identity in selected:
            path = root/(identity+'.json')
            path.write_bytes(b'{"synthetic":"extension-credential"}\n'); path.chmod(0o600)
            value['credentials'][identity+'/bootstrap'] = {'file': str(path)}
        base = root/'base.tar'
        with tarfile.open(base, 'w') as archive:
            # Extension accounts are supplied by the admitted overlay, so use
            # the base registry without the just-created fixture consumers.
            for name in ('passwd', 'group'):
                path = root/name
                path.write_text(''.join(line+'\n' for line in Path('/etc', name).read_text().splitlines()
                                       if not line.startswith(('fixture-app:', 'fixture-critical:'))))
                archive.add(path, arcname='etc/'+name, recursive=False)
        basic = minimal()
        basic['credentials'] = {'unused': {'file': str(root/'unavailable-secret')}}
        build.assembly(basic, base, root/'basic', version='0.1.0', sequence=11)
        basic_tree = root/'basic/mkosi.extra'
        basic_installed = json.loads((basic_tree/'usr/share/lanrith/installed.json').read_bytes())
        assert basic_installed['credential_catalog_sha256'] is None
        assert not (basic_tree/'usr/lib/systemd/system/lanrith-credential-ready.service').exists()
        assert not (basic_tree/'usr/lib/lanrith/credentials').exists()
        started = time.monotonic()
        assert credential_operation.wait_ready(basic_installed)
        assert time.monotonic()-started < 3
        native_service_authentication(root)
        first = credential_image.resolve(config.normalize(value), selected)
        build.assembly(value, base, root/'first', version='0.1.0', sequence=12, integrations=selected)
        (root/'ingest').write_bytes(b'synthetic-rotated-log-password\n')
        second = credential_image.resolve(config.normalize(value), selected)
        build.assembly(value, base, root/'second', version='0.1.0', sequence=13, integrations=selected)
        tree = root/'first/mkosi.extra'
        units = Path('/run/systemd/system'); units.mkdir(parents=True, exist_ok=True)
        shutil.copytree(tree/'usr/lib/lanrith', '/usr/lib/lanrith', dirs_exist_ok=True)
        shutil.copytree(tree/'usr/share/lanrith', '/usr/share/lanrith', dirs_exist_ok=True)
        for name in ('lanrith-credentials', 'lanrith-extension-credentials'):
            shutil.copyfile(tree/'usr/bin'/name, Path('/usr/bin')/name)
            (Path('/usr/bin')/name).chmod(0o755)
        for path in (tree/'usr/lib/systemd/system').glob('*credential*'):
            shutil.copyfile(path, units/path.name)
        catalog = credential_config.catalog(config.normalize(value))
        # This synthetic daemon exercises PID1 with every compiled native
        # format. Real DNS/BGP/RADIUS backend acceptance is a separate gate.
        script = Path('/usr/lib/lanrith/fixture-image-reader.py')
        script.write_text('import hashlib,json,os,pathlib\n'
            'root=pathlib.Path(os.environ["CREDENTIALS_DIRECTORY"])\n'
            'result={p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in root.iterdir()}\n'
            'pathlib.Path(os.environ["STATE_DIRECTORY"],"observed.json").write_text(json.dumps(result))\n')
        (units/'fixture-image-reader.service').write_text(
            '[Unit]\nRequires=lanrith-credential-ready.service\nAfter=lanrith-credential-ready.service\n'
            '[Service]\nType=oneshot\nRemainAfterExit=yes\nUser=fixture-app\nGroup=fixture-app\n'
            'StateDirectory=fixture-image-reader\nStateDirectoryMode=0700\n'
            'CapabilityBoundingSet=\nNoNewPrivileges=yes\nProtectSystem=strict\n'
            'PrivateNetwork=yes\nPrivateDevices=yes\n'+
            ''.join('LoadCredential='+i['reference']+':'+i['path']+'\n' for i in catalog['credentials'])+
            'ExecStart=/usr/bin/python3 /usr/lib/lanrith/fixture-image-reader.py\n')
        for identity in selected:
            shutil.copytree(tree/'opt'/identity, Path('/opt')/identity)
            shutil.copyfile(tree/'usr/lib/systemd/system'/(identity+'.service'), units/(identity+'.service'))
            shutil.copytree(tree/'etc/systemd/system'/(identity+'.service.d'), units/(identity+'.service.d'))
        dropin = units/'alloy.service.d'; dropin.mkdir()
        shutil.copyfile(tree/'etc/systemd/system/alloy.service.d/50-lanrith-credentials.conf', dropin/'50-credentials.conf')
        (units/'alloy.service').write_text('[Service]\nType=oneshot\nRemainAfterExit=yes\nExecStart=/usr/bin/true\n')
        run('systemctl', 'daemon-reload')
        run('systemd-analyze', 'verify', '--man=no', '--recursive-errors=no',
            *[str(path) for path in units.glob('*credential*')])
        for slot, expected in (('first', first), ('second', second), ('first', first)):
            run('systemctl', 'stop', 'fixture-image-reader.service', 'lanrith-credential-ready.service')
            # Replace this disposable fixture's mounted image input. No shared
            # credential state participates in the simulated slot selection.
            shutil.rmtree('/usr/lib/lanrith/credentials')
            shutil.copytree(root/slot/'mkosi.extra/usr/lib/lanrith/credentials', '/usr/lib/lanrith/credentials')
            started = time.monotonic()
            run('systemctl', 'start', 'fixture-image-reader.service')
            assert time.monotonic()-started < 20
            observed = json.loads(Path('/var/lib/fixture-image-reader/observed.json').read_bytes())
            assert observed == {i['reference']: hashlib.sha256(expected[i['reference']]).hexdigest()
                                for i in catalog['credentials']}
        for identity in selected:
            run('systemctl', 'start', identity+'.service')
            observed = json.loads(Path('/var/lib/fixture-'+identity+'/observed.json').read_bytes())
            assert observed['uid'] != 0 and int(observed['CapEff'], 16) == 0 and observed['NoNewPrivs'] == '1'
            assert observed['sha256'] == hashlib.sha256(first[identity+'/bootstrap']).hexdigest()
        # Unrelated users and the operator cannot read the immutable inputs.
        for user in ('fixture-operator', 'fixture-other', 'fixture-app'):
            result = subprocess.run(['runuser', '-u', user, '--', 'python3', '-c',
                'from pathlib import Path; Path("/usr/lib/lanrith/credentials/core/ingest").read_bytes()'],
                capture_output=True, timeout=10)
            assert result.returncode != 0
        assert not Path('/run/lanrith-credentials.sock').exists()
        assert not Path('/var/lib/lanrith/credential-provisioning').exists()
        # Corrupt/missing immutable input fails promptly, before a consumer.
        for broken in (None, b'bad\nlog-value'):
            run('systemctl', 'stop', 'fixture-image-reader.service', 'lanrith-credential-ready.service')
            source = Path('/usr/lib/lanrith/credentials/core/ingest')
            if broken is None:
                source.unlink()
            else:
                source.write_bytes(broken); source.chmod(0o600)
            started = time.monotonic()
            failed = subprocess.run(['systemctl', 'start', 'fixture-image-reader.service'],
                                    capture_output=True, timeout=35)
            assert failed.returncode != 0 and time.monotonic()-started < 20
            assert not active('fixture-image-reader.service')
            run('systemctl', 'reset-failed')
        source.write_bytes(first['ingest']); source.chmod(0o600)
        run('systemctl', 'start', 'lanrith-credential-ready.service')
        generated_log_staging(tree, units, first['ingest'].removesuffix(b'\n'), value)
        import pwd
        try:
            pwd.getpwnam('Debian-snmp')
        except KeyError:
            run('useradd', '--system', '--no-create-home', 'Debian-snmp')
        policy = tree/'etc/lanrith/integrations/snmp-runtime-policy.json'
        snmp_source = Path('/usr/lib/lanrith/credentials/core/monitor_user/snmpd.conf')
        before = snmp_source.stat()
        run('python3', '-c', 'import sys,json;sys.path.insert(0,"/usr/lib/lanrith");'
            'from pathlib import Path;from snmp_service import prepare,policy_value;'
            'p=policy_value(json.loads(Path(sys.argv[1]).read_bytes()));'
            'assert prepare(p);assert prepare(p)', str(policy))
        after = snmp_source.stat()
        assert (before.st_ino,before.st_mtime_ns,before.st_ctime_ns) == (after.st_ino,after.st_mtime_ns,after.st_ctime_ns)
        assert not Path('/var/lib/lanrith/snmp').exists()
        acl_case = CredentialACLTests('test_kernel_named_user_read_does_not_grant_even_the_owning_group')
        acl_case.test_kernel_named_user_read_does_not_grant_even_the_owning_group()
        journal = run('journalctl', '-b', '--no-pager', '-o', 'cat')
        assert not any(raw.strip() in journal for raw in first.values())
        result = {'schema': 1, 'result': 'pass', 'test': 'offline-systemd-credential-provisioning',
            'assessed_at': datetime.datetime.now(datetime.timezone.utc).isoformat(),
            'source_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
            'implementation_sha256': {name: hashlib.sha256((Path(__file__).parents[1]/name).read_bytes()).hexdigest()
                for name in IMPLEMENTATION},
            'systemd_version': run('systemctl', '--version').decode().splitlines()[0],
            'external_network': False, 'private_image_qualified': False,
            'checks': ['basic-router-no-credential-requirement', 'dns-authority-without-writer-credentials',
                       'radius-proxy-without-directory-credentials', 'enabled-log-without-authentication',
                       'nine-native-credentials-at-first-start', 'no-upload-or-mutable-credential-store',
                       'native-loadcredential-unprivileged-reader', 'operator-and-unrelated-user-read-denial',
                       'image-set-rotation-and-fallback-selection', 'missing-and-malformed-input-fast-failure',
                       'required-and-optional-extension-image-credentials', 'generated-log-credential-staging',
                       'snmp-image-input-with-separate-engine-state',
                       'pid1-named-user-acl-and-owning-group-denial', 'no-secret-in-journal'],
            'limits': ['synthetic-consumers', 'simulated-slot-selection',
                       'no-ssh-or-encryption-acceptance', 'no-full-image-or-backend-qualification']}
        args.result.write_bytes(release.canonical(result))
        print(json.dumps(result, sort_keys=True))


if __name__ == '__main__':
    main()
