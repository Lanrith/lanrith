"""Synthetic extension cases for the offline systemd credential qualification.

Boot acceptance is a controlled fixture observation, not a boot qualification.
The generated sockets, sandboxes, gates and unprivileged readers run unchanged.
"""

import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess

from lanrith import image_operation, release


IDS = ('example-addon', 'example-critical')
CHECKS = ['extension-native-loadcredential-unprivileged-readers', 'extension-operator-uid-boundary',
          'extension-exact-writable-namespace', 'optional-extension-current-boot-acceptance-gate',
          'optional-extension-no-core-service-control', 'required-extension-committed-readiness',
          'extension-invalid-and-fallback-values-preserve-consumers']
IMPLEMENTATION = ('lanrith/extension_credential_values.py', 'lanrith/extension_credential_config.py',
                  'lanrith/extension_credential_operation.py', 'lanrith/extensions.py',
                  'tests/extension_credentials_native.py')


def prepare(root):
    selected = {}
    for index, identity in enumerate(IDS):
        directory = root/identity
        tree = directory/'root'
        unit = identity+'.service'
        name = 'fixture-app' if index == 0 else 'fixture-critical'
        script = ('import hashlib,json,os,pathlib\n'
            'raw=(pathlib.Path(os.environ["CREDENTIALS_DIRECTORY"])/"bootstrap").read_bytes()\n'
            'json.loads(raw)\n'
            'status=pathlib.Path("/proc/self/status").read_text().splitlines()\n'
            'fields={k:next(x.split(":",1)[1].strip() for x in status if x.startswith(k+":")) '
            'for k in ("CapEff","CapBnd","NoNewPrivs")}\n'
            'fields.update(uid=os.getuid(),sha256=hashlib.sha256(raw).hexdigest())\n'
            'pathlib.Path(os.environ["STATE_DIRECTORY"],"observed.json").write_text(json.dumps(fields))\n')
        files = {'opt/'+identity+'/reader.py': script,
            'usr/lib/systemd/system/'+unit: (
                '[Service]\nType=oneshot\nRemainAfterExit=yes\nUser='+name+'\nGroup='+name+'\n'
                'StateDirectory=fixture-'+identity+'\nStateDirectoryMode=0700\n'
                'ExecStart=/usr/bin/python3 -I /opt/'+identity+'/reader.py\n'
                'CapabilityBoundingSet=\nAmbientCapabilities=\nNoNewPrivileges=yes\n'
                'ProtectSystem=strict\nProtectHome=yes\nPrivateNetwork=yes\nPrivateDevices=yes\n'
                'RestrictAddressFamilies=AF_UNIX\n')}
        inventory = {}
        for path, text in files.items():
            target = tree/path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(text)
            target.chmod(0o644)
            inventory[path] = {key: release.file_record(target)[key] for key in ('sha256', 'size')} | {'mode': 0o644}
        manifest = {'schema': 1, 'id': identity, 'features': [], 'files': inventory,
            'health_units': [unit] if index else [], 'start_units': [unit],
            'identities': {'users': [{'name': name, 'uid': 1703+index, 'gid': 1703+index}],
                           'groups': [{'name': name, 'gid': 1703+index}]},
            'credentials': [{'name': 'bootstrap', 'format': 'json', 'consumers': [unit]}]}
        path = directory/'extension.json'
        path.write_bytes(release.canonical(manifest))
        selected[identity] = (directory, release.file_record(path)['sha256'])
    return selected


def exercise(installed, tree, units, run, wait, active):
    from lanrith import credential_operation, extension_credential_operation as operation

    wrapper = '/usr/bin/lanrith-extension-credentials'
    shutil.copyfile(tree/'usr/bin/lanrith-extension-credentials', wrapper)
    Path(wrapper).chmod(0o755)
    for index, identity in enumerate(IDS):
        name = 'fixture-app' if index == 0 else 'fixture-critical'
        run('useradd', '--uid', str(1703+index), '--no-create-home', '--shell', '/usr/sbin/nologin', name)
        shutil.copytree(tree/'opt'/identity, Path('/opt')/identity)
        shutil.copyfile(tree/'usr/lib/systemd/system'/(identity+'.service'), units/(identity+'.service'))
        shutil.copytree(tree/'etc/systemd/system'/(identity+'.service.d'), units/(identity+'.service.d'))
    for path in (tree/'usr/lib/systemd/system').glob('lanrith-extension-credential*'):
        if path.is_file():
            shutil.copyfile(path, units/path.name)
    for path in (tree/'usr/lib/tmpfiles.d').glob('80-lanrith-extension-credential-*.conf'):
        run('systemd-tmpfiles', '--create', str(path))
    run('systemctl', 'daemon-reload')
    native_units = [str(path) for path in units.glob('lanrith-extension-credential*')]
    run('systemd-analyze', 'verify', '--man=no', '--recursive-errors=no', *native_units)
    for identity in IDS:
        run('systemctl', 'start', 'lanrith-extension-credential-'+identity+'.socket')
        path = Path(operation.socket_path(identity))
        assert path.stat().st_uid == 1701 and stat.S_IMODE(path.stat().st_mode) == 0o600

    def cli(identity, action, *arguments, raw=None, success=True, user='fixture-operator'):
        result = subprocess.run(['runuser', '-u', user, '--', wrapper, identity, action, *arguments],
            input=raw, capture_output=True, timeout=25)
        assert (result.returncode == 0) == success, 'Native extension operator result differs.'
        if not success:
            assert not result.stdout, 'Rejected native extension operation exposed output.'
            return None
        return json.loads(result.stdout)

    def payload(raw):
        import base64
        return release.canonical({'bootstrap': base64.b64encode(raw).decode()})

    optional, required = IDS
    assert cli(optional, 'status')['phase'] == 'needs-core-acceptance'
    cli(optional, 'stage', installed['configuration_sha256'], raw=payload(b'{"token":"before-core"}'), success=False)
    assert not Path('/var/lib/lanrith/extension-credentials/'+optional+'/bootstrap').exists()
    assert not operation.required_ready(installed)
    # A required extension must work before acceptance. Its ready gate permits
    # prepared readers, while the aggregate boot gate requires explicit commit.
    run('systemctl', 'start', '--no-block', required+'.service')
    first_raw = b'{"token":"synthetic-critical-reader"}\n'
    staged = cli(required, 'stage', installed['configuration_sha256'], raw=payload(first_raw))
    assert staged['phase'] == 'prepared'
    wait(lambda: active(required+'.service'))
    assert not operation.required_ready(installed)
    cli(required, 'commit', staged['transaction_id'])
    assert operation.required_ready(installed)
    for key in ('boot-complete.target', *credential_operation.OBSERVERS):
        wait(lambda selected=key: active(selected))
    tracked = {key: run('systemctl', 'show', '--property=InvocationID', '--value', key)
               for key in ('boot-complete.target', *credential_operation.OBSERVERS)}
    # Simulate the core's protected acceptance products, with this boot's ID.
    image_operation.save_accepted(installed)
    directory = Path('/run/lanrith')
    directory.mkdir(mode=0o755, exist_ok=True)
    (directory/'boot.json').write_bytes(release.canonical({'schema': 1, 'accepted': True, 'boot_complete': True,
        'image_id': installed['image_id'], 'deployment_sequence': installed['deployment_sequence'],
        'boot_id': Path('/proc/sys/kernel/random/boot_id').read_text().strip()}))
    assert operation.core_accepted(installed)
    run('systemctl', 'start', '--no-block', optional+'.service')
    second_raw = b'{"token":"synthetic-optional-reader"}\n'
    staged = cli(optional, 'stage', installed['configuration_sha256'], raw=payload(second_raw))
    assert staged['phase'] == 'prepared'
    wait(lambda: active(optional+'.service'))
    cli(optional, 'commit', staged['transaction_id'])
    for index, (identity, raw) in enumerate(zip(IDS, (second_raw, first_raw))):
        observed = json.loads(Path('/var/lib/fixture-'+identity+'/observed.json').read_bytes())
        assert observed['uid'] == 1703+index and observed['sha256'] == hashlib.sha256(raw).hexdigest()
        assert int(observed['CapEff'], 16) == int(observed['CapBnd'], 16) == 0 and observed['NoNewPrivs'] == '1'
    invocation = run('systemctl', 'show', '--property=InvocationID', '--value', optional+'.service')
    cli(optional, 'stage', installed['configuration_sha256'], raw=payload(b'{bad-json'), success=False)
    cli(optional, 'stage', installed['configuration_sha256'], raw=payload(b'{"token":"rotated"}'), success=False)
    assert invocation == run('systemctl', 'show', '--property=InvocationID', '--value', optional+'.service')
    # Even with a deliberately relaxed fixture socket mode, kernel peer UID
    # checks reject root and the other unprivileged identity.
    path = Path(operation.socket_path(optional))
    path.chmod(0o666)
    try:
        for user in ('root', 'fixture-other'):
            cli(optional, 'status', success=False, user=user)
    finally:
        path.chmod(0o600)
    control = '/var/lib/lanrith/extension-credential-provisioning/'+optional
    probe = Path('/opt/fixture-extension-sandbox.py')
    probe.write_text('import json,pathlib,socket\n'
        'result={}\n'
        'for name,path in '+repr({'core': '/var/lib/lanrith/credentials/ingest',
                                'other': '/var/lib/lanrith/extension-credentials/'+required+'/bootstrap',
                                'outside': '/etc/fixture-extension-escape'})+'.items():\n'
        ' try:\n'
        '  with open(path,"ab") as stream: stream.write(b"bad")\n'
        '  result[name]=False\n'
        ' except OSError: result[name]=True\n'
        'try: socket.socket(socket.AF_INET,socket.SOCK_STREAM); result["inet"]=False\n'
        'except OSError: result["inet"]=True\n'
        'status=pathlib.Path("/proc/self/status").read_text().splitlines()\n'
        'result["caps"]=all(int(x.split(":",1)[1].strip(),16)==0 for x in status if x.startswith(("CapEff:","CapBnd:")))\n'
        'result["nnp"]="NoNewPrivs:\\t1" in status\n'
        'pathlib.Path('+repr(control+'/fixture-sandbox.json')+').write_text(json.dumps(result))\n')
    generated = (units/('lanrith-extension-credential-'+optional+'@.service')).read_text()
    (units/'fixture-extension-sandbox.service').write_text(generated.replace(
        'ExecStart='+wrapper+' '+optional+' serve', 'ExecStart=/usr/bin/python3 -I '+str(probe)).replace(
        'StandardInput=socket', 'StandardInput=null'))
    run('systemctl', 'daemon-reload')
    run('systemctl', 'start', 'fixture-extension-sandbox.service')
    wait(lambda: Path(control+'/fixture-sandbox.json').exists())
    assert all(json.loads(Path(control+'/fixture-sandbox.json').read_bytes()).values())
    assert Path('/var/lib/lanrith/extension-credentials/'+required+'/bootstrap').read_bytes() == first_raw
    assert credential_operation.ready(installed)
    assert operation.required_ready(installed)
    assert all(previous == run('systemctl', 'show', '--property=InvocationID', '--value', unit)
               for unit, previous in tracked.items())
    assert not Path('/run/fixture-completion-stopped').exists()
    return CHECKS
