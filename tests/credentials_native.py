#!/usr/bin/env python3
"""Exercise image-owned credentials in a disposable offline systemd guest.

This checks the real LoadCredential, permissions and generated readiness path. Consumers
are synthetic; this is not full-image, encryption, SSH or backend acceptance.
"""

import argparse
from contextlib import contextmanager
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

from lanrith import build, config, image_operation, runtime, extension_observations, logs, release
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
    'lanrith/dns64.py',
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
    'tests/radius_proxy_fixture.py',
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


@contextmanager
def log_peer(root, first, second):
    """A synthetic ingest peer with separate TLS and client authentication."""
    from http.client import HTTPSConnection
    from http.server import BaseHTTPRequestHandler, HTTPServer
    import ssl
    from threading import Thread

    def header(raw):
        return 'Basic '+base64.b64encode(b'fixture:'+raw.removesuffix(b'\n')).decode()

    allowed = {header(first), header(second)}
    class Peer(BaseHTTPRequestHandler):
        def do_POST(self):
            assert self.path == '/ingest' and self.rfile.read(int(self.headers['Content-Length'])) == b'fixture'
            self.send_response(204 if self.headers.get('Authorization') in allowed else 401)
            self.end_headers()

        def log_message(self, *_):
            pass

    certificate, key = root/'peer.crt', root/'peer.key'
    run('openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
        '-subj', '/CN=fixture-ingest', '-addext', 'subjectAltName=IP:127.0.0.1',
        '-keyout', str(key), '-out', str(certificate))
    with HTTPServer(('127.0.0.1', 0), Peer) as server:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(certificate, key)
        server.socket = context.wrap_socket(server.socket, server_side=True)
        worker = Thread(target=server.serve_forever, daemon=True)
        worker.start()
        def authenticate(expected):
            # The mounted image fixture selects the input. Each POST uses a
            # new TLS connection and checks the fixture peer's certificate.
            raw = Path('/usr/lib/lanrith/credentials/core/ingest').read_bytes()
            client = HTTPSConnection('127.0.0.1', server.server_port, timeout=3,
                                     context=ssl.create_default_context(cafile=certificate))
            try:
                client.request('POST', '/ingest', body=b'fixture', headers={'Authorization': header(raw)})
                assert client.getresponse().status == expected
            finally:
                client.close()
        try:
            yield authenticate, lambda: allowed.remove(header(first))
        finally:
            server.shutdown()
            worker.join(timeout=3)


def independent_readers(tree, units, catalog):
    """Start ordinary service jobs with the image gates and actual PID1 transport."""
    script = Path('/usr/lib/lanrith/fixture-scoped-reader.py')
    script.write_text('import os,pathlib,sys\n'
        'credentials=pathlib.Path(os.environ["CREDENTIALS_DIRECTORY"])\n'
        'assert {p.name for p in credentials.iterdir()} == set(sys.argv[1:])\n'
        'assert all((credentials/n).read_bytes() for n in sys.argv[1:])\n'
        'try: pathlib.Path("/usr/lib/lanrith/credentials/core/ingest").read_bytes()\n'
        'except PermissionError: pass\n'
        'else: raise AssertionError("sibling image credential was readable")\n')
    consumers = [('tsig-base64', 'lanrith-dns-state', 'named'),
                 ('bgp-token', 'lanrith-routing-credentials', 'frr'),
                 ('radius-secret', 'lanrith-radius-runtime', 'freeradius')]
    for kind, helper, daemon in consumers:
        references = sorted(i['reference'] for i in catalog['credentials'] if i['format'] == kind)
        generated = (tree/'usr/lib/systemd/system'/(helper+'.service')).read_text()
        loads = [line for line in generated.splitlines() if line.startswith('LoadCredential=')]
        assert sorted(line.split('=', 1)[1].split(':', 1)[0] for line in loads) == references
        for name in (helper, daemon):
            unit = name+'.service'
            dropin = units/(unit+'.d')
            dropin.mkdir(exist_ok=True)
            shutil.copyfile(tree/'etc/systemd/system'/(unit+'.d')/'50-lanrith-credentials.conf',
                            dropin/'50-lanrith-credentials.conf')
        (units/(helper+'.service')).write_text('[Service]\nType=oneshot\nRemainAfterExit=yes\n'
            'User=fixture-app\nNoNewPrivileges=yes\nCapabilityBoundingSet=\n'+'\n'.join(loads)+'\n'
            'ExecStart=/usr/bin/python3 '+str(script)+' '+' '.join(references)+'\n')
        # The package daemons use the materialized output of this named prerequisite.
        (units/(daemon+'.service')).write_text('[Unit]\nRequires='+helper+'.service\nAfter='+helper+
            '.service\n[Service]\nType=oneshot\nRemainAfterExit=yes\nExecStart=/usr/bin/true\n')
    # Earlier native RADIUS qualification used a production drop-in and helper.
    # Remove only that fixture's daemon drop-in before checking startup isolation.
    (units/'freeradius.service.d/60-lanrith.conf').unlink(missing_ok=True)
    run('systemctl', 'daemon-reload')
    for _, helper, daemon in consumers:
        run('systemctl', 'start', daemon+'.service')
        assert active(daemon+'.service') and active(helper+'.service')
    failed = subprocess.run(['systemctl', 'start', 'alloy.service'], capture_output=True, timeout=35)
    assert failed.returncode != 0 and not active('alloy.service')


def radius_markers(generation):
    return {name: hashlib.sha256((generation+'/'+name).encode()).hexdigest()
            for name in ('radius_wired', 'radius_wireless', 'radius_upstream')}


@contextmanager
def radius_peer(policy, network, marker):
    upstream = policy['proxy']['address']
    with tempfile.TemporaryDirectory(prefix='radius-proxy.') as temporary:
        proof = Path(temporary)/'packets'
        with subprocess.Popen([*network, 'python3', str(Path(__file__).with_name('radius_proxy_fixture.py')),
                               upstream, str(proof)], stdin=subprocess.PIPE, stdout=subprocess.DEVNULL) as backend:
            try:
                backend.stdin.write(marker.encode()+b'\n')
                backend.stdin.close()
                wait(lambda: Path(str(proof)+'.ready').exists() or backend.poll() is not None)
                assert backend.poll() is None, 'Synthetic RADIUS upstream failed to bind.'
                yield proof
            finally:
                backend.terminate()


def radius_request(policy, network, source, marker):
    packet = ('User-Name = "020000000001"\nUser-Password = "020000000001"\n'
              'Calling-Station-Id = "02:00:00:00:00:01"\nService-Type = Call-Check\n'
              'NAS-Port = 5\nMessage-Authenticator = 0x00\nPacket-Src-IP-Address = '+source+'\n')
    result = subprocess.run([*network, 'radclient', '-x', '-t', '4', '-r', '1',
                             policy['listeners'][0]+':1812', 'auth', marker],
                            input=packet.encode(), capture_output=True, timeout=8)
    return [row.split()[1] for row in result.stdout.splitlines() if row.startswith(b'Received ')]


def native_radius_clients(policy, network, markers, *, crossed=False):
    # Expected source-to-reference assignments are independent of the renderer.
    cases = [('192.168.10.40', 'radius_wired', 'radius_wireless'),
             ('192.168.10.33', 'radius_wireless', 'radius_wired')]
    with radius_peer(policy, network, markers['radius_upstream']) as proof:
        for index, (source, reference, other) in enumerate(cases, 1):
            replies = radius_request(policy, network, source, markers[reference])
            assert replies == [b'Access-Reject'], 'Missing authenticated NAS reply for '+reference
            assert proof.read_text() == str(index), 'Missing authenticated upstream request for '+reference
            if crossed:
                assert not radius_request(policy, network, source, markers[other]), 'Cross-assigned NAS key accepted.'
                assert proof.read_text() == str(index), 'Cross-assigned NAS reached upstream.'
    if crossed:
        with radius_peer(policy, network, markers['radius_wired']) as proof:
            replies = radius_request(policy, network, cases[0][0], markers['radius_wired'])
            assert b'Access-Accept' not in replies
            assert Path(str(proof)+'.received').exists() and not proof.exists(), 'Cross-assigned upstream key accepted.'


def radius_mount(markers, *, expect_inode):
    """Read the package paths inside the running MainPID's mount namespace."""
    pid = run('systemctl', 'show', '--property=MainPID', '--value', 'freeradius.service').decode().strip()
    assert int(pid) > 1
    ns = ['nsenter', '--target', pid, '--mount', '--']
    config_dir = '/etc/freeradius/3.0/'
    for name in ('clients.conf', 'proxy.conf'):
        path = config_dir+name
        visible = run(*ns, 'runuser', '-u', 'freerad', '--', 'cat', path)
        if name == 'proxy.conf':
            assert all(marker.encode() in visible for marker in markers.values()), 'Incomplete mounted generation.'
            assert int(run(*ns, 'stat', '-c', '%i', path)) == expect_inode
            options = run(*ns, 'findmnt', '-n', '-o', 'VFS-OPTIONS', '--mountpoint', path)
            assert b'ro' in options.strip().split(b','), 'Writable credential bind mount.'
            denied = subprocess.run([*ns, 'runuser', '-u', 'fixture-other', '--', 'test', '-r', path], timeout=10)
            assert denied.returncode != 0, 'An unrelated user can read the credential generation.'
        else:
            assert visible.startswith(b'#') and b'secret' not in visible
        # Check write access without changing the content on a failing test.
        denied = subprocess.run([*ns, 'runuser', '-u', 'freerad', '--', 'python3', '-c',
                                 'import os,sys;os.close(os.open(sys.argv[1],os.O_WRONLY))', path],
                                capture_output=True, timeout=10)
        assert denied.returncode != 0, 'Daemon can write '+name


def native_radius_startup(files, policy, references):
    """Exercise storage recovery, publication, and the real daemon's read-only bind."""
    import grp
    units = Path('/run/systemd/system')
    units.mkdir(exist_ok=True)
    for name in ('lanrith-services.service', 'nftables.service'):
        (units/name).write_text('[Service]\nType=oneshot\nRemainAfterExit=yes\nExecStart=/usr/bin/true\n')
    # Network/firewall readiness is a fixture precondition. The service,
    # credentials, staging helper, privilege boundary and daemon are real.
    run('ip', 'netns', 'add', 'lanrith-services')
    network = ['nsenter', '--net=/run/netns/lanrith-services', '--']
    run(*network, 'ip', 'link', 'set', 'lo', 'up')
    for address in [*policy['listeners'], policy['proxy']['address'], '192.168.10.40', '192.168.10.33']:
        run(*network, 'ip', 'address', 'add', address+('/128' if ':' in address else '/32'), 'dev', 'lo')
    store = Path('/var/lib/lanrith/credentials')
    store.mkdir(parents=True, mode=0o700, exist_ok=True)
    first, second = radius_markers('first'), radius_markers('second')
    assert references == set(first)
    for name, marker in first.items():
        (store/name).write_text(marker)
        (store/name).chmod(0o600)
    metadata = Path('/usr/share/lanrith')
    metadata.mkdir(parents=True, exist_ok=True)
    (metadata/'radius.json').write_text(files['usr/share/lanrith/radius.json'])
    for name in ('usr/lib/systemd/system/lanrith-radius-runtime.service',
                 'etc/systemd/system/freeradius.service.d/60-lanrith.conf'):
        target = units/name.split('system/', 1)[1]
        target.parent.mkdir(exist_ok=True)
        target.write_text(files[name])
    entry = Path('/usr/lib/lanrith/radius-runtime')
    entry.write_text('#!/usr/bin/python3 -I\nimport sys\nsys.path.insert(0,"/usr/lib/lanrith")\n'
                     'from lanrith.radius_runtime import main\nsys.exit(main())\n')
    entry.chmod(0o755)
    ready = 'fixture-radius-ready.service'
    (units/ready).write_text('[Unit]\nRequires=freeradius.service\nAfter=freeradius.service\n'
                             '[Service]\nType=oneshot\nRemainAfterExit=yes\nExecStart=/usr/bin/true\n')
    run('systemctl', 'daemon-reload')
    root = Path('/run/lanrith-radius')
    root.mkdir()
    group = grp.getgrnam('freerad').gr_gid
    run('mount', '-t', 'tmpfs', '-o', f'size=64k,mode=0700,gid={group}', 'tmpfs', str(root))
    published = root/'radius.conf'
    filler = root/'space-pressure'
    filler.write_bytes(bytes(65536))
    daemon, stager = 'freeradius.service', 'lanrith-radius-runtime.service'
    shutil.rmtree('/var/log/freeradius', ignore_errors=True)
    try:
        # Release real tmpfs pressure only after the stager itself reports ENOSPC.
        run('systemctl', 'start', '--no-block', ready)
        wait(lambda: b'retrying staging after ENOSPC' in run('journalctl', '-b', '-u', stager, '-o', 'cat'))
        assert not published.exists() and not active(daemon)
        filler.unlink()
        wait(lambda: active(ready))
        assert active(daemon) and Path('/var/log/freeradius').is_dir()
        before = published.stat()
        assert (before.st_uid, before.st_gid, stat.S_IMODE(before.st_mode)) == (0, group, 0o640)
        radius_mount(first, expect_inode=before.st_ino)
        denied = subprocess.run(['runuser', '-u', 'freerad', '--', str(entry), 'stage'], capture_output=True, timeout=10)
        assert denied.returncode != 0

        for name, marker in second.items():
            (store/name).write_text(marker)
        (root/'.pending').write_bytes(b'interrupted scratch')
        run('systemctl', 'start', stager)
        assert published.stat().st_ino != before.st_ino and list(root.iterdir()) == [published]
        run('systemctl', 'reload', daemon)
        radius_mount(first, expect_inode=before.st_ino)
        native_radius_clients(policy, network, first)
        run('systemctl', 'restart', daemon)
        radius_mount(second, expect_inode=published.stat().st_ino)
        native_radius_clients(policy, network, second, crossed=True)

        run('systemctl', 'stop', daemon)
        before = published.stat()
        filler.write_bytes(bytes(os.statvfs(root).f_bavail * os.statvfs(root).f_frsize))
        started = time.monotonic()
        failed = subprocess.run(['systemctl', 'start', daemon], capture_output=True, timeout=31)
        duration = time.monotonic()-started
        assert failed.returncode and not active(daemon) and 10 <= duration < 30
        assert published.stat().st_ino == before.st_ino
        filler.unlink()
        invalid = 'invalid synthetic credential'
        manifest = metadata/'radius.json'
        for fault in ('credential', 'manifest owner', 'manifest syntax'):
            run('systemctl', 'reset-failed')
            (store/'radius_wired').write_text(invalid if fault == 'credential' else second['radius_wired'])
            os.chown(manifest, 1 if fault == 'manifest owner' else 0, 0)
            manifest.write_text('{}' if fault == 'manifest syntax' else files['usr/share/lanrith/radius.json'])
            started = time.monotonic()
            failed = subprocess.run(['systemctl', 'start', daemon], capture_output=True, timeout=12)
            assert failed.returncode and not active(daemon) and time.monotonic()-started < 10, fault
            assert published.stat().st_ino == before.st_ino and list(root.iterdir()) == [published]
        manifest.write_text(files['usr/share/lanrith/radius.json'])
        run('systemctl', 'reset-failed')
        run('systemctl', 'start', daemon)
        radius_mount(second, expect_inode=published.stat().st_ino)
        journal = run('journalctl', '-b', '-u', stager, '-u', daemon, '-o', 'cat')
        assert b'ENOSPC; service remains closed' in journal
        assert not any(marker.encode() in journal for marker in [*first.values(), *second.values(), invalid])
        print(f'Nested NAS and proxy keys, pinned rotation and recoverable startup passed. '
              f'Persistent ENOSPC withheld startup in {duration:.2f}s.', flush=True)
    finally:
        run('systemctl', 'stop', daemon)
        run('ip', 'netns', 'delete', 'lanrith-services')
        run('umount', str(root))


def native_dns64_startup():
    """Run the generated DNS64 unit with its real sandbox and query loopback."""
    value = dns_declaration()
    value['translation'] = {'nat64': {'enabled': True}}
    files = config.render(value)
    units = Path('/run/systemd/system')
    units.mkdir(exist_ok=True)
    for name in ('lanrith-services.service', 'nftables.service', 'named.service'):
        (units/name).write_text('[Service]\nType=oneshot\nRemainAfterExit=yes\nExecStart=/usr/bin/true\n')
    run('ip', 'netns', 'add', 'lanrith-services')
    network = ['nsenter', '--net=/run/netns/lanrith-services', '--']
    run(*network, 'ip', 'link', 'set', 'lo', 'up')
    unit = 'lanrith-dns64-private.service'
    (units/unit).write_text(files['usr/lib/systemd/system/'+unit])
    Path('/etc/unbound/unbound-private.conf').write_text(files['etc/unbound/unbound-private.conf'])
    run('systemctl', 'daemon-reload')
    try:
        for action in ('start', 'restart'):
            run('systemctl', action, unit)
            for attempt in range(20):
                answer = subprocess.run([*network, 'dig', '@127.0.0.1', '-p', '5354',
                    'localhost', 'A', '+short', '+time=1', '+tries=1'], capture_output=True, timeout=3)
                if answer.returncode == 0 and answer.stdout.strip() == b'127.0.0.1':
                    break
                time.sleep(.1)
            else:
                raise AssertionError('Generated DNS64 sandbox cannot start and answer local DNS.')
            run('systemctl', 'is-active', '--quiet', unit)
    finally:
        run('systemctl', 'stop', unit)
        run('ip', 'netns', 'delete', 'lanrith-services')


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
    value['identity']['radius']['clients']['wireless']['address'] = '192.168.10.32/27'
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
    policy = json.loads(files['usr/share/lanrith/radius.json'])
    references = {item['reference'] for item in credential_config.catalog(config.normalize(value))['credentials']}
    run('freeradius', '-Cx', '-lstdout')
    native_radius_startup(files, policy, references)
    native_dns64_startup()


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
        shutil.copytree(basic_tree/'usr/lib/lanrith', '/usr/lib/lanrith', dirs_exist_ok=True)
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
        with log_peer(root, first['ingest'], second['ingest']) as (authenticate, retire):
            retired = False
            for slot, expected, status in (('first', first, 204), ('second', second, 204), ('first', first, 204),
                                          ('first', first, 401), ('second', second, 204), ('first', first, 401)):
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
                if status == 401 and not retired:
                    retire()
                    retired = True
                authenticate(status)
        installed = json.loads((tree/'usr/share/lanrith/installed.json').read_bytes())
        optional = next(name for name, row in installed['extension_credential_catalogs'].items()
                        if not row['core_required'])
        required = next(name for name, row in installed['extension_credential_catalogs'].items()
                        if row['core_required'])
        run('systemctl', 'start', required+'.service')
        failed = subprocess.run(['systemctl', 'start', optional+'.service'], capture_output=True, timeout=35)
        assert failed.returncode and not active(optional+'.service')
        Path(installed['state_directory']).chmod(0o700)  # Normally set by appliance initialization.
        image_operation.save_accepted(installed)
        runtime.publish_boot(installed, Path(installed['uki_name']), accepted=True)
        for identity in selected:
            run('systemctl', 'start', identity+'.service')
            observed = json.loads(Path('/var/lib/fixture-'+identity+'/observed.json').read_bytes())
            assert observed['uid'] != 0 and int(observed['CapEff'], 16) == 0 and observed['NoNewPrivs'] == '1'
            assert observed['sha256'] == hashlib.sha256(first[identity+'/bootstrap']).hexdigest()
        # A direct restart must consult the visible promotion again, even on
        # the same boot when a previous activation successfully loaded its file.
        run('systemctl', 'stop', optional+'.service')
        pending = {'schema': 1, 'target': image_operation.identity(installed), 'previous': None,
                   'operation': None, 'manual': True}
        image_operation.atomic(image_operation.promotion_path(installed), pending)
        failed = subprocess.run(['systemctl', 'start', optional+'.service'], capture_output=True, timeout=35)
        assert failed.returncode and not active(optional+'.service')
        image_operation.finish_promotion(installed)
        run('systemctl', 'start', optional+'.service')
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
        independent_readers(tree, units, catalog)
        source.write_bytes(first['ingest']); source.chmod(0o600)
        run('systemctl', 'start', 'lanrith-credential-ready.service')
        generated_log_staging(tree, units, first['ingest'].removesuffix(b'\n'), value)
        import pwd
        try:
            pwd.getpwnam('Debian-snmp')
        except KeyError:
            run('useradd', '--system', '--no-create-home', 'Debian-snmp')
        policy = tree/'etc/lanrith/integrations/snmp-runtime-policy.json'
        # Fresh /var contains no package-created engine directory. It must exist
        # before systemd constructs the daemon's ReadWritePaths sandbox.
        shutil.rmtree('/var/lib/snmp', ignore_errors=True)
        run('systemd-tmpfiles', '--create', str(tree/'usr/lib/tmpfiles.d/80-lanrith-snmp.conf'))
        engine = Path('/var/lib/snmp').stat()
        assert engine.st_uid == pwd.getpwnam('Debian-snmp').pw_uid
        assert stat.S_IMODE(engine.st_mode) == 0o700
        unit = (tree/'usr/lib/systemd/system/snmpd.service').read_text()
        assert 'ExecStartPre=/usr/lib/lanrith/snmp-runtime prepare\n' in unit
        assert 'ExecCondition=' not in unit
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
                       'radius-native-cold-start-restart-and-readonly-fragments', 'all-radius-nas-clients-reach-authenticated-proxy',
                       'radius-bounded-storage-recovery', 'radius-atomic-rotation-and-nested-credentials',
                       'dns64-native-sandbox-cold-start-restart',
                       'nine-native-credentials-at-first-start', 'no-upload-or-mutable-credential-store',
                       'native-loadcredential-unprivileged-reader', 'operator-and-unrelated-user-read-denial',
                       'image-set-rotation-and-fallback-selection', 'fresh-log-peer-authentication-through-retirement',
                       'missing-and-malformed-input-fast-failure',
                       'independent-service-credential-startup', 'optional-credential-current-boot-commit',
                       'required-and-optional-extension-image-credentials', 'generated-log-credential-staging',
                       'snmp-image-input-with-separate-engine-state', 'snmp-fresh-engine-directory-before-sandbox',
                       'pid1-named-user-acl-and-owning-group-denial', 'no-secret-in-journal'],
            'limits': ['synthetic-consumers', 'simulated-slot-selection',
                       'no-ssh-or-encryption-acceptance', 'no-full-image-or-backend-qualification']}
        args.result.write_bytes(release.canonical(result))
        print(json.dumps(result, sort_keys=True))


if __name__ == '__main__':
    main()
