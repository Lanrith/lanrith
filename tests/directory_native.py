#!/usr/bin/env python3
"""Qualify directory TLS and host egress in a disposable offline namespace."""

import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import pwd
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parent))
from lanrith import config, directory_runtime
from test_directory import fixture


CHECKS = {'ldaps-ipv4-ipv6', 'starttls-ipv4-ipv6', 'hostname-and-authority-validation',
          'expired-certificate-rejection', 'no-plaintext-fallback-or-bind', 'bounded-slow-peer',
          'reader-and-observer-exact-egress', 'other-identities-destination-port-source-interface-denied',
          'independent-observer-identity', 'private-fresh-observation', 'disabled-components-remove-paths'}
IMPLEMENTATION = ('lanrith/directory_config.py', 'lanrith/directory_runtime.py', 'lanrith/firewall.py',
                  'lanrith/metrics.py', 'lanrith/router_metrics_runtime.py', 'lanrith/integrations.py',
                  'lanrith/config.py', 'lanrith/build.py', 'lanrith/runtime_plan.py',
                  'tests/test_directory.py', 'tests/test_policy_agent.py', 'tests/test_intent.py')
SUCCESS = bytes.fromhex('300c02010178070a010004000400')
CONNECT = '''
import socket,sys
address,port,source=sys.argv[1:]
with socket.socket(socket.AF_INET6 if ':' in address else socket.AF_INET,socket.SOCK_STREAM) as s:
    s.settimeout(.5)
    if source:
        s.setsockopt(socket.IPPROTO_IPV6 if ':' in address else socket.IPPROTO_IP,78 if ':' in address else 15,1)
        s.bind((source,0))
    try:s.connect((address,int(port)))
    except OSError:sys.exit(10)
'''


def run(*args, **kwargs):
    completed = subprocess.run(args, stdin=subprocess.DEVNULL, capture_output=True, timeout=60, **kwargs)
    if completed.returncode:
        # Only disposable fixture commands; no production keys or logs enter.
        print(completed.stderr.decode(errors='replace')[-2048:], file=sys.stderr)
    completed.check_returncode()
    return completed


def peer_run(*args):
    return run('nsenter', '--net=/run/netns/directory-peer', '--', 'ip', *args)


def serve(root):
    counters = {'connections': 0, 'starttls_requests': 0, 'application_bytes': 0}
    lock = threading.Lock()

    def increment(name, amount=1):
        with lock:
            counters[name] += amount
            temporary = root/'server-counters.tmp'
            temporary.write_text(json.dumps(counters))
            os.replace(temporary, root/'server-counters.json')

    def handle(stream):
        with stream:
            stream.settimeout(3)
            control = json.loads((root/'server.json').read_text())
            try:
                increment('connections')
                if control['mode'] == 'slow':
                    time.sleep(3)
                    return
                if control['mode'] in ('starttls', 'plaintext'):
                    request = directory_runtime.receive(stream, len(directory_runtime.STARTTLS_REQUEST), time.monotonic()+2)
                    assert request == directory_runtime.STARTTLS_REQUEST
                    increment('starttls_requests')
                    stream.sendall(SUCCESS)
                    if control['mode'] == 'plaintext':
                        stream.sendall(b'NOT_TLS')
                        return
                context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                context.load_cert_chain(str(root/(control['certificate']+'.crt')), str(root/'server.key'))
                with context.wrap_socket(stream, server_side=True) as secured:
                    increment('application_bytes', len(secured.recv(4096)))
            except (OSError, ValueError):
                pass

    def accept(listener):
        while True:
            stream, _ = listener.accept()
            threading.Thread(target=handle, args=(stream,), daemon=True).start()

    listeners = []
    for address in ('192.168.10.30', '192.168.10.31', 'fd42:1234:5678:10::30', 'fd42:1234:5678:10::31'):
        for port in (389, 636, 637):
            listener = socket.socket(socket.AF_INET6 if ':' in address else socket.AF_INET, socket.SOCK_STREAM)
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            listener.bind((address, port))
            listener.listen(16)
            listeners.append(listener)
            threading.Thread(target=accept, args=(listener,), daemon=True).start()
    (root/'server-ready').write_text('ready')
    while True:
        time.sleep(1)


def certificates(root):
    run('openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '2',
        '-subj', '/CN=Synthetic directory authority', '-addext', 'basicConstraints=critical,CA:TRUE',
        '-addext', 'keyUsage=critical,keyCertSign,cRLSign', '-keyout', str(root/'ca.key'), '-out', str(root/'ca.crt'))
    run('openssl', 'req', '-newkey', 'rsa:2048', '-nodes', '-subj', '/CN=directory.example.test',
        '-keyout', str(root/'server.key'), '-out', str(root/'server.csr'))
    for name, san, days in (('server', 'DNS:directory.example.test,IP:192.168.10.30,IP:fd42:1234:5678:10::30', '2'),
                             ('wrong-name', 'DNS:other.example.test', '2'),
                             ('expired', 'DNS:directory.example.test', '2')):
        extension = root/(name+'.ext')
        extension.write_text('basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\n'
                             'extendedKeyUsage=serverAuth\nsubjectAltName='+san+'\n')
        validity = ['-not_before', '20200101000000Z', '-not_after', '20200102000000Z'] if name == 'expired' else []
        run('openssl', 'x509', '-req', '-in', str(root/'server.csr'), '-CA', str(root/'ca.crt'),
            '-CAkey', str(root/'ca.key'), '-CAcreateserial', '-days', days, '-extfile', str(extension),
            '-out', str(root/(name+'.crt')), *validity)
    run('openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '2',
        '-subj', '/CN=Other synthetic authority', '-keyout', str(root/'other.key'), '-out', str(root/'other.crt'))
    for path in root.glob('*.key'):
        path.chmod(0o600)


def qualify(result):
    assert os.geteuid() == 0 and {i['ifname'] for i in json.loads(run('ip', '-j', 'link').stdout)} == {'lo'}, \
        'Refusing an existing network topology.'
    environment = {**os.environ, 'PYTHONPATH': str(Path(__file__).resolve().parents[1])}
    with tempfile.TemporaryDirectory(prefix='directory-native.') as temporary:
        root = Path(temporary)
        root.chmod(0o755)
        accounts = root/'accounts.conf'
        accounts.write_text('u router-policy-reader - "Synthetic reader" /\n'
                            'u lanrith-directory-health - "Synthetic TLS observer" /\n')
        run('systemd-sysusers', str(accounts))
        reader = pwd.getpwnam('router-policy-reader')
        observer = pwd.getpwnam('lanrith-directory-health')
        assert 0 not in (reader.pw_uid, observer.pw_uid) and reader.pw_uid != observer.pw_uid
        certificates(root)
        run('ip', 'link', 'set', 'lo', 'up')
        run('ip', 'netns', 'add', 'directory-peer')
        for host, peer in (('lan.1', 'peer-lan'), ('wan', 'peer-wan')):
            run('ip', 'link', 'add', host, 'type', 'veth', 'peer', 'name', peer, 'netns', 'directory-peer')
            run('ip', 'link', 'set', host, 'up')
            peer_run('link', 'set', peer, 'up')
        for address, device in (('192.168.10.1/24', 'lan.1'), ('192.168.10.99/32', 'lan.1'),
                                ('fd42:1234:5678:10::1/64', 'lan.1'),
                                ('192.0.2.2/24', 'wan')):
            run('ip', 'address', 'add', address, 'dev', device, *(['nodad'] if ':' in address else []))
        peer_run('link', 'set', 'lo', 'up')
        for address, device in (('192.168.10.30/24', 'peer-lan'), ('192.168.10.31/24', 'peer-lan'),
                                ('fd42:1234:5678:10::30/64', 'peer-lan'), ('fd42:1234:5678:10::31/64', 'peer-lan'),
                                ('192.0.2.1/24', 'peer-wan')):
            peer_run('address', 'add', address, 'dev', device,
                *(['nodad'] if ':' in address else []))
        authority = Path('/usr/share/lanrith/trust/directory.pem')
        authority.parent.mkdir(parents=True, exist_ok=True)
        authority.write_bytes((root/'ca.crt').read_bytes())
        authority.chmod(0o644)
        cache = directory_runtime.OBSERVATION
        cache.parent.mkdir(mode=0o750, parents=True, exist_ok=True)
        os.chown(cache.parent, observer.pw_uid, observer.pw_gid)
        control = root/'server.json'
        control.write_text(json.dumps({'mode': 'ldaps', 'certificate': 'server'}))
        server_log = (root/'server.log').open('wb')
        server = subprocess.Popen(['nsenter', '--net=/run/netns/directory-peer', '--', sys.executable, __file__,
                                   '--server', str(root)], env=environment, stdin=subprocess.DEVNULL,
                                  stdout=server_log, stderr=server_log)

        def connect(address, port=636, *, account=reader, source='', expected=0):
            command = [sys.executable, '-c', CONNECT, address, str(port), source]
            completed = subprocess.run(command, user=account.pw_uid, group=account.pw_gid, extra_groups=(),
                env=environment, stdin=subprocess.DEVNULL, capture_output=True, timeout=4)
            assert completed.returncode == expected, 'Unexpected host directory egress result.'

        def install(*, mode='ldaps', addresses=None, literal=False, metrics=True, enabled=True):
            value = fixture()
            settings = value['identity']['directories']['directory']
            addresses = addresses or ['192.168.10.30', 'fd42:1234:5678:10::30']
            host = addresses[0] if literal else 'directory.example.test'
            settings['url'] = ('ldaps' if mode == 'ldaps' else 'ldap+starttls')+'://'+('['+host+']' if ':' in host else host)
            if not literal:
                settings['addresses'] = addresses
            value['observability']['metrics']['enabled'] = metrics
            value['identity']['policy']['enabled'] = enabled
            if not enabled:
                value['access']['rules'] = []
            files = config.render(value)
            Path('/etc/hosts').write_text(files['etc/hosts'])
            (root/'rules.nft').write_text(files['etc/nftables.conf'])
            run('nft', '-f', str(root/'rules.nft'))
            run('nft', 'add', 'rule', 'inet', 'lanrith', 'output', 'counter', 'comment', '"synthetic-denied-output"')
            if metrics and enabled:
                directory_runtime.MANIFEST.write_text(files['usr/share/lanrith/directory-health.json'])
                directory_runtime.MANIFEST.chmod(0o644)
            return files

        def observe(expected, *, mode='ldaps', certificate='server'):
            control.write_text(json.dumps({'mode': mode, 'certificate': certificate}))
            started = time.monotonic()
            completed = subprocess.run([sys.executable, '-m', 'lanrith.directory_runtime'],
                user=observer.pw_uid, group=observer.pw_gid, extra_groups=(), env=environment,
                stdin=subprocess.DEVNULL, capture_output=True, timeout=20)
            assert completed.returncode == 0, completed.stderr.decode()[-1024:]
            value = directory_runtime.read_observation()
            assert value['tls_verified'] is expected
            assert value['endpoints_verified'] == (value['endpoints_total'] if expected else 0)
            return time.monotonic()-started

        try:
            deadline = time.monotonic()+10
            while not (root/'server-ready').exists():
                assert server.poll() is None, (root/'server.log').read_text()[-1024:]
                assert time.monotonic() < deadline
                time.sleep(.1)
            # Positive controls precede enforcement; every denied target/port is
            # backed by a real listener rather than an unreachable fixture.
            for address in ('192.168.10.30', '192.168.10.31', 'fd42:1234:5678:10::30'):
                connect(address)
            connect('192.168.10.30', 637)
            connect('192.168.10.30', source='192.168.10.99')
            install()
            connect('directory.example.test')
            for address in ('192.168.10.30', 'fd42:1234:5678:10::30'):
                connect(address)
            observe(True)
            for address in ('192.168.10.30', 'fd42:1234:5678:10::30'):
                install(addresses=[address], literal=True)
                observe(True)
            install(mode='starttls')
            observe(True, mode='starttls')
            observe(False, mode='starttls', certificate='wrong-name')
            observe(False, mode='starttls', certificate='expired')
            authority.write_bytes((root/'other.crt').read_bytes())
            observe(False, mode='starttls')
            authority.write_bytes((root/'ca.crt').read_bytes())
            observe(False, mode='plaintext')
            elapsed = observe(False, mode='slow')
            assert elapsed < 6, 'Slow TLS peers exceeded the bounded probe deadline.'
            install()
            observe(True)
            nobody = pwd.getpwnam('nobody')
            for address in ('192.168.10.30', 'fd42:1234:5678:10::30'):
                connect(address, account=nobody, expected=10)
                connect(address, port=637, expected=10)
            connect('192.168.10.31', expected=10)
            connect('fd42:1234:5678:10::31', expected=10)
            connect('192.168.10.30', source='192.168.10.99', expected=10)
            # Route the same address over a second working wire while retaining
            # the permitted source. The generated output rule must reject it.
            run('nft', 'flush', 'ruleset')
            run('ip', 'route', 'replace', '192.168.10.30/32', 'via', '192.0.2.1', 'dev', 'wan', 'src', '192.168.10.1')
            peer_run('route', 'replace', '192.168.10.1/32', 'via', '192.0.2.2', 'dev', 'peer-wan')
            connect('192.168.10.30')
            install()
            connect('192.168.10.30', expected=10)
            counters = json.loads(run('nft', '-j', 'list', 'chain', 'inet', 'lanrith', 'output').stdout)
            denied = next(row['rule'] for row in counters['nftables'] if row.get('rule', {}).get('comment') == 'synthetic-denied-output')
            assert any(e.get('counter', {}).get('packets', 0) > 0 for e in denied['expr'])
            run('ip', 'route', 'del', '192.168.10.30/32')
            peer_run('route', 'del', '192.168.10.1/32')
            files = install(metrics=False)
            assert not any('directory-health' in name for name in files)
            connect('192.168.10.30')
            connect('192.168.10.30', account=observer, expected=10)
            install(enabled=False)
            connect('192.168.10.30', expected=10)
            # A capabilities-free root collector receives only the observer's
            # read group; neither this group nor the observer is the reader UID.
            private = root/'reader-private'
            private.mkdir(mode=0o700)
            os.chown(private, reader.pw_uid, reader.pw_gid)
            credential = private/'credentials.json'
            credential.write_text('disposable-secret')
            credential.chmod(0o600)
            os.chown(credential, reader.pw_uid, reader.pw_gid)
            reader_program = ('from pathlib import Path; from lanrith.directory_runtime import read_observation; '
                'import sys; read_observation();\ntry:Path(sys.argv[1]).read_bytes()'
                '\nexcept PermissionError:pass\nelse:raise AssertionError("Observer can read policy credentials")')
            run('setpriv', '--bounding-set=-all', '--inh-caps=-all', '--ambient-caps=-all',
                '--groups='+str(observer.pw_gid), sys.executable, '-c', reader_program, str(credential), env=environment)
            run('setpriv', '--reuid='+str(observer.pw_uid), '--regid='+str(observer.pw_gid), '--clear-groups',
                '--bounding-set=-all', '--inh-caps=-all', '--ambient-caps=-all',
                sys.executable, '-c', reader_program, str(credential), env=environment)
            denied = subprocess.run([sys.executable, '-c', reader_program, str(credential)],
                user=nobody.pw_uid, group=nobody.pw_gid, extra_groups=(), env=environment,
                stdin=subprocess.DEVNULL, capture_output=True, timeout=3)
            assert denied.returncode != 0
            assert json.loads((root/'server-counters.json').read_text())['application_bytes'] == 0
            output = {'schema': 1, 'result': 'pass', 'test': 'offline-directory-tls-egress',
                'assessed_at': datetime.datetime.now(datetime.timezone.utc).isoformat(), 'checks': sorted(CHECKS),
                'source_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                'implementation_sha256': {name: hashlib.sha256((Path(__file__).parents[1]/name).read_bytes()).hexdigest()
                                          for name in IMPLEMENTATION},
                'external_network': False, 'private_image_qualified': False, 'physical_router_qualified': False}
            result.parent.mkdir(parents=True, exist_ok=True)
            result.write_text(json.dumps(output, sort_keys=True)+'\n')
            print(json.dumps(output, sort_keys=True))
        finally:
            server.terminate()
            server.wait(timeout=5)
            server_log.close()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--server', type=Path)
    parser.add_argument('--result', type=Path)
    args = parser.parse_args()
    if args.server:
        serve(args.server)
    else:
        assert args.result is not None
        qualify(args.result)
