#!/usr/bin/env python3
"""Qualify generated journal delivery with a real exporter in an offline netns."""

import argparse
import base64
import datetime
import gzip
import hashlib
import http.client
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import os
from pathlib import Path
import pwd
import signal
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from lanrith import config, logs, logs_runtime
from test_intent import minimal


CHECKS = {'generated-graph-readiness', 'exited-exporter-not-ready', 'real-journal-ingestion',
          'own-journal-exclusion', 'redaction-before-queue', 'authenticated-verified-https',
          'collector-outage', 'bounded-nonblocking-overflow', 'persistent-queue-crash-restart',
          'collector-return-delivery', 'private-state-directory-boundary'}
MARKER = b'LANRITH_SYNTHETIC_QUEUED_RECORD'
SELF = b'LANRITH_SYNTHETIC_EXPORTER_SELF_RECORD'
SECRET = b'lanrith-disposable-secret-value'
RUN = ('import json,sys; from lanrith.logs_runtime import supervise; '
       'supervise(json.loads(sys.argv[1]), startup_seconds=float(sys.argv[2]), interval=.2)')


def run(*arguments, **kwargs):
    return subprocess.run(arguments, check=True, stdin=subprocess.DEVNULL, capture_output=True,
                          timeout=60, **kwargs)


def until(check, seconds=60):
    deadline = time.monotonic()+seconds
    while time.monotonic() < deadline:
        result = check()
        if result:
            return result
        time.sleep(.2)
    raise AssertionError('Native journal delivery did not reach the required state.')


def metrics():
    connection = http.client.HTTPConnection('127.0.0.1', 12345, timeout=2)
    try:
        connection.request('GET', '/metrics')
        response = connection.getresponse()
        text = response.read(1024*1024+1).decode('ascii')
        assert response.status == 200 and len(text) <= 1024*1024
        return text
    except OSError:
        return ''
    finally:
        connection.close()


def metric(text, name):
    return sum(float(line.split()[-1]) for line in text.splitlines()
               if line.startswith(name+'{') and 'component_id="otelcol.exporter.otlphttp.router"' in line
               and ('data_type="logs"' in line or 'data_type=' not in line))


def journal(root):
    export = root/'journal.export'
    stamp = int(time.time()*1000000)
    with export.open('wb') as stream:
        def entry(number, unit, message):
            stream.write(('__REALTIME_TIMESTAMP='+str(stamp+number)+'\n__MONOTONIC_TIMESTAMP='+str(number+1)+
                          '\n_BOOT_ID='+'1'*32+'\n_MACHINE_ID='+'2'*32+
                          '\n_HOSTNAME=synthetic-router\n_TRANSPORT=stdout\nPRIORITY=6\n_SYSTEMD_UNIT='+unit+
                          '\nMESSAGE=').encode()+message+b'\n\n')
        entry(0, 'fixture.service', MARKER+b' password='+SECRET)
        entry(1, 'alloy.service', SELF)
        # More than the production queue's 64 MiB logical capacity. The test
        # retains that capacity instead of substituting a tiny fixture queue.
        for number in range(7200):
            entry(number+2, 'fixture-burst.service', ('BURST_'+str(number)+' ').encode()+b'x'*16384)
    (root/'journal').mkdir()
    run('/usr/lib/systemd/systemd-journal-remote', '--split-mode=none',
        '--output='+str(root/'journal/system.journal'), str(export))
    export.unlink()
    for path in (root/'journal').iterdir():
        path.chmod(0o644)
    assert int(run('journalctl', '--directory='+str(root/'journal'), '--no-pager', '-o', 'cat',
                   '--output-fields=MESSAGE', text=True).stdout.count('BURST_')) == 7200


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--alloy', type=Path, default=Path('/usr/bin/alloy'))
    parser.add_argument('--alloy-sha256', required=True)
    parser.add_argument('--result', type=Path, required=True)
    args = parser.parse_args()
    assert os.geteuid() == 0 and {a['ifname'] for a in json.loads(run('ip', '-j', 'link').stdout)} == {'lo'}, \
        'Refusing an existing network topology.'
    digest = hashlib.sha256(args.alloy.read_bytes()).hexdigest()
    assert digest == args.alloy_sha256, 'Reviewed Alloy binary differs.'
    run('ip', 'link', 'set', 'lo', 'up')
    run('ip', 'address', 'add', '192.0.2.31/32', 'dev', 'lo')
    processes = []
    server = worker = None
    with tempfile.TemporaryDirectory(prefix='logs-native.') as directory:
        root = Path(directory)
        root.chmod(0o755)
        accounts = root/'accounts.conf'
        accounts.write_text('u alloy - "Synthetic exporter" /\n')
        run('systemd-sysusers', str(accounts))
        account = pwd.getpwnam('alloy')
        # Reproduce the StateDirectory/BindPaths contract in a child mount
        # namespace. Never relax the parent control directory's 0700 mode.
        private, visible = root/'private-control', root/'alloy-view'
        private.mkdir(mode=0o700)
        backing = private/'alloy'
        backing.mkdir(mode=0o750)
        os.chown(backing, account.pw_uid, account.pw_gid)
        visible.mkdir()
        proof = '''
import os,pathlib,subprocess,sys
backing,visible,uid,gid=sys.argv[1:]
subprocess.run(['mount','--bind',backing,visible],check=True)
os.setgroups([]);os.setgid(int(gid));os.setuid(int(uid))
pathlib.Path(visible,'proof').write_text('synthetic state')
try:pathlib.Path(backing,'proof').read_text()
except PermissionError:pass
else:raise AssertionError('Exporter can traverse the private control directory')
'''
        run('unshare', '--mount', '--propagation', 'private', sys.executable, '-c', proof,
            str(backing), str(visible), str(account.pw_uid), str(account.pw_gid))
        assert (backing/'proof').read_text() == 'synthetic state'
        assert private.stat().st_mode & 0o777 == 0o700
        journal(root)
        run('openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
            '-subj', '/CN=logs.example.test', '-addext', 'subjectAltName=DNS:logs.example.test',
            '-keyout', str(root/'collector.key'), '-out', str(root/'collector.crt'))
        (root/'collector.key').chmod(0o600)
        (root/'password').write_text('disposable-ingest-password')
        (root/'password').chmod(0o400)
        os.chown(root/'password', account.pw_uid, account.pw_gid)
        for name in ('state', 'queue', 'bad-state', 'bad-queue'):
            path = root/name
            path.mkdir(mode=0o700)
            os.chown(path, account.pw_uid, account.pw_gid)
        value = minimal()
        value['networks']['home']['ipv4'] = '192.0.2.0/24'
        value['networks']['home']['dhcp4'] = {'pools': ['192.0.2.100-192.0.2.199']}
        value['observability'] = {'logs': {'enabled': True, 'endpoint': 'https://192.0.2.31/otlp',
            'tls_server_name': 'logs.example.test', 'username': 'synthetic-router', 'credential': 'ingest'}}
        value = config.normalize(value)
        files = config.render(value)
        original = files['etc/alloy/config.alloy']
        content = original.replace('/var/log/journal', str(root/'journal')).replace(
            '/var/lib/lanrith-alloy/queue', str(root/'queue')).replace(
            '/run/lanrith-logs/password', str(root/'password'))
        (root/'config.alloy').write_text(content)
        (root/'bad.alloy').write_text(content.replace('min_version = "1.2"', 'min_version = "TLS1.2"').replace(
            str(root/'queue'), str(root/'bad-queue')))
        # The real exporter uses the test CA through its ordinary system trust
        # interface. No insecure_skip_verify or TLS downgrade is introduced.
        environment = {**os.environ, 'SSL_CERT_FILE': str(root/'collector.crt'), 'GOMAXPROCS': '2',
                       'GOMEMLIMIT': '128MiB', 'PYTHONPATH': str(Path(__file__).resolve().parents[1])}
        notifications = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        notifications.bind(str(root/'notify'))
        (root/'notify').chmod(0o666)
        notifications.settimeout(.1)
        environment['NOTIFY_SOCKET'] = str(root/'notify')

        def launch(bad=False):
            command = [str(args.alloy), *logs_runtime.ALLOY[1:-1]]
            command[-1] = '--storage.path='+str(root/('bad-state' if bad else 'state'))
            command.append(str(root/('bad.alloy' if bad else 'config.alloy')))
            log = root/('bad.log' if bad else 'alloy.log')
            with log.open('ab') as stream:
                process = subprocess.Popen([sys.executable, '-c', RUN, json.dumps(command), '3' if bad else '25'],
                    env=environment, stdin=subprocess.DEVNULL, stdout=stream, stderr=subprocess.STDOUT,
                    user=account.pw_uid, group=account.pw_gid, extra_groups=(), start_new_session=True)
            processes.append(process)
            return process

        def ready(process):
            assert process.poll() is None, 'Exporter supervisor exited before readiness.'
            try:
                return notifications.recv(256) == b'READY=1'
            except socket.timeout:
                return False

        received = {'marker': False, 'redacted': False, 'self': False, 'secret': False, 'records': 0,
                    'authenticated': True, 'sni': True, 'path': True}
        expected_auth = 'Basic '+base64.b64encode(b'synthetic-router:disposable-ingest-password').decode()

        class Collector(BaseHTTPRequestHandler):
            def do_POST(self):
                length = int(self.headers.get('Content-Length', '0'))
                assert 0 <= length <= 2*1024*1024
                data = self.rfile.read(length)
                if self.headers.get('Content-Encoding') == 'gzip':
                    data = gzip.decompress(data)
                assert len(data) <= 2*1024*1024
                received['marker'] |= MARKER in data
                received['redacted'] |= b'[REDACTED]' in data
                received['self'] |= SELF in data
                received['secret'] |= SECRET in data
                received['authenticated'] &= self.headers.get('Authorization') == expected_auth
                received['path'] &= self.path == '/otlp/v1/logs'
                received['records'] += 1
                self.send_response(200)
                self.send_header('Content-Type', 'application/x-protobuf')
                self.send_header('Content-Length', '0')
                self.end_headers()

            def log_message(self, *arguments):
                pass

        try:
            bad = launch(bad=True)
            until(lambda: bool(metrics()), 10)
            # The negative control reproduces the original misleading HTTP
            # health. Our graph check and notify readiness must both reject it.
            assert not logs_runtime.pipeline_healthy(metrics())
            assert bad.wait(timeout=10) != 0
            try:
                assert notifications.recv(256) != b'READY=1', 'Exited exporter was marked ready.'
            except socket.timeout:
                pass
            process = launch()
            until(lambda: ready(process), 30)
            assert logs_runtime.pipeline_healthy(metrics())
            until(lambda: metric(metrics(), 'otelcol_exporter_enqueue_failed_log_records_total') > 0, 90)
            overflow = metric(metrics(), 'otelcol_exporter_enqueue_failed_log_records_total')
            queue = metric(metrics(), 'otelcol_exporter_queue_size')
            assert 0 < queue <= 67108864
            # Let the journal cursor commit before the forced process crash.
            time.sleep(12)
            assert process.poll() is None and logs_runtime.pipeline_healthy(metrics())
            physical = sum(path.stat().st_size for path in (root/'queue').rglob('*') if path.is_file())
            assert physical <= 160*1024*1024, 'Queue physical storage exceeded its tested bound.'
            assert (root/'alloy.log').stat().st_size < 2*1024*1024, 'Exporter outage amplified its own log.'
            os.killpg(process.pid, signal.SIGKILL)
            process.wait(timeout=10)
            while True:
                try:
                    notifications.recv(256)
                except socket.timeout:
                    break
            process = launch()
            until(lambda: ready(process), 30)
            assert metric(metrics(), 'otelcol_exporter_queue_size') > 0, 'Persistent retry queue was lost.'
            server = HTTPServer(('192.0.2.31', 443), Collector)
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.minimum_version = ssl.TLSVersion.TLSv1_2
            context.load_cert_chain(root/'collector.crt', root/'collector.key')

            def sni(stream, name, ssl_context):
                received['sni'] &= name == 'logs.example.test'

            context.set_servername_callback(sni)
            server.socket = context.wrap_socket(server.socket, server_side=True)
            worker = threading.Thread(target=server.serve_forever, daemon=True)
            worker.start()
            until(lambda: received['marker'] and metric(metrics(), 'otelcol_exporter_queue_size') == 0, 90)
            assert received['redacted'] and not received['secret'] and not received['self']
            assert received['authenticated'] and received['sni'] and received['path']
            assert process.poll() is None and logs_runtime.pipeline_healthy(metrics())
            result = {'schema': 1, 'test': 'offline-journal-https-outage', 'result': 'pass',
                'assessed_at': datetime.datetime.now(datetime.timezone.utc).isoformat(),
                'source_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                'implementation_sha256': {name: hashlib.sha256((Path(__file__).parents[1]/name).read_bytes()).hexdigest()
                    for name in ('lanrith/logs.py', 'lanrith/logs_runtime.py', 'lanrith/service_plane.py')},
                'alloy_sha256': digest, 'configuration_sha256': hashlib.sha256(original.encode()).hexdigest(),
                'checks': sorted(CHECKS), 'queue_capacity_bytes': 67108864, 'queue_physical_bytes': physical,
                'overflow_records': overflow, 'delivered_batches': received['records'],
                'physical_router_qualified': False}
            args.result.parent.mkdir(parents=True, exist_ok=True)
            args.result.write_text(json.dumps(result, sort_keys=True)+'\n')
            print(json.dumps(result, sort_keys=True))
        except BaseException:
            # Only this test's synthetic process output; never a host journal.
            for name in ('bad.log', 'alloy.log'):
                path = root/name
                if path.is_file():
                    print(name+':\n'+path.read_text(errors='replace')[-8192:], file=sys.stderr)
            raise
        finally:
            for process in reversed(processes):
                if process.poll() is None:
                    os.killpg(process.pid, signal.SIGTERM)
                    try:
                        process.wait(timeout=15)
                    except subprocess.TimeoutExpired:
                        os.killpg(process.pid, signal.SIGKILL)
                        process.wait(timeout=5)
            notifications.close()
            if server:
                server.shutdown()
                server.server_close()
            if worker:
                worker.join(timeout=5)


if __name__ == '__main__':
    main()
