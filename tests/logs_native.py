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
import math
import mmap
import os
from pathlib import Path
import pwd
import queue
import signal
import socket
import ssl
import stat
import subprocess
import sys
import tempfile
import threading
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from lanrith import config, logs, logs_runtime
from lanrith.dns_metadata import varint
from test_intent import minimal


CHECKS = {'unauthenticated-verified-https', 'generated-graph-readiness', 'exited-exporter-not-ready', 'real-journal-ingestion',
          'field-only-queue-and-receiver', 'permanent-auth-rejection-and-recovery', 'receiver-observed-exporter-source',
          'own-journal-exclusion', 'redaction-before-queue', 'authenticated-verified-https',
          'collector-outage', 'bounded-nonblocking-overflow', 'persistent-queue-crash-restart',
          'collector-return-delivery', 'private-state-directory-boundary', 'exporter-loss-observations',
          'local-metadata-body-withheld', 'local-reader-and-credential-boundary',
          'local-bounded-rotation', 'local-filesystem-failure-independent-delivery', 'local-producer-restart-identity'}
MARKER = b'LANRITH_SYNTHETIC_QUEUED_RECORD'
SELF = b'LANRITH_SYNTHETIC_EXPORTER_SELF_RECORD'
SECRET = b'lanrith-disposable-secret-value'
UNSELECTED = b'LANRITH_SYNTHETIC_UNSELECTED_FIELD'
ABSENT_BODY = b'journal message absent'
REJECTED = 'LANRITH_SYNTHETIC_PERMANENTLY_REJECTED'
LOCAL_RECOVERY = 'LANRITH_LOCAL_RECOVERY_MARKER'
RUN = ('import json,sys; from pathlib import Path; from lanrith.logs_runtime import supervise; '
       'supervise(json.loads(sys.argv[1]), startup_seconds=float(sys.argv[2]), interval=.2, observation_path=Path(sys.argv[3]), local=True)')


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
    values = [float(line.split()[-1]) for line in text.splitlines()
               if line.startswith(name+'{') and 'component_id="otelcol.exporter.otlphttp.router"' in line
               and ('data_type="logs"' in line or 'data_type=' not in line)]
    assert all(math.isfinite(value) and 0 <= value < 2**63 for value in values)
    return sum(values)


def journal(root):
    export = root/'journal.export'
    stamp = int(time.time()*1000000)
    with export.open('wb') as stream:
        def entry(number, unit, message, extra=b''):
            stream.write(('__REALTIME_TIMESTAMP='+str(stamp+number)+'\n__MONOTONIC_TIMESTAMP='+str(number+1)+
                          '\n_BOOT_ID='+'1'*32+'\n_MACHINE_ID='+'2'*32+
                          '\n_HOSTNAME=synthetic-router\n_TRANSPORT=stdout\nPRIORITY=6\n_SYSTEMD_UNIT='+unit+
                          '\n').encode()+extra)
            if message is not None:
                stream.write(b'MESSAGE='+message+b'\n')
            stream.write(b'\n')
        extra = b'FIXTURE_UNUSED='+UNSELECTED+b'\n'
        entry(0, 'fixture.service', MARKER+b' password='+SECRET, extra)
        entry(1, 'fixture-missing.service', None, extra)
        entry(2, 'fixture-empty.service', b'', extra)
        entry(3, 'alloy.service', SELF)
        # More than the production queue's 64 MiB logical capacity. The test
        # retains that capacity instead of substituting a tiny fixture queue.
        for number in range(7200):
            entry(number+4, 'fixture-burst.service', ('BURST_'+str(number)+' ').encode()+b'x'*16384)
    (root/'journal').mkdir()
    run('/usr/lib/systemd/systemd-journal-remote', '--split-mode=none',
        '--output='+str(root/'journal/system.journal'), str(export))
    export.unlink()
    for path in (root/'journal').iterdir():
        path.chmod(0o644)
    assert int(run('journalctl', '--directory='+str(root/'journal'), '--no-pager', '-o', 'cat',
                   '--output-fields=MESSAGE', text=True).stdout.count('BURST_')) == 7200
    return stamp


def embedded(data, field):
    # ExportLogsServiceRequest, ResourceLogs and ScopeLogs carry only embedded
    # messages or strings, all length-delimited. Keep repeated log records.
    offset = 0
    while offset < len(data):
        tag, offset = varint(data, offset)
        size, offset = varint(data, offset)
        assert tag & 7 == 2 and offset+size <= len(data)
        if tag >> 3 == field:
            yield data[offset:offset+size]
        offset += size


def check_received_projection(data, stamp, seen, expected):
    for resource in embedded(data, 1):
        labels, = embedded(resource, 1)
        for scope in embedded(resource, 2):
            for record in embedded(scope, 2):
                for index, (unit, body) in enumerate(expected):
                    timestamp = b'\x09'+((stamp+index)*1000).to_bytes(8, 'little')
                    if timestamp in record:
                        # LogRecord.body (5), AnyValue.string_value (1).
                        assert b'\x2a'+bytes([len(body)+2])+b'\x0a'+bytes([len(body)])+body in record
                        assert unit in labels and b'journal_boot' in record and b'journal_transport' in record
                        seen.add(index)


def check_queued_projection(directory):
    seen = set()
    for file in directory.rglob('*'):
        if not file.is_file() or not file.stat().st_size:
            continue
        with file.open('rb') as stream, mmap.mmap(stream.fileno(), 0, access=mmap.ACCESS_READ) as queued:
            for marker in (UNSELECTED, SECRET, SELF):
                assert queued.find(marker) == -1, 'Unselected field or omitted content in persistent queue.'
            for marker in (ABSENT_BODY, MARKER, b'[REDACTED]'):
                if queued.find(marker) != -1:
                    seen.add(marker)
    assert seen == {ABSENT_BODY, MARKER, b'[REDACTED]'}, 'Queued projection controls missing.'


def append_journal(root, count, marker, *, unit='fixture.service', redaction_probe=True):
    export = root/'append.export'
    stamp = int(time.time()*1000000)
    with export.open('wb') as stream:
        for number in range(count):
            stream.write(('__REALTIME_TIMESTAMP='+str(stamp+number)+'\n__MONOTONIC_TIMESTAMP='+str(stamp+number)+
                '\n_BOOT_ID='+'1'*32+'\n_MACHINE_ID='+'2'*32+
                '\n_HOSTNAME=synthetic-router\n_TRANSPORT=stdout\nPRIORITY=4\n_SYSTEMD_UNIT='+unit+
                '\nMESSAGE='+marker+(' password='+SECRET.decode() if redaction_probe else '')+'\n\n').encode())
    run('/usr/lib/systemd/systemd-journal-remote', '--split-mode=none',
        '--output='+str(root/'journal/system.journal'), str(export))
    export.unlink()
    return stamp


def local_records():
    records = []
    for path in logs_runtime.LOCAL.glob('events*.jsonl'):
        try:
            content = path.read_bytes()
        except FileNotFoundError:
            # Rotation can remove a generation after glob enumerates it.
            continue
        for line in content.splitlines():
            # The observer may sample while the exporter finishes a line.
            try:
                document = json.loads(line)
            except json.JSONDecodeError:
                continue
            for resource in document.get('resourceLogs', []):
                for scope in resource.get('scopeLogs', []):
                    records.extend(scope.get('logRecords', []))
    return records


def wait_for_drain(received):
    smallest = None
    last_progress = time.monotonic()

    def drained():
        nonlocal smallest, last_progress
        size = logs_runtime.health()['queue_size_bytes']
        if smallest is None or size < smallest:
            smallest = size
            last_progress = time.monotonic()
        assert time.monotonic()-last_progress < 90, 'Persistent queue drain stalled.'
        return received['marker'] and size == 0

    until(drained, 300)


def exercise_file_failure(root):
    # The file exporter can write to an open file until its next rotation.
    # Stop feeding it once the fault is observed so recovery has no bulk backlog.
    initial = logs_runtime.health(local=True)

    def batch_processed():
        current = logs_runtime.health(local=True)
        if (current['local_failed_records'] > initial['local_failed_records'] or
                current['local_sent_records'] >= initial['local_sent_records']+submitted):
            return current

    for submitted in range(100, 5001, 100):
        append_journal(root, 100, 'LANRITH_LOCAL_FAILURE_REMOTE_MARKER')
        if until(batch_processed, 30)['local_failed_records'] > initial['local_failed_records']:
            return
    raise AssertionError('File exporter never rejected a record during the filesystem fault.')


def unauthenticated_delivery(binary, *, message='LANRITH_NO_AUTH_SYNTHETIC_RECORD', unit='fixture.service',
                             redaction_probe=True):
    """An enabled exporter sends over verified TLS with no password or auth header."""
    with tempfile.TemporaryDirectory(prefix='logs-no-auth.') as directory:
        root = Path(directory)
        (root/'journal').mkdir()
        append_journal(root, 1, message, unit=unit, redaction_probe=redaction_probe)
        run('openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
            '-subj', '/CN=logs.example.test', '-addext', 'subjectAltName=DNS:logs.example.test',
            '-keyout', str(root/'collector.key'), '-out', str(root/'collector.crt'))
        received = queue.Queue()

        class Collector(BaseHTTPRequestHandler):
            def do_POST(self):
                size = int(self.headers.get('Content-Length', '0'))
                assert 0 < size <= 2*1024*1024
                data = self.rfile.read(size)
                if self.headers.get('Content-Encoding') == 'gzip':
                    data = gzip.decompress(data)
                received.put((self.headers.get('Authorization'), self.path, data))
                self.send_response(200)
                self.send_header('Content-Type', 'application/x-protobuf')
                self.send_header('Content-Length', '0')
                self.end_headers()

            def log_message(self, *_):
                pass

        server = HTTPServer(('127.0.0.1', 0), Collector)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(root/'collector.crt', root/'collector.key')
        server.socket = context.wrap_socket(server.socket, server_side=True)
        worker = threading.Thread(target=server.serve_forever, daemon=True)
        worker.start()
        value = minimal()
        value['observability'] = {'logs': {'enabled': True,
            'endpoint': 'https://192.168.10.31/otlp', 'tls_server_name': 'logs.example.test'}}
        content = logs.configuration(config.normalize(value)).replace(
            'https://192.168.10.31/otlp', 'https://127.0.0.1:'+str(server.server_port)+'/otlp').replace(
            '/var/log/journal', str(root/'journal')).replace('/var/lib/lanrith-alloy/queue', str(root/'queue'))
        assert 'router_password' not in content and 'otelcol.auth.' not in content
        (root/'config.alloy').write_text(content)
        environment = {key: val for key, val in os.environ.items() if key != 'CREDENTIALS_DIRECTORY'}
        environment.update(SSL_CERT_FILE=str(root/'collector.crt'), GOMAXPROCS='2', GOMEMLIMIT='128MiB')
        process = None
        try:
            with (root/'alloy.log').open('wb') as output:
                process = subprocess.Popen([str(binary), 'run', '--disable-reporting',
                    '--stability.level=public-preview', '--server.http.listen-addr=127.0.0.1:12345',
                    '--storage.path='+str(root/'state'), str(root/'config.alloy')],
                    env=environment, stdin=subprocess.DEVNULL, stdout=output, stderr=subprocess.STDOUT)
            auth, path, data = received.get(timeout=40)
            assert auth is None and path == '/otlp/v1/logs'
            assert message.encode() in data and unit.encode() in data and SECRET not in data
            assert process.poll() is None
            until(lambda: logs_runtime.pipeline_healthy(metrics(), minimum_components=7), seconds=10)
        except BaseException:
            print((root/'alloy.log').read_text(errors='replace')[-8192:], file=sys.stderr)
            raise
        finally:
            if process is not None and process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=15)
                except subprocess.TimeoutExpired:
                    process.kill(); process.wait(timeout=5)
            server.shutdown(); server.server_close(); worker.join(timeout=5)


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
    unauthenticated_delivery(args.alloy)
    processes = []
    server = worker = None
    with tempfile.TemporaryDirectory(prefix='logs-native.') as directory:
        root = Path(directory)
        root.chmod(0o755)
        accounts = root/'accounts.conf'
        assert not any(entry.pw_uid == 58010 for entry in pwd.getpwall())
        accounts.write_text('u alloy - "Synthetic exporter" /\ng observation-reader 58010\n'
                            'u observation-reader 58010:58010 "Synthetic observation reader" /\n')
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
        journal_stamp = journal(root)
        os.chown(root/'journal', 0, account.pw_gid)
        (root/'journal').chmod(0o750)
        for path in (root/'journal').iterdir():
            os.chown(path, 0, account.pw_gid)
            path.chmod(0o640)
        logs_runtime.LOCAL.mkdir(mode=0o750)
        os.chown(logs_runtime.LOCAL, account.pw_uid, account.pw_gid)
        observer = {'user': 'observation-reader', 'uid': 58010, 'gid': 58010}
        logs_runtime.prepare_local(observer, account)
        run('openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
            '-subj', '/CN=logs.example.test', '-addext', 'subjectAltName=DNS:logs.example.test',
            '-keyout', str(root/'collector.key'), '-out', str(root/'collector.crt'))
        (root/'collector.key').chmod(0o600)
        (root/'password').write_text('disposable-ingest-password')
        (root/'password').chmod(0o400)
        os.chown(root/'password', account.pw_uid, account.pw_gid)
        for name in ('state', 'queue', 'bad-state', 'bad-queue'):
            path = root/name
            path.mkdir(mode=0o750)
            os.chown(path, account.pw_uid, account.pw_gid)
        value = minimal()
        value['networks']['home']['ipv4'] = '192.0.2.0/24'
        value['networks']['home']['dhcp4'] = {'pools': ['192.0.2.100-192.0.2.199']}
        value['observability'] = {'logs': {'enabled': True, 'endpoint': 'https://192.0.2.31/otlp',
            'tls_server_name': 'logs.example.test', 'username': 'synthetic-router', 'credential': 'ingest'}}
        value = config.normalize(value)
        files = config.render(value)
        assert 'lanrith-log-observations' not in files['etc/alloy/config.alloy']
        route = next(item for item in json.loads(files['usr/share/lanrith/service-plane.json'])['dependency_routes']
                     if item['to'] == '192.0.2.31/32')
        source = json.loads(files['usr/share/lanrith/logs.json'])['source']
        assert source == route['source']
        run('ip', 'address', 'add', source+'/32', 'dev', 'lo')
        run('ip', 'route', 'replace', 'local', route['to'], 'dev', 'lo', 'src', source, 'table', 'local')
        original = logs.render(value, observer=observer)['etc/alloy/config.alloy']
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
        # PID 1 continuously consumes notifications. Leaving this datagram
        # socket undrained blocks the supervisor after the small kernel queue
        # fills and falsely makes its observations appear stale.
        ready_notifications = queue.Queue(maxsize=4)
        notification_stop = threading.Event()

        def consume_notifications():
            while not notification_stop.is_set():
                try:
                    message = notifications.recv(256)
                except socket.timeout:
                    continue
                if message == b'READY=1':
                    ready_notifications.put_nowait(message)

        notification_worker = threading.Thread(target=consume_notifications, daemon=True)
        notification_worker.start()

        peak_queue_bytes = 0

        def sample_queue_disk():
            nonlocal peak_queue_bytes
            while not notification_stop.wait(.05):
                total = 0
                for path in (root/'queue').rglob('*'):
                    try:
                        info = path.stat()
                    except FileNotFoundError:
                        continue  # Compaction renamed a file during this sample.
                    if stat.S_ISREG(info.st_mode):
                        total += info.st_blocks*512
                peak_queue_bytes = max(peak_queue_bytes, total)

        disk_worker = threading.Thread(target=sample_queue_disk, daemon=True)
        disk_worker.start()

        def launch(bad=False):
            command = [str(args.alloy), *logs_runtime.ALLOY[1:-1]]
            command[-1] = '--storage.path='+str(root/('bad-state' if bad else 'state'))
            command.append(str(root/('bad.alloy' if bad else 'config.alloy')))
            log = root/('bad.log' if bad else 'alloy.log')
            with log.open('ab') as stream:
                process = subprocess.Popen([sys.executable, '-c', RUN, json.dumps(command), '3' if bad else '25',
                    str(root/('bad-state' if bad else 'state')/'health.json')],
                    env=environment, stdin=subprocess.DEVNULL, stdout=stream, stderr=subprocess.STDOUT,
                    user=account.pw_uid, group=account.pw_gid, extra_groups=(), umask=0o027, start_new_session=True)
            processes.append(process)
            return process

        def ready(process):
            assert process.poll() is None, 'Exporter supervisor exited before readiness.'
            try:
                return ready_notifications.get(timeout=.1) == b'READY=1'
            except queue.Empty:
                return False

        received = {'marker': False, 'redacted': False, 'self': False, 'secret': False, 'records': 0,
                    'authenticated': True, 'sni': True, 'path': True, 'local_failure_marker': False}
        observed_bodies = set()
        accepted_heartbeats = set()
        heartbeats = []

        def heartbeat():
            message = json.dumps({'schema': 1, 'event': 'lanrith-heartbeat', 'boot_id': '11111111-1111-1111-1111-111111111111',
                'selected_entry': 'lanrith_14.efi', 'image_id': 'lanrith', 'platform_version': '0.2.0',
                'configuration_sha256': 'a'*64, 'deployment_sequence': 14, 'monotonic_ns': time.monotonic_ns()},
                separators=(',', ':'))
            heartbeats.append(message)
            append_journal(root, 1, message, unit='lanrith-telemetry-heartbeat.service', redaction_probe=False)
            until(lambda: message in accepted_heartbeats)

        rejected = []
        accept_requests = threading.Event()
        accept_requests.set()
        expected_auth = 'Basic '+base64.b64encode(b'synthetic-router:disposable-ingest-password').decode()

        class Collector(BaseHTTPRequestHandler):
            def do_POST(self):
                if self.client_address[0] != source:
                    self.send_response(403)
                    self.send_header('Content-Length', '0')
                    self.end_headers()
                    return
                length = int(self.headers.get('Content-Length', '0'))
                assert 0 <= length <= 2*1024*1024
                data = self.rfile.read(length)
                if self.headers.get('Content-Encoding') == 'gzip':
                    data = gzip.decompress(data)
                assert len(data) <= 2*1024*1024
                if not accept_requests.is_set():
                    rejected.append(REJECTED.encode() in data)
                    self.send_response(401)
                    self.send_header('Content-Length', '0')
                    self.end_headers()
                    return
                # Search every accepted payload, including batches after restart.
                received['unselected'] = received.get('unselected', False) or UNSELECTED in data
                received['replayed_rejection'] = received.get('replayed_rejection', False) or REJECTED.encode() in data
                if MARKER in data or ABSENT_BODY in data:
                    check_received_projection(data, journal_stamp, observed_bodies,
                        ((b'fixture.service', MARKER+b' password=[REDACTED]'), (b'fixture-missing.service', ABSENT_BODY),
                         (b'fixture-empty.service', ABSENT_BODY)))
                if LOCAL_RECOVERY.encode() in data:
                    received.setdefault('local_recovery_payload', data)
                for heartbeat_body in heartbeats:
                    if heartbeat_body.encode() in data and b'lanrith-telemetry-heartbeat.service' in data:
                        accepted_heartbeats.add(heartbeat_body)
                received['marker'] |= MARKER in data
                received['local_failure_marker'] |= b'LANRITH_LOCAL_FAILURE_REMOTE_MARKER' in data
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
            assert ready_notifications.empty(), 'Exited exporter was marked ready.'
            process = launch()
            until(lambda: ready(process), 30)
            assert logs_runtime.pipeline_healthy(metrics())
            until(lambda: metric(metrics(), 'otelcol_exporter_enqueue_failed_log_records_total') > 0, 90)
            overflow = metric(metrics(), 'otelcol_exporter_enqueue_failed_log_records_total')
            queue_size = metric(metrics(), 'otelcol_exporter_queue_size')
            assert 0 < queue_size <= 67108864
            cache = root/'state/health.json'
            state = until(lambda: (value if (value := logs_runtime.read_observation(cache, owner=account.pw_uid))[
                'enqueue_failed_records'] > 0 else None), 10)
            assert state['queue_size_bytes'] > 0 and cache.stat().st_mode & 0o777 == 0o640
            # The root collector needs only a supplementary read group, with
            # every capability removed. Other service identities cannot read it.
            reader = ('from pathlib import Path; import sys; from lanrith.logs_runtime import read_observation; '
                      'read_observation(Path(sys.argv[1]), owner=int(sys.argv[2])); '
                      '\ntry: Path(sys.argv[3]).read_bytes()'
                      '\nexcept PermissionError: pass'
                      '\nelse: raise AssertionError("Observer can read the exporter credential")')
            run('setpriv', '--bounding-set=-all', '--inh-caps=-all', '--ambient-caps=-all',
                '--groups='+str(account.pw_gid), sys.executable, '-c', reader, str(cache), str(account.pw_uid), str(root/'password'),
                env=environment)
            denied = subprocess.run(['setpriv', '--reuid=nobody', '--regid=nogroup', '--clear-groups',
                sys.executable, '-c', reader, str(cache), str(account.pw_uid), str(root/'password')], env=environment,
                stdin=subprocess.DEVNULL, capture_output=True, timeout=10)
            assert denied.returncode != 0, 'Another service identity can read private exporter observations.'
            # Let the journal cursor commit before the forced process crash.
            time.sleep(12)
            assert process.poll() is None and logs_runtime.pipeline_healthy(metrics())
            assert (root/'alloy.log').stat().st_size < 2*1024*1024, 'Exporter outage amplified its own log.'
            old_epoch = logs_runtime.read_observation(logs_runtime.LOCAL/'health.json', owner=account.pw_uid)['producer_epoch']
            os.killpg(process.pid, signal.SIGKILL)
            process.wait(timeout=10)
            check_queued_projection(root/'queue')
            assert ready_notifications.empty(), 'Exporter emitted duplicate readiness.'
            process = launch()
            until(lambda: ready(process), 30)
            assert metric(metrics(), 'otelcol_exporter_queue_size') > 0, 'Persistent retry queue was lost.'
            assert logs_runtime.read_observation(logs_runtime.LOCAL/'health.json', owner=account.pw_uid)['producer_epoch'] != old_epoch
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
            # A second source with the correct disposable credential still fails
            # at this receiver. Verify TLS and SNI for both source paths.
            client = ssl.create_default_context(cafile=str(root/'collector.crt'))
            with socket.create_connection(server.server_address, timeout=3, source_address=('127.0.0.1', 0)) as tcp:
                with client.wrap_socket(tcp, server_hostname='logs.example.test') as tls:
                    tls.sendall(('POST /otlp/v1/logs HTTP/1.1\r\nHost: logs.example.test\r\nAuthorization: '+
                                 expected_auth+'\r\nContent-Length: 0\r\nConnection: close\r\n\r\n').encode('ascii'))
                    response = http.client.HTTPResponse(tls)
                    response.begin()
                    assert response.status == 403
                    response.close()
            wait_for_drain(received)
            assert observed_bodies == {0, 1, 2} and not received['unselected']
            assert received['redacted'] and not received['secret'] and not received['self']
            assert received['authenticated'] and received['sni'] and received['path']
            assert process.poll() is None and logs_runtime.pipeline_healthy(metrics())
            # Reader absence never blocks the producer. The local branch has
            # already rotated while the remote collector was unavailable.
            until(lambda: local_records(), 10)
            local_files = sorted(logs_runtime.LOCAL.glob('events*.jsonl'))
            assert 2 <= len(local_files) <= 3, 'Local output did not exercise bounded rotation.'
            local_bytes = sum(path.stat().st_size for path in local_files)
            assert local_bytes <= 3*1024*1024
            rows = local_records()
            assert rows and all(row['body'] == {'stringValue': 'journal message withheld'} for row in rows)
            raw = b''.join(path.read_bytes() for path in local_files)
            assert not any(value in raw for value in (MARKER, SELF, SECRET, b'BURST_'))
            assert all((path.stat().st_uid, path.stat().st_gid) == (account.pw_uid, 58010) and
                       not path.stat().st_mode & 0o022 for path in local_files)
            # The exporter creates 0644 files. Their nontraversable, setgid
            # parent supplies the actual read boundary, including after rotation.
            code = ('from pathlib import Path; import sys; p=Path(sys.argv[1]); p.read_bytes(); '
                    '\nfor path,write in [(p,True),(p.parent,True),(Path(sys.argv[2]),False),(Path(sys.argv[3]),False)]: '
                    '\n try: '
                    '\n  if write and path.is_dir(): (path/"forbidden").write_text("x")'
                    '\n  elif write: path.open("ab").close()'
                    '\n  else: path.read_bytes()'
                    '\n except PermissionError: pass'
                    '\n else: raise AssertionError("observation role has extra authority")')
            run('setpriv', '--reuid=58010', '--regid=58010', '--clear-groups', '--bounding-set=-all',
                '--inh-caps=-all', '--ambient-caps=-all', sys.executable, '-c', code, str(local_files[-1]),
                str(root/'password'), str(root/'journal/system.journal'))
            denied = subprocess.run(['setpriv', '--reuid=nobody', '--regid=nogroup', '--clear-groups',
                sys.executable, '-c', 'from pathlib import Path; import sys; Path(sys.argv[1]).read_bytes()',
                str(local_files[-1])], capture_output=True, timeout=10)
            assert denied.returncode != 0, 'Another identity can traverse the observation directory.'
            try:
                os.chown(logs_runtime.LOCAL, 0, 0)
                logs_runtime.LOCAL.chmod(0o500)
                exercise_file_failure(root)
                until(lambda: received['local_failure_marker'], 30)
                assert process.poll() is None and logs_runtime.pipeline_healthy(metrics())
            finally:
                os.chown(logs_runtime.LOCAL, account.pw_uid, 58010)
                logs_runtime.LOCAL.chmod(0o2750)
            stamp = append_journal(root, 1, LOCAL_RECOVERY)
            def recovered():
                for row in local_records():
                    attributes = {item['key']: item['value'].get('stringValue') for item in row.get('attributes', [])}
                    if row.get('timeUnixNano') == str(stamp*1000):
                        assert attributes.get('journal_boot') == '1'*32 and attributes.get('journal_transport') == 'stdout'
                        assert row['body'] == {'stringValue': 'journal message withheld'}
                        return True
                return False
            until(recovered, 15)
            recovered_bodies = set()
            recovery_payload = until(lambda: received.get('local_recovery_payload'), 30)
            check_received_projection(recovery_payload, stamp, recovered_bodies,
                ((b'fixture.service', LOCAL_RECOVERY.encode()+b' password=[REDACTED]'),))
            assert recovered_bodies == {0}, 'Collector missed the redacted recovery record at its journal timestamp.'
            local_health = until(lambda: (item if (item := logs_runtime.read_observation(
                logs_runtime.LOCAL/'health.json', owner=account.pw_uid))['local_failed_records'] > 0 else None), 10)
            assert local_health['local_sent_records'] > 0
            heartbeat()
            before_rejection = metric(metrics(), 'otelcol_exporter_send_failed_log_records_total')
            accept_requests.clear()
            append_journal(root, 1, REJECTED)
            until(lambda: any(rejected) and metric(metrics(), 'otelcol_exporter_send_failed_log_records_total') > before_rejection)
            assert metric(metrics(), 'otelcol_exporter_queue_size') == 0
            accept_requests.set()
            heartbeat()
            failed_sends = int(metric(metrics(), 'otelcol_exporter_send_failed_log_records_total')-before_rejection)
            assert len(accepted_heartbeats) == 2 and failed_sends > 0
            assert disk_worker.is_alive() and 0 < peak_queue_bytes <= 160*1024*1024, 'Queue physical storage exceeded its tested bound.'
            assert not received['replayed_rejection'] and received['authenticated'] and received['sni'] and received['path']
            assert not received['unselected'] and not received['secret'] and not received['self']
            result = {'schema': 1, 'test': 'offline-journal-https-outage', 'result': 'pass',
                'assessed_at': datetime.datetime.now(datetime.timezone.utc).isoformat(),
                'source_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                'implementation_sha256': {name: hashlib.sha256((Path(__file__).parents[1]/name).read_bytes()).hexdigest()
                    for name in ('lanrith/logs.py', 'lanrith/logs_runtime.py', 'lanrith/service_plane.py', 'lanrith/extension_observations.py', 'lanrith/dns_metadata.py')},
                'alloy_sha256': digest, 'configuration_sha256': hashlib.sha256(original.encode()).hexdigest(),
                'checks': sorted(CHECKS), 'queue_capacity_bytes': 67108864, 'queue_physical_bytes': peak_queue_bytes,
                'auth_rejection_failed_records': failed_sends, 'fresh_heartbeat_receipts': len(accepted_heartbeats),
                'overflow_records': overflow, 'delivered_batches': received['records'],
                'local_output_bytes': local_bytes, 'local_output_files': len(local_files),
                'local_failed_records': local_health['local_failed_records'],
                'physical_router_qualified': False}
            args.result.parent.mkdir(parents=True, exist_ok=True)
            args.result.write_text(json.dumps(result, sort_keys=True, allow_nan=False)+'\n')
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
            notification_stop.set()
            notification_worker.join(timeout=2)
            disk_worker.join(timeout=2)
            notifications.close()
            if server:
                server.shutdown()
                server.server_close()
            if worker:
                worker.join(timeout=5)


if __name__ == '__main__':
    main()
