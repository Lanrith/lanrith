#!/usr/bin/python3
"""Qualify timer, journal provenance and receiver freshness in a disposable offline PID 1 guest."""

import base64
import gzip
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import os
from pathlib import Path
import pwd
import runpy
import shutil
import signal
import ssl
import subprocess
import sys
import threading
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


WORK = Path('/run/heartbeat-fixture')
UNITS = Path('/etc/systemd/system')
UNIT = 'lanrith-telemetry-heartbeat.service'
TIMER = UNIT.replace('.service', '.timer')
STATIC = '[Service]\nType=oneshot\nRemainAfterExit=yes\nExecStart=/bin/true\n'
CHECKER = ROOT/'scripts/check-heartbeat-receipts.py'


def run(*args, ok=True):
    result = subprocess.run(args, capture_output=True, text=True, timeout=100)
    if ok and result.returncode:
        raise AssertionError((args, result.returncode, result.stderr))
    return result


def until(check, timeout):
    end = time.monotonic()+timeout
    while time.monotonic() < end:
        if result := check():
            return result
        time.sleep(.5)
    raise AssertionError('Fixture timed out')


def fields(data, number):
    from lanrith.dns_metadata import varint
    # OTLP protobuf allows repeated KeyValues, ScopeLogs and LogRecords.
    offset = 0
    while offset < len(data):
        tag, offset = varint(data, offset)
        wire = tag & 7
        if wire == 0:
            value, offset = varint(data, offset)
        else:
            if wire == 2:
                size, offset = varint(data, offset)
            else:
                size = {1: 8, 5: 4}[wire]
            assert size <= len(data)-offset
            value = data[offset:offset+size]
            offset += size
        if tag >> 3 == number:
            yield value


def one(data, number):
    item, = fields(data, number)
    return item


def attributes(message, number):
    return {one(item, 1).decode(): one(one(item, 2), 1).decode() for item in fields(message, number)}


def received_streams(data):
    for resource in fields(data, 1):
        labels = attributes(one(resource, 1), 1)
        if labels.get('unit') != UNIT:
            continue
        for scope in fields(resource, 2):
            for record in fields(scope, 2):
                body = one(one(record, 5), 1).decode()
                if '"event":"lanrith-heartbeat"' in body:
                    stamp = int.from_bytes(one(record, 1), 'little')
                    metadata = attributes(record, 6)
                    assert metadata['journal_boot'] == json.loads(body)['boot_id'].replace('-', '')
                    assert metadata['journal_transport'] == 'stdout'
                    yield {'stream': {**labels, **metadata}, 'values': [[str(stamp), body]]}


def writer_access():
    uid = os.getuid()
    assert uid not in (0, pwd.getpwnam('alloy').pw_uid)
    for name in ('/usr/share/lanrith/installed.json', '/run/lanrith/boot.json', '/run/lanrith/committed-boot.json'):
        assert Path(name).read_bytes() and not os.access(name, os.W_OK)
    try:
        Path('/run/lanrith-logs/password').read_bytes()
    except PermissionError:
        pass
    else:
        raise AssertionError('Writer could read exporter password')
    print(f'heartbeat fixture uid={uid}', flush=True)
    if (WORK/'hold').exists():
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
        time.sleep(120)


def qualify():
    from lanrith import build, image_operation, logs_runtime, runtime
    from lanrith.release import canonical
    from test_intent import minimal
    assert os.geteuid() == 0 and Path('/proc/1/comm').read_text().strip() == 'systemd'
    assert 'rdinit=/fixture-init' in Path('/proc/cmdline').read_text().split()
    assert {i['ifname'] for i in json.loads(run('ip', '-j', 'link').stdout)} == {'lo'}
    assert not runtime.INSTALLED.exists()
    WORK.mkdir()
    password = WORK/'credential'
    password.write_bytes(b'disposable-heartbeat-qualification')
    password.chmod(0o600)
    value = minimal()
    value['credentials'] = {'ingest': {'file': str(password)}}
    target = '192.168.10.31'
    value['observability'] = {'logs': {'enabled': True, 'endpoint': 'https://'+target+'/otlp',
        'username': 'router', 'credential': 'ingest', 'tls_server_name': 'logs.example.test'}}
    base = WORK/'base'
    base.touch()
    build.assembly(value, base, WORK/'assembly', version='0.1.32', sequence=7)
    image = WORK/'assembly/mkosi.extra'
    for name in ('usr/share/lanrith', 'usr/lib/lanrith', 'etc/alloy', 'etc/systemd/system/alloy.service.d'):
        shutil.copytree(image/name, '/'+name, dirs_exist_ok=True)
    for name in ('lanrith-runtime', 'lanrith-credentials'):
        shutil.copy2(image/'usr/bin'/name, Path('/usr/bin')/name)
    for name in (UNIT, TIMER, 'lanrith-credential-log-password.service'):
        shutil.copy2(image/'usr/lib/systemd/system'/name, UNITS/name)
    platform = Path('/opt/fixture-platform')
    shutil.copy2(platform/'usr/lib/systemd/system/alloy.service', UNITS/'alloy.service')
    Path('/usr/bin/alloy').unlink(missing_ok=True)
    Path('/usr/bin/alloy').symlink_to(platform/'usr/bin/alloy')
    for unit in ('lanrith-services.service', 'nftables.service'):
        (UNITS/unit).write_text(STATIC)
    (UNITS/'boot-complete.target').write_text('[Unit]\nDescription=Fixture complete target\nDefaultDependencies=no\n')
    accounts = WORK/'accounts.conf'
    accounts.write_text('u alloy - "Fixture exporter" /\n')
    run('systemd-sysusers', str(accounts))
    installed = runtime.installed()
    state = Path(installed['state_directory'])
    state.mkdir(exist_ok=True, mode=0o700)
    state.chmod(0o700)
    Path('/var/lib/lanrith-alloy').mkdir(exist_ok=True)
    run('ip', 'link', 'set', 'lo', 'up')
    source = json.loads(logs_runtime.MANIFEST.read_bytes())['source']
    plane = json.loads((image/'usr/share/lanrith/service-plane.json').read_bytes())
    route, = [r for r in plane['dependency_routes'] if r['to'] == target+'/32']
    assert route['source'] == source
    for address in (source, target):
        run('ip', 'address', 'add', address+'/32', 'dev', 'lo')
    run('ip', 'route', 'replace', 'local', route['to'], 'dev', 'lo', 'src', source, 'table', 'local')
    run('ip', 'netns', 'attach', 'lanrith-services', '1')
    Path('/var/log/journal').mkdir(exist_ok=True)
    run('systemd-tmpfiles', '--create', '--prefix=/var/log/journal')
    run('journalctl', '--flush')
    run('openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1', '-subj', '/CN=logs.example.test',
        '-addext', 'subjectAltName=DNS:logs.example.test', '-keyout', WORK/'key', '-out', WORK/'ca.crt')
    (UNITS/'alloy.service.d/99-fixture.conf').write_text('[Service]\nEnvironment=SSL_CERT_FILE='+str(WORK/'ca.crt')+'\n')
    probe = UNITS/(UNIT+'.d')
    probe.mkdir()
    access = WORK/'fixture.py'
    shutil.copyfile(__file__, access)
    (probe/'fixture.conf').write_text('[Service]\nExecStartPre=/usr/bin/python3 '+str(access)+' access\n')
    streams = []
    auth = 'Basic '+base64.b64encode(b'router:'+password.read_bytes()).decode()

    class Collector(BaseHTTPRequestHandler):
        def do_POST(self):
            assert self.client_address[0] == source and self.headers['Authorization'] == auth
            assert self.path == '/otlp/v1/logs' and self.headers['Content-Type'] == 'application/x-protobuf'
            data = self.rfile.read(int(self.headers['Content-Length']))
            if self.headers.get('Content-Encoding') == 'gzip':
                data = gzip.decompress(data)
            streams.extend(received_streams(data))
            self.send_response(200)
            self.send_header('Content-Type', 'application/x-protobuf')
            self.send_header('Content-Length', '0')
            self.end_headers()

        def log_message(self, *_):
            pass

    with HTTPServer((target, 443), Collector) as server:
        tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tls.load_cert_chain(WORK/'ca.crt', WORK/'key')
        server.socket = tls.wrap_socket(server.socket, server_side=True)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        try:
            run('systemctl', 'daemon-reload')
            run('systemctl', 'start', 'alloy.service', 'boot-complete.target')
            staged = logs_runtime.RUNTIME/'password'
            assert staged.read_bytes() == password.read_bytes() and staged.stat().st_mode & 0o777 == 0o400
            assert staged.stat().st_uid == pwd.getpwnam('alloy').pw_uid
            selected = Path(installed['uki_name'])
            runtime.publish_boot(installed, selected)
            run('systemctl', 'start', TIMER)
            until(lambda: run('systemctl', 'show', UNIT, '-P', 'Result').stdout.strip() == 'exec-condition', 85)
            assert not streams
            image_operation.save_accepted(installed)
            runtime.publish_boot(installed, selected, accepted=True)
            status = runtime.status()
            (WORK/'status.json').write_bytes(canonical(status))
            check = runpy.run_path(str(CHECKER))['check']
            def query():
                return {'status': 'success', 'data': {'resultType': 'streams', 'result': streams.copy()}}
            def evaluate():
                return check(value['hostname'], installed, status, query(), now_ns=time.time_ns())
            until(lambda: len(streams) >= 1, 85)
            until(lambda: len(streams) >= 2, 85)
            tick = evaluate()
            checker_cli = [sys.executable, CHECKER, '--image-root', image, '--status', WORK/'status.json', WORK/'range.json']
            (WORK/'range.json').write_bytes(canonical(query()))
            run(*checker_cli)
            (WORK/'hold').touch()
            until(lambda: run('systemctl', 'show', UNIT, '-P', 'Result').stdout.strip() == 'timeout', 105)
            (WORK/'hold').unlink()
            last = json.loads(streams[-1]['values'][0][1])['emitted_unix_ns']
            until(lambda: time.time_ns() > last+90*10**9, 35)
            # Use the actual received records as an independent query client
            # would see them during silence. Replays and delayed input must
            # leave the alarm active until the timer emits again.
            alarm = run(*checker_cli, ok=False)
            assert alarm.returncode == 1 and 'overdue' in alarm.stderr
            original = streams[-1]
            _, line = original['values'][0]
            event = json.loads(line)
            now = time.time_ns()
            delayed = {'stream': original['stream'], 'values': [[str(now), line]]}
            old_boot = {**event, 'boot_id': '00000000-0000-0000-0000-000000000001',
                        'emitted_unix_ns': now, 'monotonic_ns': event['monotonic_ns']+1}
            other = {'stream': {**original['stream'], 'journal_boot': old_boot['boot_id'].replace('-', '')},
                     'values': [[str(now), json.dumps(old_boot)]]}
            for additions in ([], [original], [delayed], [other]):
                response = query()
                response['data']['result'].extend(additions)
                try:
                    check(value['hostname'], installed, status, response, now_ns=now)
                except ValueError:
                    pass
                else:
                    raise AssertionError('Silence or an unrelated record cleared the receiver alarm')
            until(lambda: len(streams) >= 3, 60)
            assert evaluate() > tick
            (WORK/'range.json').write_bytes(canonical(query()))
            run(*checker_cli)
            until(lambda: run('systemctl', 'show', UNIT, '-P', 'SubState').stdout.strip() == 'dead', 8)
            assert run('systemctl', 'show', UNIT, '-P', 'Result').stdout.strip() == 'success'
            # Verify each received timestamp and trusted UID against its individual guest journal record.
            rows = [json.loads(row) for row in run('journalctl', '-u', UNIT, '-b', '-o', 'json', '--no-pager').stdout.splitlines()]
            for stream in streams:
                (stamp, body), = stream['values']
                row, = [row for row in rows if row.get('MESSAGE') == body]
                assert row['_SYSTEMD_UNIT'] == UNIT and int(row['_UID']) not in (0, pwd.getpwnam('alloy').pw_uid)
                assert int(stamp) == int(row['__REALTIME_TIMESTAMP'])*1000
            elapsed = {}
            for key in ('InactiveExitTimestampMonotonic', 'InactiveEnterTimestampMonotonic'):
                elapsed[key] = int(run('systemctl', 'show', UNIT, '-P', key).stdout.strip())
            duration = (elapsed['InactiveEnterTimestampMonotonic']-elapsed['InactiveExitTimestampMonotonic'])/10**6
            assert 0 < duration < 20
            ticks = [json.loads(stream['values'][0][1])['monotonic_ns'] for stream in streams]
            intervals = [round((later-earlier)/10**9, 3) for earlier, later in zip(ticks, ticks[1:])]
            assert 50 <= intervals[0] <= 90 and 90 < intervals[1] <= 180, intervals
            print(json.dumps({'received': len(streams), 'writer_uid': row['_UID'], 'normal_seconds': duration,
                'emission_intervals_seconds': intervals, 'stop_timeout_seconds': 5,
                'start_timeout_seconds': 20, 'overdue_seconds': 90, 'recovered': True}), flush=True)
        finally:
            server.shutdown()
            if sys.exc_info()[0]:
                print(run('journalctl', '-b', '-u', UNIT, '-u', 'alloy.service', '-n', '35', '--no-pager').stdout)


if __name__ == '__main__':
    if sys.argv[1:] == ['access']:
        writer_access()
    else:
        qualify()
