"""Stage log credentials and supervise the compiled exporter component graph."""

import argparse
import grp
import http.client
import ipaddress as ip
import json
import math
import os
from pathlib import Path
import re
import pwd
import signal
import socket
import stat
import subprocess
import tempfile
import time
import uuid
from urllib.parse import urlsplit

from .policy_runtime import decode, exact, read
from .systemd_credential import read as read_credential


MANIFEST = Path('/usr/share/lanrith/logs.json')
RUNTIME = Path('/run/lanrith-logs')
LOCAL = Path('/run/lanrith-log-observations')
NAME = re.compile(r'[a-z][a-z0-9_-]{0,63}\Z')
ALLOY = ('/usr/bin/alloy', 'run', '--stability.level=public-preview', '--disable-reporting',
         '--server.http.listen-addr=127.0.0.1:12345', '--storage.path=/var/lib/lanrith-alloy/state',
         '/etc/alloy/config.alloy')
GRAPH = re.compile(r'alloy_component_controller_running_components\{controller_id="",'
                   r'controller_path="/",health_type="([a-z_]+)"\} ([^\s]+)\Z')
EVALUATING = re.compile(r'alloy_component_controller_evaluating\{controller_id="",'
                        r'controller_path="/"\} ([^\s]+)\Z')
OBSERVATION = RUNTIME/'health.json'
COUNTERS = {
    'queue_capacity_bytes': 'otelcol_exporter_queue_capacity',
    'queue_size_bytes': 'otelcol_exporter_queue_size',
    'enqueue_failed_records': 'otelcol_exporter_enqueue_failed_log_records_total',
    'send_failed_records': 'otelcol_exporter_send_failed_log_records_total',
}
LOCAL_COUNTERS = {'local_sent_records': 'otelcol_exporter_sent_log_records_total',
                  'local_failed_records': 'otelcol_exporter_send_failed_log_records_total'}


class LogsRuntimeError(ValueError):
    """The compiled delivery contract or protected credential differs."""


def load(path=MANIFEST, *, owner=0):
    value = decode(read(path, 64*1024, owner=owner), 64*1024)
    value = exact(value, {
        'schema_version', 'endpoint', 'target', 'source', 'tls_server_name',
        'username', 'credential_name'} | ({'observer'} if isinstance(value, dict) and 'observer' in value else set()),
        'logs runtime')
    if 'observer' in value:
        observer = exact(value['observer'], {'user', 'uid', 'gid'}, 'Log observer')
        if (not isinstance(observer['user'], str) or
                not re.fullmatch(r'[a-z_][a-z0-9_-]{0,31}', observer['user']) or
                any(type(observer[key]) is not int or not 100 <= observer[key] <= 59999 for key in ('uid', 'gid'))):
            raise LogsRuntimeError('Log observer identity differs.')
    try:
        target = ip.ip_address(value['target'])
        source = ip.ip_address(value['source'])
        parsed = urlsplit(value['endpoint'])
    except (TypeError, ValueError) as error:
        raise LogsRuntimeError('Log delivery address differs.') from error
    if (type(value['schema_version']) is not int or value['schema_version'] != 1 or parsed.scheme != 'https' or parsed.hostname != str(target) or
            parsed.port not in (None, 443) or parsed.username or parsed.password or parsed.query or parsed.fragment or
            target.version != source.version or not isinstance(value['tls_server_name'], str) or
            not 1 <= len(value['tls_server_name']) <= 253 or not isinstance(value['username'], str) or
            not 1 <= len(value['username']) <= 64 or not isinstance(value['credential_name'], str) or
            not NAME.fullmatch(value['credential_name'])):
        raise LogsRuntimeError('Log delivery contract differs.')
    return value


def credential(name):
    root = os.environ.get('CREDENTIALS_DIRECTORY')
    if not root or '/' in name or name in ('', '.', '..'):
        raise LogsRuntimeError('Log credential transport differs.')
    raw = read_credential(Path(root)/name, 4097, pwd.getpwnam('alloy').pw_uid)
    if raw.endswith(b'\n'):
        raw = raw[:-1]
    if not 1 <= len(raw) <= 4096 or b'\x00' in raw or b'\n' in raw or b'\r' in raw:
        raise LogsRuntimeError('Log credential value differs.')
    return raw


def write(path, data, uid, gid):
    descriptor, temporary = tempfile.mkstemp(prefix='.'+path.name+'.', dir=path.parent)
    temporary = Path(temporary)
    try:
        with os.fdopen(descriptor, 'wb') as stream:
            os.fchmod(stream.fileno(), 0o400)
            os.fchown(stream.fileno(), uid, gid)
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def stage(path=MANIFEST):
    if os.getuid() != 0 or os.geteuid() != 0:
        raise LogsRuntimeError('Log credential staging requires root.')
    policy = load(path)
    account = __import__('pwd').getpwnam('alloy')
    group = grp.getgrnam('alloy')
    info = RUNTIME.lstat()
    if not stat.S_ISDIR(info.st_mode):
        raise LogsRuntimeError('Log runtime directory differs.')
    os.chown(RUNTIME, account.pw_uid, group.gr_gid)
    os.chmod(RUNTIME, 0o750)
    if 'observer' in policy:
        prepare_local(policy['observer'], account)
    write(RUNTIME/'password', credential(policy['credential_name']), account.pw_uid, group.gr_gid)


def prepare_local(observer, account, path=LOCAL):
    """Keep the optional reader out of the credential group and all write paths.

    Root prepares this separate fixed directory: systemd must not reset its
    reader group between pre-start and the main command. A missing/reassigned reader
    closes only read access; the exporter can continue writing private metadata.
    Existing aliases or unexpected files are never repaired or followed.
    """
    for parent in path.parents:
        info = parent.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise LogsRuntimeError('Log observation ancestor differs.')
    try:
        path.mkdir(mode=0o700)
    except FileExistsError:
        pass
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        info = os.fstat(descriptor)
        # Recover only an empty, unpublished directory left between mkdir and
        # chown. An existing root-owned nonempty/unexpected path is not adopted.
        if info.st_uid == 0 and account.pw_uid != 0:
            if info.st_gid != 0 or stat.S_IMODE(info.st_mode) != 0o700 or os.listdir(descriptor):
                raise LogsRuntimeError('Unpublished log observation directory differs.')
            os.fchown(descriptor, account.pw_uid, account.pw_gid)
            info = os.fstat(descriptor)
        if info.st_uid != account.pw_uid or info.st_gid not in (account.pw_gid, observer['gid']) or info.st_mode & 0o027:
            raise LogsRuntimeError('Log observation directory differs.')
        try:
            reader = pwd.getpwnam(observer['user'])
            admitted = (reader.pw_uid, reader.pw_gid) == (observer['uid'], observer['gid'])
        except KeyError:
            admitted = False
        gid = observer['gid'] if admitted else account.pw_gid
        entries = os.listdir(descriptor)
        if len(entries) > 8:
            raise LogsRuntimeError('Log observation inventory exceeds its bound.')
        for name in entries:
            temporary = re.fullmatch(r'\.health\.[a-z0-9_]{8}', name) is not None
            if not temporary and name != 'health.json' and not re.fullmatch(
                    r'events(?:-\d{4}-\d{2}-\d{2}T\d{2}-\d{2}-\d{2}\.\d{3})?\.jsonl', name):
                raise LogsRuntimeError('Log observation filename differs.')
            file = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=descriptor)
            try:
                current = os.fstat(file)
                if (not stat.S_ISREG(current.st_mode) or current.st_uid != account.pw_uid or
                        current.st_nlink != 1 or current.st_mode & 0o022 or
                        current.st_size > (4096 if name == 'health.json' or temporary else 1024*1024)):
                    raise LogsRuntimeError('Log observation file differs.')
                if temporary:
                    os.unlink(name, dir_fd=descriptor)
                else:
                    os.fchown(file, account.pw_uid, gid)
                    os.fchmod(file, 0o640)
            finally:
                os.close(file)
        os.fchown(descriptor, account.pw_uid, gid)
        os.fchmod(descriptor, 0o2750 if admitted else 0o2700)
    finally:
        os.close(descriptor)


def pipeline_healthy(text):
    """Alloy's HTTP health endpoints also succeed for an exited exporter.

    Require the complete generated graph (nine components), no evaluation in
    progress, and no failed/unknown/exited component. Extra admitted components
    must also be healthy; metrics from nested controllers cannot substitute.
    """
    counts = {}
    evaluating = []
    try:
        for line in text.splitlines():
            if match := GRAPH.fullmatch(line):
                name, number = match.groups()
                value = float(number)
                if name in counts or not math.isfinite(value) or not value.is_integer() or not 0 <= value <= 4096:
                    return False
                counts[name] = int(value)
            elif match := EVALUATING.fullmatch(line):
                evaluating.append(float(match[1]))
        return (evaluating == [0] and counts.get('healthy', 0) >= 9 and
                all(number == 0 for name, number in counts.items() if name != 'healthy'))
    except (ValueError, OverflowError):
        return False


def health(*, local=False):
    connection = http.client.HTTPConnection('127.0.0.1', 12345, timeout=2)
    try:
        connection.request('GET', '/metrics', headers={'Connection': 'close'})
        response = connection.getresponse()
        data = response.read(1024*1024+1)
        if response.status != 200 or len(data) > 1024*1024 or not pipeline_healthy(data.decode('ascii')):
            raise LogsRuntimeError('Log component graph is not healthy.')
        return observation(data.decode('ascii'), local=local)
    except (OSError, http.client.HTTPException, UnicodeError) as error:
        raise LogsRuntimeError('Log component graph is unavailable.') from error
    finally:
        connection.close()


def observation(text, *, local=False):
    values = {}
    for field, metric in COUNTERS.items():
        numbers = []
        for line in text.splitlines():
            if (line.startswith(metric+'{') and 'component_id="otelcol.exporter.otlphttp.router"' in line and
                    ('data_type="logs"' in line or 'data_type=' not in line)):
                try:
                    number = float(line.rsplit(' ', 1)[1])
                except (ValueError, IndexError) as error:
                    raise LogsRuntimeError('Log metric value differs.') from error
                if not math.isfinite(number) or not number.is_integer() or not 0 <= number < 2**63:
                    raise LogsRuntimeError('Log metric value differs.')
                numbers.append(int(number))
        # Counters appear on the first event. Queue gauges must always exist.
        if len(numbers) > 1 or field.startswith('queue_') and not numbers:
            raise LogsRuntimeError('Log metric series differs.')
        values[field] = numbers[0] if numbers else 0
    if values['queue_capacity_bytes'] != 67108864 or values['queue_size_bytes'] > values['queue_capacity_bytes']:
        raise LogsRuntimeError('Log queue bounds differ.')
    if local:
        for field, metric in LOCAL_COUNTERS.items():
            numbers = []
            for line in text.splitlines():
                if line.startswith(metric+'{') and 'component_id="otelcol.exporter.file.router_observations"' in line:
                    try:
                        number = float(line.rsplit(' ', 1)[1])
                    except (ValueError, IndexError) as error:
                        raise LogsRuntimeError('Local log metric differs.') from error
                    if not math.isfinite(number) or not number.is_integer() or not 0 <= number < 2**63:
                        raise LogsRuntimeError('Local log metric differs.')
                    numbers.append(int(number))
            if len(numbers) > 1:
                raise LogsRuntimeError('Local log metric series differs.')
            # Exporter counters are created on the first successful/failed send.
            values[field] = numbers[0] if numbers else 0
    return {'schema': 1, 'boot_id': Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
            'observed_monotonic_ns': time.monotonic_ns(), **values}


def publish_observation(value, path=OBSERVATION):
    data = json.dumps(value, separators=(',', ':'), allow_nan=False).encode('ascii')+b'\n'
    if len(data) > 4096:
        raise LogsRuntimeError('Log observation exceeds its bound.')
    descriptor, temporary = tempfile.mkstemp(prefix='.health.', dir=path.parent)
    try:
        with os.fdopen(descriptor, 'wb') as stream:
            os.fchmod(stream.fileno(), 0o640)
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        Path(temporary).unlink(missing_ok=True)


def read_observation(path=OBSERVATION, *, owner=None, now=None, boot_id=None):
    owner = pwd.getpwnam('alloy').pw_uid if owner is None else owner
    boot_id = Path('/proc/sys/kernel/random/boot_id').read_text().strip() if boot_id is None else boot_id
    value = decode(read(path, 4096, owner=owner), 4096)
    fields = set(LOCAL_COUNTERS) if isinstance(value, dict) and set(value) & LOCAL_COUNTERS.keys() else set()
    epoch = {'producer_epoch'} if isinstance(value, dict) and 'producer_epoch' in value else set()
    value = exact(value, {'schema', 'boot_id', 'observed_monotonic_ns', *COUNTERS, *fields, *epoch}, 'Log observation')
    if epoch and (not fields or not isinstance(value['producer_epoch'], str) or
                  re.fullmatch(r'[a-f0-9]{32}', value['producer_epoch']) is None):
        raise LogsRuntimeError('Local log producer epoch differs.')
    # A concurrent atomic publication can be newer than a clock sampled before
    # opening the file. Compare against the time after this snapshot was read.
    now = time.monotonic_ns() if now is None else now
    if (type(value['schema']) is not int or value['schema'] != 1 or value['boot_id'] != boot_id or
            type(value['observed_monotonic_ns']) is not int or
            value['observed_monotonic_ns'] < 0 or
            not 0 <= now-value['observed_monotonic_ns'] <= 15*10**9 or
            not all(type(value[key]) is int and 0 <= value[key] < 2**63 for key in {*COUNTERS, *fields}) or
            value['queue_capacity_bytes'] != 67108864 or value['queue_size_bytes'] > value['queue_capacity_bytes']):
        raise LogsRuntimeError('Log observation is stale or differs from the compiled queue.')
    return value


def notify(message):
    address = os.environ.get('NOTIFY_SOCKET')
    if address:
        if address.startswith('@'):
            address = '\0'+address[1:]
        with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as stream:
            stream.sendto(message.encode('ascii'), address)


def supervise(command=ALLOY, *, startup_seconds=25, interval=3, observation_path=OBSERVATION, local=False):
    stopping = False

    def stop(signum, frame):
        nonlocal stopping
        stopping = True

    previous = {name: signal.signal(name, stop) for name in (signal.SIGTERM, signal.SIGINT)}
    child = None
    epoch = uuid.uuid4().hex if local else None
    try:
        environment = {key: value for key, value in os.environ.items()
                       if key not in ('NOTIFY_SOCKET', 'WATCHDOG_PID', 'WATCHDOG_USEC')}
        child = subprocess.Popen(command, stdin=subprocess.DEVNULL, env=environment)
        deadline = time.monotonic()+startup_seconds
        ready = False
        while not stopping:
            if child.poll() is not None:
                raise LogsRuntimeError('Log exporter exited.')
            try:
                value = health(local=True) if local else health()
                publish_observation(value, observation_path)
                if local:
                    try:
                        publish_observation({**value, 'producer_epoch': epoch}, LOCAL/'health.json')
                    except (OSError, LogsRuntimeError):
                        # An optional local filesystem fault must not stop
                        # remote journal delivery or its liveness watchdog.
                        pass
            except LogsRuntimeError:
                if ready or time.monotonic() >= deadline:
                    raise
            else:
                if not ready:
                    notify('READY=1')
                    ready = True
                notify('WATCHDOG=1')
            time.sleep(interval)
    finally:
        try:
            if child is not None and child.poll() is None:
                child.terminate()
                try:
                    child.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    child.kill()
                    child.wait(timeout=2)
        finally:
            for name, handler in previous.items():
                signal.signal(name, handler)


def main(arguments=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('operation', choices=('stage', 'run'))
    args = parser.parse_args(arguments)
    try:
        if args.operation == 'stage':
            stage()
        else:
            policy = load()
            supervise(local='observer' in policy)
    except (OSError, KeyError, TypeError, ValueError, subprocess.SubprocessError) as error:
        print('logs-runtime: '+type(error).__name__+'; delivery remains closed', file=os.sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
