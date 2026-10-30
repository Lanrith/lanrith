"""Stage log credentials and supervise the compiled exporter component graph."""

import argparse
import grp
import http.client
import ipaddress as ip
import math
import os
from pathlib import Path
import re
import signal
import socket
import stat
import subprocess
import tempfile
import time
from urllib.parse import urlsplit

from .policy_runtime import decode, exact, read


MANIFEST = Path('/usr/share/lanrith/logs.json')
RUNTIME = Path('/run/lanrith-logs')
NAME = re.compile(r'[a-z][a-z0-9_-]{0,63}\Z')
ALLOY = ('/usr/bin/alloy', 'run', '--stability.level=public-preview', '--disable-reporting',
         '--server.http.listen-addr=127.0.0.1:12345', '--storage.path=/var/lib/lanrith/alloy/state',
         '/etc/alloy/config.alloy')
GRAPH = re.compile(r'alloy_component_controller_running_components\{controller_id="",'
                   r'controller_path="/",health_type="([a-z_]+)"\} ([^\s]+)\Z')
EVALUATING = re.compile(r'alloy_component_controller_evaluating\{controller_id="",'
                        r'controller_path="/"\} ([^\s]+)\Z')


class LogsRuntimeError(ValueError):
    """The compiled delivery contract or protected credential differs."""


def load(path=MANIFEST, *, owner=0):
    value = exact(decode(read(path, 64*1024, owner=owner), 64*1024), {
        'schema_version', 'endpoint', 'target', 'source', 'tls_server_name',
        'username', 'credential_name'}, 'logs runtime')
    try:
        target = ip.ip_address(value['target'])
        source = ip.ip_address(value['source'])
        parsed = urlsplit(value['endpoint'])
    except (TypeError, ValueError) as error:
        raise LogsRuntimeError('Log delivery address differs.') from error
    if (value['schema_version'] != 1 or parsed.scheme != 'https' or parsed.hostname != str(target) or
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
    raw = read(Path(root)/name, 4097, private=True)
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
    write(RUNTIME/'password', credential(policy['credential_name']), account.pw_uid, group.gr_gid)


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


def health():
    connection = http.client.HTTPConnection('127.0.0.1', 12345, timeout=2)
    try:
        connection.request('GET', '/metrics', headers={'Connection': 'close'})
        response = connection.getresponse()
        data = response.read(1024*1024+1)
        if response.status != 200 or len(data) > 1024*1024 or not pipeline_healthy(data.decode('ascii')):
            raise LogsRuntimeError('Log component graph is not healthy.')
    except (OSError, http.client.HTTPException, UnicodeError) as error:
        raise LogsRuntimeError('Log component graph is unavailable.') from error
    finally:
        connection.close()


def notify(message):
    address = os.environ.get('NOTIFY_SOCKET')
    if address:
        if address.startswith('@'):
            address = '\0'+address[1:]
        with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as stream:
            stream.sendto(message.encode('ascii'), address)


def supervise(command=ALLOY, *, startup_seconds=25, interval=3):
    stopping = False

    def stop(signum, frame):
        nonlocal stopping
        stopping = True

    previous = {name: signal.signal(name, stop) for name in (signal.SIGTERM, signal.SIGINT)}
    child = None
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
                health()
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
            load()
            supervise()
    except (OSError, KeyError, TypeError, ValueError, subprocess.SubprocessError) as error:
        print('logs-runtime: '+type(error).__name__+'; delivery remains closed', file=os.sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
