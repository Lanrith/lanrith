"""Socket-activated, unprivileged DNS metadata collector with a bounded spool."""

import json
import os
from pathlib import Path
import pwd
import re
import select
import signal
import socket
import stat
import struct
import tempfile
import time
import uuid

from . import dns_metadata
from .policy_runtime import decode, exact, read


MANIFEST = Path('/usr/share/lanrith/dns-observations.json')
DIRECTORY = Path('/run/lanrith-dns-observations')
LIMIT = 1024*1024
LINE = 16384
MAX = 2**63-1


def load(path=MANIFEST, *, owner=0):
    value = exact(decode(read(path, 4096, owner=owner), 4096), {'schema', 'record_schema', 'observer'}, 'DNS observations')
    observer = exact(value['observer'], {'user', 'uid', 'gid'}, 'DNS reader')
    if (type(value['schema']) is not int or value['schema'] != 1 or
            type(value['record_schema']) is not int or value['record_schema'] != 1 or
            not isinstance(observer['user'], str) or
            re.fullmatch(r'[a-z_][a-z0-9_-]{0,31}', observer['user']) is None or
            any(type(observer[k]) is not int or not 100 <= observer[k] <= 59999 for k in ('uid', 'gid'))):
        raise ValueError('DNS reader contract differs.')
    account = pwd.getpwnam(observer['user'])
    if (account.pw_uid, account.pw_gid) != (observer['uid'], observer['gid']):
        raise ValueError('DNS reader identity drift.')
    return observer


def regular(path, *, maximum=LIMIT):
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(descriptor)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or
                info.st_gid != os.getegid() or info.st_nlink != 1 or
                stat.S_IMODE(info.st_mode) != 0o640 or info.st_size > maximum):
            raise ValueError('DNS observation file custody differs.')
        return os.read(descriptor, maximum+1)
    finally:
        os.close(descriptor)


class Spool:
    def __init__(self, path=DIRECTORY, *, boot=Path('/run/lanrith-dns-boot-id')):
        for parent in path.parents:
            info = parent.lstat()
            if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
                raise ValueError('DNS observation ancestor differs.')
        info = path.lstat()
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or
                info.st_gid != os.getegid() or stat.S_IMODE(info.st_mode) != 0o750):
            raise ValueError('DNS observation directory custody differs.')
        self.path, self.counts = path, {}
        entries = list(path.iterdir())
        if len(entries) > 8:
            raise ValueError('DNS observation inventory bound.')
        for entry in entries:
            if re.fullmatch(r'\.health\.[a-z0-9_]{8}', entry.name):
                regular(entry, maximum=4096)
                entry.unlink()
            elif entry.name in ('events.jsonl', 'events.jsonl.1', 'events.jsonl.2'):
                data = regular(entry)
                self.counts[entry.name] = data.count(b'\n')
                # A killed writer may have left one incomplete final line. Keep
                # complete records; readers already reject incomplete lines.
                if data and not data.endswith(b'\n'):
                    boundary = data.rfind(b'\n')+1
                    descriptor = os.open(entry, os.O_WRONLY | os.O_NOFOLLOW)
                    try:
                        os.ftruncate(descriptor, boundary)
                    finally:
                        os.close(descriptor)
            elif entry.name == 'health.json':
                regular(entry, maximum=4096)
            else:
                raise ValueError('Unexpected DNS observation file.')
        self.counters = dict(emitted=0, rejected=0, write_failed=0, overwritten=0, disconnects=0)
        self.epoch = uuid.uuid4().hex
        self.boot = boot.read_text().strip()
        if re.fullmatch(r'[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}', self.boot) is None:
            raise ValueError('DNS observation boot identity differs.')

    def bump(self, name, count=1):
        self.counters[name] = min(MAX, self.counters[name]+count)

    def append(self, value):
        if self.counters['emitted'] == MAX:
            raise ValueError('DNS observation sequence exhausted.')
        value = {**value, 'producer_epoch': self.epoch, 'boot_id': self.boot,
                 'sequence': self.counters['emitted']+1}
        data = json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode()+b'\n'
        if len(data) > LINE:
            self.bump('rejected')
            return
        path = self.path/'events.jsonl'
        if path.exists() and path.stat().st_size+len(data) > LIMIT:
            oldest = self.path/'events.jsonl.2'
            self.bump('overwritten', self.counts.pop(oldest.name, 0))
            oldest.unlink(missing_ok=True)
            for src, dst in (('events.jsonl.1', 'events.jsonl.2'), ('events.jsonl', 'events.jsonl.1')):
                if (self.path/src).exists():
                    os.replace(self.path/src, self.path/dst)
                    self.counts[dst] = self.counts.pop(src, 0)
        descriptor = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW, 0o640)
        try:
            info = os.fstat(descriptor)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or
                    info.st_gid != os.getegid() or info.st_nlink != 1 or
                    stat.S_IMODE(info.st_mode) != 0o640 or info.st_size+len(data) > LIMIT):
                raise ValueError('DNS output file custody differs.')
            try:
                if os.write(descriptor, data) != len(data):
                    raise OSError('Incomplete DNS metadata write.')
            except OSError:
                os.ftruncate(descriptor, info.st_size)
                raise
        finally:
            os.close(descriptor)
        self.counts[path.name] = self.counts.get(path.name, 0)+1
        self.bump('emitted')

    def health(self):
        value = {'schema': 1, 'producer_epoch': self.epoch, 'boot_id': self.boot,
                 'observed_monotonic_ns': time.monotonic_ns(), **self.counters}
        descriptor, temporary = tempfile.mkstemp(prefix='.health.', dir=self.path)
        try:
            os.fchmod(descriptor, 0o640)
            with os.fdopen(descriptor, 'wb') as stream:
                stream.write(json.dumps(value, sort_keys=True).encode()+b'\n')
            os.replace(temporary, self.path/'health.json')
        finally:
            Path(temporary).unlink(missing_ok=True)


def listener():
    if (os.environ.get('LISTEN_PID') != str(os.getpid()) or os.environ.get('LISTEN_FDS') != '1' or
            os.environ.get('LISTEN_FDNAMES') != 'dns-tap'):
        raise ValueError('DNS socket activation differs.')
    source = socket.socket(fileno=3)
    if (source.family != socket.AF_UNIX or source.type != socket.SOCK_STREAM or
            not source.getsockopt(socket.SOL_SOCKET, socket.SO_ACCEPTCONN) or
            source.getsockname() != '/run/lanrith-dns-tap.sock'):
        raise ValueError('DNS observation ingress differs.')
    source.setblocking(False)
    return source


def serve(source, spool, unbound_uid, *, stopped=lambda: False):
    connection, decoder, pending, active_at, health_at = None, None, b'', 0., 0.
    try:
        while not stopped():
            now = time.monotonic()
            if now-health_at >= 3:
                spool.health()
                health_at = now
            # Idle/broken peers cannot retain the only connection forever.
            if connection is not None and now-active_at > 30:
                connection.close()
                connection = None
                spool.bump('disconnects')
            ready, writable, _ = select.select([source]+([connection] if connection else []),
                                               [connection] if connection and pending else [], [], .2)
            if source in ready:
                peer, _ = source.accept()
                _, uid, _ = struct.unpack('3i', peer.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
                if uid != unbound_uid or connection is not None:
                    peer.close()
                    spool.bump('rejected')
                else:
                    connection, decoder, pending, active_at = peer, dns_metadata.FrameStream(), b'', now
                    connection.setblocking(False)
            try:
                if connection in writable:
                    pending = pending[connection.send(pending):]
                if connection in ready:
                    data = connection.recv(65536)
                    if not data:
                        raise ConnectionError('DNS tap disconnected.')
                    active_at = now
                    frames, replies = decoder.feed(data)
                    pending += b''.join(replies)
                    if len(pending) > 2048:
                        raise ValueError('DNS control reply bound.')
                    for frame in frames:
                        try:
                            value = dns_metadata.normalize(frame, now_ns=time.time_ns())
                            if value is not None:
                                spool.append(value)
                        except (ValueError, KeyError, TypeError, OverflowError):
                            spool.bump('rejected')
                        except OSError:
                            spool.bump('write_failed')
            except (ValueError, OSError):
                if connection is not None:
                    connection.close()
                connection, pending = None, b''
                spool.bump('disconnects')
    finally:
        if connection is not None:
            connection.close()


def main():
    phase = 'contract'
    try:
        observer = load()
        phase = 'identity'
        account = pwd.getpwnam('lanrith-dns-observer')
        unbound = pwd.getpwnam('unbound')
        if (os.geteuid() == 0 or os.geteuid() != account.pw_uid or
                os.geteuid() in (observer['uid'], unbound.pw_uid) or
                os.getegid() != observer['gid'] or
                set(os.getgroups())-set((observer['gid'],))):
            raise ValueError('DNS collector process identity differs.')
        done = False

        def stop(signum, frame):
            nonlocal done
            done = True

        signal.signal(signal.SIGTERM, stop)
        signal.signal(signal.SIGINT, stop)
        phase = 'socket'
        with listener() as source:
            phase = 'spool'
            spool = Spool()
            phase = 'stream'
            serve(source, spool, unbound.pw_uid, stopped=lambda: done)
        return 0
    except (ValueError, OSError, KeyError) as error:
        reason = str(error) if type(error) is ValueError and str(error).startswith('DNS observation ') else type(error).__name__
        print('Optional DNS observation collector unavailable: '+phase+' '+reason, flush=True)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
