"""Socket-activated, unprivileged DNS metadata collector with a bounded spool."""

import json
import os
from pathlib import Path
import pwd
import re
import select
import signal
import socket
import struct
import time

from . import dns_metadata
from .policy_runtime import decode, exact, read
from .observation_spool import Spool as MetadataSpool, regular, LIMIT, LINE, MAX


MANIFEST = Path('/usr/share/lanrith/dns-observations.json')
DIRECTORY = Path('/run/lanrith-dns-observations')


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


class Spool(MetadataSpool):
    def __init__(self, path=DIRECTORY, *, boot=Path('/run/lanrith-dns-boot-id')):
        super().__init__(path, boot=boot, limit=LIMIT, line=LINE)


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
