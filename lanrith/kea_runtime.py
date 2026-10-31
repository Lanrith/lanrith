"""Prepare the fixed Kea control socket as its unprivileged service identity."""

import errno
import os
from pathlib import Path
import pwd
import re
import socket
import stat
import struct
import sys
import time

ENDPOINT = Path('/run/kea/kea4-ctrl-socket')


def require(value):
    if not value:
        raise ValueError('Kea control readiness is unavailable.')


def constrain(path, uid, pid, deadline):
    require(path.is_absolute() and path.resolve(strict=True) == path)
    for parent in (path.parent, *path.parent.parents):
        info = parent.lstat()
        require(stat.S_ISDIR(info.st_mode) and info.st_uid == (uid if parent == path.parent else 0) and
                not info.st_mode & 0o022)
    descriptor = os.open(path, os.O_PATH | os.O_NOFOLLOW)
    try:
        info = os.fstat(descriptor)
        require(stat.S_ISSOCK(info.st_mode) and info.st_uid == uid and info.st_nlink == 1 and
                stat.S_IMODE(info.st_mode) in (0o600, 0o700))
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
            connection.settimeout(max(0.001, min(1, deadline-time.monotonic())))
            connection.connect(str(path))
            peer_pid, peer_uid, _ = struct.unpack('3i', connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
            require((peer_pid, peer_uid) == (pid, uid))
        # O_PATH plus the procfs descriptor link changes this checked inode,
        # rather than following a replaced pathname. No request is sent to Kea.
        os.chmod('/proc/self/fd/'+str(descriptor), 0o600)
        current = path.lstat()
        require((current.st_dev, current.st_ino) == (info.st_dev, info.st_ino) and
                current.st_uid == uid and stat.S_IMODE(current.st_mode) == 0o600 and
                time.monotonic() <= deadline)
    finally:
        os.close(descriptor)


def ready(pid):
    uid = pwd.getpwnam('_kea').pw_uid
    require(0 < uid < (1 << 32) and os.getuid() == os.geteuid() == uid and
            type(pid) is int and 1 < pid <= (1 << 31)-1)
    deadline = time.monotonic()+10
    while True:
        try:
            constrain(ENDPOINT, uid, pid, deadline)
            return
        except OSError as error:
            if error.errno not in (errno.ENOENT, errno.ECONNREFUSED):
                raise
        require(time.monotonic() < deadline)
        time.sleep(min(0.1, max(0, deadline-time.monotonic())))


def main(arguments=None):
    arguments = sys.argv[1:] if arguments is None else arguments
    if len(arguments) != 1 or re.fullmatch(r'[1-9][0-9]{0,9}', arguments[0]) is None:
        return 64
    try:
        ready(int(arguments[0]))
        return 0
    except (OSError, KeyError, ValueError):
        print('Kea control readiness failed.', file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
