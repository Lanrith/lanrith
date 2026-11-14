"""Observe Chrony as its service identity without exposing its control socket."""

import json
import os
from pathlib import Path
import pwd
import stat
import time

from .policy_runtime import decode, exact, read
from .router_metrics_runtime import command, tracking


OUTPUT = Path('/run/lanrith-ntp-health/health.json')
CONTROL = Path('/run/chrony/chronyd.sock')
NAMESPACE = Path('/run/netns/lanrith-services')
FIELDS = {'schema', 'boot_id', 'network_namespace_inode', 'observed_monotonic_ns',
          'observed_timestamp_seconds', 'query_success', 'synchronised'}


class NtpHealthError(ValueError):
    """An NTP observation is unavailable or outside its fixed boundary."""


def require(condition):
    if not condition:
        raise NtpHealthError('NTP health contract differs.')


def private_directory(path, uid, gid, mode):
    info = path.lstat()
    require(path.resolve() == path and stat.S_ISDIR(info.st_mode) and
            info.st_uid == uid and info.st_gid == gid and stat.S_IMODE(info.st_mode) == mode)


def boot_id():
    return Path('/proc/sys/kernel/random/boot_id').read_text().strip()


def probe():
    account = pwd.getpwnam('_chrony')
    boot, namespace = boot_id(), os.stat('/proc/self/ns/net').st_ino
    require(namespace == NAMESPACE.stat().st_ino)
    succeeded, synchronised = False, False
    try:
        private_directory(CONTROL.parent, account.pw_uid, account.pw_gid, 0o700)
        before = CONTROL.lstat()
        require(stat.S_ISSOCK(before.st_mode) and before.st_uid == account.pw_uid and
                before.st_gid == account.pw_gid and not before.st_mode & 0o022)
        synchronised = bool(tracking(command(['/usr/bin/chronyc', '-h', str(CONTROL), '-n', '-c', 'tracking'],
                                             time.monotonic()+2, limit=4096)))
        after = CONTROL.lstat()
        require((before.st_dev, before.st_ino, before.st_ctime_ns) ==
                (after.st_dev, after.st_ino, after.st_ctime_ns))
        succeeded = True
    except (OSError, ValueError, KeyError, TypeError):
        synchronised = False
    require(boot == boot_id() and namespace == NAMESPACE.stat().st_ino)
    return {'schema': 1, 'boot_id': boot, 'network_namespace_inode': namespace,
            'observed_monotonic_ns': time.monotonic_ns(), 'observed_timestamp_seconds': int(time.time()),
            'query_success': succeeded, 'synchronised': synchronised}


def publish(value, path=OUTPUT):
    account = pwd.getpwnam('_chrony')
    private_directory(path.parent, account.pw_uid, account.pw_gid, 0o750)
    data = json.dumps(value, separators=(',', ':'), allow_nan=False).encode('ascii')+b'\n'
    require(len(data) <= 4096)
    # A single systemd oneshot serializes this producer. A fixed temporary name
    # bounds debris even if the process is killed before its atomic rename.
    temporary = path.with_name('.health.json.tmp')
    for candidate in (path, temporary):
        try:
            info = candidate.lstat()
        except FileNotFoundError:
            continue
        require(stat.S_ISREG(info.st_mode) and info.st_uid == account.pw_uid and info.st_gid == account.pw_gid and
                info.st_nlink == 1 and stat.S_IMODE(info.st_mode) in (0o600, 0o640))
    temporary.unlink(missing_ok=True)
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(descriptor, 'wb') as stream:
            os.fchmod(stream.fileno(), 0o640)
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def read_observation(path=OUTPUT, *, now=None, boot=None, namespace=None):
    account = pwd.getpwnam('_chrony')
    private_directory(path.parent, account.pw_uid, account.pw_gid, 0o750)
    info = path.lstat()
    require(info.st_gid == account.pw_gid and stat.S_IMODE(info.st_mode) == 0o640)
    value = exact(decode(read(path, 4096, owner=account.pw_uid), 4096), FIELDS, 'NTP observation')
    boot = boot_id() if boot is None else boot
    namespace = NAMESPACE.stat().st_ino if namespace is None else namespace
    now = time.monotonic_ns() if now is None else now
    require(type(value['schema']) is int and value['schema'] == 1 and value['boot_id'] == boot and
            type(value['query_success']) is bool and type(value['synchronised']) is bool and
            (value['query_success'] or not value['synchronised']) and
            all(type(value[key]) is int and 0 < value[key] < 2**63 for key in
                ('observed_monotonic_ns', 'observed_timestamp_seconds', 'network_namespace_inode')) and
            value['network_namespace_inode'] == namespace and
            0 <= now-value['observed_monotonic_ns'] <= 90*10**9 and
            value['observed_timestamp_seconds'] <= time.time()+5)
    return value


def main():
    try:
        account = pwd.getpwnam('_chrony')
        require(os.getuid() == os.geteuid() == account.pw_uid != 0 and
                os.getgid() == os.getegid() == account.pw_gid and len(os.sys.argv) == 1)
        publish(probe())
    except (OSError, ValueError, KeyError, TypeError) as error:
        print('ntp-health: '+type(error).__name__+'; observation unavailable', file=os.sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
