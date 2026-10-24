"""Stage the log exporter password from a systemd credential."""

import argparse
import grp
import ipaddress as ip
import os
from pathlib import Path
import re
import stat
import tempfile
from urllib.parse import urlsplit

from .policy_runtime import decode, exact, read


MANIFEST = Path('/usr/share/lanrith/logs.json')
RUNTIME = Path('/run/lanrith-logs')
NAME = re.compile(r'[a-z][a-z0-9_-]{0,63}\Z')


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


def main(arguments=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('operation', choices=('stage',))
    args = parser.parse_args(arguments)
    try:
        if args.operation == 'stage':
            stage()
    except (OSError, KeyError, TypeError, ValueError) as error:
        print('logs-runtime: '+type(error).__name__+'; delivery remains closed', file=os.sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
