"""Seed absent zones and prepare TSIG includes without reading private journals."""

import base64
import grp
import json
import os
from pathlib import Path
import pwd
import re
import stat
import tempfile


def read_regular(path, maximum, *, private=False):
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, 'rb') as stream:
        info = os.fstat(stream.fileno())
        if (not stat.S_ISREG(info.st_mode) or not 0 < info.st_size <= maximum
                or private and (info.st_uid != 0 or info.st_mode & 0o077)):
            raise ValueError('Invalid DNS input metadata.')
        result = stream.read(maximum+1)
        if len(result) > maximum:
            raise ValueError('DNS input exceeds its bound.')
        return result


def prepare(manifest, credentials, runtime, *, root=Path('/')):
    if (set(manifest) != {'schema', 'seeds', 'credentials'} or manifest['schema'] != 1
            or not isinstance(manifest['seeds'], list) or len(manifest['seeds']) > 64
            or not isinstance(manifest['credentials'], dict) or len(manifest['credentials']) > 64):
        raise ValueError('Invalid authoritative DNS manifest.')
    content = ''
    for key, reference in manifest['credentials'].items():
        if (not re.fullmatch(r'[a-zA-Z0-9_.-]{1,253}', key)
                or not re.fullmatch(r'[a-z][a-z0-9_-]{0,47}', reference)):
            raise ValueError('Invalid DNS credential reference.')
        secret = read_regular(credentials/reference, 256, private=True).removesuffix(b'\n')
        try:
            decoded = base64.b64decode(secret, validate=True)
            if not 16 <= len(decoded) <= 128 or base64.b64encode(decoded) != secret:
                raise ValueError()
        except ValueError:
            raise ValueError('Invalid DNS credential encoding.') from None
        content += f'key "{key}" {{ algorithm hmac-sha256; secret "{secret.decode("ascii")}"; }};\n'
    bind = pwd.getpwnam('bind')
    for seed in manifest['seeds']:
        if (set(seed) != {'source', 'target'} or
                not re.fullmatch(r'/usr/share/lanrith/zones/db\.[a-zA-Z0-9_.-]+', seed['source']) or
                seed['target'] != '/var/cache/bind/'+Path(seed['source']).name):
            raise ValueError('Invalid persistent DNS seed.')
        source, target = root/seed['source'].lstrip('/'), root/seed['target'].lstrip('/')
        content_zone = read_regular(source, 1024*1024)
        if target.parent.is_symlink() or not target.parent.is_dir():
            raise ValueError('Invalid persistent DNS directory.')
        descriptor, temporary = tempfile.mkstemp(prefix='.lanrith-seed-', dir=target.parent)
        try:
            with os.fdopen(descriptor, 'wb') as stream:
                stream.write(content_zone)
                stream.flush()
                os.fsync(stream.fileno())
                os.fchmod(stream.fileno(), 0o640)
                os.fchown(stream.fileno(), bind.pw_uid, bind.pw_gid)
            try:
                # Link a complete file without replacing an existing name.
                # A killed initializer cannot leave a partially written zone.
                os.link(temporary, target, follow_symlinks=False)
            except FileExistsError:
                metadata = target.lstat()
                if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != bind.pw_uid or metadata.st_mode & 0o022:
                    raise ValueError('Existing persistent DNS zone has unsafe metadata.') from None
        finally:
            os.unlink(temporary)
    descriptor, temporary = tempfile.mkstemp(prefix='.keys-', dir=runtime)
    try:
        with os.fdopen(descriptor, 'w') as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
            os.fchmod(stream.fileno(), 0o640)
            os.fchown(stream.fileno(), 0, grp.getgrnam('bind').gr_gid)
        os.replace(temporary, runtime/'keys.conf')
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


if __name__ == '__main__':
    try:
        manifest = json.loads(read_regular(Path('/usr/share/lanrith/authoritative.json'), 1024*1024))
        prepare(manifest, Path(os.environ.get('CREDENTIALS_DIRECTORY', '/run/credentials/lanrith-dns-state.service')),
                Path('/run/lanrith-dns'))
    except Exception:
        raise SystemExit('Unable to prepare authoritative DNS state.') from None
