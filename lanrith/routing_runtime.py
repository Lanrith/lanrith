"""Materialize only declared BGP credentials from systemd's private store."""

import json
import os
from pathlib import Path
import re
import stat
import tempfile


def materialize(manifest, credentials, target):
    if (set(manifest) != {'schema', 'template', 'credentials'} or manifest['schema'] != 1
            or not isinstance(manifest['template'], str) or len(manifest['template']) > 1024*1024
            or not isinstance(manifest['credentials'], dict) or len(manifest['credentials']) > 64):
        raise ValueError('Invalid routing credential manifest.')
    text = manifest['template']
    for marker, key in manifest['credentials'].items():
        if (not re.fullmatch(r'@LANRITH_BGP_[0-9]+@', marker) or text.count(marker) != 1
                or not re.fullmatch(r'[a-z][a-z0-9_-]{0,47}', key)):
            raise ValueError('Invalid routing credential reference.')
        descriptor = os.open(credentials/key, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(descriptor, 'rb') as stream:
            info = os.fstat(stream.fileno())
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o077
                    or not 1 <= info.st_size <= 81):
                raise ValueError('Invalid routing credential metadata.')
            secret = stream.read(82).removesuffix(b'\n')
        # Restrict the token to FRR's single-token password grammar. Never log
        # the source or a daemon diagnostic containing the substituted line.
        if not re.fullmatch(rb'[a-zA-Z0-9_+=./:-]{1,80}', secret):
            raise ValueError('Invalid routing credential encoding.')
        text = text.replace(marker, secret.decode('ascii'))
    if '@LANRITH_BGP_' in text:
        raise ValueError('Unresolved routing credential.')
    descriptor, temporary = tempfile.mkstemp(prefix='.frr-', dir=target.parent)
    try:
        with os.fdopen(descriptor, 'w') as stream:
            stream.write(text)
            stream.flush()
            os.fsync(stream.fileno())
            os.fchmod(stream.fileno(), 0o640)
        os.replace(temporary, target)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


if __name__ == '__main__':
    try:
        materialize(json.loads(Path('/usr/share/lanrith/routing.json').read_bytes()),
                    Path(os.environ['CREDENTIALS_DIRECTORY']), Path('/run/lanrith-routing/frr.conf'))
    except Exception:
        raise SystemExit('Unable to prepare authenticated routing configuration.') from None
