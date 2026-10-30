"""Authorize offline writes only from an explicitly admitted recovery initrd."""

import json
import os
from pathlib import Path

from . import factory, release


def permits(operation, binding=None):
    if operation not in ('backup', 'restore', 'repair') or os.geteuid() != 0 or not Path('/etc/initrd-release').is_file():
        return False
    from . import recovery_console
    path = Path('/usr/share/lanrith/recovery-console.json')
    if not path.is_file():
        return False
    try:
        data = recovery_console.protected_file(path, 4096, private=False)
    except OSError:
        return False
    value = recovery_console.policy(json.loads(data, object_pairs_hook=release.unique))
    if operation not in value.get('operations', []):
        return False
    release.require(binding is None or binding == (value if operation == 'repair' else value['offline_backup']),
                    'Offline write binding differs from the signed recovery policy.')
    factory.secure_boot()
    factory.verified_root('/sysroot')
    return True
