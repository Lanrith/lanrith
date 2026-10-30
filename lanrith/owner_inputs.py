"""Read optional owner build inputs without installing their source files."""

import hashlib
import json
from pathlib import Path

from . import config, release


FILES = {'target_facts': 'hardware-facts.json',
         'retained_allocations': 'translation-allocations.json'}


def load(owner, value):
    """Validate one immutable input set for admission, assembly and evidence."""
    release.require(isinstance(owner, Path) and owner.is_dir() and
                    owner.resolve() == owner.absolute() and not owner.is_symlink(),
                    'Owner build inputs require a canonical directory.')
    options, records = {}, {}
    for argument, name in FILES.items():
        path = owner/name
        if not path.exists() and not path.is_symlink():
            continue
        raw = release.read(path, 1024*1024)
        try:
            item = json.loads(raw, object_pairs_hook=release.unique,
                parse_constant=lambda _: release.require(False, 'Invalid owner input number.'))
        except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as error:
            raise release.ReleaseError('Invalid owner build input JSON.') from error
        release.require(isinstance(item, dict), 'Owner build inputs must be JSON objects.')
        options[argument] = item
        records[name] = {'size': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()}
    # Rendering validates ownership, allocations and their component references
    # before signing material is opened. No source file is emitted here.
    config.render(value, **options)
    return options, records
