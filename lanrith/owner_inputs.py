"""Read optional owner build inputs without installing their source files."""

import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import stat

from . import config, release


FILES = {'target_facts': 'hardware-facts.json',
         'retained_allocations': 'translation-allocations.json'}


def snapshot(owner, destination, records):
    """Copy admitted bytes through pinned directory handles before key access."""
    release.require(owner.is_dir() and owner.resolve() == owner.absolute() and not owner.is_symlink() and
                    destination.parent.resolve() == destination.parent.absolute() and
                    not destination.exists() and not destination.is_symlink(),
                    'Owner snapshot needs canonical source and a new private destination.')
    release.require(isinstance(records, dict) and records and all(isinstance(name, str) for name in records),
                    'Owner snapshot has no valid admitted inventory.')
    destination.mkdir(mode=0o700)
    try:
        for name, record in sorted(records.items()):
            path = PurePosixPath(name)
            release.require(isinstance(name, str) and not path.is_absolute() and '..' not in path.parts and
                            path.parts and path.as_posix() == name and
                            isinstance(record, dict) and set(record) == {'name', 'size', 'sha256', 'mode'} and
                            record['name'] == path.name and type(record['size']) is int and record['size'] > 0 and
                            type(record['mode']) is int and 0 <= record['mode'] <= 0o777 and
                            isinstance(record['sha256'], str) and release.HEX.fullmatch(record['sha256']),
                            'Invalid admitted owner snapshot entry.')
            directory = os.open(owner, os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
            try:
                for component in path.parts[:-1]:
                    child = os.open(component, os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW, dir_fd=directory)
                    os.close(directory)
                    directory = child
                descriptor = os.open(path.name, os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK, dir_fd=directory)
            finally:
                os.close(directory)
            with os.fdopen(descriptor, 'rb') as source:
                before = os.fstat(source.fileno())
                release.require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and
                                before.st_size == record['size'] and stat.S_IMODE(before.st_mode) == record['mode'],
                                'Owner snapshot source metadata changed.')
                target = destination/name
                target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                opened = os.open(target, os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW, 0o600)
                digest, remaining = hashlib.sha256(), record['size']
                with os.fdopen(opened, 'wb') as output:
                    while remaining:
                        data = source.read(min(1024*1024, remaining))
                        release.require(data, 'Owner snapshot source was truncated.')
                        output.write(data)
                        digest.update(data)
                        remaining -= len(data)
                    after = os.fstat(source.fileno())
                    release.require(not source.read(1) and digest.hexdigest() == record['sha256'] and
                                    (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) ==
                                    (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns),
                                    'Owner input changed during snapshot.')
                    output.flush()
                    os.fchmod(output.fileno(), record['mode'])
                    os.fsync(output.fileno())
    except BaseException:
        shutil.rmtree(destination)
        raise
    return destination


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
