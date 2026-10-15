"""Bounded extraction of Lanrith's ordinary-file handoff archives."""

import gzip
import os
from pathlib import Path
import re
import tarfile

from .release import ReleaseError, require


def extract(source, destination, *, entries, maximum_size, maximum_file, nested=False):
    """Reject links, metadata extensions, duplicates and oversized input before copying."""
    destination = Path(destination)
    require(destination.is_dir() and not destination.is_symlink() and not any(destination.iterdir()),
            'Archive destination must be an empty ordinary directory.')
    seen, total, extended = set(), 0, {}
    try:
        with gzip.open(source, 'rb') as stream:
            while True:
                header = stream.read(512)
                require(len(header) == 512, 'Truncated handoff archive.')
                if header == bytes(512):
                    require(not extended and stream.read(512) == bytes(512), 'Missing archive terminator.')
                    padding = stream.read(10241)
                    require(len(padding) <= 10240 and len(padding) % 512 == 0 and not any(padding),
                            'Unexpected data after the archive terminator.')
                    break
                member = tarfile.TarInfo.frombuf(header, 'utf-8', 'strict')
                # Bound PAX metadata before parsing it. This supports large disk images
                # without tarfile allocating an attacker-selected extension size.
                if member.type == tarfile.XHDTYPE:
                    require(not extended and 0 < member.size <= 4096, 'Oversized or repeated archive metadata.')
                    metadata = stream.read(member.size)
                    require(len(metadata) == member.size, 'Truncated archive metadata.')
                    while metadata:
                        length, separator, _ = metadata.partition(b' ')
                        require(separator and re.fullmatch(rb'[1-9][0-9]{0,3}', length), 'Invalid archive metadata.')
                        size = int(length)
                        record, metadata = metadata[:size], metadata[size:]
                        require(len(record) == size and record.endswith(b'\n'), 'Invalid archive metadata length.')
                        key, separator, data = record[len(length)+1:-1].partition(b'=')
                        require(separator and key in (b'path', b'size', b'mtime') and key not in extended,
                                'Unsupported archive metadata.')
                        extended[key] = data.decode('utf-8')
                    padding_size = (-member.size) % 512
                    require(stream.read(padding_size) == bytes(padding_size), 'Invalid archive metadata padding.')
                    continue
                require(member.type in (tarfile.REGTYPE, tarfile.AREGTYPE, tarfile.DIRTYPE),
                        'Archive links and metadata extensions are not permitted.')
                if extended:
                    member.name = extended.get(b'path', member.name)
                    if b'size' in extended:
                        require(re.fullmatch(r'0|[1-9][0-9]{0,14}', extended[b'size']), 'Invalid extended archive size.')
                        member.size = int(extended[b'size'])
                    require(b'mtime' not in extended or
                            re.fullmatch(r'[0-9]{1,15}(\.[0-9]{1,9})?', extended[b'mtime']),
                            'Invalid extended archive timestamp.')
                    extended = {}
                name = member.name.rstrip('/') if member.isdir() else member.name
                parts = name.split('/')
                require(name and len(name) <= 255 and all(re.fullmatch(r'[A-Za-z0-9_.+@-]{1,100}', part)
                        and part not in ('.', '..') for part in parts) and
                        (nested or len(parts) == 1) and name not in seen,
                        'Unsafe or duplicate archive path.')
                seen.add(name)
                require(len(seen) <= entries and 0 <= member.size <= maximum_file and
                        not member.mode & 0o7000, 'Archive entry exceeds its permitted bounds.')
                total += member.size
                require(total <= maximum_size, 'Archive exceeds its permitted total size.')
                target = destination.joinpath(*parts)
                if member.isdir():
                    require(nested and member.size == 0, 'Unexpected archive directory.')
                    target.mkdir(mode=0o755, parents=True, exist_ok=True)
                else:
                    target.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
                    descriptor = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
                    with os.fdopen(descriptor, 'wb') as output:
                        remaining = member.size
                        while remaining:
                            block = stream.read(min(1024*1024, remaining))
                            require(block, 'Truncated archive member.')
                            output.write(block)
                            remaining -= len(block)
                    target.chmod(member.mode & 0o755)
                    padding_size = (-member.size) % 512
                    require(stream.read(padding_size) == bytes(padding_size), 'Invalid archive member padding.')
    except (OSError, EOFError, UnicodeError, tarfile.TarError) as error:
        raise ReleaseError('Invalid handoff archive.') from error
    return seen
