"""Bind an independent scan subject to its exact bytes in a deployed binary."""

import hashlib
import mmap

from .release import require


def verify(container, subject, expected):
    require(subject.is_file() and not subject.is_symlink() and 0 < subject.stat().st_size <= 512*1024*1024,
            'Embedded scan subject is missing or oversized.')
    with subject.open('rb') as stream:
        require(hashlib.file_digest(stream, 'sha256').hexdigest() == expected,
                'Embedded scan subject differs from its fresh assessment.')
        stream.seek(0)
        prefix = stream.read(65536)
    size = subject.stat().st_size
    offsets = []
    with container.open('rb') as stream, mmap.mmap(stream.fileno(), 0, access=mmap.ACCESS_READ) as binary:
        start = 0
        while (offset := binary.find(prefix, start)) >= 0:
            if offset+size <= len(binary):
                with memoryview(binary)[offset:offset+size] as content:
                    if hashlib.sha256(content).hexdigest() == expected:
                        offsets.append(offset)
            start = offset+1
    require(len(offsets) == 1, 'Installed binary does not contain the exact independently scanned payload once.')
    return {'offset': offsets[0], 'size': size, 'sha256': expected}
