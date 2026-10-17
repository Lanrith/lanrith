#!/usr/bin/env python3
"""Fingerprint installed compiler inputs, independently of snapshot timestamps."""

import hashlib
import os
from pathlib import Path
import stat


def identity(roots):
    digest = hashlib.sha256()
    for root in roots:
        paths = [root, *sorted(root.rglob('*'))] if root.is_dir() and not root.is_symlink() else [root]
        for path in paths:
            if not path.exists() and not path.is_symlink():
                continue
            info = path.lstat()
            digest.update(str(path).encode()+b'\0'+str(stat.S_IMODE(info.st_mode)).encode()+b'\0')
            if path.is_symlink():
                digest.update(b'link\0'+os.readlink(path).encode()+b'\0')
                # A symlink may select a loader or compiler configuration file
                # outside /usr. Bind its bytes as well as its target name.
                if path.is_file():
                    with path.open('rb') as stream:
                        digest.update(hashlib.file_digest(stream, 'sha256').digest())
            elif stat.S_ISREG(info.st_mode):
                with path.open('rb') as stream:
                    digest.update(hashlib.file_digest(stream, 'sha256').digest())
            elif not stat.S_ISDIR(info.st_mode):
                raise ValueError('Compiler image contains an unsupported special file.')
            digest.update(b'\0')
    return digest.hexdigest()


if __name__ == '__main__':
    # CGO's cache does not track replaced system C libraries. Include the actual
    # Go/C/Node tools, headers, libraries, symlink selections and loader config.
    # An archive timestamp change alone does not alter any of these bytes.
    print(identity([Path(name) for name in ('/usr', '/bin', '/sbin', '/lib', '/lib64',
        '/etc/alternatives', '/etc/ld.so.cache', '/etc/ld.so.conf', '/etc/ld.so.conf.d')]))
