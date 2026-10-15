#!/usr/bin/env python3
"""Reject credentials and generated state from the public source tree."""

from pathlib import Path
import subprocess

root = Path(__file__).resolve().parents[1]
result = subprocess.run(['git', 'ls-files', '-z'], cwd=root, capture_output=True)
paths = [root/name for name in result.stdout.decode().split('\0') if name] if result.returncode == 0 else [
    path for path in root.rglob('*') if path.is_file() and '.git' not in path.parts and '__pycache__' not in path.parts]
errors = []
for path in paths:
    name = path.relative_to(root).as_posix()
    if path.is_symlink() or any(part in ('keys', 'secrets', 'output', '.config') for part in path.parts):
        errors.append(name)
        continue
    data = path.read_bytes()
    # Construct patterns so the checker does not match its own source.
    if any(pattern in data for pattern in (b'-----BEGIN '+b'PRIVATE KEY-----',
                                          b'-----BEGIN RSA '+b'PRIVATE KEY-----',
                                          b'-----BEGIN EC '+b'PRIVATE KEY-----',
                                          b'$ANSIBLE_'+b'VAULT;')):
        errors.append(name)
if errors:
    raise SystemExit('Public source boundary failed in: '+', '.join(sorted(set(errors))))
print('Public source boundary passed for '+str(len(paths))+' files.')
