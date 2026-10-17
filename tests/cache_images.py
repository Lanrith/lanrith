#!/usr/bin/env python3
"""Check inline image caching across two fresh hosted VMs with synthetic files."""

import argparse
import hashlib
from pathlib import Path
import re
import subprocess
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from lanrith.build_cache import validate_images

TAG = 'lanrith-cache-probe:'+hashlib.sha256(b'Lanrith inline cache fixture v1').hexdigest()
CONTENTS = b'synthetic public cache probe\n'


def run(*argv, **kwargs):
    return subprocess.run(argv, check=True, capture_output=True, **kwargs)


def build(root, tag):
    return run('docker', 'build', '--network', 'none', '--progress', 'plain',
        '--build-arg', 'BUILDKIT_INLINE_CACHE=1', '--cache-from', TAG, '--tag', tag, str(root))


def contents(tag, destination):
    container = run('docker', 'create', tag, '/never-executed').stdout.decode().strip()
    try:
        run('docker', 'cp', container+':/probe', str(destination))
        return destination.read_bytes()
    finally:
        run('docker', 'rm', container)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode', choices=('produce', 'consume'))
    parser.add_argument('--work', type=Path, required=True)
    parser.add_argument('--image', type=Path, required=True)
    args = parser.parse_args()
    args.work.mkdir(mode=0o700)
    context = args.work/'context'
    context.mkdir()
    (context/'Dockerfile').write_text('FROM scratch AS source\nCOPY input /probe\n'
        'FROM scratch\nCOPY --from=source /probe /probe\n')
    (context/'input').write_bytes(CONTENTS)
    # Use Docker's conventional filename for the same default driver as the
    # public builds; no BuildKit service or additional image is downloaded.
    if args.mode == 'produce':
        run('docker', 'build', '--network', 'none', '--build-arg', 'BUILDKIT_INLINE_CACHE=1',
            '--tag', TAG, str(context))
        run('docker', 'save', '--output', str(args.image), TAG)
        validate_images(args.image, {'fixture': TAG})
        print('Synthetic inline cache image exported.')
        return
    assert subprocess.run(['docker', 'image', 'inspect', TAG], capture_output=True).returncode != 0, \
        'The consumer must start with an empty image store for the fixture.'
    validate_images(args.image, {'fixture': TAG})
    run('docker', 'load', '--input', str(args.image))
    warm = build(context, TAG)
    log = warm.stderr+warm.stdout
    copies = re.findall(rb'^(#\d+) .*COPY .*/probe.*$', log, re.MULTILINE)
    assert copies and any(step+b' CACHED' in log for step in copies), 'The imported image cache was not used.'
    assert contents(TAG, args.work/'warm') == CONTENTS
    (context/'input').write_bytes(b'changed public cache probe\n')
    changed = TAG+'-changed'
    build(context, changed)
    assert contents(changed, args.work/'changed') == b'changed public cache probe\n', \
        'An input change must not return the old cached filesystem.'
    print('Fresh-VM inline cache hit and changed-input invalidation passed.')


if __name__ == '__main__':
    main()
