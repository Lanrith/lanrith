#!/usr/bin/env python3
"""Preflight and assemble an owner image with existing local signing files."""

import argparse
from pathlib import Path
import subprocess
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from lanrith import build_inputs, local, release


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--boot-inputs', type=Path, help='Private build-time JSON paths for PCR signing and bound recovery')
    parser.add_argument('command', choices=('preflight', 'assemble'))
    parser.add_argument('--owner', type=Path, required=True)
    parser.add_argument('--platform', type=Path, required=True)
    parser.add_argument('--request', type=Path, required=True)
    parser.add_argument('--engine', choices=('podman', 'docker'), default='podman')
    parser.add_argument('--sequence', type=int)
    parser.add_argument('--work', type=Path)
    parser.add_argument('--output', type=Path)
    parser.add_argument('--boot-key', type=Path)
    parser.add_argument('--boot-certificate', type=Path)
    parser.add_argument('--serial-hash', type=Path)
    args = parser.parse_args()
    extra = {'boot_options': build_inputs.load(args.boot_inputs)} if args.boot_inputs else {}
    if args.command == 'preflight':
        release.require(args.sequence is not None, 'Preflight requires a deployment sequence.')
        release.require(not args.request.exists() and not args.request.is_symlink(), 'Request already exists.')
        value = local.admit(args.owner.resolve(), args.platform.resolve(), args.sequence, args.engine, args.serial_hash, **extra)
        with args.request.open('xb') as stream:
            args.request.chmod(0o600)
            stream.write(release.canonical(value))
        print('Local platform, configuration and builder admission passed; exact request written.')
    else:
        release.require(all((args.work, args.output, args.boot_key, args.boot_certificate)),
                        'Assembly requires new work/output paths and existing boot key/certificate files.')
        local.assemble(args.owner.resolve(), args.platform.resolve(), args.request.resolve(),
            args.work.absolute(), args.output.absolute(), key=args.boot_key, certificate=args.boot_certificate,
            serial_hash=args.serial_hash, engine=args.engine, **extra)
        print('Signed update and factory artifacts verified and retained privately.')


if __name__ == '__main__':
    try:
        main()
    except (release.ReleaseError, OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as error:
        print(str(error) if isinstance(error, release.ReleaseError) else 'Local image build failed.', file=sys.stderr)
        sys.exit(1)
