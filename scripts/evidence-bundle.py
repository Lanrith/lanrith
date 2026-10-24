#!/usr/bin/env python3
"""Seal or verify a complete candidate-bound security campaign bundle."""

import argparse
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from lanrith import evidence_bundle
from lanrith.release import ReleaseError


def main(arguments=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='operation', required=True)
    seal = commands.add_parser('seal')
    seal.add_argument('directory', type=Path)
    seal.add_argument('--key', required=True, type=Path)
    verify = commands.add_parser('verify')
    verify.add_argument('directory', type=Path)
    verify.add_argument('--certificate', required=True, type=Path)
    args = parser.parse_args(arguments)
    try:
        root = args.directory.absolute()
        if args.operation == 'seal':
            value = evidence_bundle.seal(root, args.key.absolute())
        else:
            value = evidence_bundle.verify(root, args.certificate.absolute())
        print(value['campaign_id']+': '+str(len(value['files']))+' files')
    except (OSError, ValueError, ReleaseError) as error:
        print('evidence-bundle: '+str(error), file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
