#!/usr/bin/env python3
"""Prepare workflow update data using only the trusted controller implementation."""
import argparse
import os
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from automation.common import canonical, repository
from automation.control_updates import prepare

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--owner', required=True, type=Path)
parser.add_argument('--output', required=True, type=Path)
args = parser.parse_args()
record = prepare(args.owner.resolve(), ROOT, repository(os.environ['GITHUB_REPOSITORY']))
args.output.write_bytes(canonical({'changed': bool(record), 'record': record}))
if os.environ.get('GITHUB_OUTPUT'):
    with open(os.environ['GITHUB_OUTPUT'], 'a') as stream:
        stream.write('changed='+str(bool(record)).lower()+'\n')
