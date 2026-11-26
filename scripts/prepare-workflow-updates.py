#!/usr/bin/env python3
"""Prepare workflow update data using only the trusted controller implementation."""
import argparse
import os
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from automation.common import canonical, repository
from automation.control_updates import prepare, proposal_paths

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--owner', required=True, type=Path)
parser.add_argument('--output', required=True, type=Path)
args = parser.parse_args()
owner = args.owner.resolve()
repo = repository(os.environ['GITHUB_REPOSITORY'])
record = prepare(owner, ROOT, repo)
paths = proposal_paths(owner, repo) if record else []
args.output.write_bytes(canonical({'changed': bool(record), 'record': record, 'paths': paths}))
if os.environ.get('GITHUB_OUTPUT'):
    with open(os.environ['GITHUB_OUTPUT'], 'a') as stream:
        stream.write('changed='+str(bool(record)).lower()+'\n')
        if paths:
            stream.write('paths<<LANRITH_PROPOSAL_PATHS\n'+'\n'.join(paths)+'\nLANRITH_PROPOSAL_PATHS\n')
