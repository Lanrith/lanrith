#!/usr/bin/env python3
"""Plan or execute a bounded, archived recovery of an undersized hosted runner."""
import argparse
import os
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from automation import capacity, evidence
from automation.common import document


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=('plan', 'execute'))
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--plan', type=Path)
    parser.add_argument('--audit-tag')
    args = parser.parse_args()
    source = os.environ['LANRITH_TOOLS_SHA']
    if args.command == 'plan':
        event = document(Path(os.environ['GITHUB_EVENT_PATH']).read_bytes())
        record = capacity.inspect(os.environ['GITHUB_REPOSITORY'], event, source)
        evidence.write(args.output, record)
        with open(os.environ['GITHUB_OUTPUT'], 'a') as stream:
            stream.write('eligible='+str(record['eligible']).lower()+'\narchive='+str(record['archive']).lower()+'\n')
        print(record['state']+': '+record.get('reason', 'No retry.'))
    else:
        if not args.plan or not args.audit_tag:
            parser.error('execute requires --plan and --audit-tag')
        capacity.execute(evidence.read(args.plan), source, args.audit_tag,
            progress=lambda record: evidence.write(args.output, record))


if __name__ == '__main__':
    main()
