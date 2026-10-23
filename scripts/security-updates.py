#!/usr/bin/env python3
"""Trusted maintenance entry point; PR inputs are data, never executable review code."""

import argparse
import os
from pathlib import Path
import subprocess
import sys

TOOLS = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(TOOLS))

from automation import cleanup, evidence, proposal, releases, review
from automation.common import MaintenanceError, document, metadata_bundle, now, repository


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=('propose', 'review', 'approve', 'collect-release',
                                           'proposal-state', 'blocked-issue', 'cleanup', 'stage', 'apply-proposal', 'bundle', 'review-event', 'track', 'admission', 'complete-release', 'finalize'))
    parser.add_argument('--owner', type=Path, default=Path('.'))
    parser.add_argument('--repository', default=os.environ.get('GITHUB_REPOSITORY'))
    parser.add_argument('--source', default=os.environ.get('LANRITH_TOOLS_SHA', os.environ.get('GITHUB_SHA')))
    parser.add_argument('--pr', type=int)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--candidate', type=Path)
    parser.add_argument('--body', type=Path)
    parser.add_argument('--version')
    parser.add_argument('--audit-tag')
    parser.add_argument('--apply', action='store_true')
    args = parser.parse_args()
    repo = repository(args.repository)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    if args.command == 'propose':
        try:
            record = proposal.propose(args.owner.resolve(), TOOLS, repo, args.source)
            evidence.write(args.output, {'schema': 1, 'kind': 'proposal-result', 'created_at': now(),
                'state': 'proposed' if record else 'current', 'candidate': record})
            if os.environ.get('GITHUB_OUTPUT'):
                with open(os.environ['GITHUB_OUTPUT'], 'a') as stream:
                    stream.write('changed='+('true' if record else 'false')+'\n')
        except (MaintenanceError, ValueError, KeyError, OSError, subprocess.SubprocessError) as error:
            evidence.write(args.output, {'schema': 1, 'kind': 'proposal-result', 'created_at': now(),
                'state': 'blocked', 'error': str(error)[-2000:],
                'run_url': 'https://github.com/'+repo+'/actions/runs/'+os.environ.get('GITHUB_RUN_ID', 'local')})
            raise
    elif args.command in ('review', 'review-event'):
        number = args.pr
        if args.command == 'review-event' and not number:
            number = review.event_target(repo, document(Path(os.environ['GITHUB_EVENT_PATH']).read_bytes()))
        if not number:
            evidence.write(args.output, {'schema': 1, 'kind': 'no-review-target', 'created_at': now()})
            return
        record, policy = review.inspect(repo, number, args.source, args.output)
        if os.environ.get('GITHUB_OUTPUT'):
            with open(os.environ['GITHUB_OUTPUT'], 'a') as stream:
                stream.write('pr='+str(number)+'\neligible='+str(record['eligible']).lower()+'\nmode='+policy['mode']+'\n')
    elif args.command == 'approve':
        try:
            review.approve(repo, args.pr, args.output, args.source, os.environ.get('LANRITH_SECURITY_APPROVALS_ENABLED', 'false'))
        except (MaintenanceError, ValueError, KeyError, OSError, subprocess.SubprocessError) as error:
            recheck = args.output.with_name('approval-recheck.json')
            record = evidence.read(recheck if recheck.exists() else args.output)
            record['eligible'] = False
            record['findings'].append('Approval blocked: '+str(error)[-2000:])
            evidence.write(args.output, record)
            raise
    elif args.command == 'admission':
        review.admission(repo, args.pr, args.output, args.source, int(os.environ['LANRITH_REVIEW_APP_ID']))
    elif args.command == 'finalize':
        review.finalize(repo, args.pr, args.output, args.source,
                        os.environ.get('LANRITH_SECURITY_APPROVALS_ENABLED', 'false'), args.audit_tag)
    elif args.command == 'collect-release':
        releases.collect(repo, args.source, args.output, args.version)
    elif args.command == 'proposal-state':
        changed = releases.proposal_state(repo, args.candidate, args.body)
        evidence.write(args.output, {'publish': changed})
        if os.environ.get('GITHUB_OUTPUT'):
            with open(os.environ['GITHUB_OUTPUT'], 'a') as stream:
                record = evidence.read(args.candidate)
                stream.write('publish='+str(changed).lower()+'\nrequires-human='+str(record['requires_human']).lower()+'\n')
    elif args.command == 'blocked-issue':
        releases.blocked_issue(repo, args.output)
    elif args.command == 'cleanup':
        record = cleanup.plan(repo)
        evidence.write(args.output, record)
        print(str(len(record['artifacts']))+' completed artifacts; '+str(record['bytes'])+' bytes.')
        if args.apply:
            cleanup.execute(record)
    elif args.command == 'stage':
        releases.stage(args.owner, args.output)
    elif args.command == 'apply-proposal':
        releases.apply_proposal(args.owner, args.candidate)
        evidence.write(args.output, {'state': 'applied'})
    elif args.command == 'bundle':
        releases.bundle(args.candidate, args.output, args.owner if args.owner != Path('.') else None)
    elif args.command == 'track':
        releases.track(repo, args.candidate, args.pr)
    elif args.command == 'complete-release':
        evidence.write(args.output, releases.complete(repo, args.source, args.candidate, args.audit_tag))


if __name__ == '__main__':
    try:
        main()
    finally:
        if os.environ.get('LANRITH_EVIDENCE_DIR'):
            # CLI output paths are controlled by the trusted workflow, never PR data.
            parser = argparse.ArgumentParser(add_help=False)
            parser.add_argument('--output', type=Path)
            options, _ = parser.parse_known_args()
            if options.output:
                metadata_bundle(options.output.parent)
