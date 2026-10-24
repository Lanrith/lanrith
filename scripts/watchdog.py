#!/usr/bin/env python3
"""Track failed maintenance and stale security assessments independently."""

import datetime
import os
import re
from pathlib import Path
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from automation.common import api, digest, document, pages, require, run, timestamp

TITLE = 'Security maintenance requires attention'
OLD_TITLE = 'Security assessment has not succeeded within 48 hours'


def assess(repo, releases, clock):
    stable = [r for r in releases if not r['draft'] and not r['prerelease'] and
              re.fullmatch(r'v[0-9]+\.[0-9]+\.[0-9]+', r['tag_name'])]
    findings = []
    for workflow in ('security-audit.yml', 'update-inputs.yml', 'release.yml'):
        rows = api('repos/'+repo+'/actions/workflows/'+workflow+'/runs?branch=main&per_page=5')['workflow_runs']
        finished = [r for r in rows if r['status'] == 'completed']
        latest = max(finished, key=lambda r: r['id']) if finished else None
        if latest and latest['conclusion'] != 'success':
            findings.append(workflow+': '+str(latest['conclusion'])+' — '+latest['html_url'])
        if workflow == 'security-audit.yml' and stable:
            if not latest or not datetime.timedelta(0) <= clock-timestamp(latest['updated_at']) <= datetime.timedelta(hours=18):
                findings.append('No completed security assessment within 18 hours. Production admission expires at 24 hours.')
    return findings, max(stable, key=lambda r: tuple(map(int, r['tag_name'][1:].split('.')))) if stable else None


def verified_publication(repo, releases, stable):
    """A healthy scan alone cannot claim that remediation has been released."""
    if not stable or stable.get('immutable') is not True:
        return None
    audits = [r for r in releases if r['tag_name'].startswith('audit-publication-') and
              not r['draft'] and r.get('immutable') is True]
    for audit in sorted(audits, key=lambda r: r['id'], reverse=True)[:20]:
        with tempfile.TemporaryDirectory(prefix='lanrith-watchdog.') as temporary:
            root = Path(temporary)
            run('gh', 'release', 'download', audit['tag_name'], '--repo', repo, '--dir', temporary,
                '--pattern', 'publication-verification.json', '--pattern', 'evidence.intoto.jsonl', capture_output=True)
            raw = (root/'publication-verification.json').read_bytes()
            value = document(raw)
            if value.get('repository') != repo or value.get('release_id') != stable['id']:
                continue
            require(value['result'] == 'pass' and value['immutable'] is True and value['tag'] == stable['tag_name'] and
                    value['assets'] == {a['name']: a['digest'] for a in stable['assets']} and any(
                        a['name'] == 'publication-verification.json' and a['digest'] == 'sha256:'+digest(raw)
                        for a in audit['assets']), 'Publication evidence differs from stable release assets.')
            run('gh', 'attestation', 'verify', str(root/'publication-verification.json'),
                '--bundle', str(root/'evidence.intoto.jsonl'), '--repo', repo,
                '--signer-workflow', 'Lanrith/lanrith/.github/workflows/archive-evidence.yml',
                '--source-digest', value['source_commit'], '--source-ref', 'refs/heads/main',
                '--deny-self-hosted-runners', capture_output=True)
            return audit
    return None


def main():
    repo = os.environ['GITHUB_REPOSITORY']
    clock = datetime.datetime.now(datetime.timezone.utc)
    releases = pages('repos/'+repo+'/releases?per_page=100')
    findings, stable = assess(repo, releases, clock)
    issues = [i for i in pages('repos/'+repo+'/issues?state=open&creator=github-actions%5Bbot%5D&per_page=100')
              if i['title'] in (TITLE, OLD_TITLE) and 'pull_request' not in i]
    if findings:
        body = ('State: **blocked; no claim of completed remediation**.\n\n'+
                '\n'.join('- '+f for f in findings)+'\n\nInspect the security-update PR and its attested audit records. '
                'This issue closes only after a healthy assessment and verified immutable publication.\n')
        payload = {'title': TITLE, 'body': body}
        if issues:
            for issue in issues:
                api('repos/'+repo+'/issues/'+str(issue['number']), method='PATCH', payload=payload)
        else:
            api('repos/'+repo+'/issues', method='POST', payload=payload)
        raise SystemExit('Security maintenance requires attention.')
    if issues:
        audit = verified_publication(repo, releases, stable)
        if audit:
            for issue in issues:
                api('repos/'+repo+'/issues/'+str(issue['number']), method='PATCH', payload={
                    'state': 'closed', 'state_reason': 'completed',
                    'body': (issue.get('body') or '')+'\n\nResolved after a healthy assessment and verified immutable release: '+
                            stable['html_url']+'\n\nPublication evidence: '+audit['html_url']+'\n'})
    print('Maintenance workflows and security assessment freshness passed.')


if __name__ == '__main__':
    main()
