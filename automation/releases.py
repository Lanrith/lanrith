"""Collect the review history that accompanies an independently attested release."""

import os
import re
import tarfile
from pathlib import Path

from . import evidence
from .common import api, canonical, contents, digest, document, metadata_bundle, now, pages, repository, require, sha


def stage(owner, destination):
    record = evidence.validate_candidate(evidence.read(owner/evidence.CANDIDATE))
    require(not destination.exists(), 'Proposal staging directory must be new.')
    destination.mkdir(parents=True)
    for name in [*record['changes'], evidence.CANDIDATE]:
        source, target = owner/name, destination/name
        require(source.is_file() and not source.is_symlink() and source.stat().st_size <= 4*1024*1024,
                'A proposed input is not a bounded regular file.')
        raw = source.read_bytes()
        if name != evidence.CANDIDATE:
            require(digest(raw) == record['changes'][name]['after_sha256'], 'Staged proposal changed after resolution.')
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(raw)


def apply_proposal(owner, staged):
    record = evidence.validate_candidate(evidence.read(staged/evidence.CANDIDATE))
    from .common import run
    head = run('git', 'rev-parse', 'HEAD', cwd=owner, capture_output=True, text=True).stdout.strip()
    require(head == record['base_sha'], 'Main changed during proposal generation; resolve again.')
    policy = (owner/'security/update-policy.json').read_bytes()
    require(digest(policy) == record['policy_sha256'] and document(policy)['repository'] == record['repository'], 'Proposal policy or repository changed.')
    files = [p for p in staged.rglob('*') if p.is_file() or p.is_symlink()]
    require({p.relative_to(staged).as_posix() for p in files} == set(record['changes']) | {evidence.CANDIDATE} and
            all(not p.is_symlink() and p.stat().st_size <= 4*1024*1024 for p in files), 'Unexpected staged proposal files.')
    # The publishing credential cannot turn an extra artifact member into a source change.
    from .inputs import validate_changes
    before = {n: (owner/n).read_bytes() for n in record['changes']}
    after = {n: (staged/n).read_bytes() for n in record['changes']}
    for name, change in record['changes'].items():
        require(digest(before[name]) == change['before_sha256'] and digest(after[name]) == change['after_sha256'],
                'Staged input does not match its recorded before/after digests.')
    validate_changes(before, after, record['reasons'], document(policy),
                     lambda n: (owner/n).read_bytes(), lambda n: (staged/n).read_bytes() if n in after else (owner/n).read_bytes())
    for name in [*record['changes'], evidence.CANDIDATE]:
        target = owner/name
        require(not target.is_symlink(), 'Proposal cannot replace a source symlink.')
        target.write_bytes((staged/name).read_bytes())


def bundle(report, destination, proposed=None):
    value = evidence.read(report)
    require(not destination.exists(), 'Audit bundle directory must be new.')
    destination.mkdir(parents=True)
    evidence.write(destination/'update-record.json', value)
    metadata_bundle(destination)
    if proposed and proposed.exists():
        record = evidence.validate_candidate(evidence.read(proposed/evidence.CANDIDATE))
        with tarfile.open(destination/'proposed-inputs.tar.gz', 'w:gz') as archive:
            for name in sorted([*record['changes'], evidence.CANDIDATE]):
                path = proposed/name
                require(path.is_file() and not path.is_symlink(), 'Audit input is not regular source data.')
                archive.add(path, arcname=name, recursive=False)


def collect(repo, source, output, version):
    repository(repo)
    sha(source)
    associated = pages('repos/'+repo+'/commits/'+source+'/pulls?per_page=100')
    pulls = []
    for item in associated:
        if not item.get('merged_at') or item.get('merge_commit_sha') != source:
            continue
        pr = api('repos/'+repo+'/pulls/'+str(item['number']))
        reviews = pages('repos/'+repo+'/pulls/'+str(pr['number'])+'/reviews?per_page=100')
        latest = {r['user']['id']: r for r in sorted(reviews, key=lambda r: r['id'])
                  if r['state'] in ('APPROVED', 'CHANGES_REQUESTED', 'DISMISSED')}
        approvals = [r for r in latest.values() if r['state'] == 'APPROVED' and r['commit_id'] == pr['head']['sha']]
        require(approvals, 'A merged release change lacks a commit-bound approval.')
        policy_raw = contents(repo, 'security/update-policy.json', source)
        policy = document(policy_raw)
        latest_runs = []
        for path in policy['required_workflows']:
            result = api('repos/'+repo+'/actions/workflows/'+path.rsplit('/', 1)[-1]+'/runs?event=pull_request&head_sha='+pr['head']['sha']+'&per_page=100')
            candidates = [r for r in result['workflow_runs'] if r['head_sha'] == pr['head']['sha'] and r['event'] == 'pull_request']
            require(candidates, 'Release change has no successful required validation: '+path)
            run = max(candidates, key=lambda r: r['id'])
            require(run['status'] == 'completed' and run['conclusion'] == 'success', 'Latest required validation did not pass: '+path)
            latest_runs.append({'workflow': path, 'id': run['id'], 'attempt': run['run_attempt'],
                'url': run['html_url'], 'head_sha': run['head_sha'], 'conclusion': run['conclusion']})
        candidate = None
        if pr['head']['ref'] == policy['proposal_branch']:
            candidate = evidence.validate_candidate(document(contents(repo, evidence.CANDIDATE, pr['head']['sha'])))
        pulls.append({'number': pr['number'], 'url': pr['html_url'], 'author': pr['user']['login'],
            'head_sha': pr['head']['sha'], 'merge_commit_sha': source, 'merged_at': pr['merged_at'],
            'candidate': candidate, 'validation': latest_runs,
            'approvals': [{'id': r['id'], 'actor': r['user']['login'], 'actor_id': r['user']['id'],
                          'commit_id': r['commit_id'], 'submitted_at': r['submitted_at'], 'url': r['html_url']}
                         for r in approvals]})
    require(pulls, 'Release source is not a reviewed merged pull request; direct-push releases are blocked.')
    record = {'schema': 1, 'kind': 'release-update-record', 'created_at': now(), 'repository': repo,
        'source_commit': source, 'version': version, 'state': 'qualified-awaiting-publication', 'pull_requests': pulls,
        'release_run': {'id': os.environ['GITHUB_RUN_ID'], 'attempt': os.environ['GITHUB_RUN_ATTEMPT'],
            'url': 'https://github.com/'+repo+'/actions/runs/'+os.environ['GITHUB_RUN_ID']}}
    evidence.write(output, record)
    return record


def proposal_state(repo, candidate_path, body_path):
    record = evidence.validate_candidate(evidence.read(candidate_path))
    policy = document(contents(repo, 'security/update-policy.json', record['base_sha']))
    pulls = pages('repos/'+repo+'/pulls?state=open&head='+repo.split('/')[0]+':'+policy['proposal_branch']+'&per_page=100')
    if pulls:
        require(len(pulls) == 1 and pulls[0]['user']['login'] == policy['proposer_login'], 'Proposal branch is owned by an unexpected PR.')
        current = document(contents(repo, evidence.CANDIDATE, pulls[0]['head']['sha']))
        if current.get('candidate_id') == record['candidate_id']:
            return False
    lines = ['Security remediation `'+record['remediation_id']+'`.', '',
        'Candidate: `'+record['candidate_id']+'`', 'Base: `'+record['base_sha']+'`',
        'Policy: `'+record['policy_sha256']+'`', '', 'Reasons:', '']
    for r in record['reasons']:
        lines.append('- '+r['id']+': '+r['package']+' '+r['installed']+' → '+r['fixed']+' ('+r['source']+').')
    lines += ['', 'Approval: **'+('independent human review required' if record['requires_human'] else 'eligible for independent App review after qualification')+'**.']
    lines += ['', 'This proposal needs full qualification and independent approval. The candidate record binds the reasons to every changed file digest.']
    body_path.write_text('\n'.join(lines)+'\n')
    return True


def blocked_issue(repo, report):
    value = evidence.read(report)
    title = 'Security update automation needs attention'
    existing = pages('repos/'+repo+'/issues?state=open&creator=github-actions%5Bbot%5D&per_page=100')
    matches = [i for i in existing if i['title'] == title and 'pull_request' not in i]
    body = ('The trusted security proposal resolver could not complete.\n\n'
        'State: **blocked**. This is not a successful security assessment.\n\n'
        'Reason: '+value.get('error', 'The proposal could not be published; inspect its durable evidence and workflow log.')+'\n\nRun: '+
        value.get('run_url', 'https://github.com/'+repo+'/actions/runs/'+os.environ['GITHUB_RUN_ID'])+'\n\n'
        'Resolve the recorded source, compatibility or infrastructure problem. Do not bypass the security gate.')
    if not matches:
        api('repos/'+repo+'/issues', method='POST', payload={'title': title, 'body': body})
    else:
        api('repos/'+repo+'/issues/'+str(matches[0]['number']), method='PATCH', payload={'body': body})


def track(repo, candidate_path, pr=None):
    record = evidence.validate_candidate(evidence.read(candidate_path))
    title = '['+record['remediation_id']+'] Apply verified security fixes'
    existing = pages('repos/'+repo+'/issues?state=all&per_page=100')
    matches = [i for i in existing if i['title'] == title and 'pull_request' not in i]
    lines = ['Security remediation `'+record['remediation_id']+'`.', '', 'State: **proposed; not yet released**.', '',
             'Candidate: `'+record['candidate_id']+'`', 'Base: `'+record['base_sha']+'`', '', 'Reasons:', '']
    lines += ['- '+r['id']+': '+r['package']+' '+r['installed']+' → '+r['fixed']+' ('+r['source']+').' for r in record['reasons']]
    lines += ['', 'Validation and approval must cover the exact candidate before merge. Completion requires verified publication.',
              'Audit run: https://github.com/'+repo+'/actions/runs/'+os.environ['GITHUB_RUN_ID']]
    if pr:
        require(type(pr) is int and pr > 0, 'Invalid tracked PR identity.')
        lines += ['Pull request: https://github.com/'+repo+'/pull/'+str(pr)]
    value = {'title': title, 'body': '\n'.join(lines)+'\n', 'state': 'open'}
    if matches:
        api('repos/'+repo+'/issues/'+str(matches[0]['number']), method='PATCH', payload=value)
    else:
        api('repos/'+repo+'/issues', method='POST', payload={k: v for k, v in value.items() if k != 'state'})


def complete(repo, source, verification, audit_tag=None):
    """Close only the exact remediation after its publication audit is durable."""
    import tempfile
    from .common import run
    repository(repo)
    sha(source)
    value = evidence.read(verification)
    require(value['repository'] == repo and value['source_commit'] == source and value['result'] == 'pass' and
            value['immutable'] is True and value['run_id'] == os.environ['GITHUB_RUN_ID'] and
            str(value['run_attempt']).isdigit() and 1 <= int(value['run_attempt']) <= int(os.environ['GITHUB_RUN_ATTEMPT']), 'Publication verification belongs to another subject.')
    audit_tag = audit_tag or 'audit-publication-'+value['run_id']+'-'+value['run_attempt']
    require(re.fullmatch('audit-publication-'+re.escape(value['run_id'])+r'-[1-9][0-9]*', audit_tag),
            'Publication archive belongs to another run.')
    audit = api('repos/'+repo+'/releases/tags/'+audit_tag)
    require(audit.get('immutable') is True and not audit['draft'] and any(
        a['name'] == 'publication-verification.json' and a['digest'] == 'sha256:'+digest(verification.read_bytes())
        for a in audit['assets']), 'Publication verification has not been archived immutably.')
    release = api('repos/'+repo+'/releases/tags/'+value['tag'])
    require(release['id'] == value['release_id'] and release.get('immutable') is True and
            not release['draft'] and not release['prerelease'] and
            {a['name']: a['digest'] for a in release['assets']} == value['assets'], 'Published release changed after verification.')
    with tempfile.TemporaryDirectory(prefix='lanrith-completion.') as temporary:
        run('gh', 'release', 'download', value['tag'], '--repo', repo, '--dir', temporary,
            '--pattern', 'update-record.json', capture_output=True)
        raw = (Path(temporary)/'update-record.json').read_bytes()
        require(digest(raw) == value['update_record_sha256'], 'Release audit record differs from verified publication.')
        record = document(raw)
    require(record['repository'] == repo and record['source_commit'] == source, 'Release audit subject differs.')
    issues = pages('repos/'+repo+'/issues?state=open&creator=github-actions%5Bbot%5D&per_page=100')
    closed = []
    for pull in record['pull_requests']:
        candidate = pull.get('candidate')
        if not candidate:
            continue
        evidence.validate_candidate(candidate)
        title = '['+candidate['remediation_id']+'] Apply verified security fixes'
        for issue in issues:
            if issue['title'] != title or 'pull_request' in issue or candidate['candidate_id'] not in (issue.get('body') or ''):
                continue
            body = (issue['body']+'\n\nState: **fixed in verified immutable release**.\n\n'
                    'Release: '+release['html_url']+'\n\nPublication verification: '+audit['html_url']+'\n\n'
                    'Release update record SHA-256: `'+value['update_record_sha256']+'`.\n')
            api('repos/'+repo+'/issues/'+str(issue['number']), method='PATCH',
                payload={'body': body, 'state': 'closed', 'state_reason': 'completed'})
            closed.append(issue['number'])
    return {'schema': 1, 'kind': 'remediation-completion', 'repository': repo, 'closed_issues': closed,
            'release_url': release['html_url'], 'verification_url': audit['html_url']}
