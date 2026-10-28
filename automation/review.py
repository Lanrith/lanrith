"""Independent review of source bytes and GitHub-controlled validation results."""

import datetime
import json
from pathlib import Path
import subprocess

from . import evidence, inputs
from .common import (MaintenanceError, api, canonical, contents, digest, document, fetch_json,
                     now, pages, repository, require, sha, timestamp)


class ValidationPending(MaintenanceError):
    """Required runs are unfinished; none of these observations grants approval."""

    def __init__(self, workflows, completed):
        self.workflows = workflows
        self.completed = completed
        super().__init__('Waiting for required validation: '+', '.join(w['workflow'] for w in workflows))


def policy_document(raw, repo):
    policy = document(raw)
    require(set(policy) - {'automatic_minor_security_updates'} == {'schema', 'repository', 'mode', 'proposal_branch', 'proposer_login',
        'proposer_app_id', 'proposer_user_id', 'reviewer_app_id', 'required_workflows', 'maximum_validation_age_hours', 'go_branches',
        'node_branches', 'npm_packages', 'component_repositories', 'maximum_changes',
        'large_artifact_retention_days', 'paid_ai'}, 'Maintenance policy schema differs.')
    require(type(policy.get('automatic_minor_security_updates', False)) is bool,
            'Minor security update policy must be an explicit boolean.')
    require(policy['schema'] == 1 and policy['repository'] == repo and policy['mode'] in ('report-only', 'enforce') and
            policy['paid_ai'] is False and 0 < policy['maximum_validation_age_hours'] <= 24 and
            0 < policy['maximum_changes'] <= 30 and policy['required_workflows'], 'Invalid maintenance policy.')
    require(policy['mode'] != 'enforce' or type(policy['reviewer_app_id']) is int and
            policy['reviewer_app_id'] > 0 and policy['reviewer_app_id'] != policy['proposer_app_id'],
            'Enforcement needs the independent reviewer App identity.')
    return policy


def manual_validation_policy(repo, number, policy, *, files=None):
    """Use the same build-path requirements for admission and review readiness."""
    result = dict(policy)
    if repo == 'Lanrith/lanrith':
        files = pages('repos/'+repo+'/pulls/'+str(number)+'/files?per_page=100') if files is None else files
        build_paths = ('builders/', 'scripts/', 'security/', 'mkosi/', 'lanrith/', 'tests/',
                       'automation/', 'schemas/', '.github/workflows/')
        needs_image = any(f['filename'].startswith(build_paths) or f['filename'] in
                          ('build-inputs.json', 'VERSION', '.go-version') for f in files)
        if not needs_image:
            result['required_workflows'] = {p: j for p, j in policy['required_workflows'].items() if p.endswith('/check.yml')}
    return result


def validation_runs(repo, pr, policy, *, get=api, clock=None, manual=False):
    clock = clock or datetime.datetime.now(datetime.timezone.utc)
    results, pending = [], []
    for path, required_jobs in policy['required_workflows'].items():
        filename = path.rsplit('/', 1)[-1]
        value = get('repos/'+repo+'/actions/workflows/'+filename+'/runs?event=pull_request&head_sha='+pr['head']['sha']+'&per_page=100')
        runs = [r for r in value['workflow_runs'] if r['head_sha'] == pr['head']['sha'] and r['event'] == 'pull_request' and
                r['path'] == path and r.get('head_repository', {}).get('full_name') ==
                (pr['head']['repo']['full_name'] if manual else repo)]
        if not value['workflow_runs']:
            pending.append({'workflow': path, 'status': 'not_started',
                            'url': 'https://github.com/'+repo+'/actions/workflows/'+filename})
            continue
        require(runs, 'Required validation has no run for this source and repository: '+path)
        run = max(runs, key=lambda r: r['id'])
        require(datetime.timedelta(0) <= clock-timestamp(run['updated_at']) <=
                datetime.timedelta(hours=policy['maximum_validation_age_hours']), 'Validation is stale or future-dated: '+path)
        # GitHub's PR association must identify this PR and the tested head/base pair.
        associations = run.get('pull_requests', [])
        require(any(p['number'] == pr['number'] and p.get('head', {}).get('sha') == pr['head']['sha'] and
                    p.get('base', {}).get('sha') == pr['base']['sha'] for p in associations),
                'Validation belongs to another PR or base commit: '+path)
        if run['status'] in ('queued', 'in_progress', 'requested', 'waiting', 'pending'):
            require(run['conclusion'] is None, 'Unfinished validation has a terminal conclusion: '+path)
            pending.append({'workflow': path, 'status': run['status'], 'run_id': run['id'],
                            'run_attempt': run['run_attempt'], 'url': run['html_url']})
            continue
        require(run['status'] == 'completed' and run['conclusion'] == 'success',
                'Required validation did not succeed: '+path+' ('+str(run['conclusion'])+')')
        response = get('repos/'+repo+'/actions/runs/'+str(run['id'])+'/jobs?filter=latest&per_page=100')
        require(response['total_count'] <= 100, 'Validation job enumeration is incomplete.')
        jobs = response['jobs']
        for name in required_jobs:
            matching = [job for job in jobs if job['name'] == name]
            require(len(matching) == 1 and matching[0]['status'] == 'completed' and matching[0]['conclusion'] == 'success',
                    'A mandatory validation job did not pass: '+name)
        results.append({'workflow': path, 'run_id': run['id'], 'run_attempt': run['run_attempt'],
            'head_sha': run['head_sha'], 'base_sha': pr['base']['sha'], 'url': run['html_url'],
            'completed_at': run['updated_at'], 'conclusion': 'success',
            'jobs': [{'id': job['id'], 'name': job['name'], 'conclusion': job['conclusion']}
                     for job in jobs if job['name'] in required_jobs]})
    # Check every workflow so a running prerequisite never hides a finished failure.
    if pending:
        raise ValidationPending(pending, results)
    return results


def validate_reasons(reasons):
    tracker = None
    for record in reasons:
        if record['type'] == 'security-fix':
            inputs.validate_reason(record)
        elif record['type'] == 'node-security-release':
            require(record['package'] == 'node' and record['ecosystem'] == 'Node.js' and
                    record['source'] == 'https://nodejs.org/dist/index.json', 'Unapproved Node advisory source.')
            rows = fetch_json(record['source'])
            selected = next((r for r in rows if r['version'] == 'v'+record['fixed']), None)
            require(selected and selected.get('security') is True and selected.get('lts') and
                    digest(canonical(selected)) == record['evidence_sha256'], 'Node security-release metadata changed.')
        elif record['type'] == 'debian-security-fix':
            from .common import fetch
            require(record['ecosystem'] == 'Debian' and record['source'] ==
                    'https://security-tracker.debian.org/tracker/data/json', 'Unapproved Debian advisory source.')
            # The relevant record's digest is stable when unrelated tracker entries change.
            if tracker is None:
                tracker = json.loads(fetch(record['source'], maximum=128*1024*1024))
            current = tracker.get(record['package'], {}).get(record['id'])
            require(current and digest(canonical(current)) == record['evidence_sha256'] and
                    current['releases']['trixie'].get('fixed_version') == record['fixed'],
                    'Debian advisory or its fixed version changed.')
        elif record['type'] == 'qualified-component-update':
            from .proposal import component_selection
            repo = 'Lanrith/'+record['package']
            selected = component_selection(repo, record['fixed'])
            require(record['source'] == 'https://github.com/'+repo+'/releases/tag/'+record['fixed'] and
                    record['id'] == repo+'@'+record['fixed'] and
                    digest(canonical(selected)) == record['evidence_sha256'], 'Component reason does not match qualified provenance.')
        else:
            require(False, 'Unknown update reason; human review is required.')


def inspect(repo, number, reviewer_source, output):
    repository(repo)
    sha(reviewer_source)
    require(type(number) is int and number > 0, 'Invalid pull request number.')
    pr = api('repos/'+repo+'/pulls/'+str(number))
    base, head = sha(pr['base']['sha']), sha(pr['head']['sha'])
    policy_raw = contents(repo, 'security/update-policy.json', base)
    policy = policy_document(policy_raw, repo)
    record, checks, findings, inspected, pending = {}, [], [], [], []
    try:
        require(pr['state'] == 'open' and not pr['draft'] and pr['base']['ref'] == 'main' and
                pr['head']['ref'] == policy['proposal_branch'] and pr['head']['repo']['full_name'] == repo,
                'PR is outside the automatic security-update lane.')
        require(pr['user']['login'] == policy['proposer_login'] and pr['user']['type'] == 'Bot' and
                pr['user']['id'] == policy['proposer_user_id'],
                'PR author is not the installed updater identity.')
        require(api('repos/'+repo+'/commits/main')['sha'] == base, 'The base branch advanced; update and requalify this candidate.')
        comparison = api('repos/'+repo+'/compare/'+base+'...'+head)
        require(comparison['merge_base_commit']['sha'] == base, 'Candidate is not based on current main.')
        files = pages('repos/'+repo+'/pulls/'+str(number)+'/files?per_page=100')
        require(len(files) <= policy['maximum_changes']+1 and
                all(f['status'] == 'modified' or f['filename'] == evidence.CANDIDATE and f['status'] == 'added' for f in files),
                'Automatic source additions, deletions or renames are forbidden.')
        record = evidence.validate_candidate(document(contents(repo, evidence.CANDIDATE, head)))
        require(record['repository'] == repo and record['base_sha'] == base and
                record['policy_sha256'] == digest(policy_raw) and record['producer_sha'] == reviewer_source,
                'Candidate does not bind this base, policy and trusted producer implementation.')
        require({f['filename'] for f in files} == set(record['changes']) | {evidence.CANDIDATE},
                'PR files differ from the recorded change set.')
        old_cache, new_cache = {}, {}
        def old(path):
            if path not in old_cache:
                old_cache[path] = contents(repo, path, base)
            return old_cache[path]
        def new(path):
            if path not in new_cache:
                new_cache[path] = contents(repo, path, head)
            return new_cache[path]
        before, after = {}, {}
        for path, change in record['changes'].items():
            before[path], after[path] = old(path), new(path)
            require(digest(before[path]) == change['before_sha256'] and digest(after[path]) == change['after_sha256'],
                    'PR source bytes differ from the recorded update: '+path)
        validate_reasons(record['reasons'])
        manual_findings = inputs.validate_changes(before, after, record['reasons'], policy, old, new)
        inspected = [{'path': path, **record['changes'][path], 'result': 'pass',
                      'method': 'Authenticated advisory, permitted semantic change and upstream input validation'}
                     for path in sorted(record['changes'])]
        require(record['requires_human'] is bool(manual_findings),
                'Candidate misclassified a dependency update as an automatic change.')
        findings.extend(manual_findings)
        checks = validation_runs(repo, pr, policy)
    except ValidationPending as waiting:
        pending, checks = waiting.workflows, waiting.completed
    except (MaintenanceError, KeyError, TypeError, ValueError, OSError, subprocess.SubprocessError) as error:
        findings.append(str(error))
    decision = evidence.decision(record, head=head, base=base, policy=policy_raw, checks=checks,
        eligible=not findings and not pending, findings=findings, reviewer_source=reviewer_source)
    decision['validation_pending'] = pending
    decision['input_validation'] = inspected
    decision['repository'] = repo
    decision['pull_request'] = {'number': number, 'url': pr['html_url'], 'author': pr['user']['login']}
    evidence.write(output, decision)
    print('Security update '+('eligible' if decision['eligible'] else 'blocked')+': '+str(number))
    for finding in findings:
        print(finding)
    for workflow in pending:
        print('Waiting for '+workflow['workflow']+': '+workflow['status'])
    return decision, policy


def approval_authority(repo, number, head, base, approval):
    """A successful review submission alone does not satisfy required reviews."""
    repository(repo)
    owner, name = repo.split('/')
    response = api('graphql', method='POST', payload={
        'query': '''query($owner:String!,$name:String!,$number:Int!){
          repository(owner:$owner,name:$name){nameWithOwner pullRequest(number:$number){
            number headRefOid baseRefOid reviews(last:100){nodes{
              databaseId state authorCanPushToRepository
              author{__typename login} commit{oid}
            }}
          }}
        }''', 'variables': {'owner': owner, 'name': name, 'number': number}})
    require(isinstance(response, dict) and not response.get('errors'),
            'GitHub could not establish the approving review authority.')
    observed = (response.get('data') or {}).get('repository') or {}
    pull = observed.get('pullRequest') or {}
    require(observed.get('nameWithOwner') == repo and pull.get('number') == number and
            pull.get('headRefOid') == head and pull.get('baseRefOid') == base,
            'Approval authority belongs to another repository, PR or source.')
    matches = [r for r in (pull.get('reviews') or {}).get('nodes', [])
               if r and r.get('databaseId') == approval['review_id']]
    require(len(matches) == 1, 'The exact approving review authority is missing or ambiguous.')
    actual = matches[0]
    actor = actual.get('author') or {}
    require(actual.get('state') == 'APPROVED' and
            (actual.get('commit') or {}).get('oid') == approval['commit_id'] == head and
            actor.get('__typename') == 'Bot' and
            actor.get('login') == approval['reviewer_login'].removesuffix('[bot]'),
            'Approval authority differs from the independent commit-bound App review.')
    require(actual.get('authorCanPushToRepository') is True,
            'The approving App lacks repository write access required by GitHub review protection.')
    return True


def approve(repo, number, decision_path, reviewer_source, enabled):
    """Re-evaluate at the credential boundary; never approve a downloaded decision blindly."""
    previous = evidence.read(decision_path)
    fresh_path = decision_path.with_name('approval-recheck.json')
    fresh, policy = inspect(repo, number, reviewer_source, fresh_path)
    require(fresh['eligible'] and previous['eligible'] and
            fresh['candidate_id'] == previous['candidate_id'] and fresh['head_sha'] == previous['head_sha'] and
            fresh['base_sha'] == previous['base_sha'] and fresh['policy_sha256'] == previous['policy_sha256'] and
            fresh['validation'] == previous['validation'], 'Approval inputs changed after independent inspection.')
    require(policy['mode'] == 'enforce' and enabled == 'true', 'Approval is disabled during the report-only pilot.')
    # A second App is required: its identity must differ from the author installation.
    claimed = previous.get('admission_check', {})
    require(type(claimed.get('id')) is int and claimed.get('app_id') == policy['reviewer_app_id'],
            'Approval needs the independently published qualification check.')
    check = api('repos/'+repo+'/check-runs/'+str(claimed['id']))
    require(check['name'] == 'Security update admission' and check['head_sha'] == fresh['head_sha'] and
            check['app']['id'] == policy['reviewer_app_id'] and check['app']['id'] != policy['proposer_app_id'],
            'Approval did not use the reviewed independent App identity.')
    # Recheck the PR immediately before a commit-bound review. Branch protection also rejects stale reviews.
    current = api('repos/'+repo+'/pulls/'+str(number))
    require(current['head']['sha'] == fresh['head_sha'] and current['base']['sha'] == fresh['base_sha'],
            'PR changed before approval.')
    review = api('repos/'+repo+'/pulls/'+str(number)+'/reviews', method='POST', payload={
        'commit_id': fresh['head_sha'], 'event': 'APPROVE',
        'body': 'Automated security approval for candidate `'+fresh['candidate_id']+'`.\n\n'
                'Policy: `'+fresh['policy_sha256']+'`. Reviewer implementation: `'+reviewer_source+'`.\n\n'
                'The durable decision record contains the advisory reasons, changed input digests and exact validation runs.'})
    require(review['state'] == 'APPROVED' and review['commit_id'] == fresh['head_sha'], 'GitHub did not accept the commit-bound approval.')
    fresh['approval'] = {'review_id': review['id'], 'reviewer_login': review['user']['login'],
        'reviewer_app_id': check['app']['id'], 'check_run_id': check['id'], 'submitted_at': review['submitted_at'],
        'commit_id': review['commit_id'], 'state': review['state'], 'url': review['html_url']}
    # The separately archived approval must exist before this check can permit merge.
    fresh['admission_check'] = {**claimed, 'conclusion': None, 'manual_review_required': False}
    fresh['approval']['repository_write_access_verified'] = False
    evidence.write(decision_path, fresh)
    try:
        fresh['approval']['repository_write_access_verified'] = approval_authority(
            repo, number, fresh['head_sha'], fresh['base_sha'], fresh['approval'])
    except MaintenanceError as error:
        fresh['eligible'] = False
        fresh['findings'].append(str(error))
        evidence.write(decision_path, fresh)
        raise
    evidence.write(decision_path, fresh)
    return fresh


def finalize(repo, number, decision_path, reviewer_source, enabled, audit_tag):
    """Release the merge gate only after immutable approval evidence is verified."""
    import os
    import re
    previous = evidence.read(decision_path)
    require(isinstance(audit_tag, str) and re.fullmatch(
        'audit-decision-'+re.escape(os.environ['GITHUB_RUN_ID'])+r'-[1-9][0-9]*', audit_tag),
        'Approval archive does not belong to this trusted run.')
    archived = api('repos/'+repo+'/releases/tags/'+audit_tag)
    require(archived.get('immutable') is True and not archived['draft'] and any(
        a['name'] == 'update-record.json' and a['digest'] == 'sha256:'+digest(decision_path.read_bytes())
        for a in archived['assets']), 'Exact approval evidence has not been archived immutably.')
    fresh, policy = inspect(repo, number, reviewer_source, decision_path.with_name('final-recheck.json'))
    require(enabled == 'true' and policy['mode'] == 'enforce' and fresh['eligible'] and previous['eligible'] and
            all(fresh[k] == previous[k] for k in ('candidate_id', 'head_sha', 'base_sha', 'policy_sha256', 'validation')),
            'Approval subject or validation changed before the durable merge gate.')
    approval = previous.get('approval') or {}
    claimed = previous.get('admission_check') or {}
    require(type(claimed.get('id')) is int and type(approval.get('review_id')) is int and
            approval.get('reviewer_app_id') == policy['reviewer_app_id'] and
            claimed.get('app_id') == policy['reviewer_app_id'], 'Approval or check identity is missing.')
    check = api('repos/'+repo+'/check-runs/'+str(claimed['id']))
    require(check['name'] == 'Security update admission' and check['head_sha'] == fresh['head_sha'] and
            check['app']['id'] == policy['reviewer_app_id'] != policy['proposer_app_id'],
            'Final merge gate is not owned by the independent reviewer.')
    reviews = pages('repos/'+repo+'/pulls/'+str(number)+'/reviews?per_page=100')
    actor = check['app']['slug']+'[bot]'
    latest = [r for r in reviews if r['user']['login'] == actor and r['state'] in ('APPROVED', 'CHANGES_REQUESTED', 'DISMISSED')]
    require(latest, 'Independent approval is missing.')
    observed = max(latest, key=lambda r: r['id'])
    require(observed['id'] == approval['review_id'] and observed['state'] == approval.get('state') == 'APPROVED' and
            observed['commit_id'] == approval.get('commit_id') == fresh['head_sha'] and approval.get('reviewer_login') == actor, 'Independent approval was superseded or dismissed.')
    require(approval.get('repository_write_access_verified') is True,
            'Archived approval does not establish the reviewer repository write access.')
    approval_authority(repo, number, fresh['head_sha'], fresh['base_sha'], approval)
    current = api('repos/'+repo+'/pulls/'+str(number))
    require(current['head']['sha'] == fresh['head_sha'] and current['base']['sha'] == fresh['base_sha'],
            'PR changed before the final merge gate.')
    api('repos/'+repo+'/check-runs/'+str(check['id']), method='PATCH', payload={
        'status': 'completed', 'conclusion': 'success', 'completed_at': now(),
        'output': {'title': 'Qualified, independently approved and durably archived',
                   'summary': 'Exact decision and approval evidence: '+archived['html_url']}})
    return previous


def event_target(repo, event):
    if 'workflow_run' in event:
        run = event['workflow_run']
        require(event.get('repository', {}).get('full_name') == repo and run.get('event') == 'pull_request',
                'Review trigger is not a validation for this repository.')
        candidates = pages('repos/'+repo+'/pulls?state=open&per_page=100')
        matches = [p['number'] for p in candidates if p['head']['sha'] == run['head_sha'] and p['base']['repo']['full_name'] == repo]
        require(len(matches) <= 1, 'Review trigger has ambiguous PR association.')
        return matches[0] if matches else None
    return None


def admission(repo, number, decision_path, reviewer_source, app_id, *, notify=False):
    """Publish qualification status for manual PRs without granting them App approval."""
    record, policy = inspect(repo, number, reviewer_source, decision_path)
    pr = api('repos/'+repo+'/pulls/'+str(number))
    qualified_manual = (record.get('candidate', {}).get('requires_human') is True and bool(record['findings']) and
                        set(record['findings']) <= inputs.HUMAN_REVIEW_FINDINGS)
    automatic = pr['head']['ref'] == policy['proposal_branch'] and pr['head']['repo']['full_name'] == repo and not qualified_manual
    error, pending = None, record.get('validation_pending', [])
    if not automatic:
        pending = []
        try:
            manual_policy = manual_validation_policy(repo, number, policy)
            record['validation'] = validation_runs(repo, pr, manual_policy, manual=True)
        except ValidationPending as waiting:
            pending = waiting.workflows
            record['validation'] = waiting.completed
        except (MaintenanceError, KeyError, OSError, ValueError) as failure:
            error = str(failure)
    elif not record['eligible'] and (record['findings'] or not pending):
        error = '; '.join(record['findings'])
        require(error, 'Ineligible decision has no failure or pending validation.')
    record['validation_pending'] = pending
    if notify and (not automatic or policy['mode'] == 'report-only' or error):
        from .notifications import request_review
        record['human_review_request'] = request_review(repo, number, record['head_sha'],
            error or 'The change is outside automatic approval and requires independent human review.')
    require(type(app_id) is int and app_id > 0 and app_id != policy['proposer_app_id'], 'Independent check App identity is invalid.')
    payload = {
        'name': 'Security update admission', 'head_sha': record['head_sha'], 'status': 'in_progress',
        'output': {'title': 'Independent qualification review',
                   'summary': 'Human review remains required for changes outside the automatic security policy.'}}
    if pending and not error:
        payload['details_url'] = pending[0]['url']
        payload['output'] = {'title': 'Waiting for required qualification', 'summary':
            '\n'.join('- ['+w['workflow']+']('+w['url']+'): '+w['status'] for w in pending)+
            '\n\nAdmission reruns when validation completes. Merge and automated approval remain blocked.'}
    response = api('repos/'+repo+'/commits/'+record['head_sha']+
                   '/check-runs?check_name=Security%20update%20admission&filter=latest&per_page=100')
    require(response['total_count'] <= 100, 'Admission check enumeration is incomplete.')
    unfinished = [c for c in response['check_runs'] if c['name'] == payload['name'] and
                  c['head_sha'] == record['head_sha'] and c['app']['id'] == app_id and
                  c['status'] == 'in_progress']
    if unfinished:
        # Complete the existing waiting check rather than leave an orphaned spinner.
        previous = max(unfinished, key=lambda c: c['id'])
        check = api('repos/'+repo+'/check-runs/'+str(previous['id']), method='PATCH',
                    payload={k: v for k, v in payload.items() if k != 'head_sha'})
    else:
        check = api('repos/'+repo+'/check-runs', method='POST', payload=payload)
    require(check['app']['id'] == app_id, 'Check did not come from the configured reviewer App.')
    conclusion = 'failure' if error else 'success'
    # In enforcement mode an automatic candidate needs the separately submitted approval too.
    if not error and (pending or automatic and policy['mode'] == 'enforce'):
        conclusion = None
    if conclusion:
        api('repos/'+repo+'/check-runs/'+str(check['id']), method='PATCH', payload={
            'status': 'completed', 'conclusion': conclusion, 'completed_at': now(),
            'output': {'title': 'Qualification '+conclusion,
                       'summary': error or ('Policy-eligible pilot; human approval required.' if automatic else
                                           'Required qualification passed. An independent human review is required.')}})
    record['admission_check'] = {'id': check['id'], 'app_id': app_id, 'conclusion': conclusion,
                                 'manual_review_required': not automatic or policy['mode'] == 'report-only'}
    evidence.write(decision_path, record)
    return record
