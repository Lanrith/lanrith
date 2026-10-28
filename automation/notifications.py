"""Request the owner's review using trusted metadata, without approving any source."""
from . import evidence
from .common import MaintenanceError, api, contents, digest, document, now, pages, repository, require, sha

HUMAN_REVIEWER = 'mikenorgate'
AUTOMATIC_INPUTS = frozenset(('.go-version', '.github/toolchains.json', 'go.mod', 'go.sum',
    'builders/alloy/source.json', 'builders/node-exporter/source.json', 'builders/alloy/ui-dependencies.patch',
    'builders/unbound-source.lock', 'build-inputs.json', 'builders/build-inputs.lock', 'security/policy.json'))
ROUTING_WORKFLOWS = frozenset(('.github/workflows/review-routing.yml', '.github/workflows/check.yml',
                             '.github/workflows/package-check.yml', '.github/workflows/ci.yml'))


def qualification(repo, pr):
    """Only GitHub's fresh, successful builds for this head/base allow a request."""
    from .review import ValidationPending, manual_validation_policy, policy_document, validation_runs
    result = {'base_sha': pr['base']['sha'], 'validation': []}
    try:
        require(pr['base']['repo']['full_name'] == repo and pr['base']['ref'] == 'main' and
                api('repos/'+repo+'/commits/main')['sha'] == pr['base']['sha'],
                'The protected base changed; update and requalify before human review.')
        raw = contents(repo, 'security/update-policy.json', pr['base']['sha'])
        policy = policy_document(raw, repo)
        files = pages('repos/'+repo+'/pulls/'+str(pr['number'])+'/files?per_page=100')
        policy = manual_validation_policy(repo, pr['number'], policy, files=files)
        result['policy_sha256'] = digest(raw)
        result['validation'] = validation_runs(repo, pr, policy, get=api, manual=True)
    except ValidationPending as waiting:
        return result | {'state': 'deferred-ci-pending', 'validation_pending': waiting.workflows,
                         'validation': waiting.completed}
    except (MaintenanceError, KeyError, TypeError, ValueError, OSError) as error:
        return result | {'state': 'deferred-ci-unqualified', 'error': str(error)[:1000]}
    return result | {'state': 'qualified'}


def same_subject(pr, head, base):
    return (pr['head']['sha'] == head and pr['base']['sha'] == base and pr['base']['ref'] == 'main' and
            pr['state'] == 'open' and not pr['draft'])


def defer_request(endpoint, record, readiness):
    """Withdraw an outstanding request when a new head or rerun is not ready."""
    pending = api(endpoint+'/requested_reviewers')
    if any(r['login'] == HUMAN_REVIEWER for r in pending['users']):
        require(same_subject(api(endpoint), record['head_sha'], readiness['base_sha']),
                'PR changed before withdrawing the premature review request.')
        api(endpoint+'/requested_reviewers', method='DELETE', payload={'reviewers': [HUMAN_REVIEWER]})
        require(not any(r['login'] == HUMAN_REVIEWER for r in api(endpoint+'/requested_reviewers')['users']),
                'GitHub did not confirm withdrawal of the premature review request.')
        readiness['previous_request'] = ('withdrawn-until-ci-passes' if readiness['state'].startswith('deferred-ci-')
                                         else 'withdrawn-automatic-lane')
    return record | readiness


def request_review(repo, number, head, reason):
    repository(repo)
    sha(head)
    require(type(number) is int and number > 0, 'Invalid human-review PR number.')
    endpoint = 'repos/'+repo+'/pulls/'+str(number)
    pr = api(endpoint)
    require(pr['number'] == number and pr['head']['sha'] == head and pr['base']['ref'] == 'main',
            'Human-review subject changed.')
    record = {'schema': 1, 'kind': 'human-review-request', 'created_at': now(), 'repository': repo,
              'pull_request': number, 'head_sha': head, 'reviewer': HUMAN_REVIEWER, 'reason': reason}
    if pr['state'] != 'open' or pr['draft']:
        return record | {'state': 'deferred-draft-or-closed'}
    readiness = qualification(repo, pr)
    if readiness['state'] != 'qualified':
        return defer_request(endpoint, record, readiness)
    record.update({k: v for k, v in readiness.items() if k != 'state'})
    if pr['user']['login'] == HUMAN_REVIEWER:
        return record | {'state': 'author-needs-independent-reviewer'}
    permission = api('repos/'+repo+'/collaborators/'+HUMAN_REVIEWER+'/permission')
    require(permission['permission'] in ('write', 'maintain', 'admin') and
            permission['user']['login'] == HUMAN_REVIEWER and permission['user']['type'] == 'User',
            'Configured human reviewer lacks current repository write access.')
    reviews = [r for r in pages(endpoint+'/reviews?per_page=100') if r['user']['login'] == HUMAN_REVIEWER and
               r['state'] in ('APPROVED', 'CHANGES_REQUESTED', 'DISMISSED')]
    latest = max(reviews, key=lambda r: r['id']) if reviews else None
    if latest and latest['commit_id'] == head and latest['state'] in ('APPROVED', 'CHANGES_REQUESTED'):
        return record | {'state': 'already-reviewed-current-head', 'review_id': latest['id']}
    pending = api(endpoint+'/requested_reviewers')
    if any(r['login'] == HUMAN_REVIEWER for r in pending['users']):
        return record | {'state': 'already-requested'}
    require(same_subject(api(endpoint), head, pr['base']['sha']), 'PR changed before requesting human review.')
    # Another run attempt may have started while roles/reviews were enumerated.
    readiness = qualification(repo, pr)
    if readiness['state'] != 'qualified':
        return defer_request(endpoint, record, readiness)
    record.update({k: v for k, v in readiness.items() if k != 'state'})
    require(same_subject(api(endpoint), head, pr['base']['sha']), 'PR changed during the final CI readiness check.')
    requested = api(endpoint+'/requested_reviewers', method='POST', payload={'reviewers': [HUMAN_REVIEWER]})
    require(any(r['login'] == HUMAN_REVIEWER for r in requested['requested_reviewers']) and
            same_subject(api(endpoint), head, pr['base']['sha']), 'GitHub did not confirm the exact human-review request.')
    return record | {'state': 'requested', 'reviewer_id': permission['user']['id']}


def assign_attention(repo, number):
    """Assign blocked attention issues once, including failures that cannot form a PR."""
    repository(repo)
    require(type(number) is int and number > 0, 'Invalid attention issue number.')
    endpoint = 'repos/'+repo+'/issues/'+str(number)
    issue = api(endpoint)
    if issue['state'] != 'open':
        return {'state': 'closed', 'issue': number}
    if any(a['login'] == HUMAN_REVIEWER for a in issue.get('assignees', [])):
        return {'state': 'already-assigned', 'issue': number, 'assignee': HUMAN_REVIEWER}
    assigned = api(endpoint+'/assignees', method='POST', payload={'assignees': [HUMAN_REVIEWER]})
    require(any(a['login'] == HUMAN_REVIEWER for a in assigned['assignees']), 'GitHub did not assign the attention issue.')
    return {'state': 'assigned', 'issue': number, 'assignee': HUMAN_REVIEWER}


def route(repo, number, source, enabled):
    """Conservatively route early events; the independent reviewer decides eligibility."""
    repository(repo)
    sha(source)
    pr = api('repos/'+repo+'/pulls/'+str(number))
    reason = 'Source or security-control changes require independent human review.'
    if pr['state'] == 'open' and not pr['draft']:
        try:
            from .review import policy_document
            raw = contents(repo, 'security/update-policy.json', pr['base']['sha'])
            policy = policy_document(raw, repo)
            automatic = (enabled == 'true' and policy['mode'] == 'enforce' and
                pr['head']['ref'] == policy['proposal_branch'] and pr['head']['repo']['full_name'] == repo and
                pr['user']['login'] == policy['proposer_login'] and pr['user']['id'] == policy['proposer_user_id'] and
                pr['user']['type'] == 'Bot')
            if automatic:
                candidate = evidence.validate_candidate(document(contents(repo, evidence.CANDIDATE, pr['head']['sha'])))
                require(candidate['repository'] == repo and candidate['base_sha'] == pr['base']['sha'] and
                        candidate['producer_sha'] == source and candidate['policy_sha256'] == digest(raw),
                        'Review-routing candidate does not bind the trusted producer, base and policy.')
                if candidate['requires_human'] is False:
                    require(set(candidate['changes']) <= AUTOMATIC_INPUTS,
                            'Review-routing candidate contains source outside automatic input paths.')
                    files = pages('repos/'+repo+'/pulls/'+str(number)+'/files?per_page=100')
                    require({f['filename'] for f in files} == set(candidate['changes']) | {evidence.CANDIDATE} and
                            all(f['status'] == 'modified' or f['filename'] == evidence.CANDIDATE and f['status'] == 'added' for f in files),
                            'Review-routing candidate differs from actual PR files.')
                    record = {'schema': 1, 'kind': 'human-review-routing', 'repository': repo,
                              'pull_request': number, 'head_sha': pr['head']['sha']}
                    readiness = qualification(repo, pr)
                    if readiness['state'] == 'qualified':
                        readiness['state'] = 'awaiting-independent-automatic-validation'
                    return defer_request('repos/'+repo+'/pulls/'+str(number), record, readiness)
                reason = 'The verified update candidate requires independent human review.'
        except (MaintenanceError, KeyError, ValueError, OSError) as error:
            reason = 'The proposed change needs human attention: '+str(error)[:1000]
    record = request_review(repo, number, pr['head']['sha'], reason)
    if record['state'] == 'author-needs-independent-reviewer':
        record['attention_assignment'] = assign_attention(repo, number)
    return record


def event_requests(repo, event, source, enabled, number=None):
    repository(repo)
    if number is not None:
        require(type(number) is int and number > 0, 'Invalid explicit review target.')
        targets = [number]
    else:
        run = event.get('workflow_run') or {}
        require(event.get('repository', {}).get('full_name') == repo and run.get('event') == 'pull_request' and
                run.get('path') in ROUTING_WORKFLOWS, 'Untrusted human-review routing event.')
        head = sha(run['head_sha'])
        targets = [p['number'] for p in pages('repos/'+repo+'/pulls?state=open&per_page=100')
                   if p['head']['sha'] == head and p['base']['repo']['full_name'] == repo and p['base']['ref'] == 'main']
    return {'schema': 1, 'kind': 'human-review-routing-results', 'created_at': now(),
            'repository': repo, 'requests': [route(repo, n, source, enabled) for n in targets]}
