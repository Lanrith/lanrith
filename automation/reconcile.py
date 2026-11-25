"""Recover missed maintenance events with bounded retries and an assigned blocker."""
import datetime
import json
import os

from .common import api, canonical, contents, document, now, pages, require, timestamp
from .review import ValidationPending, manual_validation_policy, validation_runs
from .common import MaintenanceError

TITLE = 'Security automation reconciliation'


def decision(pr, policy, attempts, *, clock=None):
    """Return only safe recovery actions; a failed build is never blindly rerun."""
    clock = clock or datetime.datetime.now(datetime.timezone.utc)
    repo, number = policy['repository'], pr['number']
    if pr['draft'] or (pr['head']['repo'] or {}).get('full_name') != repo or pr['base']['ref'] != 'main':
        return [], []
    proposer = (pr['user']['login'] == policy['proposer_login'] and pr['user']['type'] == 'Bot' and
                pr['user'].get('id') == policy['proposer_user_id'])
    automatic = pr['head']['ref'] == policy['proposal_branch'] and proposer
    control = pr['head']['ref'] == 'automation/workflow-updates' and proposer
    dependabot = pr['user']['login'] == 'dependabot[bot]' and pr['user']['type'] == 'Bot'
    bot = proposer or dependabot
    if not bot:
        return [], []
    subject = str(number)+':'+pr['head']['sha']+':'+pr['base']['sha']
    used = attempts.get(subject, [])
    actions, blockers = [], []
    comparison = api('repos/'+repo+'/compare/'+pr['base']['sha']+'...'+pr['head']['sha'])
    if comparison['merge_base_commit']['sha'] != pr['base']['sha']:
        if not (automatic or control or dependabot):
            return [], ['#'+str(number)+': manual repair branch needs a reviewed rebase; it was not rewritten.']
        kind = 'proposal' if automatic else 'controls' if control else 'refresh'
        if kind not in used:
            actions.append({'kind': kind, 'pr': number, 'head': pr['head']['sha'], 'subject': subject})
        else:
            blockers.append('#'+str(number)+': branch refresh did not complete; inspect its update conflict.')
        return actions, blockers
    try:
        validation_runs(repo, pr, manual_validation_policy(repo, number, policy), manual=True)
    except ValidationPending as waiting:
        if pr.get('updated_at') and clock-timestamp(pr['updated_at']) > datetime.timedelta(hours=24):
            return [], ['#'+str(number)+': required qualification has remained incomplete for more than 24 hours: '+str(waiting)]
        return [], []
    except MaintenanceError as failure:
        blockers.append('#'+str(number)+': '+str(failure))
        # A previous successful run can expire before review. Refresh it once per
        # subject; failed/cancelled runs always require a real fix instead.
        if str(failure).startswith('Validation is stale') and 'validation' not in used:
            for path in policy['required_workflows']:
                response = api('repos/'+repo+'/actions/workflows/'+path.rsplit('/', 1)[1]+
                               '/runs?event=pull_request&head_sha='+pr['head']['sha']+'&per_page=100')
                runs = [r for r in response['workflow_runs'] if r['head_sha'] == pr['head']['sha'] and
                        r['path'] == path and r['event'] == 'pull_request' and any(p['number'] == number and
                        p['base']['sha'] == pr['base']['sha'] for p in r.get('pull_requests', []))]
                latest_run = max(runs, key=lambda r: r['id']) if runs else None
                if latest_run and latest_run['status'] == 'completed' and latest_run['conclusion'] == 'success':
                    actions.append({'kind': 'validation', 'pr': number, 'head': pr['head']['sha'],
                                    'run': latest_run['id'], 'subject': subject})
        return actions, blockers
    response = api('repos/'+repo+'/commits/'+pr['head']['sha']+
                   '/check-runs?check_name=Security%20update%20admission&filter=latest&per_page=100')
    require(response['total_count'] <= 100, 'Reconciliation check enumeration is incomplete.')
    owned = [c for c in response['check_runs'] if c['name'] == 'Security update admission' and
             c['app']['id'] == policy['reviewer_app_id'] and c['head_sha'] == pr['head']['sha']]
    latest = max(owned, key=lambda c: c['id']) if owned else None
    if latest and latest.get('conclusion') == 'success':
        if automatic and not pr.get('auto_merge') and 'merge' not in used:
            actions.append({'kind': 'merge', 'pr': number, 'head': pr['head']['sha'], 'subject': subject})
        elif not automatic and not pr.get('requested_reviewers') and 'notify' not in used:
            actions.append({'kind': 'notify', 'pr': number, 'head': pr['head']['sha'], 'subject': subject})
        return actions, []
    if latest and clock-timestamp(latest['started_at']) < datetime.timedelta(hours=1):
        return [], []
    if used.count('review') < 2:
        actions.append({'kind': 'review', 'pr': number, 'head': pr['head']['sha'], 'subject': subject})
    else:
        blockers.append('#'+str(number)+': admission still incomplete after two recovery attempts.')
    return actions, blockers


def reconcile(repo, output, *, apply=False):
    main = api('repos/'+repo+'/commits/main')['sha']
    policy = document(contents(repo, 'security/update-policy.json', main))
    issues = pages('repos/'+repo+'/issues?state=all&creator=github-actions%5Bbot%5D&per_page=100')
    matches = [i for i in issues if i['title'] == TITLE and 'pull_request' not in i]
    require(len(matches) <= 1, 'Reconciliation state is ambiguous.')
    attempts = {}
    if matches:
        body = matches[0].get('body') or ''
        require('<!-- recovery-state\n' in body and '\n-->' in body, 'Reconciliation state is missing.')
        attempts = document(body.split('<!-- recovery-state\n', 1)[1].split('\n-->', 1)[0])
    pulls = pages('repos/'+repo+'/pulls?state=open&per_page=100')
    require(len(pulls) <= 100, 'Too many open PRs for bounded maintenance reconciliation.')
    subjects = {str(p['number'])+':'+p['head']['sha']+':'+p['base']['sha'] for p in pulls}
    attempts = {k: v for k, v in attempts.items() if k in subjects}
    actions, blockers = [], []
    for pr in pulls:
        proposed, failed = decision(pr, policy, attempts)
        actions.extend(proposed)
        blockers.extend(failed)
    require(len(actions) <= 30, 'Recovery action budget exceeded.')
    record = {'schema': 1, 'repository': repo, 'source_commit': main, 'created_at': now(),
              'actions': actions, 'blockers': blockers}
    output.write_bytes(canonical(record))
    if not apply:
        return record
    # Persist reservations before dispatch. A crash cannot create an infinite
    # retry loop; a reserved but interrupted attempt remains visible to operators.
    for action in actions:
        attempts.setdefault(action['subject'], []).append(action['kind'])
    body = ('State: **'+('attention required' if blockers else 'reconciled')+'**.\n\n'+
            '\n'.join('- '+b for b in blockers)+'\n\nLatest run: https://github.com/'+repo+'/actions/runs/'+
            os.environ['GITHUB_RUN_ID']+'\n\n<!-- recovery-state\n'+json.dumps(attempts, sort_keys=True)+'\n-->')
    payload = {'title': TITLE, 'body': body}
    if matches:
        payload['state'] = 'open' if actions or blockers else 'closed'
    issue = api('repos/'+repo+'/issues'+('/'+str(matches[0]['number']) if matches else ''),
                method='PATCH' if matches else 'POST', payload=payload)
    if blockers:
        from .notifications import assign_attention
        assign_attention(repo, issue['number'])
    for action in actions:
        current = api('repos/'+repo+'/pulls/'+str(action['pr']))
        require(current['state'] == 'open' and current['head']['sha'] == action['head'] and
                current['base']['sha'] == action['subject'].rsplit(':', 1)[1], 'PR changed before recovery dispatch.')
        if action['kind'] in ('refresh', 'merge'):
            # This API operation uses the updater App, so subsequent PR CI runs.
            previous = os.environ.get('GH_TOKEN')
            require(os.environ.get('LANRITH_BRANCH_TOKEN'), 'Branch refresh needs the scoped updater authority.')
            try:
                os.environ['GH_TOKEN'] = os.environ['LANRITH_BRANCH_TOKEN']
                if action['kind'] == 'refresh':
                    api('repos/'+repo+'/pulls/'+str(action['pr'])+'/update-branch', method='PUT',
                        payload={'expected_head_sha': action['head']})
                else:
                    from .common import run
                    run('gh', 'pr', 'merge', str(action['pr']), '--repo', repo, '--auto', '--squash',
                        '--match-head-commit', action['head'], capture_output=True)
            finally:
                if previous is None:
                    os.environ.pop('GH_TOKEN', None)
                else:
                    os.environ['GH_TOKEN'] = previous
        elif action['kind'] == 'validation':
            api('repos/'+repo+'/actions/runs/'+str(action['run'])+'/rerun', method='POST')
        else:
            workflow = {'review': 'security-review.yml', 'notify': 'request-human-review.yml',
                        'proposal': 'update-inputs.yml', 'controls': 'prepare-workflow-updates.yml'}[action['kind']]
            payload = {'ref': 'main'}
            if action['kind'] in ('review', 'notify'):
                payload['inputs'] = {'pr': str(action['pr'])}
            api('repos/'+repo+'/actions/workflows/'+workflow+'/dispatches', method='POST', payload=payload)
    return record
