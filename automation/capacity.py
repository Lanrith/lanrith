"""Retry only proven hosted-runner capacity failures, after durable intent archival."""

import io
import os
from pathlib import Path
import re
import stat
import tempfile
import time
import zipfile

from .common import api, canonical, contents, digest, document, now, require, run, sha

REPO = 'Lanrith/lanrith'
MINIMUM = 60 * 1024**3
MAX_ATTEMPTS = 3
WORKFLOWS = {'.github/workflows/release.yml': 'Release',
             '.github/workflows/package-check.yml': 'Package qualification'}
ROLES = {'build / packages': 'packages', 'build / build': 'native',
         'Unsigned package compilation': 'packages', 'Unsigned filesystem and native qualification': 'native'}


def artifact_report(repo, identity):
    require(repo == REPO and type(identity) is int and identity > 0, 'Invalid capacity-report subject.')
    raw = run('gh', 'api', f'repos/{repo}/actions/artifacts/{identity}/zip', capture_output=True).stdout
    require(0 < len(raw) <= 16384, 'Capacity report archive exceeds its bound.')
    with zipfile.ZipFile(io.BytesIO(raw)) as packed:
        members = packed.infolist()
        require(len(members) == 1, 'Capacity report must have one member.')
        member = members[0]
        require(member.filename == 'runner-disk.json' and not stat.S_ISLNK(member.external_attr >> 16) and
                0 < member.file_size <= 16384, 'Invalid capacity-report envelope.')
        return document(packed.read(member), maximum=16384)


def inspect(repo, event, source, *, get=api, read_source=contents, load_report=artifact_report):
    require(repo == REPO, 'Capacity recovery is limited to the root repository.')
    sha(source)
    result = {'schema': 1, 'kind': 'runner-capacity-retry-plan', 'created_at': now(),
              'repository': repo, 'controller_source': source, 'eligible': False,
              'archive': False, 'state': 'ignored', 'maximum_attempts': MAX_ATTEMPTS}

    def ignore(reason):
        return result | {'reason': reason}

    trigger = event.get('workflow_run') or {}
    if event.get('action') != 'completed' or event.get('repository', {}).get('full_name') != repo or \
            type(trigger.get('id')) is not int or trigger['id'] <= 0:
        return ignore('Unsupported workflow event.')
    current = get(f'repos/{repo}/actions/runs/{trigger["id"]}')
    require(current['id'] == trigger['id'], 'Run identity differs from the requested resource.')
    if any(current.get(key) != trigger.get(key) for key in ('head_sha', 'run_attempt', 'path', 'event')):
        return ignore('A newer run attempt or source superseded this event.')
    if current['status'] != 'completed' or current['conclusion'] != 'failure' or \
            current.get('path') not in WORKFLOWS or current.get('name') != WORKFLOWS[current['path']] or \
            current.get('head_repository', {}).get('full_name') != repo:
        return ignore('The run is not a failed, supported same-repository build.')
    if type(current['run_attempt']) is not int or current['run_attempt'] <= 0:
        return ignore('Invalid run-attempt identity.')
    main = get(f'repos/{repo}/git/ref/heads/main')['object']['sha']
    if main != source:
        return ignore('The trusted controller source was superseded.')
    number = None
    if current['path'].endswith('/release.yml'):
        if current['event'] not in ('push', 'workflow_dispatch') or current['head_branch'] != 'main' or current['head_sha'] != main:
            return ignore('The release does not build current protected Main.')
    else:
        if current['event'] != 'pull_request':
            return ignore('Only pull-request qualification can be recovered automatically.')
        associated = current.get('pull_requests', [])
        if len(associated) != 1 or type(associated[0].get('number')) is not int:
            return ignore('Qualification does not identify one PR.')
        number = associated[0]['number']
        pr = get(f'repos/{repo}/pulls/{number}')
        if pr['state'] != 'open' or pr['draft'] or pr['head']['repo']['full_name'] != repo or \
                pr['head']['sha'] != current['head_sha'] or pr['base']['sha'] != main or pr['base']['ref'] != 'main' or \
                associated[0].get('head', {}).get('sha') != pr['head']['sha'] or \
                associated[0].get('base', {}).get('sha') != main:
            return ignore('The PR, tested head or protected base changed.')
    prepared = read_source(repo, 'scripts/prepare-runner.py', current['head_sha'])
    if prepared != read_source(repo, 'scripts/prepare-runner.py', source):
        return ignore('The failed run changed the reviewed disk-preparation code.')
    jobs = get(f'repos/{repo}/actions/runs/{current["id"]}/jobs?filter=latest&per_page=100')
    require(jobs['total_count'] <= 100 and len(jobs['jobs']) == jobs['total_count'], 'Incomplete capacity job enumeration.')
    failed = [job for job in jobs['jobs'] if job['conclusion'] == 'failure']
    if len(failed) != 1 or failed[0]['name'] not in ROLES:
        return ignore('Failure is not confined to one compiler/native job.')
    job = failed[0]
    wrong_workflow = (current['path'].endswith('/release.yml')) != job['name'].startswith('build / ')
    if wrong_workflow or job['status'] != 'completed' or \
            [s['name'] for s in job['steps'] if s['conclusion'] == 'failure'] != ['Prepare hosted runner disk']:
        return ignore('A build, test, scanner or other preparation step failed.')
    build_steps = ('Compile and assess packages without privileged containers',
                   'Assemble and qualify the exact package stage on a separate VM')
    if any(s['name'] in build_steps and s['conclusion'] != 'skipped' for s in job['steps']):
        return ignore('Compilation or native qualification has already executed.')
    artifacts = get(f'repos/{repo}/actions/runs/{current["id"]}/artifacts?per_page=100')
    require(artifacts['total_count'] <= 100 and len(artifacts['artifacts']) == artifacts['total_count'], 'Incomplete capacity artifact enumeration.')
    role = ROLES[job['name']]
    expected = f'runner-disk-{role}-{current["run_attempt"]}'
    matching = [a for a in artifacts['artifacts'] if a['name'] == expected and not a['expired']]
    if len(matching) != 1:
        return ignore('The exact failed-attempt capacity report is unavailable.')
    artifact = matching[0]
    require(artifact['workflow_run']['id'] == current['id'] and type(artifact['size_in_bytes']) is int and
            0 < artifact['size_in_bytes'] <= 16384, 'Capacity report has a different run or exceeds its bound.')
    report = load_report(repo, artifact['id'])
    if type(report.get('schema')) is not int or report['schema'] != 1 or report.get('kind') != 'hosted-runner-disk-preparation' or report.get('result') != 'fail' or \
            report.get('minimum_free_bytes') != MINIMUM or not isinstance(report.get('error'), str) or \
            not report['error'].startswith('Insufficient runner disk:'):
        return ignore('The report is not the unchanged insufficient-disk guard.')
    for phase in ('before', 'after'):
        usage = report.get(phase, {})
        require(all(type(usage.get(key)) is int and 0 <= usage[key] < 2**63 for key in ('total_bytes', 'used_bytes', 'free_bytes')) and
                usage['total_bytes'] > 0 and usage['used_bytes'] + usage['free_bytes'] <= usage['total_bytes'], 'Malformed capacity measurements.')
    if report['after']['free_bytes'] >= MINIMUM or report['before']['total_bytes'] != report['after']['total_bytes'] or \
            report.get('runner', {}).get('GITHUB_RUN_ID') != str(current['id']) or \
            report['runner'].get('GITHUB_RUN_ATTEMPT') != str(current['run_attempt']) or \
            report['runner'].get('RUNNER_ENVIRONMENT') != 'github-hosted' or report['runner'].get('RUNNER_OS') != 'Linux':
        return ignore('The reported shortage or hosted run identity is inconsistent.')
    handoffs = []
    if role == 'native':
        prefix = 'package-stage-' if current['path'].endswith('/release.yml') else 'unsigned-package-stage-'
        handoffs = [{'id': a['id'], 'name': a['name'], 'digest': a.get('digest')} for a in artifacts['artifacts']
                    if re.fullmatch(re.escape(prefix)+r'[1-9][0-9]*', a['name']) and not a['expired'] and a['workflow_run']['id'] == current['id']]
        if not handoffs:
            return ignore('The successful package handoff is unavailable; do not retry native work blindly.')
    result.update(archive=True, state='ready' if current['run_attempt'] < MAX_ATTEMPTS else 'budget-exhausted',
        eligible=current['run_attempt'] < MAX_ATTEMPTS,
        reason='Hosted runner free space stayed below the unchanged 60 GiB minimum before build execution.',
        target={'id': current['id'], 'head_sha': current['head_sha'], 'run_attempt': current['run_attempt'],
                'path': current['path'], 'event': current['event']},
        target_updated_at=current['updated_at'], base_sha=main, pull_request=number,
        failed_job={'id': job['id'], 'name': job['name']}, preparation_source_sha256=digest(prepared),
        report_artifact=artifact['id'], report_sha256=digest(canonical(report)),
        capacity={phase: {key: report[phase][key] for key in ('total_bytes', 'used_bytes', 'free_bytes')}
                  for phase in ('before', 'after')},
        package_handoffs=sorted(handoffs, key=lambda a: a['id']),
        scope='No source changes, approval or waived qualification. Only this failed job and its dependants may rerun; maximum three total attempts.')
    return result


def verify_archive(plan, tag, source, *, get=api):
    require(re.fullmatch('audit-capacity-plan-'+re.escape(os.environ['GITHUB_RUN_ID'])+r'-[1-9][0-9]*', tag or ''), 'Retry archive belongs to another controller run.')
    archived = get(f'repos/{REPO}/releases/tags/{tag}')
    require(archived.get('immutable') is True and not archived['draft'] and archived['target_commitish'] == source and
            any(a['name'] == 'capacity-record.json' and a['digest'] == 'sha256:'+digest(canonical(plan)) for a in archived['assets']),
            'Exact retry intent is not durably archived.')
    with tempfile.TemporaryDirectory(prefix='capacity-intent.') as temporary:
        directory = Path(temporary)
        run('gh', 'release', 'download', tag, '--repo', REPO, '--pattern', 'capacity-record.json',
            '--pattern', 'evidence.intoto.jsonl', '--dir', temporary, capture_output=True)
        require((directory/'capacity-record.json').read_bytes() == canonical(plan), 'Archived intent bytes differ.')
        run('gh', 'attestation', 'verify', str(directory/'capacity-record.json'), '--bundle', str(directory/'evidence.intoto.jsonl'),
            '--repo', REPO, '--signer-workflow', REPO+'/.github/workflows/archive-evidence.yml', '--source-digest', source,
            '--signer-digest', source, '--source-ref', 'refs/heads/main',
            '--cert-oidc-issuer', 'https://token.actions.githubusercontent.com', '--deny-self-hosted-runners', capture_output=True)
    return archived['html_url']


def execute(plan, source, tag, *, get=api, read_source=contents, load_report=artifact_report, verify=verify_archive, progress=None, pause=time.sleep):
    result = {'schema': 1, 'kind': 'runner-capacity-retry-result', 'repository': REPO, 'created_at': now(),
              'plan_sha256': digest(canonical(plan)), 'state': 'blocked', 'security_validation_bypassed': False}
    def save():
        if progress:
            progress(result)
    try:
        require(plan.get('kind') == 'runner-capacity-retry-plan' and plan.get('repository') == REPO and
                plan.get('eligible') is True and plan.get('controller_source') == source and plan.get('maximum_attempts') == MAX_ATTEMPTS,
                'Retry intent is not eligible for this reviewed controller.')
        result['intent_archive'] = verify(plan, tag, source, get=get)
        target = plan['target']
        fresh = inspect(REPO, {'action': 'completed', 'repository': {'full_name': REPO}, 'workflow_run': target}, source,
                        get=get, read_source=read_source, load_report=load_report)
        keys = ('eligible', 'maximum_attempts', 'controller_source', 'target', 'target_updated_at', 'base_sha', 'pull_request',
                'failed_job', 'preparation_source_sha256', 'report_artifact', 'report_sha256', 'package_handoffs')
        require(all(fresh.get(key) == plan.get(key) for key in keys), 'Capacity intent became stale or its evidence changed.')
        result.update(target=target, failed_job=plan['failed_job'], state='retry-requesting', retry_accepted=False)
        save()
        # One mutation only. A transport error is never retried: GitHub may have accepted it.
        get(f'repos/{REPO}/actions/jobs/{plan["failed_job"]["id"]}/rerun', method='POST')
        result.update(state='retry-requested', retry_accepted=True, requested_at=now())
        save()
        observed = None
        for _ in range(5):
            observed = get(f'repos/{REPO}/actions/runs/{target["id"]}')
            require(observed['head_sha'] == target['head_sha'] and target['run_attempt'] <= observed['run_attempt'] <= target['run_attempt']+1,
                    'Retry source or attempt changed unexpectedly; inspect before any further action.')
            if observed['run_attempt'] > target['run_attempt']:
                break
            pause(1)
        result['observed_target'] = {key: observed[key] for key in ('id', 'head_sha', 'run_attempt', 'status', 'conclusion')}
        if plan['pull_request'] is not None and observed['run_attempt'] > target['run_attempt']:
            try:
                get(f'repos/{REPO}/actions/workflows/security-review.yml/dispatches', method='POST',
                    payload={'ref': 'main', 'inputs': {'pr': str(plan['pull_request'])}})
                result['admission_refresh'] = 'requested-through-normal-trusted-reviewer'
            except Exception as error:
                result['admission_refresh'] = 'failed; actual qualification remains mandatory'
                result['refresh_error'] = str(error)[:1000]
        return result
    except Exception as error:
        if result['state'] == 'retry-requesting':
            result['state'] = 'retry-outcome-unknown'
        result['error'] = str(error)[:2000]
        raise
    finally:
        result['completed_at'] = now()
        save()
