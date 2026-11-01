"""Delete only temporary artifacts from completed, explicitly known workflows."""

import datetime
import re

from .common import api, canonical, digest, now, repository, require, timestamp


TEMPORARY = re.compile(r'^(?:unsigned-package-(?:qualification|stage)|qualified-base|attested-base|package-stage|'
                       r'unsigned-build-cache|untrusted-build-cache|verified-build-cache|synthetic-inline-cache|'
                       r'qualified-release|attested-release|qualified-(?:amd64|arm64)|'
                       r'assessed-inventories|signed-assessments|security-proposal|security-decision|'
                       r'runner-disk-(?:packages|native)|publication-verification|attested-publication|security-proposal-audit|security-proposal-result|'
                       r'security-approved-decision|security-admission-decision|package-security-diagnostics|cleanup-plan|cleanup-result|attested-maintenance-(?:proposal|decision|cleanup|cleanup-result|publication))(?:-[0-9]+)?$')
WORKFLOWS = {'Package qualification', 'Release', 'Retained release security', 'Check', 'CI',
             'Propose dependency updates', 'Security update review'}


def plan(repo, *, get=api, clock=None):
    clock = clock or datetime.datetime.now(datetime.timezone.utc)
    result = []
    endpoint = 'repos/'+repo+'/actions/artifacts?per_page=100'
    pages = get(endpoint, paginate=True)
    runs = {}
    candidates = []
    for page in pages:
        require(isinstance(page.get('artifacts'), list), 'Incomplete artifact enumeration.')
        for artifact in page['artifacts']:
            if not TEMPORARY.fullmatch(artifact['name']) or artifact.get('expired'):
                continue
            run_id = artifact.get('workflow_run', {}).get('id')
            if not run_id:
                continue
            if run_id not in runs:
                runs[run_id] = get('repos/'+repo+'/actions/runs/'+str(run_id))
            run = runs[run_id]
            candidates.append((artifact,run_id,run))
    # Keep one final signed bundle, for at most one day, from the latest failed
    # release. Intermediate stages and older failed releases remain disposable.
    retry_candidates = [(a,rid,r) for a,rid,r in candidates
                        if r['name']=='Release' and r['status']=='completed'
                        and r.get('conclusion')=='failure'
                        and re.fullmatch(r'attested-(?:base|release)(?:-[0-9]+)?',a['name'])
                        and clock-timestamp(a.get('created_at',r['updated_at'])) < datetime.timedelta(days=1)]
    retained = []
    if retry_candidates:
        latest = get('repos/'+repo+'/actions/workflows/release.yml/runs?status=completed&per_page=1')['workflow_runs']
        require(isinstance(latest,list) and len(latest)<=1, 'Incomplete latest release observation.')
        if latest and latest[0]['conclusion']=='failure':
            eligible = [a for a,rid,_ in retry_candidates if rid==latest[0]['id']]
            if eligible:
                retained = [max(eligible,key=lambda a:a['id'])]
    retained_ids = {a['id'] for a in retained}
    for artifact,run_id,run in candidates:
        # Active consumers and the short retry window are always protected.
        if artifact['id'] in retained_ids:
            continue
        if run['status'] != 'completed' or run['name'] not in WORKFLOWS or \
                clock-timestamp(run['updated_at']) < datetime.timedelta(hours=2):
            continue
        result.append({'id': artifact['id'], 'name': artifact['name'], 'size_in_bytes': artifact['size_in_bytes'],
                       'run_id': run_id, 'completed_at': run['updated_at']})
    return {'schema': 1, 'kind': 'temporary-artifact-cleanup', 'repository': repo, 'created_at': clock.isoformat(),
            'reason': 'Completed workflow handoffs and duplicate build outputs; durable release assets are excluded.',
            'bytes': sum(a['size_in_bytes'] for a in result), 'artifacts': result,
            'retained_retry_artifacts': [{'id':a['id'],'name':a['name'],'run_id':a['workflow_run']['id'],
                'size_in_bytes':a['size_in_bytes'],'reason':'Latest failed release final attested bundle; maximum one day.'}
                for a in retained]}


def execute(record, *, progress=None):
    repository(record['repository'])
    require(record['schema'] == 1 and record['kind'] == 'temporary-artifact-cleanup', 'Invalid cleanup record.')
    result = {'schema': 1, 'kind': 'temporary-artifact-cleanup-result', 'repository': record['repository'],
              'plan_sha256': digest(canonical(record)), 'started_at': now(), 'deleted': [], 'already_absent': [],
              'result': 'in-progress'}
    def save():
        if progress:
            progress(result)
    save()
    try:
        for artifact in record['artifacts']:
            require(TEMPORARY.fullmatch(artifact['name']), 'Cleanup record contains a durable or unknown artifact.')
            current = api('repos/'+record['repository']+'/actions/runs/'+str(artifact['run_id']))
            require(current['status'] == 'completed' and current['name'] in WORKFLOWS and
                    current['updated_at'] == artifact['completed_at'], 'A workflow changed after cleanup planning.')
            actual = api('repos/'+record['repository']+'/actions/artifacts/'+str(artifact['id']), missing_ok=True)
            if actual is None:
                # GitHub may expire an artifact between planning and deletion.
                # This is an absence observation, never a claimed successful delete.
                result['already_absent'].append(artifact['id'])
                save()
                continue
            require(actual['name'] == artifact['name'] and actual['workflow_run']['id'] == artifact['run_id'] and
                    actual['size_in_bytes'] == artifact['size_in_bytes'], 'Artifact differs from the archived cleanup record.')
            api('repos/'+record['repository']+'/actions/artifacts/'+str(artifact['id']), method='DELETE')
            result['deleted'].append(artifact['id'])
            save()
        result['result'] = 'pass'
    except Exception as error:
        result['result'] = 'blocked'
        result['error'] = str(error)[-2000:]
        raise
    finally:
        result['completed_at'] = now()
        save()
    return result
