"""Bound disposal of known image caches without importing their untrusted contents."""

import datetime
import re

from .common import api, canonical, digest, now, repository, require, timestamp


REPOSITORY = 'Lanrith/lanrith'
KEY = re.compile(r'^lanrith-build-v1-Linux-X64-[0-9a-f]{64}-([1-9][0-9]{0,18})-([1-9][0-9]{0,3})$')
POLICY = {'successful_sources': 2, 'recent_access_hours': 2, 'failed_retry_hours': 24,
          'maximum_deletions': 20, 'maximum_inventory': 500, 'maximum_producers': 100,
          'maximum_plan_age_hours': 2}
CACHE_FIELDS = ('id', 'key', 'ref', 'version', 'size_in_bytes', 'created_at', 'last_accessed_at')
RUN_FIELDS = ('id', 'run_attempt', 'name', 'path', 'event', 'head_branch', 'head_sha',
              'status', 'conclusion', 'updated_at')


def rows(get, endpoint, field):
    pages = get(endpoint, paginate=True)
    require(isinstance(pages, list) and pages and all(isinstance(p, dict) and
            isinstance(p.get(field), list) and type(p.get('total_count')) is int and
            0 <= p['total_count'] <= POLICY['maximum_inventory'] for p in pages),
            'Build-cache inventory is incomplete or exceeds its review bound.')
    result = [r for p in pages for r in p[field]]
    require(all(p['total_count'] == len(result) for p in pages) and
            all(isinstance(r, dict) and type(r.get('id')) is int and r['id'] > 0 for r in result) and
            len({r['id'] for r in result}) == len(result), 'Build-cache inventory changed or contains duplicate identities.')
    return result


def inventory(repo, get):
    result = []
    for cache in rows(get, 'repos/'+repo+'/actions/caches?per_page=100', 'actions_caches'):
        if cache.get('ref') != 'refs/heads/main' or not isinstance(cache.get('key'), str) or not KEY.fullmatch(cache['key']):
            continue
        require(all(k in cache for k in CACHE_FIELDS) and type(cache['size_in_bytes']) is int and
                0 <= cache['size_in_bytes'] <= 64*1024**3 and isinstance(cache['version'], str) and
                re.fullmatch('[0-9a-f]{64}', cache['version']), 'Managed build-cache metadata is malformed.')
        created, accessed = timestamp(cache['created_at']), timestamp(cache['last_accessed_at'])
        require(created <= accessed, 'Build-cache access predates its creation.')
        result.append({k: cache[k] for k in CACHE_FIELDS})
    return result


def active(repo, get):
    result = {}
    for state in ('in_progress', 'queued', 'waiting', 'pending', 'requested'):
        for run in rows(get, 'repos/'+repo+'/actions/runs?status='+state+'&per_page=100', 'workflow_runs'):
            # The cleanup itself never restores caches or executes cache content.
            if run.get('path') == '.github/workflows/cleanup-artifacts.yml' and run.get('head_branch') == 'main':
                continue
            result[run['id']] = {'id': run['id'], 'path': run.get('path'), 'status': run.get('status')}
    return list(result.values())


def producer(repo, cache, get):
    match = KEY.fullmatch(cache['key'])
    identity, attempt = map(int, match.groups())
    value = get('repos/'+repo+'/actions/runs/'+str(identity))
    valid = (all(k in value for k in RUN_FIELDS) and type(value['id']) is int and value['id'] == identity and
             type(value['run_attempt']) is int and value['run_attempt'] >= attempt and
             value['path'] == '.github/workflows/release.yml' and value['name'] == 'Release' and
             value['event'] in ('push', 'workflow_dispatch') and value['head_branch'] == 'main' and
             isinstance(value.get('head_repository'), dict) and value['head_repository'].get('full_name') == repo and
             (value['status'] != 'completed' or value['conclusion'] in
              ('success', 'failure', 'cancelled', 'timed_out', 'startup_failure', 'action_required', 'neutral', 'skipped')) and
             isinstance(value['head_sha'], str) and re.fullmatch('[0-9a-f]{40}', value['head_sha']))
    return ({k: value[k] for k in RUN_FIELDS}, attempt) if valid else (None, attempt)


def plan(repo, *, get=api, clock=None):
    repository(repo)
    clock = clock or datetime.datetime.now(datetime.timezone.utc)
    record = {'schema': 1, 'kind': 'build-cache-cleanup', 'repository': repo, 'created_at': clock.isoformat(),
              'policy': dict(POLICY), 'reason': 'Obsolete completed Main image cache generations; retain two successful source generations, recent access and one failed-release retry cache. Cache contents are never restored or executed.',
              'caches': [], 'retained': [], 'protected_successful': [], 'blocked_by_runs': [], 'bytes': 0}
    if repo != REPOSITORY:
        return record
    caches = inventory(repo, get)
    if len(caches) <= POLICY['successful_sources']:
        record['retained'] = [{'cache': c, 'reason': 'within-retained-generation-floor'} for c in caches]
        return record
    record['blocked_by_runs'] = active(repo, get)
    if record['blocked_by_runs']:
        record['retained'] = [{'cache': c, 'reason': 'workflows-active'} for c in caches]
        return record
    require(len({KEY.fullmatch(c['key']).group(1) for c in caches}) <= POLICY['maximum_producers'],
            'Too many build-cache producers for bounded review.')
    known, producer_cache = [], {}
    for cache in caches:
        identity = int(KEY.fullmatch(cache['key']).group(1))
        if identity not in producer_cache:
            producer_cache[identity] = get('repos/'+repo+'/actions/runs/'+str(identity))
        value, attempt = producer(repo, cache, lambda _: producer_cache[identity])
        if value is None or value['status'] != 'completed':
            record['retained'].append({'cache': cache, 'reason': 'unknown-or-active-producer'})
        else:
            known.append(cache | {'producer': value, 'cache_attempt': attempt})
    newest = sorted(known, key=lambda c: (timestamp(c['created_at']), c['id']), reverse=True)
    successful, sources = [], set()
    for cache in newest:
        run = cache['producer']
        if run['conclusion'] == 'success' and run['run_attempt'] == cache['cache_attempt'] and run['head_sha'] not in sources:
            successful.append(cache); sources.add(run['head_sha'])
            if len(successful) == POLICY['successful_sources']:
                break
    record['protected_successful'] = successful
    keep = {c['id'] for c in successful}
    failed = next((c['id'] for c in newest if c['producer']['conclusion'] == 'failure' and
                   c['producer']['run_attempt'] == c['cache_attempt'] and
                   clock-timestamp(c['created_at']) < datetime.timedelta(hours=POLICY['failed_retry_hours'])), None)
    for cache in reversed(newest):
        reason = ('latest-successful-source' if cache['id'] in keep else
                  'recent-cache-access' if clock-timestamp(cache['last_accessed_at']) <
                  datetime.timedelta(hours=POLICY['recent_access_hours']) else
                  'failed-release-retry-window' if cache['id'] == failed else
                  'per-run-deletion-bound' if len(record['caches']) >= POLICY['maximum_deletions'] else None)
        if reason:
            record['retained'].append({'cache': cache, 'reason': reason})
        else:
            record['caches'].append(cache)
    record['bytes'] = sum(c['size_in_bytes'] for c in record['caches'])
    return record


def execute(record, *, request=api, progress=None, clock=None):
    repo = repository(record['repository'])
    current_time = lambda: clock or datetime.datetime.now(datetime.timezone.utc)
    require(record['schema'] == 1 and record['kind'] == 'build-cache-cleanup' and record['policy'] == POLICY and
            isinstance(record['caches'], list) and len(record['caches']) <= POLICY['maximum_deletions'] and
            len({c['id'] for c in record['caches']}) == len(record['caches']) and
            datetime.timedelta(0) <= current_time()-timestamp(record['created_at']) <=
            datetime.timedelta(hours=POLICY['maximum_plan_age_hours']), 'Build-cache cleanup plan is invalid or stale.')
    result = {'schema': 1, 'kind': 'build-cache-cleanup-result', 'repository': repo, 'started_at': now(),
              'plan_sha256': digest(canonical(record)), 'deleted': [], 'already_absent': [], 'deferred': [],
              'deleted_bytes': 0, 'result': 'in-progress'}
    def save():
        if progress:
            progress(result)
    save()
    try:
        fresh = plan(repo, get=request, clock=current_time())
        eligible = {c['id']: c for c in fresh['caches']}
        for index, cache in enumerate(record['caches']):
            require(repo == REPOSITORY and KEY.fullmatch(cache['key']) and cache['ref'] == 'refs/heads/main',
                    'Cache cleanup cannot address another namespace or branch.')
            blockers = active(repo, request)
            if blockers:
                result['deferred'].extend({'id': c['id'], 'reason': 'workflows-became-active'} for c in record['caches'][index:])
                break
            actual = {c['id']: c for c in inventory(repo, request)}
            if cache['id'] not in actual:
                result['already_absent'].append(cache['id']); save(); continue
            if eligible.get(cache['id']) != cache:
                result['deferred'].append({'id': cache['id'], 'reason': 'no-longer-eligible'}); save(); continue
            # Rechecking the retained floor prevents an external eviction from
            # promoting an older candidate into the two generations we protect.
            retained = fresh['protected_successful']
            floor_changed = False
            for keep in retained:
                if keep['id'] not in actual:
                    floor_changed = True; break
                run, _ = producer(repo, keep, request)
                if run != keep['producer']:
                    floor_changed = True; break
            if floor_changed:
                result['deferred'].extend({'id': c['id'], 'reason': 'retained-floor-changed'} for c in record['caches'][index:])
                break
            run, attempt = producer(repo, cache, request)
            require(run == cache['producer'] and attempt == cache['cache_attempt'] and run['status'] == 'completed',
                    'Cache producer changed or was rerun after planning.')
            if actual[cache['id']] != {k: cache[k] for k in CACHE_FIELDS} or \
                    current_time()-timestamp(actual[cache['id']]['last_accessed_at']) < \
                    datetime.timedelta(hours=POLICY['recent_access_hours']):
                result['deferred'].append({'id': cache['id'], 'reason': 'cache-changed-or-accessed'}); save(); continue
            request('repos/'+repo+'/actions/caches/'+str(cache['id']), method='DELETE')
            result['deleted'].append(cache['id']); result['deleted_bytes'] += cache['size_in_bytes']; save()
        result['result'] = 'pass'
    except Exception as error:
        result.update(result='blocked', error=str(error)[-2000:])
        raise
    finally:
        result['completed_at'] = now(); save()
    return result
