"""Cache retention must protect useful generations and refuse unsafe deletion races."""

import copy
import datetime
import importlib.util
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

from automation import cache_cleanup, cleanup
from automation.common import MaintenanceError


REPO = 'Lanrith/lanrith'
CLOCK = datetime.datetime(2026, 11, 4, 9, tzinfo=datetime.timezone.utc)
ROOT = Path(__file__).resolve().parents[1]


class GitHub:
    def __init__(self):
        self.caches = [self.cache(n) for n in range(1, 8)]
        self.runs = {100+n: self.run(n) for n in range(1, 8)}
        self.active = []
        self.deleted = []
        self.after_delete = None

    def cache(self, n, *, age=None):
        created = CLOCK-datetime.timedelta(hours=age if age is not None else (8-n)*3)
        return {'id': n, 'key': 'lanrith-build-v1-Linux-X64-'+'a'*64+'-'+str(100+n)+'-1',
                'ref': 'refs/heads/main', 'version': 'b'*64, 'size_in_bytes': 100,
                'created_at': created.isoformat(), 'last_accessed_at': created.isoformat()}

    def run(self, n):
        return {'id': 100+n, 'run_attempt': 1, 'name': 'Release', 'path': '.github/workflows/release.yml',
                'event': 'push', 'head_branch': 'main', 'head_sha': f'{n:040x}', 'status': 'completed',
                'conclusion': 'success', 'updated_at': (CLOCK-datetime.timedelta(hours=2)).isoformat(),
                'head_repository': {'full_name': REPO}}

    def __call__(self, endpoint, **kwargs):
        if kwargs.get('method') == 'DELETE':
            self.assert_cache_endpoint(endpoint)
            identity = int(endpoint.rsplit('/', 1)[-1])
            self.deleted.append(identity)
            self.caches = [c for c in self.caches if c['id'] != identity]
            if self.after_delete:
                self.after_delete(identity)
            return None
        if '/actions/caches?' in endpoint:
            assert kwargs.get('paginate')
            return [{'total_count': len(self.caches), 'actions_caches': copy.deepcopy(self.caches)}]
        if '/actions/runs?status=' in endpoint:
            assert kwargs.get('paginate')
            state = endpoint.split('status=', 1)[1].split('&', 1)[0]
            values = [r for r in self.active if r['status'] == state]
            return [{'total_count': len(values), 'workflow_runs': copy.deepcopy(values)}]
        if '/actions/runs/' in endpoint:
            return copy.deepcopy(self.runs[int(endpoint.rsplit('/', 1)[-1])])
        raise AssertionError(endpoint)

    def assert_cache_endpoint(self, endpoint):
        assert endpoint.startswith('repos/'+REPO+'/actions/caches/')


class BuildCacheCleanupTests(unittest.TestCase):
    def setUp(self):
        self.github = GitHub()

    def plan(self):
        return cache_cleanup.plan(REPO, get=self.github, clock=CLOCK)

    def execute(self, record):
        self.progress = []
        return cache_cleanup.execute(record, request=self.github, clock=CLOCK,
            progress=lambda value: self.progress.append(copy.deepcopy(value)))

    def test_keep_two_successful_sources_and_select_only_oldest_obsolete_caches(self):
        record = self.plan()
        self.assertEqual([c['id'] for c in record['caches']], [1, 2, 3, 4, 5])
        self.assertEqual([c['id'] for c in record['protected_successful']], [7, 6])
        self.assertEqual(record['bytes'], 500)

    def test_multiple_attempts_of_one_source_do_not_crowd_out_the_previous_source(self):
        self.github.runs[106]['head_sha'] = self.github.runs[107]['head_sha']
        record = self.plan()
        self.assertEqual([c['id'] for c in record['protected_successful']], [7, 5])
        self.assertIn(6, [c['id'] for c in record['caches']])

    def test_other_repositories_keys_and_refs_are_never_addressed(self):
        for slug in ('router-policy-agent', 'discovery-bridge'):
            self.assertEqual(cache_cleanup.plan('Lanrith/'+slug, get=lambda *a, **k: self.fail('unexpected API'))['caches'], [])
        for change in ({'key': 'owner-private-data'}, {'ref': 'refs/pull/9/merge'}, {'key': 'lanrith-build-v1-../../authority'}):
            with self.subTest(change=change):
                self.github = GitHub(); self.github.caches[0].update(change)
                self.assertNotIn(1, [c['id'] for c in self.plan()['caches']])

    def test_minimum_generation_floor_never_prunes_two_remaining_caches(self):
        self.github.caches = self.github.caches[-2:]
        self.assertEqual(self.plan()['caches'], [])

    def test_recent_access_and_future_clock_skew_are_protected(self):
        for accessed in (CLOCK-datetime.timedelta(minutes=30), CLOCK+datetime.timedelta(minutes=1)):
            self.github.caches[0]['last_accessed_at'] = accessed.isoformat()
            self.assertNotIn(1, [c['id'] for c in self.plan()['caches']])

    def test_unknown_and_running_producers_are_protected(self):
        for change in ({'path': '.github/workflows/untrusted.yml'}, {'head_branch': 'feature'},
                       {'head_repository': {'full_name': 'attacker/repo'}}, {'head_repository': None},
                       {'conclusion': None}, {'status': 'in_progress'}):
            with self.subTest(change=change):
                self.github = GitHub(); self.github.runs[101].update(change)
                self.assertNotIn(1, [c['id'] for c in self.plan()['caches']])

    def test_only_one_recent_failed_release_cache_gets_the_extra_retry_window(self):
        for n, age in ((8, 4), (9, 3)):
            self.github.caches.append(self.github.cache(n, age=age)); self.github.runs[100+n] = self.github.run(n)
            self.github.runs[100+n]['conclusion'] = 'failure'
        record = self.plan()
        self.assertNotIn(9, [c['id'] for c in record['caches']])
        self.assertIn(8, [c['id'] for c in record['caches']])
        self.github.caches[-1].update(self.github.cache(9, age=25))
        self.github.caches[-2].update(self.github.cache(8, age=26))
        self.assertTrue({8, 9} <= {c['id'] for c in self.plan()['caches']})

    def test_pending_or_active_workflows_defer_pruning_but_cleanup_does_not_block_itself(self):
        for state in ('queued', 'in_progress', 'waiting', 'pending', 'requested'):
            self.github.active = [{'id': 900, 'path': '.github/workflows/new-consumer.yml', 'status': state, 'head_branch': 'main'}]
            self.assertEqual(self.plan()['caches'], [])
        self.github.active = [{'id': 900, 'path': '.github/workflows/cleanup-artifacts.yml', 'status': 'in_progress', 'head_branch': 'main'}]
        self.assertEqual(len(self.plan()['caches']), 5)

    def test_api_enumeration_and_deletion_budgets_are_bounded(self):
        def incomplete(endpoint, **kwargs):
            return [{'total_count': 1000, 'actions_caches': []}]
        with self.assertRaises(MaintenanceError): cache_cleanup.plan(REPO, get=incomplete, clock=CLOCK)
        self.github.caches.append(copy.deepcopy(self.github.caches[0]))
        with self.assertRaises(MaintenanceError): self.plan()
        self.github = GitHub()
        self.github.caches = [self.github.cache(n, age=100-n) for n in range(1, 41)]
        self.github.runs = {100+n: self.github.run(n) for n in range(1, 41)}
        self.assertEqual(len(self.plan()['caches']), 20)

    def test_exact_revalidated_plan_deletes_only_obsolete_caches_and_records_bytes(self):
        result = self.execute(self.plan())
        self.assertEqual(self.github.deleted, [1, 2, 3, 4, 5])
        self.assertEqual(result['deleted_bytes'], 500)
        self.assertEqual(result['result'], 'pass')
        self.assertEqual(self.progress[-1], result)
        self.assertEqual({c['id'] for c in self.github.caches}, {6, 7})

    def test_forged_plan_cannot_delete_a_current_protected_generation_or_change_policy(self):
        record = self.plan(); record['caches'] = [record['protected_successful'][0]]
        result = self.execute(record)
        self.assertEqual(self.github.deleted, [])
        self.assertEqual(result['deferred'][0]['id'], 7)
        record['policy']['successful_sources'] = 0
        with self.assertRaises(MaintenanceError): self.execute(record)

    def test_expired_plan_is_rejected_before_any_delete(self):
        record = self.plan(); record['created_at'] = (CLOCK-datetime.timedelta(hours=3)).isoformat()
        with self.assertRaises(MaintenanceError): self.execute(record)
        self.assertEqual(self.github.deleted, [])

    def test_recently_accessed_or_externally_evicted_cache_is_not_claimed_deleted(self):
        record = self.plan(); self.github.caches[0]['last_accessed_at'] = CLOCK.isoformat()
        result = self.execute(record)
        self.assertNotIn(1, result['deleted'])
        self.assertEqual(result['deferred'][0]['id'], 1)
        self.github = GitHub(); record = self.plan(); self.github.caches = self.github.caches[1:]
        result = self.execute(record)
        self.assertEqual(result['already_absent'], [1])
        self.assertNotIn(1, self.github.deleted)

    def test_consumer_starting_during_cleanup_defers_every_remaining_candidate(self):
        def start(_):
            self.github.active = [{'id': 900, 'path': '.github/workflows/release.yml', 'status': 'queued', 'head_branch': 'main'}]
        record = self.plan(); self.github.after_delete = start
        result = self.execute(record)
        self.assertEqual(result['deleted'], [1])
        self.assertEqual([c['id'] for c in result['deferred']], [2, 3, 4, 5])

    def test_retained_floor_disappearing_stops_further_deletions(self):
        def evict(_): self.github.caches = [c for c in self.github.caches if c['id'] != 7]
        record = self.plan(); self.github.after_delete = evict
        result = self.execute(record)
        self.assertEqual(result['deleted'], [1])
        self.assertEqual(result['deferred'][0]['reason'], 'retained-floor-changed')

    def test_producer_rerun_after_partial_cleanup_preserves_actual_progress_and_blocks(self):
        def rerun(_): self.github.runs[102]['run_attempt'] = 2
        record = self.plan(); self.github.after_delete = rerun
        with self.assertRaises(MaintenanceError): self.execute(record)
        self.assertEqual(self.github.deleted, [1])
        self.assertEqual(self.progress[-1]['result'], 'blocked')

    def test_cache_only_work_uses_the_existing_workflow_gate_and_signed_cleanup_result(self):
        spec = importlib.util.spec_from_file_location('cache_cleanup_cli', ROOT/'scripts/security-updates.py')
        cli = importlib.util.module_from_spec(spec); spec.loader.exec_module(cli)
        nested = self.plan()
        record = {'schema': 1, 'kind': 'temporary-artifact-cleanup', 'repository': REPO,
                  'artifacts': [], 'bytes': 0, 'build_caches': nested}
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); flags = root/'outputs'
            with patch.object(sys, 'argv', ['security-updates.py', 'cleanup', '--repository', REPO, '--output', str(root/'plan.json')]), \
                    patch.dict(os.environ, {'GITHUB_OUTPUT': str(flags)}), patch.object(cli.cleanup, 'plan', return_value=record):
                cli.main()
            self.assertEqual(flags.read_text(), 'has-artifacts=true\n')
        with patch.object(cleanup, 'api', side_effect=self.github), patch.object(cache_cleanup.datetime, 'datetime', wraps=datetime.datetime) as clock:
            clock.now.return_value = CLOCK
            result = cleanup.execute(record)
        self.assertEqual(result['deleted'], [])
        self.assertEqual(result['build_caches']['deleted'], [1, 2, 3, 4, 5])
        self.assertEqual(result['result'], 'pass')
