"""Unfinished qualification blocks admission without claiming a test failure."""

import copy
import datetime
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from automation import evidence, inputs, review
from automation.common import MaintenanceError, canonical


ROOT = Path(__file__).resolve().parents[1]
REPO = 'Lanrith/lanrith'
BASE, HEAD, PRODUCER = 'a'*40, 'b'*40, 'c'*40
CHECK = '.github/workflows/check.yml'
PACKAGE = '.github/workflows/package-check.yml'


def policy():
    value = json.loads((ROOT/'security/update-policy.json').read_text())
    value['required_workflows'] = {CHECK: ['Required checks']}
    return value


class PendingValidationTests(unittest.TestCase):
    def setUp(self):
        self.clock = datetime.datetime(2026, 10, 26, 10, tzinfo=datetime.timezone.utc)
        self.policy = policy()
        self.pr = {'number': 16, 'head': {'sha': HEAD, 'repo': {'full_name': REPO}},
                   'base': {'sha': BASE}}
        self.run = {'id': 123, 'run_attempt': 1, 'head_sha': HEAD, 'event': 'pull_request',
            'path': CHECK, 'head_repository': {'full_name': REPO}, 'status': 'in_progress',
            'conclusion': None, 'updated_at': self.clock.isoformat(),
            'html_url': 'https://github.com/'+REPO+'/actions/runs/123',
            'pull_requests': [{'number': 16, 'head': {'sha': HEAD}, 'base': {'sha': BASE}}]}
        self.runs = {CHECK: [self.run]}
        self.jobs = {'total_count': 1, 'jobs': [{'id': 456, 'name': 'Required checks',
                                              'status': 'completed', 'conclusion': 'success'}]}
        self.job_requests = []

    def get(self, endpoint):
        if '/jobs?' in endpoint:
            self.job_requests.append(endpoint)
            return self.jobs
        name = endpoint.split('/workflows/')[1].split('/runs?')[0]
        return {'workflow_runs': self.runs['.github/workflows/'+name]}

    def evaluate(self):
        return review.validation_runs(REPO, self.pr, self.policy, get=self.get, clock=self.clock)

    def assert_failure(self):
        with self.assertRaises(MaintenanceError) as caught:
            self.evaluate()
        self.assertNotIsInstance(caught.exception, review.ValidationPending)

    def test_known_unfinished_states_are_pending_with_run_identity(self):
        for state in ('queued', 'in_progress', 'requested', 'waiting', 'pending'):
            self.run['status'] = state
            with self.subTest(state=state), self.assertRaises(review.ValidationPending) as caught:
                self.evaluate()
            waiting = caught.exception.workflows
            self.assertEqual(waiting, [{'workflow': CHECK, 'status': state, 'run_id': 123,
                                       'run_attempt': 1, 'url': self.run['html_url']}])
            self.assertEqual(caught.exception.completed, [])
        self.assertEqual(self.job_requests, [])

    def test_not_yet_started_workflow_is_pending_without_fabricated_run(self):
        self.runs[CHECK] = []
        with self.assertRaises(review.ValidationPending) as caught:
            self.evaluate()
        self.assertEqual(caught.exception.workflows, [{'workflow': CHECK, 'status': 'not_started',
            'url': 'https://github.com/'+REPO+'/actions/workflows/check.yml'}])

    def test_completed_non_success_is_a_failure(self):
        self.run['status'] = 'completed'
        for conclusion in ('failure', 'cancelled', 'skipped', 'timed_out', 'action_required',
                           'neutral', 'stale', 'startup_failure', None):
            self.run['conclusion'] = conclusion
            with self.subTest(conclusion=conclusion):
                self.assert_failure()

    def test_wrong_subject_stale_or_malformed_runs_are_never_pending(self):
        original = copy.deepcopy(self.run)
        mutations = [('head_sha', 'f'*40), ('event', 'push'), ('path', PACKAGE),
            ('head_repository', {'full_name': 'other/fork'}),
            ('pull_requests', [{'number': 16, 'head': {'sha': HEAD}, 'base': {'sha': 'f'*40}}]),
            ('pull_requests', [{'number': 17, 'head': {'sha': HEAD}, 'base': {'sha': BASE}}]),
            ('updated_at', (self.clock-datetime.timedelta(hours=13)).isoformat()),
            ('updated_at', (self.clock+datetime.timedelta(minutes=1)).isoformat()),
            ('status', 'unknown'), ('conclusion', 'failure')]
        for field, value in mutations:
            self.run = copy.deepcopy(original)
            self.run[field] = value
            self.runs[CHECK] = [self.run]
            with self.subTest(field=field, value=value):
                self.assert_failure()

    def test_new_unfinished_run_cannot_reuse_old_success(self):
        old = dict(self.run, id=122, status='completed', conclusion='success')
        self.runs[CHECK] = [self.run, old]
        with self.assertRaises(review.ValidationPending) as caught:
            self.evaluate()
        self.assertEqual(caught.exception.workflows[0]['run_id'], 123)

    def test_pending_workflow_does_not_hide_failure_in_another_workflow(self):
        self.runs[PACKAGE] = [dict(self.run, path=PACKAGE, id=124, status='completed', conclusion='failure')]
        for paths in ((CHECK, PACKAGE), (PACKAGE, CHECK)):
            self.policy['required_workflows'] = {name: ['Required checks'] for name in paths}
            with self.subTest(paths=paths):
                self.assert_failure()

    def test_pending_record_preserves_already_successful_validation(self):
        self.run.update(status='completed', conclusion='success')
        self.runs[PACKAGE] = [dict(self.run, path=PACKAGE, id=124, status='queued', conclusion=None)]
        self.policy['required_workflows'][PACKAGE] = ['Unsigned package compilation']
        with self.assertRaises(review.ValidationPending) as caught:
            self.evaluate()
        self.assertEqual(caught.exception.completed[0]['run_id'], 123)
        self.assertEqual(caught.exception.completed[0]['base_sha'], BASE)
        self.assertEqual(caught.exception.workflows[0]['run_id'], 124)

    def test_finished_run_still_requires_each_mandatory_job(self):
        self.run.update(status='completed', conclusion='success')
        for status, conclusion in (('in_progress', None), ('completed', 'skipped'), ('completed', 'failure')):
            self.jobs['jobs'][0].update(status=status, conclusion=conclusion)
            with self.subTest(status=status, conclusion=conclusion):
                self.assert_failure()


class PendingAdmissionTests(unittest.TestCase):
    def setUp(self):
        self.policy = policy()
        self.pr = {'head': {'ref': 'security/manual-repair', 'repo': {'full_name': REPO}}}
        self.record = evidence.decision({}, head=HEAD, base=BASE, policy=canonical(self.policy),
            checks=[], eligible=False, findings=['PR is outside the automatic security-update lane.'],
            reviewer_source=PRODUCER)
        self.waiting = [{'workflow': PACKAGE, 'status': 'in_progress', 'run_id': 123,
                         'run_attempt': 1, 'url': 'https://github.com/'+REPO+'/actions/runs/123'}]
        self.completed = [{'workflow': CHECK, 'run_id': 122}]
        self.validation_error = review.ValidationPending(self.waiting, self.completed)
        self.checks, self.writes = [], []

    def api(self, endpoint, **kwargs):
        if kwargs.get('method'):
            self.writes.append((endpoint, kwargs))
            payload = kwargs['payload']
            if kwargs['method'] == 'POST':
                check = {'id': 99, 'app': {'id': self.policy['reviewer_app_id']},
                         **copy.deepcopy(payload)}
                self.checks.append(check)
            else:
                check = next(c for c in self.checks if endpoint.endswith('/'+str(c['id'])))
                check.update(copy.deepcopy(payload))
            return copy.deepcopy(check)
        if '/check-runs?' in endpoint:
            return {'total_count': len(self.checks), 'check_runs': copy.deepcopy(self.checks)}
        return self.pr

    def admit(self):
        with tempfile.TemporaryDirectory() as temporary, \
                patch.object(review, 'inspect', return_value=(copy.deepcopy(self.record), self.policy)), \
                patch.object(review, 'api', side_effect=self.api), \
                patch.object(review, 'pages', return_value=[{'filename': 'automation/review.py'}]), \
                patch.object(review, 'validation_runs', side_effect=self.validation_error,
                             return_value=self.completed) as validation:
            path = Path(temporary)/'decision.json'
            result = review.admission(REPO, 16, path, PRODUCER, self.policy['reviewer_app_id'])
            self.assertEqual(result, evidence.read(path))
            return result, validation

    def automatic(self, mode):
        self.policy['mode'] = mode
        self.pr['head']['ref'] = self.policy['proposal_branch']
        self.record.update(findings=[], validation_pending=self.waiting, validation=self.completed)

    def test_manual_qualification_waits_and_archives_run_identity_without_approval(self):
        result, validation = self.admit()
        self.assertIsNone(result['admission_check']['conclusion'])
        self.assertEqual(result['validation_pending'], self.waiting)
        self.assertEqual(result['validation'], self.completed)
        self.assertFalse(result['eligible'])
        self.assertTrue(result['admission_check']['manual_review_required'])
        self.assertTrue(validation.call_args.kwargs['manual'])
        self.assertEqual(self.checks[0]['status'], 'in_progress')
        self.assertEqual(self.checks[0]['details_url'], self.waiting[0]['url'])
        self.assertIn('Waiting', self.checks[0]['output']['title'])
        self.assertIn(str(self.waiting[0]['run_id']), self.checks[0]['output']['summary'])
        self.assertFalse(any(endpoint.endswith('/reviews') for endpoint, _ in self.writes))

    def test_automatic_pending_blocks_report_only_and_enforcement_lanes(self):
        for mode in ('report-only', 'enforce'):
            self.setUp()
            self.automatic(mode)
            with self.subTest(mode=mode):
                result, validation = self.admit()
                validation.assert_not_called()
                self.assertIsNone(result['admission_check']['conclusion'])
                self.assertFalse(result['eligible'])
                self.assertEqual(len(self.writes), 1)
                self.assertEqual(self.checks[0]['status'], 'in_progress')

    def test_finished_success_completes_existing_pending_manual_check(self):
        first, _ = self.admit()
        self.validation_error = None
        second, _ = self.admit()
        self.assertEqual(second['admission_check']['id'], first['admission_check']['id'])
        self.assertEqual(len(self.checks), 1)
        self.assertEqual(self.checks[0]['status'], 'completed')
        self.assertEqual(self.checks[0]['conclusion'], 'success')
        self.assertEqual(second['validation_pending'], [])
        self.assertTrue(second['admission_check']['manual_review_required'])
        self.assertIsNone(second['approval'])

    def test_real_failure_completes_existing_pending_check_as_failure(self):
        self.admit()
        self.validation_error = MaintenanceError('Native qualification failed.')
        result, _ = self.admit()
        self.assertEqual(len(self.checks), 1)
        self.assertEqual(self.checks[0]['conclusion'], 'failure')
        self.assertIn('Native qualification failed', self.checks[0]['output']['summary'])
        self.assertEqual(result['validation_pending'], [])

    def test_eligible_automatic_enforcement_still_waits_for_separate_approval(self):
        self.automatic('enforce')
        self.admit()
        self.record.update(eligible=True, validation_pending=[])
        result, _ = self.admit()
        self.assertEqual(len(self.checks), 1)
        self.assertEqual(self.checks[0]['status'], 'in_progress')
        self.assertIsNone(result['admission_check']['conclusion'])
        self.assertIsNone(result['approval'])

    def test_automatic_failure_is_not_hidden_by_pending_metadata(self):
        self.automatic('enforce')
        self.record['findings'] = ['Advisory evidence changed.']
        result, _ = self.admit()
        self.assertEqual(result['admission_check']['conclusion'], 'failure')
        self.assertEqual(self.checks[0]['conclusion'], 'failure')
        self.assertIn('Advisory evidence changed', self.checks[0]['output']['summary'])

    def test_other_apps_or_sources_cannot_supply_the_waiting_check(self):
        for mutation in ({'app': {'id': self.policy['proposer_app_id']}}, {'head_sha': 'f'*40}):
            self.setUp()
            self.checks = [{'id': 98, 'name': 'Security update admission', 'head_sha': HEAD,
                            'app': {'id': self.policy['reviewer_app_id']}, 'status': 'in_progress', **mutation}]
            with self.subTest(mutation=mutation):
                result, _ = self.admit()
                self.assertEqual(result['admission_check']['id'], 99)
                self.assertEqual(self.checks[0]['status'], 'in_progress')

    def test_pending_inspection_cannot_submit_an_approval(self):
        self.automatic('enforce')
        with tempfile.TemporaryDirectory() as temporary, \
                patch.object(review, 'inspect', return_value=(self.record, self.policy)), \
                patch.object(review, 'api') as api:
            path = Path(temporary)/'decision.json'
            evidence.write(path, self.record)
            with self.assertRaises(MaintenanceError):
                review.approve(REPO, 16, path, PRODUCER, 'true')
            api.assert_not_called()


class PendingInspectionTests(unittest.TestCase):
    def test_pending_is_structured_and_never_eligible_even_with_no_source_findings(self):
        value = policy()
        candidate = evidence.candidate(REPO, BASE, canonical(value), {'.go-version': b'old'},
            {'.go-version': b'new'}, [{'id': 'test', 'type': 'security-fix'}], PRODUCER)
        pr = {'state': 'open', 'draft': False, 'number': 16, 'html_url': 'https://github.com/'+REPO+'/pull/16',
            'base': {'sha': BASE, 'ref': 'main'},
            'head': {'sha': HEAD, 'ref': value['proposal_branch'], 'repo': {'full_name': REPO}},
            'user': {'login': value['proposer_login'], 'type': 'Bot', 'id': value['proposer_user_id']}}
        def api(endpoint):
            if '/pulls/' in endpoint:
                return pr
            return {'sha': BASE} if endpoint.endswith('/commits/main') else {'merge_base_commit': {'sha': BASE}}
        def contents(repo, name, revision):
            if name == 'security/update-policy.json':
                return canonical(value)
            if name == evidence.CANDIDATE:
                return canonical(candidate)
            return b'old' if revision == BASE else b'new'
        waiting = [{'workflow': PACKAGE, 'status': 'in_progress', 'url': pr['html_url']}]
        files = [{'filename': '.go-version', 'status': 'modified'},
                 {'filename': evidence.CANDIDATE, 'status': 'added'}]
        for findings in ([], [inputs.HUMAN_NPM_REVIEW]):
            candidate['requires_human'] = bool(findings)
            with self.subTest(findings=findings), tempfile.TemporaryDirectory() as temporary, \
                    patch.object(review, 'api', side_effect=api), \
                    patch.object(review, 'contents', side_effect=contents), \
                    patch.object(review, 'pages', return_value=files), \
                    patch.object(evidence, 'validate_candidate', side_effect=lambda record: record), \
                    patch.object(review, 'validate_reasons'), \
                    patch.object(inputs, 'validate_changes', return_value=findings), \
                    patch.object(review, 'validation_runs', side_effect=review.ValidationPending(waiting, [])):
                path = Path(temporary)/'decision.json'
                result, _ = review.inspect(REPO, 16, PRODUCER, path)
                self.assertFalse(result['eligible'])
                self.assertEqual(result['findings'], findings)
                self.assertEqual(result['validation_pending'], waiting)
                self.assertEqual(evidence.read(path), result)
