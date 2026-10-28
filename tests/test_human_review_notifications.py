"""Human-required changes create real, idempotent GitHub review requests."""
import copy
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from automation import evidence, notifications as notify, releases, review
from automation.common import MaintenanceError, canonical, digest

ROOT = Path(__file__).resolve().parents[1]
REPO, BASE, HEAD, SOURCE = 'Lanrith/lanrith', 'a'*40, 'b'*40, 'c'*40


class HumanNotificationTests(unittest.TestCase):
    def setUp(self):
        self.policy = json.loads((ROOT/'security/update-policy.json').read_bytes())
        self.pr = {'number': 12, 'state': 'open', 'draft': False,
            'user': {'login': self.policy['proposer_login'], 'id': self.policy['proposer_user_id'], 'type': 'Bot'},
            'head': {'sha': HEAD, 'ref': 'security/source-change', 'repo': {'full_name': REPO}},
            'base': {'sha': BASE, 'ref': 'main', 'repo': {'full_name': REPO}}}
        self.permission = 'admin'
        self.requests, self.reviews, self.writes, self.assignees = [], [], [], []
        self.candidate = evidence.candidate(REPO, BASE, canonical(self.policy), {'.go-version': b'1.27.2\n'},
            {'.go-version': b'1.27.3\n'}, [{'id': 'GO-2026-6809', 'type': 'security-fix', 'ecosystem': 'Go',
                'package': 'stdlib', 'installed': '1.27.2', 'fixed': '1.27.3',
                'source': 'https://api.osv.dev/v1/vulns/GO-2026-6809', 'evidence_sha256': 'd'*64}], SOURCE)
        self.files = [{'filename': '.go-version', 'status': 'modified'}, {'filename': evidence.CANDIDATE, 'status': 'added'}]

    def api(self, endpoint, **kwargs):
        if kwargs.get('method'):
            self.writes.append((endpoint, kwargs))
            if endpoint.endswith('/requested_reviewers'):
                self.requests.append({'login': notify.HUMAN_REVIEWER})
                return {'requested_reviewers': self.requests}
            self.assignees.append({'login': notify.HUMAN_REVIEWER})
            return {'assignees': self.assignees}
        if '/collaborators/' in endpoint:
            return {'permission': self.permission, 'user': {'login': notify.HUMAN_REVIEWER, 'type': 'User', 'id': 7}}
        if endpoint.endswith('/requested_reviewers'):
            return {'users': self.requests}
        if '/issues/' in endpoint:
            return {'number': 12, 'state': 'open', 'assignees': self.assignees}
        return copy.deepcopy(self.pr)

    def pages(self, endpoint):
        if '/files?' in endpoint:
            return self.files
        if '/reviews?' in endpoint:
            return self.reviews
        return [self.pr]

    def contents(self, repo, name, source):
        return canonical(self.policy if name == 'security/update-policy.json' else self.candidate)

    def request(self):
        with patch.object(notify, 'api', side_effect=self.api), patch.object(notify, 'pages', side_effect=self.pages):
            return notify.request_review(REPO, 12, HEAD, 'Human-required source change.')

    def route(self, enabled='true'):
        with patch.object(notify, 'api', side_effect=self.api), patch.object(notify, 'pages', side_effect=self.pages), \
                patch.object(notify, 'contents', side_effect=self.contents):
            return notify.route(REPO, 12, SOURCE, enabled)

    def test_request_posts_only_the_configured_human_and_never_an_approval(self):
        self.assertEqual(self.request()['state'], 'requested')
        self.assertEqual(self.writes, [('repos/'+REPO+'/pulls/12/requested_reviewers',
            {'method': 'POST', 'payload': {'reviewers': ['mikenorgate']}})])

    def test_pending_requests_are_not_repeated_on_each_ci_completion(self):
        self.request()
        self.assertEqual(self.request()['state'], 'already-requested')
        self.assertEqual(len(self.writes), 1)

    def test_current_human_review_is_respected_and_new_heads_get_a_new_request(self):
        self.reviews = [{'id': 9, 'state': 'APPROVED', 'commit_id': HEAD, 'user': {'login': 'mikenorgate'}}]
        self.assertEqual(self.request()['state'], 'already-reviewed-current-head')
        self.assertEqual(self.writes, [])
        self.reviews[0]['commit_id'] = 'd'*40
        self.assertEqual(self.request()['state'], 'requested')

    def test_drafts_and_closed_prs_do_not_notify_until_ready(self):
        self.pr['draft'] = True
        self.assertEqual(self.route()['state'], 'deferred-draft-or-closed')
        self.assertEqual(self.writes, [])
        self.pr['draft'] = False
        self.assertEqual(self.route()['state'], 'requested')

    def test_invalid_role_or_changed_subject_cannot_claim_notification_success(self):
        self.permission = 'read'
        with self.assertRaises(MaintenanceError):
            self.request()
        self.assertEqual(self.writes, [])
        self.permission = 'admin'
        self.pr['head']['sha'] = 'e'*40
        with self.assertRaises(MaintenanceError):
            self.request()
        self.assertEqual(self.writes, [])

    def test_human_authored_pr_assigns_attention_instead_of_self_review(self):
        self.pr['user']['login'] = 'mikenorgate'
        self.assertEqual(self.route()['attention_assignment']['state'], 'assigned')
        self.assertTrue(self.writes[0][0].endswith('/issues/12/assignees'))
        self.route()
        self.assertEqual(len(self.writes), 1)

    def test_valid_automatic_candidate_waits_for_app_validation_without_human_noise(self):
        self.pr['head']['ref'] = self.policy['proposal_branch']
        self.assertEqual(self.route()['state'], 'awaiting-independent-automatic-validation')
        self.assertEqual(self.writes, [])

    def test_human_flag_report_only_or_disabled_approval_requests_review(self):
        for mode in ('human', 'pilot', 'disabled'):
            self.setUp()
            self.pr['head']['ref'] = self.policy['proposal_branch']
            if mode == 'human':
                self.candidate['requires_human'] = True
                subject = {k: self.candidate[k] for k in ('repository', 'base_sha', 'changes', 'reasons', 'policy_sha256', 'producer_sha', 'requires_human')}
                self.candidate['candidate_id'] = digest(canonical(subject))
            elif mode == 'pilot':
                self.policy['mode'] = 'report-only'
            with self.subTest(mode=mode):
                self.assertEqual(self.route('false' if mode == 'disabled' else 'true')['state'], 'requested')

    def test_forged_author_policy_producer_or_file_scope_cannot_suppress_review(self):
        for attack in ('author', 'policy', 'producer', 'files'):
            self.setUp()
            self.pr['head']['ref'] = self.policy['proposal_branch']
            if attack == 'author': self.pr['user']['login'] = 'attacker'
            elif attack == 'policy': self.candidate['policy_sha256'] = 'f'*64
            elif attack == 'producer': self.candidate['producer_sha'] = 'f'*40
            else: self.files.append({'filename': 'automation/review.py', 'status': 'modified'})
            with self.subTest(attack=attack):
                self.assertEqual(self.route()['state'], 'requested')

    def test_untrusted_event_cannot_choose_a_review_target(self):
        event = {'repository': {'full_name': REPO}, 'workflow_run': {'event': 'push', 'head_sha': HEAD, 'path': '.github/workflows/review-routing.yml'}}
        with self.assertRaises(MaintenanceError):
            notify.event_requests(REPO, event, SOURCE, 'true')

    def test_missing_api_confirmation_cannot_be_recorded_as_a_sent_request(self):
        def api(endpoint, **kwargs):
            if kwargs.get('method'):
                return {'requested_reviewers': []}
            return self.api(endpoint, **kwargs)
        with patch.object(notify, 'api', side_effect=api), patch.object(notify, 'pages', side_effect=self.pages), \
                self.assertRaises(MaintenanceError):
            notify.request_review(REPO, 12, HEAD, 'Human required.')

    def test_blocked_resolver_assigns_the_attention_issue_when_no_pr_can_be_formed(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary)/'blocked.json'
            evidence.write(path, {'error': 'A new module requires human review.', 'run_url': 'https://example.test/run'})
            with patch.dict(os.environ, {'GITHUB_RUN_ID': '123'}), \
                    patch.object(releases, 'pages', return_value=[]), patch.object(releases, 'api', return_value={'number': 42}), \
                    patch.object(notify, 'assign_attention', return_value={'state': 'assigned'}) as assign:
                releases.blocked_issue(REPO, path)
                assign.assert_called_once_with(REPO, 42)

    def test_admission_requests_manual_review_even_while_ci_is_pending_or_failed(self):
        for state in ('completed', 'pending', 'failed'):
            record = {'candidate': {}, 'head_sha': HEAD, 'findings': ['Outside automatic source inputs.'],
                      'eligible': False, 'validation_pending': []}
            def api(endpoint, **kwargs):
                if '/check-runs?' in endpoint:
                    return {'total_count': 0, 'check_runs': []}
                if kwargs.get('method'):
                    return {'id': 99, 'app': {'id': self.policy['reviewer_app_id']}}
                return self.pr
            waiting = review.ValidationPending([{'workflow': 'CI', 'status': 'in_progress', 'url': 'https://example.test/run'}], [])
            with self.subTest(state=state), tempfile.TemporaryDirectory() as temporary, \
                    patch.object(review, 'inspect', return_value=(record, self.policy)), patch.object(review, 'api', side_effect=api), \
                    patch.object(review, 'pages', return_value=[]), patch.object(review, 'validation_runs',
                        side_effect=None if state == 'completed' else waiting if state == 'pending' else MaintenanceError('CI failed'), return_value=[]), \
                    patch.object(notify, 'request_review', return_value={'state': 'requested'}) as request:
                result = review.admission(REPO, 12, Path(temporary)/'record.json', SOURCE,
                    self.policy['reviewer_app_id'], notify=True)
                request.assert_called_once()
                self.assertEqual(result['human_review_request']['state'], 'requested')


class ApprovalFailureCliEvidenceTests(unittest.TestCase):
    def test_an_automatic_approval_failure_requests_and_records_human_attention(self):
        spec = importlib.util.spec_from_file_location('maintenance_failed_approval_entry', ROOT/'scripts/security-updates.py')
        entry = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(entry)
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary)/'update-record.json'
            def blocked(*args):
                evidence.write(path, {'eligible': False, 'findings': [], 'approval': {'review_id': 21}, 'head_sha': HEAD})
                raise MaintenanceError('Repository write authority was revoked')
            with patch('sys.argv', ['security-updates.py', 'approve', '--repository', REPO,
                    '--source', SOURCE, '--pr', '12', '--output', str(path)]), \
                    patch.object(entry.review, 'approve', side_effect=blocked), \
                    patch.object(entry.notifications, 'request_review', return_value={'state': 'requested'}) as request, \
                    self.assertRaises(MaintenanceError):
                entry.main()
            self.assertEqual(request.call_args.args[:3], (REPO, 12, HEAD))
            self.assertEqual(evidence.read(path)['human_review_request']['state'], 'requested')

    def test_actual_submitted_review_survives_cli_error_handling(self):
        spec = importlib.util.spec_from_file_location('maintenance_entry', ROOT/'scripts/security-updates.py')
        entry = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(entry)
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary)/'update-record.json'
            def blocked(*args):
                evidence.write(path, {'eligible': False, 'findings': [], 'approval': {'review_id': 21}})
                evidence.write(path.with_name('approval-recheck.json'), {'eligible': True, 'findings': [], 'approval': None})
                raise MaintenanceError('Authority check failed')
            with patch('sys.argv', ['security-updates.py', 'approve', '--repository', REPO,
                    '--source', SOURCE, '--pr', '12', '--output', str(path)]), \
                    patch.object(entry.review, 'approve', side_effect=blocked), self.assertRaises(MaintenanceError):
                entry.main()
            self.assertEqual(evidence.read(path)['approval']['review_id'], 21)
