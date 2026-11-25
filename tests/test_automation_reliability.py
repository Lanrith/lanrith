"""Regression coverage for missed findings, unsafe recovery and partial update bundles."""
import copy
import datetime
import json
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from automation import control_updates as control, published_go, python_dependencies as python, reconcile, releases, evidence
from automation.common import MaintenanceError, canonical

ROOT = Path(__file__).resolve().parents[1]
REPO = 'Lanrith/lanrith'


class PublishedCoverageTests(unittest.TestCase):
    def scan(self, *findings):
        return b'\n'.join(canonical(r) for r in [
            {'config': {'scanner_name': 'govulncheck', 'scan_mode': 'binary', 'scan_level': 'symbol', 'db': 'https://vuln.go.dev'}},
            {'SBOM': {'go_version': 'go1.27.4', 'modules': [{'path': 'example.org/a', 'version': 'v1.2.0'},
                                                        {'path': 'example.org/a/nested', 'version': 'v1.3.0'}]}},
            *({'finding': f} for f in findings)])

    def test_reachable_nested_module_uses_complete_binary_inventory(self):
        finding = {'osv': 'GO-2026-1234', 'trace': [{'module': 'example.org/a', 'package': 'example.org/a/nested/pkg',
                                                'version': 'v1.2.0', 'function': 'Unsafe'}]}
        self.assertEqual(published_go.findings(self.scan(finding)), [('GO-2026-1234', 'example.org/a/nested', 'v1.3.0')])
        del finding['trace'][0]['function']
        self.assertEqual(published_go.findings(self.scan(finding)), [])

    def test_missing_inventory_or_wrong_scan_mode_fails_closed(self):
        for raw in (b'{}', b'', self.scan().replace(b'"binary"', b'"source"'),
                    self.scan().replace(b'"SBOM"', b'"missing"')):
            with self.subTest(raw=raw[:50]), self.assertRaises(MaintenanceError):
                published_go.findings(raw)

    def test_unlisted_reachable_dependency_produces_specific_blocker(self):
        result = published_go.covered('alloy', [('GO-2026-1234', 'example.org/unlisted', 'v1.0.0')], ROOT, {})
        self.assertEqual(len(result), 1)
        self.assertIn('example.org/unlisted', result[0])

    def test_increased_version_does_not_clear_an_advisory_that_still_applies(self):
        findings = [('GO-2026-1234', 'go.opentelemetry.io/otel', 'v1.46.0')]
        affected = {'vulns': [{'id': 'GO-2026-1234'}]}
        for response, blocked in (([affected, {}], False), ([affected, affected], True), ([{}, {}], True)):
            with patch.object(published_go, 'osv_queries', return_value=response):
                self.assertEqual(bool(published_go.covered('alloy', findings, ROOT, {})), blocked)


class PythonUpdateTests(unittest.TestCase):
    def setUp(self):
        self.before = (b'[project]\nname="fixture"\ndependencies=["PyYAML==6.0.3"]\n', b'PyYAML==6.0.3\n')
        self.advisory = {'id': 'GHSA-test-test-test', 'affected': [{'package': {'name': 'PyYAML', 'ecosystem': 'PyPI'},
            'ranges': [{'events': [{'introduced': '0'}, {'fixed': '6.0.4'}]}]}]}
        self.reason = {'id': self.advisory['id'], 'ecosystem': 'PyPI'}

    def test_no_findings_preserve_exact_bytes_and_never_pick_latest(self):
        with patch.object(python, 'osv_queries', return_value=[{}]), patch.object(python, 'wheel_hashes') as hashes:
            self.assertEqual(python.resolve(self.before), (self.before, []))
            hashes.assert_not_called()

    def resolve(self, advisory=None):
        with patch.object(python, 'osv_queries', return_value=[{'vulns': [{'id': self.advisory['id']}]}]), \
                patch.object(python, 'fetch_json', return_value=advisory or self.advisory), \
                patch.object(python, 'reason', return_value=self.reason), \
                patch.object(python, 'wheel_hashes', return_value=['a'*64]):
            return python.resolve(self.before, allow_minor=True)

    def test_security_fix_pairs_project_pin_and_verified_wheel_hashes(self):
        after, reasons = self.resolve()
        self.assertIn(b'PyYAML==6.0.4', after[0])
        self.assertEqual(after[1], b'PyYAML==6.0.4 --hash=sha256:'+b'a'*64+b'\n')
        with patch.object(python, 'resolve', return_value=(after, reasons)):
            python.validate(self.before, after, reasons)
            with self.assertRaises(MaintenanceError):
                python.validate(self.before, (after[0]+b'evil=true\n', after[1]), reasons)

    def test_major_prerelease_missing_and_withdrawn_fix_need_human_review(self):
        for selected in ('7.0.0', '6.0.4rc1', ''):
            advisory = copy.deepcopy(self.advisory)
            advisory['affected'][0]['ranges'][0]['events'][1]['fixed'] = selected
            with self.subTest(selected=selected), self.assertRaises(MaintenanceError):
                self.resolve(advisory)
        with self.assertRaises(MaintenanceError):
            self.resolve({**self.advisory, 'withdrawn': '2026-11-24'})

    def test_lock_options_and_dependency_additions_are_rejected(self):
        for raw in (b'PyYAML==6.0.3 --index-url=https://evil.invalid\n', b'Other==1.0.0\n', b'PyYAML==6.0.3\nPyYAML==6.0.3\n'):
            with self.subTest(raw=raw), self.assertRaises(MaintenanceError):
                python.requirements(self.before[0], raw)


class ReconciliationTests(unittest.TestCase):
    def setUp(self):
        self.policy = json.loads((ROOT/'security/update-policy.json').read_bytes())
        self.pr = {'number': 97, 'draft': False, 'head': {'sha': 'a'*40, 'ref': 'dependabot/pip', 'repo': {'full_name': REPO}},
                   'base': {'sha': 'b'*40, 'ref': 'main'}, 'user': {'login': 'dependabot[bot]', 'type': 'Bot'}}
        self.subject = '97:'+('a'*40)+':'+('b'*40)
        self.checks = []
        self.base = 'b'*40
        self.main = 'b'*40

    def api(self, endpoint):
        if '/compare/' in endpoint:
            return {'merge_base_commit': {'sha': self.base}}
        return {'total_count': len(self.checks), 'check_runs': self.checks}

    def decide(self, attempts=None, error=None):
        with patch.object(reconcile, 'api', side_effect=self.api), \
                patch.object(reconcile, 'manual_validation_policy', return_value=self.policy), \
                patch.object(reconcile, 'validation_runs', return_value=[], side_effect=error):
            return reconcile.decision(self.pr, self.policy, attempts or {}, main=self.main)

    def test_missing_admission_recovers_at_most_twice_for_same_subject(self):
        actions, blockers = self.decide()
        self.assertEqual(actions[0]['kind'], 'review')
        actions, blockers = self.decide({self.subject: ['review', 'review']})
        self.assertEqual(actions, [])
        self.assertIn('two recovery attempts', blockers[0])

    def test_failed_ci_generates_blocker_without_repeated_build(self):
        actions, blockers = self.decide(error=MaintenanceError('Required validation did not succeed: CI (failure)'))
        self.assertEqual(actions, [])
        self.assertIn('failure', blockers[0])

    def test_only_bot_branches_can_be_refreshed(self):
        self.base = 'c'*40
        self.assertEqual(self.decide()[0][0]['kind'], 'refresh')
        self.pr['user']['login'] = 'mikenorgate'
        self.assertEqual(self.decide(), ([], []))

    def test_another_apps_success_cannot_satisfy_admission(self):
        self.checks = [{'id': 1, 'name': 'Security update admission', 'app': {'id': 999},
                        'head_sha': 'a'*40, 'conclusion': 'success'}]
        self.assertEqual(self.decide()[0][0]['kind'], 'review')

    def test_manual_updater_pr_recovers_review_but_is_not_blindly_rebased(self):
        self.pr['user'] = {'login': self.policy['proposer_login'], 'id': self.policy['proposer_user_id'], 'type': 'Bot'}
        self.pr['head']['ref'] = 'security/manual-repair'
        self.assertEqual(self.decide()[0][0]['kind'], 'review')
        self.base = 'c'*40
        actions, blockers = self.decide()
        self.assertEqual(actions, [])
        self.assertIn('not rewritten', blockers[0])

    def test_passing_manual_pr_can_recover_a_missed_human_notification(self):
        self.checks = [{'id': 1, 'name': 'Security update admission', 'app': {'id': self.policy['reviewer_app_id']},
                        'head_sha': 'a'*40, 'conclusion': 'success'}]
        self.assertEqual(self.decide()[0][0]['kind'], 'notify')
        self.assertEqual(self.decide({self.subject: ['notify']}), ([], []))

    def test_stale_latest_failure_cannot_rerun_an_older_success(self):
        def api(endpoint):
            if '/workflows/' not in endpoint:
                return self.api(endpoint)
            path = '.github/workflows/'+endpoint.split('/workflows/')[1].split('/')[0]
            run = {'id': 1, 'path': path, 'head_sha': 'a'*40, 'event': 'pull_request', 'status': 'completed',
                   'conclusion': 'success', 'pull_requests': [{'number': 97, 'base': {'sha': 'b'*40}}]}
            return {'workflow_runs': [run, {**run, 'id': 2, 'conclusion': 'failure'}]}
        with patch.object(reconcile, 'api', side_effect=api), \
                patch.object(reconcile, 'manual_validation_policy', return_value=self.policy), \
                patch.object(reconcile, 'validation_runs', side_effect=MaintenanceError('Validation is stale')):
            actions, blockers = reconcile.decision(self.pr, self.policy, {}, main=self.main)
        self.assertEqual(actions, [])
        self.assertTrue(blockers)

    def test_historical_pr_base_cannot_make_an_outdated_branch_appear_current(self):
        self.main = 'c'*40
        subject = '97:'+('a'*40)+':'+self.main
        with patch.object(reconcile, 'api', side_effect=self.api) as api, \
                patch.object(reconcile, 'validation_runs') as validation:
            actions, blockers = reconcile.decision(self.pr, self.policy, {}, main=self.main)
        api.assert_called_once_with('repos/'+REPO+'/compare/'+self.main+'...'+('a'*40))
        validation.assert_not_called()
        self.assertEqual(actions, [{'kind': 'refresh', 'pr': 97, 'head': 'a'*40, 'subject': subject}])
        self.assertEqual(blockers, [])
        self.assertEqual(self.decide({subject: ['refresh']})[0], [])

    def test_historical_manual_branch_never_retries_its_old_validation(self):
        self.main = 'c'*40
        self.pr['user'] = {'login': self.policy['proposer_login'], 'id': self.policy['proposer_user_id'], 'type': 'Bot'}
        self.pr['head']['ref'] = 'security/manual-repair'
        with patch.object(reconcile, 'api', side_effect=self.api), \
                patch.object(reconcile, 'validation_runs') as validation:
            actions, blockers = reconcile.decision(self.pr, self.policy, {}, main=self.main)
        self.assertEqual(actions, [])
        self.assertIn('reviewed rebase', blockers[0])
        validation.assert_not_called()

    def test_security_and_control_candidates_are_regenerated_against_actual_main(self):
        self.main = 'c'*40
        self.pr['user'] = {'login': self.policy['proposer_login'], 'id': self.policy['proposer_user_id'], 'type': 'Bot'}
        for branch, kind in ((self.policy['proposal_branch'], 'proposal'), ('automation/workflow-updates', 'controls')):
            self.pr['head']['ref'] = branch
            with self.subTest(branch=branch):
                self.assertEqual(self.decide()[0][0]['kind'], kind)

    def test_stale_metadata_never_reuses_validation_even_if_head_contains_main(self):
        self.main = self.base = 'c'*40
        with patch.object(reconcile, 'api', side_effect=self.api), \
                patch.object(reconcile, 'validation_runs') as validation:
            actions, blockers = reconcile.decision(self.pr, self.policy, {}, main=self.main)
        self.assertEqual(actions, [])
        self.assertIn('metadata is stale', blockers[0])
        validation.assert_not_called()

    def test_main_is_rechecked_before_dispatch_and_reservations_use_current_main(self):
        self.pr['user'] = {'login': self.policy['proposer_login'], 'id': self.policy['proposer_user_id'], 'type': 'Bot'}
        self.pr['head']['ref'] = self.policy['proposal_branch']
        for advanced in (False, True):
            calls, reads = [], []
            def api(endpoint, **kwargs):
                calls.append((endpoint, kwargs))
                if endpoint.endswith('/commits/main'):
                    reads.append(True)
                    return {'sha': ('d' if advanced and len(reads) > 1 else 'c')*40}
                if '/compare/' in endpoint:
                    return {'merge_base_commit': {'sha': 'b'*40}}
                if endpoint.endswith('/issues'):
                    state = json.loads(kwargs['payload']['body'].split('<!-- recovery-state\n')[1].split('\n-->')[0])
                    self.assertEqual(state, {'97:'+('a'*40)+':'+('c'*40): ['proposal']})
                    return {'number': 100}
                if endpoint.endswith('/pulls/97'):
                    return {**self.pr, 'state': 'open'}
                self.assertTrue(endpoint.endswith('/update-inputs.yml/dispatches'))
                return None
            def pages(endpoint):
                return [] if '/issues?' in endpoint else [self.pr]
            with self.subTest(advanced=advanced), tempfile.TemporaryDirectory() as temporary, \
                    patch.object(reconcile, 'api', side_effect=api), patch.object(reconcile, 'pages', side_effect=pages), \
                    patch.object(reconcile, 'contents', return_value=json.dumps(self.policy).encode()), \
                    patch.dict(os.environ, {'GITHUB_RUN_ID': '123'}):
                if advanced:
                    with self.assertRaisesRegex(MaintenanceError, 'main advanced'):
                        reconcile.reconcile(REPO, Path(temporary)/'result.json', apply=True)
                else:
                    reconcile.reconcile(REPO, Path(temporary)/'result.json', apply=True)
            dispatched = [call for call in calls if call[0].endswith('/dispatches')]
            self.assertEqual(len(dispatched), 0 if advanced else 1)


class ControllerBundleTests(unittest.TestCase):
    def test_preparation_combines_discovery_prs_with_unchanged_controller_references(self):
        base, path = 'e'*40, '.github/workflows/check.yml'
        before = ('    uses: Lanrith/lanrith/.github/workflows/security-review.yml@'+'f'*40+'\n'+
                  '      - uses: actions/checkout@'+'a'*40+' # v7.0.1\n'+
                  '      - uses: actions/github-script@'+'b'*40+' # v8.0.0\n')
        proposed = {'1'*40: before.replace('a'*40, 'c'*40).replace('7.0.1', '7.0.2'),
                    '2'*40: before.replace('b'*40, 'd'*40).replace('8.0.0', '8.0.1')}
        pulls = [{'number': n, 'html_url': f'https://github.com/{REPO}/pull/{n}',
                  'user': {'login': 'dependabot[bot]', 'type': 'Bot'},
                  'head': {'repo': {'full_name': REPO}, 'sha': str(n)*40}} for n in (1, 2)]
        def command(*args, **kwargs):
            if args[:2] == ('git', 'status'):
                return SimpleNamespace(stdout='')
            if args[:2] == ('git', 'rev-parse'):
                return SimpleNamespace(stdout=base)
            self.assertEqual(args, ('git', 'show', base+':'+path))
            return SimpleNamespace(stdout=before)
        def pages(endpoint):
            return [{'filename': path, 'status': 'modified'}] if '/files?' in endpoint else pulls
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root/path).parent.mkdir(parents=True)
            (root/path).write_text(before)
            (root/'security').mkdir()
            with patch.object(control, 'run', side_effect=command), \
                    patch.object(control, 'pages', side_effect=pages), \
                    patch.object(control, 'api', return_value={'merge_base_commit': {'sha': base}}), \
                    patch.object(control, 'contents', side_effect=lambda repo, path, head: proposed[head].encode()), \
                    patch.object(control, 'action_changes', return_value=[{'verified': True}]) as verify:
                record = control.prepare(root, root, REPO)
            self.assertEqual(len(record['updates']), 2)
            self.assertEqual((root/path).read_text(), proposed['1'*40].replace('b'*40, 'd'*40).replace('8.0.0', '8.0.1'))
            self.assertEqual([call.args[0] for call in verify.call_args_list], [before, before])

    def test_independent_action_proposals_in_one_workflow_do_not_revert_each_other(self):
        before = ('      - uses: actions/checkout@'+'a'*40+' # v7.0.1\n'+
                  '      - uses: actions/github-script@'+'b'*40+' # v8.0.0\n')
        first = before.replace('a'*40, 'c'*40).replace('7.0.1', '7.0.2')
        second = before.replace('b'*40, 'd'*40).replace('8.0.0', '8.0.1')
        with patch.object(control, 'action_changes', return_value=[{'verified': True}]):
            merged, _ = control.merge_action_update(before, second, first)
        self.assertEqual(merged, first.replace('b'*40, 'd'*40).replace('8.0.0', '8.0.1'))

    def test_action_merge_rejects_conflicting_pins_without_touching_controller_selection(self):
        before = ('    uses: Lanrith/lanrith/.github/workflows/security-review.yml@'+'e'*40+'\n'+
                  '      - uses: actions/checkout@'+'a'*40+' # v7.0.1\n')
        proposed = before.replace('a'*40, 'b'*40).replace('7.0.1', '7.0.2')
        current = before.replace('e'*40, 'f'*40)
        with patch.object(control, 'action_changes', return_value=[{'verified': True}]):
            merged, _ = control.merge_action_update(before, proposed, current)
            self.assertIn('f'*40, merged)
            self.assertIn('b'*40, merged)
            with self.assertRaisesRegex(MaintenanceError, 'conflicting'):
                control.merge_action_update(before, proposed,
                    current.replace('a'*40, 'c'*40).replace('7.0.1', '7.0.3'))

    def test_complete_bundle_updates_every_workflow_and_collector_atomically(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root/'security').mkdir(); (root/'.github/workflows').mkdir(parents=True)
            old = {'version': 'v0.1.1', 'source_commit': 'a'*40}
            new = {'version': 'v0.1.2', 'source_commit': 'b'*40}
            (root/'security/maintenance-source.json').write_bytes(canonical(old))
            for i in range(5):
                (root/f'.github/workflows/test-{i}.yml').write_text('    uses: Lanrith/lanrith/.github/workflows/security-review.yml@'+old['source_commit']+'\n'+
                    ('          repository: Lanrith/lanrith\n          ref: '+old['source_commit']+'\n' if i == 0 else ''))
            control.update_controller(root, new)
            self.assertEqual(json.loads((root/'security/maintenance-source.json').read_bytes()), new)
            for p in (root/'.github/workflows').iterdir():
                self.assertNotIn(old['source_commit'], p.read_text())
                self.assertIn(new['source_commit'], p.read_text())

    def test_action_data_cannot_smuggle_a_command_or_permission_change(self):
        old = '      - uses: actions/checkout@'+'a'*40+' # v7.0.1\n'
        new = old.replace('a'*40, 'b'*40).replace('7.0.1', '7.0.2')
        for attack in (new+'      - run: evil\n', new.replace('actions/checkout', 'attacker/checkout'), new.replace('7.0.2','8.0.0')):
            with self.subTest(attack=attack), self.assertRaises(MaintenanceError):
                control.action_changes(old, attack)

    def test_action_tag_must_match_the_proposed_commit(self):
        old = '      - uses: actions/checkout@'+'a'*40+' # v7.0.1\n'
        new = old.replace('a'*40, 'b'*40).replace('7.0.1', '7.0.2')
        with patch.object(control, 'api', side_effect=[{'draft': False, 'prerelease': False}, {'object': {'type': 'commit', 'sha': 'c'*40}}]), self.assertRaises(MaintenanceError):
            control.action_changes(old, new)


class RecoveryTrackingTests(unittest.TestCase):
    def test_recovery_closes_resolver_incident_without_claiming_a_release(self):
        with tempfile.TemporaryDirectory() as temporary, patch.dict(os.environ, {'GITHUB_RUN_ID': '123'}):
            path = Path(temporary)/'result.json'
            evidence.write(path, {'kind': 'proposal-result', 'state': 'current'})
            with patch.object(releases, 'pages', return_value=[{'number': 65, 'title': 'Security update automation needs attention', 'body': 'Blocked'}]), patch.object(releases, 'api') as api:
                releases.resolver_recovered(REPO, path)
                self.assertIn('does not claim a fix', api.call_args.kwargs['payload']['body'])
            evidence.write(path, {'kind': 'proposal-result', 'state': 'blocked'})
            with self.assertRaises(MaintenanceError):
                releases.resolver_recovered(REPO, path)
