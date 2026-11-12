"""A maintainer exception must preserve validation and remain visible in evidence."""

import copy
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from automation import proposal, releases, review
from automation.common import MaintenanceError, canonical, document
from automation.release_authorization import authorize_merge, maintainers, validate_record


ROOT = Path(__file__).resolve().parents[1]
REPO, SOURCE, HEAD = 'Lanrith/lanrith', 'a'*40, 'b'*40


class ReleaseAuthorizationTests(unittest.TestCase):
    def setUp(self):
        self.policy = document((ROOT/'security/update-policy.json').read_bytes())
        self.policy['release_authorization'] = {
            'mode': 'maintainer-merge', 'maintainers': [{'login': 'example-owner', 'id': 123}]}
        self.pr = {'number': 12, 'merged': True, 'merge_commit_sha': SOURCE,
            'merged_at': '2026-11-12T08:00:00Z', 'html_url': f'https://github.com/{REPO}/pull/12',
            'base': {'ref': 'main', 'repo': {'full_name': REPO}},
            'head': {'sha': HEAD, 'ref': 'feature'},
            'user': {'login': 'example-owner', 'id': 123},
            'merged_by': {'login': 'example-owner', 'id': 123, 'type': 'User'}}
        self.reviews = []
        self.run = {'id': 8, 'run_attempt': 2, 'head_sha': HEAD, 'event': 'pull_request',
            'status': 'completed', 'conclusion': 'success', 'html_url': 'https://example.test/run/8'}

    def authorize(self):
        return authorize_merge(REPO, SOURCE, self.pr, canonical(self.policy), self.reviews)

    def collect(self):
        def pages(endpoint):
            return self.reviews if '/reviews?' in endpoint else [self.pr]
        def api(endpoint):
            return {'workflow_runs': [self.run]} if '/actions/' in endpoint else self.pr
        with tempfile.TemporaryDirectory() as temporary, \
                patch.object(releases, 'pages', side_effect=pages), \
                patch.object(releases, 'api', side_effect=api), \
                patch.object(releases, 'contents', return_value=canonical(self.policy)), \
                patch.dict(os.environ, {'GITHUB_RUN_ID': '9', 'GITHUB_RUN_ATTEMPT': '1'}):
            return releases.collect(REPO, SOURCE, Path(temporary)/'record.json', '1.0.1')

    def test_missing_opt_in_keeps_existing_release_block(self):
        del self.policy['release_authorization']
        self.assertEqual(maintainers(self.policy), [])
        with self.assertRaisesRegex(MaintenanceError, 'lacks a commit-bound approval'):
            self.collect()

    def test_automated_proposals_still_require_independent_review(self):
        self.pr['head']['ref'] = self.policy['proposal_branch']
        with self.assertRaisesRegex(MaintenanceError, 'Automated proposals'):
            self.authorize()

    def test_no_merged_pr_still_blocks_direct_push_release(self):
        self.pr['merge_commit_sha'] = 'c'*40
        with self.assertRaisesRegex(MaintenanceError, 'direct-push releases are blocked'):
            self.collect()

    def test_policy_parser_accepts_explicit_human_identities_only(self):
        review.policy_document(canonical(self.policy), REPO)
        valid = copy.deepcopy(self.policy['release_authorization'])
        invalid = [None, True, {}, {'mode': 'allow'}, dict(valid, extra=True),
            dict(valid, mode='anything'), dict(valid, maintainers=[]),
            dict(valid, maintainers=[{'login': 'owner[bot]', 'id': 123}]),
            dict(valid, maintainers=[{'login': 'owner', 'id': True}]),
            dict(valid, maintainers=[{'login': 'owner', 'id': 0}]),
            dict(valid, maintainers=valid['maintainers']*2)]
        for value in invalid:
            with self.subTest(policy=value), self.assertRaises(MaintenanceError):
                self.policy['release_authorization'] = value
                review.policy_document(canonical(self.policy), REPO)

    def test_merge_actor_must_match_id_and_login_and_be_human(self):
        for field, value in [('id', 456), ('login', 'someone-else'), ('type', 'Bot')]:
            with self.subTest(field=field), self.assertRaises(MaintenanceError):
                original = self.pr['merged_by'][field]
                self.pr['merged_by'][field] = value
                try:
                    self.authorize()
                finally:
                    self.pr['merged_by'][field] = original

    def test_wrong_commit_repository_branch_or_unmerged_pr_is_denied(self):
        original = copy.deepcopy(self.pr)
        variants = [dict(original, merge_commit_sha='c'*40), dict(original, merged=False),
            dict(original, base={'ref': 'other', 'repo': {'full_name': REPO}}),
            dict(original, base={'ref': 'main', 'repo': {'full_name': 'someone/else'}}),
            dict(original, html_url='https://example.test/pull/12')]
        for value in variants:
            with self.subTest(pr=value), self.assertRaises(MaintenanceError):
                self.pr = value
                self.authorize()

    def test_change_request_cannot_be_overridden(self):
        self.reviews = [{'id': 1, 'user': {'id': 456}, 'state': 'CHANGES_REQUESTED', 'commit_id': HEAD}]
        with self.assertRaisesRegex(MaintenanceError, 'outstanding change request'):
            self.collect()

    def test_failed_pending_wrong_head_or_missing_validation_still_blocks_release(self):
        for field, value in [('conclusion', 'failure'), ('conclusion', 'skipped'),
                             ('status', 'in_progress'), ('head_sha', 'd'*40)]:
            with self.subTest(field=field, value=value), self.assertRaises(MaintenanceError):
                original = self.run[field]
                self.run[field] = value
                try:
                    self.collect()
                finally:
                    self.run[field] = original

    def test_maintainer_record_is_distinct_from_independent_approval(self):
        record = self.collect()
        pull = record['pull_requests'][0]
        self.assertEqual(pull['approvals'], [])
        self.assertEqual(pull['maintainer_authorization'], self.authorize())
        self.assertEqual(len(pull['validation']), len(self.policy['required_workflows']))
        validate_record(REPO, SOURCE, pull, canonical(self.policy))

    def test_existing_commit_bound_review_still_works_without_opt_in(self):
        del self.policy['release_authorization']
        self.reviews = [{'id': 1, 'state': 'APPROVED', 'commit_id': HEAD,
            'user': {'id': 456, 'login': 'reviewer'}, 'submitted_at': '2026-11-12T07:59:00Z',
            'html_url': 'https://example.test/review/1'}]
        pull = self.collect()['pull_requests'][0]
        self.assertNotIn('maintainer_authorization', pull)
        self.assertEqual(pull['approvals'][0]['actor_id'], 456)

    def test_consumer_rejects_replayed_or_modified_maintainer_evidence(self):
        original = self.collect()['pull_requests'][0]
        for field, value in [('actor_id', 456), ('actor', 'someone-else'),
                ('policy_sha256', '0'*64), ('repository', 'Lanrith/discovery-bridge'),
                ('head_sha', 'c'*40), ('merge_commit_sha', 'c'*40), ('pull_request', 13),
                ('kind', 'peer-review'), ('merged_at', '2026-11-12T09:00:00Z')]:
            with self.subTest(field=field), self.assertRaises(MaintenanceError):
                pull = copy.deepcopy(original)
                pull['maintainer_authorization'][field] = value
                validate_record(REPO, SOURCE, pull, canonical(self.policy))
        del self.policy['release_authorization']
        with self.assertRaises(MaintenanceError):
            validate_record(REPO, SOURCE, original, canonical(self.policy))

    def test_component_selection_verifies_attestation_and_maintainer_policy(self):
        repo = 'Lanrith/router-policy-agent'
        policy = copy.deepcopy(self.policy)
        policy['repository'] = repo
        pr = copy.deepcopy(self.pr)
        pr['base']['repo']['full_name'] = repo
        pr['html_url'] = f'https://github.com/{repo}/pull/12'
        pull = self.collect()['pull_requests'][0]
        pull['url'] = pr['html_url']
        pull['maintainer_authorization'] = authorize_merge(repo, SOURCE, pr, canonical(policy), [])
        history = {'repository': repo, 'source_commit': SOURCE, 'version': '1.0.1', 'pull_requests': [pull]}
        manifest = {'source_commit': SOURCE, 'version': '1.0.1',
                    'files': {'router-policy-helper_1.0.1_amd64.deb': {'sha256': '1'*64}}}
        observed = []

        def command(*args, **kwargs):
            observed.append(args)
            if args[:3] == ('gh', 'release', 'download'):
                directory = Path(args[args.index('--dir')+1])
                (directory/'component-release.json').write_bytes(canonical(manifest))
                (directory/'update-record.json').write_bytes(canonical(history))
            elif args[:3] == ('gh', 'attestation', 'verify'):
                self.assertIn('--deny-self-hosted-runners', args)
                self.assertEqual(args[args.index('--source-digest')+1], SOURCE)
                self.assertEqual(args[args.index('--signer-digest')+1], SOURCE)
            else:
                self.fail(f'Unexpected command: {args}')

        with patch.object(proposal, 'api', return_value={'immutable': True, 'draft': False, 'prerelease': False}), \
                patch.object(proposal, 'run', side_effect=command), \
                patch.object(proposal, 'contents', side_effect=lambda *args: canonical(policy)):
            selected = proposal.component_selection(repo, 'v1.0.1')
            self.assertIn('update-record.json', selected['files'])
            self.assertEqual(sum(c[:3] == ('gh', 'attestation', 'verify') for c in observed), 2)
            del policy['release_authorization']
            with self.assertRaises(MaintenanceError):
                proposal.component_selection(repo, 'v1.0.1')


if __name__ == '__main__':
    unittest.main()
