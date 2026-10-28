"""An accepted review must have the write authority required by GitHub protection."""
import copy
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from automation import common, evidence, review
from automation.common import MaintenanceError
import test_maintenance as fixtures

authority_response = fixtures.authority_response


class CountedApprovalTests(unittest.TestCase):
    def test_an_archive_without_verified_write_authority_cannot_release_admission(self):
        factory = fixtures.DurableApprovalTests()
        factory.setUp()
        factory.previous['approval'].pop('repository_write_access_verified')
        with self.assertRaisesRegex(MaintenanceError, 'Archived approval'):
            factory.finalize()
        self.assertEqual(factory.writes, [])

    def test_rejected_authority_preserves_the_actual_review_and_failure_for_archival(self):
        factory = fixtures.ApprovalBoundaryTests()
        factory.setUp()
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary)/'update-record.json'
            evidence.write(path, factory.record)
            with patch.object(review, 'inspect', return_value=(factory.fresh, factory.policy)), \
                    patch.object(review, 'api', side_effect=factory.api), \
                    patch.object(review, 'approval_authority', side_effect=MaintenanceError('Missing repository write access')), \
                    self.assertRaises(MaintenanceError):
                review.approve('Lanrith/lanrith', 12, path, fixtures.PRODUCER, 'true')
            rejected = evidence.read(path)
        self.assertEqual(rejected['approval']['review_id'], 21)
        self.assertEqual(rejected['approval']['commit_id'], fixtures.HEAD)
        self.assertIs(rejected['approval']['repository_write_access_verified'], False)
        self.assertIs(rejected['eligible'], False)
        self.assertEqual(rejected['findings'], ['Missing repository write access'])
        self.assertIsNone(rejected['admission_check']['conclusion'])

    def test_an_accepted_but_uncounted_app_review_cannot_finish_approval(self):
        factory = fixtures.ApprovalBoundaryTests()
        factory.setUp()
        original = factory.api

        def get(endpoint, **kwargs):
            if endpoint == 'graphql':
                value = authority_response()
                value['data']['repository']['pullRequest']['reviews']['nodes'][0]['authorCanPushToRepository'] = False
                return value
            return original(endpoint, **kwargs)

        with patch.object(factory, 'api', side_effect=get), self.assertRaisesRegex(
                MaintenanceError, 'repository write access'):
            factory.approve()

    def test_revoking_reviewer_write_access_cannot_release_the_durable_merge_gate(self):
        factory = fixtures.DurableApprovalTests()
        factory.setUp()
        original = factory.api

        def get(endpoint, **kwargs):
            if endpoint == 'graphql':
                value = authority_response()
                value['data']['repository']['pullRequest']['reviews']['nodes'][0]['authorCanPushToRepository'] = False
                return value
            return original(endpoint, **kwargs)

        with patch.object(factory, 'api', side_effect=get), self.assertRaisesRegex(
                MaintenanceError, 'repository write access'):
            factory.finalize()
        self.assertEqual(factory.writes, [])


class ApprovalAuthoritySubjectTests(unittest.TestCase):
    def test_transport_exception_does_not_allow_other_endpoints_or_graphql_get(self):
        for endpoint, method in (('graphql', 'GET'), ('https://other.example/graphql', 'POST'),
                                 ('graphql\nrepos/Lanrith/lanrith', 'POST')):
            with self.subTest(endpoint=endpoint), patch.object(common.subprocess, 'run') as request, self.assertRaises(MaintenanceError):
                common.api(endpoint, method=method)
            request.assert_not_called()

    def test_only_github_write_authority_for_the_exact_review_and_pr_is_accepted(self):
        approval = {'review_id': 21, 'reviewer_login': 'security-reviewer[bot]', 'commit_id': fixtures.HEAD}
        mutations = (
            ('other repository', lambda r, p, a: r.update(nameWithOwner='Lanrith/discovery-bridge')),
            ('other PR', lambda r, p, a: p.update(number=13)),
            ('changed head', lambda r, p, a: p.update(headRefOid='f'*40)),
            ('changed base', lambda r, p, a: p.update(baseRefOid='f'*40)),
            ('other review', lambda r, p, a: a.update(databaseId=22)),
            ('other actor', lambda r, p, a: a['author'].update(login='dependency-updater')),
            ('human identity', lambda r, p, a: a['author'].update(__typename='User')),
            ('other commit', lambda r, p, a: a['commit'].update(oid='f'*40)),
            ('dismissed review', lambda r, p, a: a.update(state='DISMISSED')),
            ('missing authority', lambda r, p, a: a.pop('authorCanPushToRepository')),
            ('nonboolean authority', lambda r, p, a: a.update(authorCanPushToRepository='true')),
            ('duplicate review', lambda r, p, a: p['reviews']['nodes'].append(copy.deepcopy(a))),
        )
        for name, change in mutations:
            value = authority_response()
            repo = value['data']['repository']
            pull = repo['pullRequest']
            change(repo, pull, pull['reviews']['nodes'][0])
            with self.subTest(name=name), patch.object(review, 'api', return_value=value), self.assertRaises(MaintenanceError):
                review.approval_authority('Lanrith/lanrith', 12, fixtures.HEAD, fixtures.BASE, approval)

    def test_graphql_errors_and_missing_data_fail_closed(self):
        approval = {'review_id': 21, 'reviewer_login': 'security-reviewer[bot]', 'commit_id': fixtures.HEAD}
        for value in ({'errors': [{'message': 'Not authorized'}]}, {'data': {'repository': None}},
                      {'errors': [{'message': 'Partial response'}], **authority_response()}):
            with self.subTest(value=value), patch.object(review, 'api', return_value=value), self.assertRaises(MaintenanceError):
                review.approval_authority('Lanrith/lanrith', 12, fixtures.HEAD, fixtures.BASE, approval)

    def test_verified_authority_is_bound_to_the_recorded_review(self):
        approval = {'review_id': 21, 'reviewer_login': 'security-reviewer[bot]', 'commit_id': fixtures.HEAD}
        with patch.object(review, 'api', return_value=authority_response()) as get:
            self.assertTrue(review.approval_authority('Lanrith/lanrith', 12, fixtures.HEAD, fixtures.BASE, approval))
        self.assertEqual(get.call_args.args, ('graphql',))
        self.assertEqual(get.call_args.kwargs['method'], 'POST')
        self.assertEqual(get.call_args.kwargs['payload']['variables'], {'owner': 'Lanrith', 'name': 'lanrith', 'number': 12})
