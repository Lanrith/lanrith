"""Transient check publication failures never change the approved subject or owner."""
import unittest
from unittest.mock import patch

from automation import review
from automation.common import MaintenanceError


class CheckRecoveryTests(unittest.TestCase):
    def setUp(self):
        self.pr = {'state': 'open', 'head': {'sha': 'a'*40}, 'base': {'sha': 'b'*40}}
        self.check = {'id': 9, 'name': 'Security update admission', 'head_sha': 'a'*40,
                      'app': {'id': 123}, 'status': 'in_progress'}
        self.failures = 1
        self.writes = []

    def api(self, endpoint, *, method='GET', payload=None):
        if method == 'PATCH':
            self.writes.append((endpoint, payload))
            if len(self.writes) <= self.failures:
                raise MaintenanceError('GitHub API operation failed: HTTP 404')
            return {**self.check, **payload}
        if '/pulls/' in endpoint:
            return self.pr
        return {'total_count': 1, 'check_runs': [self.check]}

    def update(self):
        with patch.object(review, 'api', side_effect=self.api):
            return review.update_check('Lanrith/lanrith', 97, 'a'*40, 'b'*40, 9, 123,
                                       {'status': 'completed', 'conclusion': 'success'}, sleep=lambda _: None)

    def test_transient_failure_retries_same_check_and_payload(self):
        self.assertEqual(self.update()['conclusion'], 'success')
        self.assertEqual(len(self.writes), 2)
        self.assertEqual(*self.writes)

    def test_persistent_failure_is_bounded_and_propagated(self):
        self.failures = 10
        with self.assertRaises(MaintenanceError):
            self.update()
        self.assertEqual(len(self.writes), 3)

    def test_changed_head_base_or_owner_stops_recovery(self):
        for field in ('head', 'base', 'owner', 'check', 'closed'):
            self.setUp()
            if field in ('head', 'base'):
                self.pr[field]['sha'] = 'f'*40
            elif field == 'owner':
                self.check['app']['id'] = 456
            elif field == 'check':
                self.check['id'] = 10
            else:
                self.pr['state'] = 'closed'
            with self.subTest(field=field), self.assertRaises(MaintenanceError):
                self.update()
            self.assertEqual(len(self.writes), 1)

    def test_permission_failure_is_not_retried(self):
        with patch.object(review, 'api', side_effect=MaintenanceError('HTTP 403')) as api:
            with self.assertRaises(MaintenanceError):
                review.update_check('Lanrith/lanrith', 97, 'a'*40, 'b'*40, 9, 123, {}, sleep=lambda _: None)
            self.assertEqual(api.call_count, 1)
