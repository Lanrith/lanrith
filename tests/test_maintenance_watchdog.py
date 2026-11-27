"""Conditional event skips cannot hide or falsely report maintenance failures."""
import datetime
import importlib.util
from pathlib import Path
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('maintenance_watchdog', Path(__file__).parents[1]/'scripts/watchdog.py')
watchdog = importlib.util.module_from_spec(spec)
spec.loader.exec_module(watchdog)


class MaintenanceWatchdogTests(unittest.TestCase):
    def setUp(self):
        self.clock = datetime.datetime(2026, 11, 26, 10, tzinfo=datetime.timezone.utc)

    def row(self, identity=1, conclusion='success', event='schedule', age=1):
        return {'id': identity, 'status': 'completed', 'conclusion': conclusion, 'event': event,
                'updated_at': (self.clock-datetime.timedelta(hours=age)).isoformat(),
                'html_url': 'https://github.com/Lanrith/lanrith/actions/runs/'+str(identity)}

    def findings(self, proposer, other=None):
        def api(endpoint):
            return {'workflow_runs': proposer if '/update-inputs.yml/' in endpoint else (other or [self.row()])}
        with patch.object(watchdog, 'api', side_effect=api):
            return watchdog.assess('Lanrith/lanrith', [], clock=lambda: self.clock)[0]

    def test_completion_during_each_api_read_is_not_future_dated(self):
        observation = self.clock
        stable = [{'draft': False, 'prerelease': False, 'tag_name': 'v0.1.36'}]

        def api(endpoint):
            nonlocal observation
            # Reproduce the overnight race: completion is seven seconds after
            # the request starts and visible by the time its response arrives.
            completed = observation+datetime.timedelta(seconds=7)
            observation += datetime.timedelta(seconds=12)
            return {'workflow_runs': [{**self.row(), 'updated_at': completed.isoformat()}]}

        with patch.object(watchdog, 'api', side_effect=api):
            findings, latest = watchdog.assess('Lanrith/lanrith', stable, clock=lambda: observation)
        self.assertEqual(findings, [])
        self.assertEqual(latest, stable[0])

    def test_security_freshness_still_rejects_missing_stale_and_future_runs(self):
        stable = [{'draft': False, 'prerelease': False, 'tag_name': 'v0.1.36'}]
        for runs in ([], [self.row(age=19)], [self.row(age=-1)]):
            with self.subTest(runs=runs):
                def api(endpoint):
                    return {'workflow_runs': runs if '/security-audit.yml/' in endpoint else [self.row()]}
                with patch.object(watchdog, 'api', side_effect=api):
                    findings, _ = watchdog.assess('Lanrith/lanrith', stable, clock=lambda: self.clock)
                self.assertTrue(any('within 18 hours' in item for item in findings))

    def test_healthy_scan_skip_preserves_recent_actual_success(self):
        self.assertEqual(self.findings([self.row(2, 'skipped', 'workflow_run'), self.row()]), [])

    def test_conditional_skip_cannot_mask_a_failed_actual_evaluation(self):
        result = self.findings([self.row(2, 'skipped', 'workflow_run'), self.row(conclusion='failure')])
        self.assertTrue(any('update-inputs.yml: failure' in item for item in result))

    def test_skipped_scheduled_or_manual_evaluation_still_requires_attention(self):
        for event in ('schedule', 'workflow_dispatch', 'repository_dispatch'):
            with self.subTest(event=event):
                result = self.findings([self.row(2, 'skipped', event), self.row()])
                self.assertTrue(any('update-inputs.yml: skipped' in item for item in result))

    def test_skips_do_not_reset_freshness_or_hide_a_stopped_schedule(self):
        for previous in ([], [self.row(age=9)], [self.row(age=-1)]):
            with self.subTest(previous=previous):
                result = self.findings([self.row(2, 'skipped', 'workflow_run')]+previous)
                self.assertTrue(any('within 8 hours' in item for item in result))

    def test_skip_in_another_workflow_is_not_ignored(self):
        result = self.findings([self.row()], [self.row(2, 'skipped', 'workflow_run')])
        self.assertTrue(any('security-audit.yml: skipped' in item for item in result))
