"""Keep a bounded recovery window without accumulating failed release images."""

import datetime
import unittest

from automation import cleanup


class ReleaseRetryCleanupTests(unittest.TestCase):
    def setUp(self):
        self.clock = datetime.datetime(2026,11,1,9,tzinfo=datetime.timezone.utc)
        self.runs = {i: {'id':i,'name':'Release','status':'completed','conclusion':'failure',
                        'updated_at':(self.clock-datetime.timedelta(hours=3)).isoformat()}
                     for i in (1,2,3)}
        self.latest = self.runs[3]
        self.artifacts = [self.artifact(i,i,'attested-base-1') for i in (1,2,3)]

    def artifact(self, identity, run, name):
        return {'id':identity,'name':name,'size_in_bytes':1024,'expired':False,
                'workflow_run':{'id':run},'created_at':(self.clock-datetime.timedelta(hours=4)).isoformat()}

    def plan(self):
        def get(endpoint, **kwargs):
            if kwargs.get('paginate'): return [{'artifacts':self.artifacts}]
            if '/actions/workflows/release.yml/runs?' in endpoint:
                return {'workflow_runs':[self.latest]}
            return self.runs[int(endpoint.rsplit('/',1)[-1])]
        return cleanup.plan('Lanrith/lanrith',get=get,clock=self.clock)

    def test_only_latest_failed_final_bundle_survives_the_short_cleanup_window(self):
        self.artifacts.append(self.artifact(4,3,'package-stage-1'))
        result = self.plan()
        self.assertEqual([a['id'] for a in result['artifacts']],[1,2,4])
        self.assertEqual([a['id'] for a in result['retained_retry_artifacts']],[3])

    def test_newer_success_supersedes_all_old_failed_bundles(self):
        self.latest = {'id':4,'conclusion':'success'}
        result = self.plan()
        self.assertEqual([a['id'] for a in result['artifacts']],[1,2,3])
        self.assertEqual(result['retained_retry_artifacts'],[])

    def test_recovery_retention_expires_after_one_day_even_if_run_was_retried(self):
        self.artifacts[2]['created_at']=(self.clock-datetime.timedelta(days=1,seconds=1)).isoformat()
        result = self.plan()
        self.assertEqual([a['id'] for a in result['artifacts']],[1,2,3])

    def test_multiple_attempts_keep_at_most_one_final_bundle(self):
        self.artifacts.append(self.artifact(4,3,'attested-base-2'))
        result = self.plan()
        self.assertEqual([a['id'] for a in result['artifacts']],[1,2,3])
        self.assertEqual([a['id'] for a in result['retained_retry_artifacts']],[4])

    def test_active_run_and_recent_handoffs_are_not_deleted(self):
        self.runs[1]['status']='in_progress'
        self.runs[2]['updated_at']=(self.clock-datetime.timedelta(hours=1)).isoformat()
        result = self.plan()
        self.assertEqual(result['artifacts'],[])
        self.assertEqual([a['id'] for a in result['retained_retry_artifacts']],[3])

    def test_unsigned_or_expired_images_do_not_receive_extra_retention(self):
        self.artifacts[2]['name']='qualified-base-1'
        self.artifacts[1]['expired']=True
        result = self.plan()
        self.assertEqual([a['id'] for a in result['artifacts']],[1,3])
        self.assertEqual(result['retained_retry_artifacts'],[])
