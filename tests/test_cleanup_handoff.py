"""The actual cache handoff is eligible only after its consuming run finishes."""

import datetime
from pathlib import Path
import unittest

import yaml

from automation import cleanup


ROOT = Path(__file__).resolve().parents[1]


class CacheHandoffCleanupTests(unittest.TestCase):
    def test_workflow_cache_handoff_keeps_active_and_recent_consumers(self):
        workflow = yaml.safe_load((ROOT/'.github/workflows/restore-cache.yml').read_text())
        upload = next(step for step in workflow['jobs']['restore']['steps'] if step.get('id') == 'upload')
        name = upload['with']['name'].replace('${{ github.run_attempt }}', '1')
        self.assertEqual(upload['with']['retention-days'], 1)
        clock = datetime.datetime(2026, 10, 24, 6, tzinfo=datetime.timezone.utc)
        artifacts = [{'id': number, 'name': name, 'size_in_bytes': 2*1024**3,
                      'expired': False, 'workflow_run': {'id': number}}
                     for number in range(1, 5)]
        runs = {number: {'name': 'Package qualification' if number == 1 else 'Release',
                        'status': 'completed',
                        'updated_at': (clock-datetime.timedelta(hours=3)).isoformat()}
                for number in range(1, 5)}
        runs[2]['status'] = 'in_progress'
        runs[3]['updated_at'] = (clock-datetime.timedelta(hours=1)).isoformat()

        def get(endpoint, **kwargs):
            if kwargs.get('paginate'):
                return [{'artifacts': artifacts}]
            return runs[int(endpoint.rsplit('/', 1)[-1])]

        result = cleanup.plan('Lanrith/lanrith', get=get, clock=clock)
        self.assertEqual([artifact['id'] for artifact in result['artifacts']], [1, 4])
        self.assertEqual(result['bytes'], 4*1024**3)
