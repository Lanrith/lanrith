"""Security proposals can include today's fixes without selecting future snapshots."""

import datetime
import importlib.util
from pathlib import Path
import unittest

from lanrith.release import ReleaseError


source = Path(__file__).resolve().parents[1]/'scripts/refresh-inputs.py'
spec = importlib.util.spec_from_file_location('refresh_inputs', source)
refresh = importlib.util.module_from_spec(spec)
spec.loader.exec_module(refresh)


class SnapshotSelectionTests(unittest.TestCase):
    def test_default_uses_the_current_utc_hour_including_same_day_fixes(self):
        now = datetime.datetime(2026, 10, 16, 11, 17, 55,
                                tzinfo=datetime.timezone(datetime.timedelta(hours=1)))
        self.assertEqual(refresh.snapshot(now=now), '20261016T100000Z')
        self.assertEqual(refresh.snapshot(now=now.replace(hour=1, minute=0, second=0)),
                         '20261016T000000Z')

    def test_explicit_snapshot_rejects_invalid_or_future_dates(self):
        now = datetime.datetime(2026, 10, 16, 10, 17, tzinfo=datetime.timezone.utc)
        self.assertEqual(refresh.snapshot('20261016T061025Z', now=now), '20261016T061025Z')
        for value in ('20261016T110000Z', '20260230T100000Z', '20261016T100000',
                      '20261016T100000Z\n', 'latest', None):
            with self.subTest(value=value):
                if value is None:
                    with self.assertRaises(ReleaseError):
                        refresh.snapshot(now=now.replace(tzinfo=None))
                else:
                    with self.assertRaises((ReleaseError, ValueError)):
                        refresh.snapshot(value, now=now)
