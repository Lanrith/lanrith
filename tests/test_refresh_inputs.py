"""Security proposals can include today's fixes without selecting future snapshots."""

import datetime
import hashlib
import importlib.util
import json
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

    def test_selected_security_repair_inputs_are_fixed_and_digest_bound(self):
        root = source.parents[1]
        alloy = json.loads((root/'builders/alloy/source.json').read_text())
        exporter = json.loads((root/'builders/node-exporter/source.json').read_text())
        selection = json.loads((root/'build-inputs.json').read_text())
        policy = json.loads((root/'security/policy.json').read_text())
        self.assertGreaterEqual(tuple(map(int, alloy['go_version'].split('.'))), (1, 27, 3))
        self.assertGreaterEqual(tuple(map(int, exporter['go_version'].removeprefix('go').split('.'))),
                                (1, 26, 10))
        self.assertEqual(policy['required_exact_packages']['alloy'], alloy['package_version'])
        self.assertEqual(policy['required_exact_packages']['prometheus-node-exporter'],
                         exporter['package_version'])
        self.assertEqual(policy['required_exact_packages']['unbound'], '1.26.2-0+deb13u1')
        for component, minimum in (('discovery-bridge', (0, 1, 1)), ('router-policy-agent', (0, 1, 4))):
            pin = selection['component_releases'][component]
            self.assertGreaterEqual(tuple(map(int, pin['tag'].removeprefix('v').split('.'))), minimum)
            names = ['discovery-bridge'] if component == 'discovery-bridge' else [
                'router-policy-reader', 'router-policy-helper', 'router-policy-collector']
            for name in names:
                self.assertEqual(policy['required_exact_packages'][name], pin['tag'][1:])
                self.assertEqual(policy['local_package_sources'][name]['version'], pin['tag'][1:])
        ui_patch = (root/'builders/alloy/ui-dependencies.patch').read_text()
        for dependency, vulnerable, fixed in (('@vitest/mocker', '4.1.11', '4.1.12'),
                                              ('undici', '7.29.1', '7.30.1'),
                                              ('minimatch', '3.1.5', '11.0.1'),
                                              ('minimatch', '10.2.6', '11.0.1'),
                                              ('vite', '7.3.5', '7.3.7')):
            with self.subTest(dependency=dependency):
                self.assertIn('"version": "'+fixed+'"', ui_patch)
                self.assertNotIn(' "version": "'+vulnerable+'"',
                                 '\n'.join(line for line in ui_patch.splitlines()
                                           if line.startswith(('+', ' '))))
        for name, expected in selection['custom_package_inputs'].items():
            self.assertEqual(hashlib.sha256((root/name).read_bytes()).hexdigest(), expected, name)
