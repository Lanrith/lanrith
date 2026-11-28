"""Bounded EVE projections, freshness and restart boundaries."""
import copy
import datetime
import json
import os
from pathlib import Path
import tempfile
import types
import unittest
from unittest.mock import patch

from lanrith import config, ids, ids_observer as observer
from lanrith.release import ReleaseError
from test_intent import minimal


class ObservationTests(unittest.TestCase):
    def test_export_is_explicit_and_metrics_select_only_stats(self):
        value = minimal()
        value['observability'] = {'ids': {'enabled': True}, 'metrics': {'enabled': True, 'clients': ['home']}}
        files = ids.render(config.normalize(value))
        unit = files['usr/lib/systemd/system/lanrith-ids-observer.service']
        self.assertIn('wan --stats\n', unit)
        self.assertNotIn('--alerts', unit)
        value['observability']['ids']['forward_alerts'] = True
        with self.assertRaises(ReleaseError):
            config.normalize(value)
        value['observability']['logs'] = {'enabled': True, 'endpoint': 'https://192.168.10.2/otlp',
                                        'tls_server_name': 'logs.test'}
        files = ids.render(config.normalize(value))
        self.assertIn('wan --alerts --stats\n', files['usr/lib/systemd/system/lanrith-ids-observer.service'])
        self.assertNotIn('lanrith-ids ', files['usr/lib/systemd/system/lanrith-ids-observer.service'])

    def test_only_reviewed_fields_enter_alert_output(self):
        event = {'timestamp': '2026-01-01T10:11:12+0100', 'in_iface': 'wan',
                 'alert': {'signature_id': 1000001, 'message': 'secret'}, 'payload': 'secret'}
        self.assertEqual(observer.alert(event, 'wan'), {'event_time': '2026-01-01T09:11:12+00:00',
                         'interface': 'wan', 'sid': 1000001})
        self.assertIsNone(observer.alert(event, 'lan'))
        event['alert']['signature_id'] = 42
        self.assertIsNone(observer.alert(event, 'wan'))

    def test_stats_schema_staleness_and_engine_reset(self):
        stamp = '2026-01-01T00:00:00+00:00'
        wall = int(datetime.datetime.fromisoformat(stamp).timestamp())
        event = {'timestamp': stamp, 'stats': {'uptime': 44}}
        for group, key in observer.FIELDS.values():
            event['stats'].setdefault(group, {})[key] = 2
        def sample(previous, sender=1, now=wall):
            return observer.sample(event, previous, sender=sender, now_mono=20, now_utc=now)
        first = sample(None)
        self.assertIsNone(first['delta'])
        previous = (1, 43, {**first, 'monotonic_ns': 10})
        event['stats']['capture']['kernel_drops'] = 5
        self.assertEqual(sample(previous)['delta']['kernel_drops'], 3)
        self.assertIsNone(sample(previous, sender=2)['delta'])
        event['stats']['uptime'] = 1
        self.assertIsNone(sample(previous)['delta'])
        with self.assertRaises(ValueError):
            sample(None, now=wall+100)
        event['stats']['tcp']['reassembly_gap'] = True
        with self.assertRaises(ValueError):
            sample(None)
        del event['stats']['tcp']['reassembly_gap']
        with self.assertRaises(KeyError):
            sample(None)
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            directory.chmod(0o755)
            path = directory/'stats.json'
            observer.publish(first, path)
            with patch.object(observer.pwd, 'getpwnam', return_value=types.SimpleNamespace(pw_uid=os.getuid())), \
                 patch.object(observer.time, 'monotonic_ns', return_value=32), \
                 patch.object(observer.time, 'time', return_value=wall):
                self.assertEqual(observer.read_observation(path), first)
                with patch.object(observer.time, 'monotonic_ns', return_value=90*10**9):
                    with self.assertRaises(ValueError):
                        observer.read_observation(path)
                corrupt = copy.deepcopy(first)
                corrupt['totals']['source_ip'] = 2
                path.write_text(json.dumps(corrupt))
                with self.assertRaises(ValueError):
                    observer.read_observation(path)
