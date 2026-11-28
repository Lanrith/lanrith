"""Receiver age and progression must come from the designated stream and accepted boot."""

import json
from pathlib import Path
import runpy
import unittest

checker = runpy.run_path(str(Path(__file__).resolve().parents[1]/'scripts/check-heartbeat-receipts.py'))
SECOND = 10**9
HOST = 'router-test'
LABELS = {'host': HOST, 'job': 'router-journal', 'unit': 'lanrith-telemetry-heartbeat.service',
          'journal_transport': 'stdout', 'journal_boot': '12345678123412341234123456789abc'}
SHARED = {'image_id': 'lanrith', 'platform_version': '0.1.32', 'deployment_sequence': 7}
INSTALLED = {**SHARED, 'uki_name': 'lanrith_7.efi', 'configuration_sha256': 'a'*64}
BOOT = {**SHARED, 'schema': 1, 'accepted': True, 'boot_complete': True, 'boot_id': '12345678-1234-1234-1234-123456789abc',
        'selected_entry': INSTALLED['uki_name']}
STATUS = {**SHARED, 'configuration_sha256': INSTALLED['configuration_sha256'], 'boot': BOOT}
EVENT = {**SHARED, 'schema': 1, 'event': 'lanrith-heartbeat', 'boot_id': BOOT['boot_id'],
         'selected_entry': BOOT['selected_entry'], 'configuration_sha256': INSTALLED['configuration_sha256']}


def entry(t, **overrides):
    return [str(t*SECOND+1000), json.dumps({**EVENT, 'monotonic_ns': t*SECOND-10, 'emitted_unix_ns': t*SECOND, **overrides})]


def check(now, entries, *, labels=LABELS, status=STATUS):
    response = {'status': 'success', 'data': {'resultType': 'streams', 'result': [{'stream': labels, 'values': entries}]}}
    return checker['check'](HOST, INSTALLED, status, response, now_ns=now*SECOND)


class HeartbeatReceiptTests(unittest.TestCase):
    def test_unordered_pair_alarm_on_silence_then_only_new_matching_heartbeat_recovers(self):
        pair = [entry(120), entry(60)]
        self.assertEqual(check(122, pair), 120*SECOND-10)
        for extra in ([], [entry(120)], [[str(215*SECOND), entry(120)[1]]],
                      [entry(215, boot_id='00000000-0000-0000-0000-000000000001')],
                      [entry(215, emitted_unix_ns=None)], [entry(215, monotonic_ns=120*SECOND-10)]):
            with self.subTest(extra=extra), self.assertRaises(ValueError):
                check(216, pair+extra)
        self.assertEqual(check(216, pair+[entry(215)]), 215*SECOND-10)
        with self.assertRaisesRegex(ValueError, 'unexpected'):
            check(130, pair+[entry(125, selected_entry='other.efi')])
        with self.assertRaisesRegex(ValueError, 'second recent'):
            check(245, [entry(60), entry(245)])

    def test_pair_requires_exact_labels_and_candidate_fields(self):
        for key in LABELS:
            with self.subTest(key=key), self.assertRaises(ValueError):
                check(125, [entry(60), entry(120)], labels={**LABELS, key: 'controller'})
        for key, value in (('image_id', 'other'), ('platform_version', '0.1.33'), ('schema', True),
                           ('configuration_sha256', 'b'*64), ('event', 'probe'), ('selected_entry', 'other.efi'),
                           ('deployment_sequence', 8), ('monotonic_ns', True), ('boot_id', 'old')):
            with self.subTest(key=key), self.assertRaises(ValueError):
                check(125, [entry(60), entry(120, **{key: value})])
        for change in ({'schema': True}, {'accepted': False}, {'boot_complete': False}, {'selected_entry': 'other.efi'},
                       {'platform_version': '0.2.0'}, {'deployment_sequence': 8}):
            with self.subTest(change=change), self.assertRaises(ValueError):
                check(125, [entry(60), entry(120)], status={**STATUS, 'boot': {**BOOT, **change}})
        with self.assertRaises(ValueError):
            check(125, [entry(60), entry(120)], status={**STATUS, 'configuration_sha256': 'b'*64})

    def test_duplicate_unknown_source_future_and_rewritten_entry_times(self):
        for entries in ([entry(60), entry(60)], [entry(60), entry(120, monotonic_ns=50)],
                        [entry(60), entry(130)], [entry(60), [str(120*SECOND), entry(61)[1]]],
                        [entry(60), [str(70*SECOND), entry(120)[1]]], [entry(60), entry(120, emitted_unix_ns=True)]):
            with self.subTest(entries=entries), self.assertRaises(ValueError):
                check(120, entries)
        old = {**EVENT, 'monotonic_ns': 123}
        with self.assertRaisesRegex(ValueError, 'unknown'):
            check(120, [entry(60), [str(120*SECOND), json.dumps(old)]])
