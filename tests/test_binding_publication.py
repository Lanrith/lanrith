"""Atomic binding publication, enrollment recheck and status boundaries."""
from contextlib import redirect_stdout
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from lanrith import policy_runtime as runtime


class BindingPublicationTests(unittest.TestCase):
    def setUp(self):
        self.space = tempfile.TemporaryDirectory()
        self.addCleanup(self.space.cleanup)
        root = Path(self.space.name)
        for key in ('BINDINGS', 'COLLECTOR'):
            directory = root/key
            directory.mkdir(mode=0o700)
            self.enterContext(patch.object(runtime, key, directory))
        self.path = runtime.BINDINGS/'bindings.json'
        original = runtime.atomic
        self.enterContext(patch.object(runtime, 'atomic', side_effect=lambda path, value, **kw:
            original(path, value, owner=os.getuid(), group=os.getgid(), **kw)))
        self.log = self.enterContext(redirect_stdout(io.StringIO()))

    def test_atomic_status_during_collection_failure_and_recovery(self):
        def status():
            return json.loads(os.getxattr(self.path, runtime.STATUS_ATTRIBUTE))
        contract = {'binding_collector': None}
        runtime.refresh_bindings(contract)
        first = self.path.read_bytes()
        success = status()['last_success']
        self.assertIsNotNone(success)
        def stopped(*_):
            self.assertEqual(self.path.read_bytes(), first)
            self.assertEqual(status()['outcome'], 'complete')
            raise runtime.BindingFailure('lease')
        with patch.object(runtime, 'collect_bindings', side_effect=stopped):
            runtime.refresh_bindings(contract)
        self.assertFalse(json.loads(self.path.read_bytes())['complete'])
        self.assertEqual(status()['last_success'], success)
        self.assertEqual(status()['outcome'], 'lease')
        with patch.object(runtime, 'collect_bindings', side_effect=ValueError('private-session-example')):
            runtime.refresh_bindings(contract)
        self.assertEqual(status()['last_success'], success)
        self.assertEqual(status()['outcome'], 'collector')
        self.assertNotIn('private-session-example', self.log.getvalue())
        runtime.refresh_bindings(contract)
        self.assertTrue(json.loads(self.path.read_bytes())['complete'])
        self.assertEqual(status()['outcome'], 'complete')
        self.assertGreater(status()['last_success'], success)

    def test_concurrent_call_cannot_overwrite_an_inflight_generation(self):
        runtime.refresh_bindings({'binding_collector': None})
        first = self.path.read_bytes()
        def concurrent(*_):
            with self.assertRaises(BlockingIOError):
                runtime.refresh_bindings({'binding_collector': None})
            self.assertEqual(self.path.read_bytes(), first)
            return runtime.binding_envelope(True)
        with patch.object(runtime, 'collect_bindings', side_effect=concurrent):
            runtime.refresh_bindings({})
        self.assertTrue(json.loads(self.path.read_bytes())['complete'])

    def test_changed_cohort_cannot_receive_worker_result(self):
        contract = {'binding_collector': {
            'radius_user': 'freerad', 'nas_prefixes': ['192.0.2.1/32'], 'kea_user': '_kea',
            'kea_socket': '/run/lanrith-kea-leases/leases.sock', 'subnet_id': 22, 'vlan': 22,
            'ipv4_prefix': '198.51.100.0/24', 'maximum_devices': 2, 'interface': 'lan.22', 'parent': 'lan'}}
        with patch.object(runtime, 'cohort', side_effect=[['02:00:00:00:00:01'], []]), \
                patch.object(runtime, 'private_directory'), \
                patch.object(runtime, 'worker_snapshot', return_value=runtime.binding_envelope(True)):
            runtime.refresh_bindings(contract, worker=True)
        self.assertFalse(json.loads(self.path.read_bytes())['complete'])
        self.assertEqual(json.loads(os.getxattr(self.path, runtime.STATUS_ATTRIBUTE))['outcome'], 'cohort')
