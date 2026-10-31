"""Observation admission cannot grant mutation or optional boot authority."""

import copy
import io
import json
import os
from pathlib import Path
import socket
import stat
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from lanrith import config, extension_observations, extensions, policy_agent, policy_runtime
from lanrith.release import ReleaseError
from test_extension_network import IDENTITIES, manifest
from test_policy_agent import declaration


SELECTED = [{'service': 'policy', 'user': 'example-agent'}]
OBSERVER = {'user': 'example-agent', 'uid': 1801, 'gid': 1801}


def settings():
    value = declaration()
    value['networks']['home']['vlan'] = 1
    value['extensions'] = ['example-observer']
    return config.normalize(value)


class ObservationAdmissionTests(unittest.TestCase):
    def test_admitted_owned_reader_generates_core_wiring_without_new_unit_or_health_exception(self):
        value = settings()
        original = config.render(value)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            extension, output = root/'extension', root/'output'
            extension.mkdir()
            pin = manifest(extension, observations=SELECTED)
            config.write(value, output)
            result = extensions.overlay(value, {'example-observer': (extension, pin)}, output)
            contract = json.loads((output/'etc/router-policy-agent/runtime/runtime.json').read_bytes())
            self.assertEqual(contract['observer'], OBSERVER)
            helper = (output/'usr/lib/systemd/system/lanrith-policy-helper.service').read_text()
            self.assertIn('ExecStart=/usr/lib/lanrith/policy-runtime serve\n', helper)
            self.assertIn('SupplementaryGroups=1801\n', helper)
            self.assertIn('CapabilityBoundingSet=CAP_NET_ADMIN\n', helper)
            self.assertNotIn('CAP_CHOWN', helper)
            self.assertNotIn('observations.socket', helper)
            self.assertEqual(result['health_units'], [])
            self.assertEqual((output/'etc/nftables.conf').read_text(), original['etc/nftables.conf'])
            self.assertEqual((output/'usr/share/lanrith/health.json').read_text(),
                             original['usr/share/lanrith/health.json'])
            self.assertEqual(stat.S_IMODE((output/'etc/router-policy-agent/runtime/runtime.json').stat().st_mode), 0o600)
            self.assertFalse(any('observations' in path.name and path.suffix == '.socket' for path in output.rglob('*')))

    def test_empty_declaration_preserves_core_bytes(self):
        value = settings()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            config.write(value, root/'output')
            before = {str(path.relative_to(root/'output')): path.read_bytes()
                      for path in (root/'output').rglob('*') if path.is_file()}
            extension_observations.install(value, [], root/'output')
            self.assertEqual(before, {str(path.relative_to(root/'output')): path.read_bytes()
                                     for path in (root/'output').rglob('*') if path.is_file()})

    def test_malformed_shared_undeclared_and_disabled_readers_are_rejected(self):
        for selection in ({}, None, SELECTED*2, [{'service': 'policy', 'user': 'root'}],
                          [{'service': 'status', 'user': 'example-agent'}],
                          [{'service': 'policy', 'user': []}],
                          [{'service': 'policy', 'user': 'example-agent', 'socket': '/tmp/any'}]):
            with self.subTest(selection=selection), self.assertRaises(ReleaseError):
                extension_observations.declarations(selection, IDENTITIES)
        identities = copy.deepcopy(IDENTITIES)
        identities['groups'] = []
        with self.assertRaises(ReleaseError):
            extension_observations.declarations(SELECTED, identities)
        selected = extension_observations.declarations(SELECTED, IDENTITIES)
        with self.assertRaises(ReleaseError):
            extension_observations.resolve({}, [selected])
        with self.assertRaises(ReleaseError):
            extension_observations.resolve(settings(), [selected, selected])
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            pin = manifest(root, observations=[{'service': 'policy', 'user': 'root'}])
            with self.assertRaises(ReleaseError):
                extensions.admit(root, pin)

    def test_runtime_rejects_unbounded_or_substituted_observer_contracts(self):
        contract = policy_agent.runtime_contract(settings())
        for observer in (None, {}, {**OBSERVER, 'uid': True}, {**OBSERVER, 'uid': 0},
                         {**OBSERVER, 'gid': 60000}, {**OBSERVER, 'user': 'bad\nname'},
                         {**OBSERVER, 'socket': '/tmp/any'}):
            with self.subTest(observer=observer), tempfile.TemporaryDirectory() as temporary:
                path = Path(temporary)/'runtime.json'
                path.write_text(json.dumps({**contract, 'observer': observer}))
                path.chmod(0o600)
                with self.assertRaises(policy_runtime.PolicyRuntimeError):
                    policy_runtime.load_contract(path, owner=os.geteuid())

    def test_runtime_identity_drift_disables_only_optional_fields(self):
        contract = {**policy_agent.runtime_contract(settings()), 'observer': OBSERVER}
        reader = SimpleNamespace(pw_uid=1701, pw_gid=1701)
        operator = SimpleNamespace(pw_uid=1702, pw_gid=1702)
        for account in (SimpleNamespace(pw_uid=1801, pw_gid=1801),
                        SimpleNamespace(pw_uid=1802, pw_gid=1801), None):
            def lookup(name):
                if name == 'router-policy-reader':
                    return reader
                if name == 'router-policy-operator':
                    return operator
                if account is None:
                    raise KeyError(name)
                return account
            with self.subTest(account=account), patch.object(policy_runtime.pwd, 'getpwnam', side_effect=lookup), \
                    patch.object(policy_runtime, 'atomic') as atomic, patch.object(policy_runtime, 'nat64_pin', return_value=None), \
                    patch.object(policy_runtime, 'prepare_observation_directory'):
                policy_runtime.publish_runtime(contract, {'floor_sha256': 'a'*64, 'profile_sha256': 'b'*64}, 'c'*64)
                helper = atomic.call_args_list[0].args[1]
                self.assertEqual('observer_uid' in helper, account is not None and account.pw_uid == 1801)
                self.assertEqual(helper['reader_uid'], 1701)
                self.assertEqual(helper['operator_uid'], 1702)

    def test_directory_setup_failure_does_not_fail_core_config_publication(self):
        contract = {**policy_agent.runtime_contract(settings()), 'observer': OBSERVER}
        accounts = {'router-policy-reader': SimpleNamespace(pw_uid=1701),
                    'router-policy-operator': SimpleNamespace(pw_uid=1702),
                    'example-agent': SimpleNamespace(pw_uid=1801, pw_gid=1801)}
        with patch.object(policy_runtime.pwd, 'getpwnam', side_effect=accounts.__getitem__), \
                patch.object(policy_runtime, 'atomic') as atomic, \
                patch.object(policy_runtime, 'nat64_pin', return_value=None), \
                patch.object(policy_runtime, 'prepare_observation_directory', side_effect=OSError('unavailable')):
            policy_runtime.publish_runtime(contract, {'floor_sha256': 'a'*64, 'profile_sha256': 'b'*64}, 'c'*64)
        self.assertNotIn('observer_uid', atomic.call_args_list[0].args[1])
        self.assertEqual(len(atomic.call_args_list), 2)


class ObservationLaunchTests(unittest.TestCase):
    def test_nonroot_or_invalid_supervisor_cannot_launch_or_prepare_observations(self):
        for uid, environment in ((1801, {}), (0, {'LISTEN_FDS': '3'}),
                                 (0, {'LISTEN_PID': str(os.getpid()), 'LISTEN_FDS': '2',
                                      'LISTEN_FDNAMES': 'requests:observations'})):
            with self.subTest(uid=uid, environment=environment), patch.object(policy_runtime.os, 'geteuid', return_value=uid), \
                    patch.dict(os.environ, environment, clear=True), patch.object(policy_runtime, 'load_contract') as load, \
                    patch.object(policy_runtime.os, 'execve') as execute:
                with self.assertRaises(policy_runtime.PolicyRuntimeError):
                    policy_runtime.serve()
                load.assert_not_called()
                execute.assert_not_called()

    def launch(self, *, setup_error=None, occupied=False):
        contract = {**policy_agent.runtime_contract(settings()), 'observer': OBSERVER}
        listener = unittest.mock.Mock()
        listener.fileno.return_value = 6
        data = json.dumps({'observer_uid': 1801, 'observations_socket': str(policy_runtime.OBSERVATIONS)}).encode()
        with patch.object(policy_runtime.os, 'geteuid', return_value=0), \
                patch.dict(os.environ, {'LISTEN_PID': str(os.getpid()), 'LISTEN_FDS': '2', 'LISTEN_FDNAMES': 'status:requests'}), \
                patch.object(policy_runtime, 'load_contract', return_value=contract), \
                patch.object(policy_runtime, 'read', return_value=data), \
                patch.object(policy_runtime, 'observation_listener', side_effect=setup_error, return_value=listener), \
                patch.object(policy_runtime.os, 'fstat', side_effect=None if occupied else OSError(9, 'closed')), \
                patch.object(policy_runtime.os, 'dup2') as dup, patch.object(policy_runtime.os, 'close') as close, \
                patch.object(policy_runtime.os, 'execve') as execute:
            policy_runtime.serve()
            return execute.call_args, dup.call_args, close.call_args

    def test_launcher_preserves_mandatory_descriptors_and_executes_only_fixed_helper(self):
        call, duplicate, close = self.launch()
        self.assertEqual(call.args[:2], ('/usr/bin/router-policy-helper', ['/usr/bin/router-policy-helper',
            '-config-directory', '/run/lanrith-policy/config', '-binding-directory', '/run/lanrith-policy/bindings']))
        self.assertEqual(call.args[2]['LISTEN_FDS'], '3')
        self.assertEqual(call.args[2]['LISTEN_FDNAMES'], 'status:requests:observations')
        self.assertEqual(duplicate.args, (6, 5))
        self.assertEqual(close.args, (5,))

    def test_optional_setup_failure_or_occupied_descriptor_keeps_two_socket_enforcement(self):
        for arguments in ({'setup_error': OSError('synthetic unavailable')}, {'occupied': True}):
            with self.subTest(arguments=arguments), patch('sys.stderr', new_callable=io.StringIO):
                call, duplicate, close = self.launch(**arguments)
                self.assertEqual(call.args[2]['LISTEN_FDS'], '2')
                self.assertEqual(call.args[2]['LISTEN_FDNAMES'], 'status:requests')
                self.assertIsNone(duplicate)
                self.assertIsNone(close)

    @unittest.skipUnless(os.geteuid() == 0, 'native socket ownership requires isolated root')
    def test_native_socket_owner_group_and_unsafe_path_denial(self):
        observer = {**OBSERVER, 'gid': os.getegid()}
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary)/'observations/socket'
            policy_runtime.prepare_observation_directory(path.parent)
            listener = policy_runtime.observation_listener(observer, path)
            try:
                info = path.stat()
                self.assertEqual((info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode)), (0, os.getegid(), 0o660))
                client = socket.socket(socket.AF_UNIX)
                try:
                    client.connect(str(path))
                    connection, _ = listener.accept()
                    connection.close()
                finally:
                    client.close()
            finally:
                listener.close()
            path.unlink()
            target = path.parent/'retained'
            target.write_text('retain')
            path.symlink_to(target)
            with self.assertRaises(policy_runtime.PolicyRuntimeError):
                policy_runtime.observation_listener(observer, path)
            self.assertEqual(target.read_text(), 'retain')


if __name__ == '__main__':
    unittest.main()
