"""Fixed operator authority, bounded requests and credential boot admission."""

from contextlib import redirect_stderr
import io
import json
import os
from pathlib import Path
import socket
import struct
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from lanrith import build, config, credential_operation as operation, credential_store, image_operation, runtime
from lanrith.release import ReleaseError, canonical
from test_credential_catalog import declaration
from test_credential_store import catalog, encoded, item
from test_intent import minimal


class CredentialProtocolTests(unittest.TestCase):
    def test_only_three_bounded_image_selected_requests_are_accepted(self):
        valid = [{'schema': 1, 'action': 'status'}, {'schema': 1, 'action': 'commit', 'transaction_id': 'a'*32},
                 {'schema': 1, 'action': 'stage', 'configuration_sha256': 'b'*64,
                  'credentials': encoded({'arbitrary_owner_reference': b'synthetic-value'})}]
        for value in valid:
            self.assertEqual(operation.request(canonical(value)), value)
        invalid = [b'', b'{}', b'{}\n{}\n', b'\xff\n', b'x'*(credential_store.LIMIT+1),
                   b'{"schema":1,"schema":1,"action":"status"}\n']
        for change in ({'schema': True}, {'action': 'restart'}, {'path': '/etc/shadow'}, {'command': 'anything'},
                       {'units': ['ssh.service']}, {'allow_replace': True}):
            invalid.append(canonical({**valid[0], **change}))
        for value in ('../other', 'A'*64, 'a'*63, None, [], True):
            invalid.append(canonical({**valid[2], 'configuration_sha256': value}))
        for value in ('not-an-id', 'A'*32, 'a'*31, None, [], True):
            invalid.append(canonical({**valid[1], 'transaction_id': value}))
        for value in ({}, {'x': 'a'*8193}, {'x': 1}, {str(i): 'YQ==' for i in range(257)}):
            invalid.append(canonical({**valid[2], 'credentials': value}))
        for value in invalid:
            with self.subTest(raw=value[:120]), self.assertRaises(ValueError):
                operation.request(value)

    def test_wrong_uid_cannot_reach_request_parsing(self):
        class Connection:
            def getsockopt(self, *_):
                return struct.pack('3i', 123, 1002, 1002)
        with patch.object(image_operation, 'policy', return_value={'operator': 'operator'}), \
                patch.object(operation.pwd, 'getpwnam', return_value=SimpleNamespace(pw_uid=1001)), \
                patch.object(operation, 'receive') as receive, patch.object(operation, 'execute') as execute, \
                self.assertRaisesRegex(ReleaseError, 'Caller'):
            operation.serve(Connection())
        receive.assert_not_called()
        execute.assert_not_called()

    def test_frame_deadline_is_absolute_and_oversize_and_truncated_requests_fail(self):
        class Connection:
            def __init__(self, blocks):
                self.blocks = iter(blocks)
            def settimeout(self, _):
                pass
            def recv(self, size):
                return next(self.blocks)[:size]
        with patch.object(operation.time, 'monotonic', side_effect=[0, 1, 11]), self.assertRaises(ValueError):
            operation.receive(Connection([b'{', b'}\n']))
        with self.assertRaises(ValueError):
            operation.receive(Connection([b'']))
        with self.assertRaises(ValueError):
            operation.receive(Connection([b'x'*65536]*33))

    def test_fixed_service_control_never_passes_request_data_or_restarts(self):
        with patch.object(operation.subprocess, 'run', return_value=SimpleNamespace(returncode=0)) as run:
            operation.control('stop', ['alloy.service'])
            self.assertEqual(run.call_args.args[0], ['/usr/bin/systemctl', 'stop', '--', 'alloy.service'])
            operation.control('start', ['alloy.service'])
            self.assertEqual(run.call_args.args[0], ['/usr/bin/systemctl', 'start', '--no-block', '--', 'alloy.service'])
            with self.assertRaises(ValueError):
                operation.control('restart', ['alloy.service'])

    def test_only_failed_units_are_reset_and_garbage_collected_consumers_can_start_normally(self):
        inventory = b'Id=alloy.service\nActiveState=inactive\n\nId=lanrith-health.service\nActiveState=failed\n'
        with patch.object(operation.subprocess, 'run', side_effect=[SimpleNamespace(returncode=0, stdout=inventory),
                SimpleNamespace(returncode=0)]) as run:
            operation.control('reset-failed', ['alloy.service', 'lanrith-health.service'])
        self.assertEqual(run.call_args.args[0], ['/usr/bin/systemctl', 'reset-failed', '--', 'lanrith-health.service'])

    def test_client_failures_never_echo_secret_parser_or_native_output(self):
        secret = 'synthetic-private-input-must-not-appear'
        for error in (ValueError(secret), KeyError(secret), OSError(secret),
                      subprocess.CalledProcessError(1, [secret], output=secret)):
            output = io.StringIO()
            with patch.object(operation, 'client', side_effect=error), redirect_stderr(output):
                self.assertEqual(operation.main(['status']), 1)
            self.assertNotIn(secret, output.getvalue())

    def test_stage_cli_reads_values_from_stdin_and_only_digest_from_argv(self):
        selected = encoded({'arbitrary_owner_name': b'synthetic-secret-value'})
        stream = SimpleNamespace(buffer=io.BytesIO(canonical(selected)))
        with patch.object(operation.sys, 'stdin', stream), patch.object(operation, 'client', return_value={}) as client, \
                patch('sys.stdout', new=io.StringIO()):
            self.assertEqual(operation.main(['stage', 'b'*64]), 0)
        self.assertEqual(client.call_args.args[0], {'schema': 1, 'action': 'stage', 'configuration_sha256': 'b'*64,
                                                  'credentials': selected})

    def test_minimal_and_both_root_modes_have_only_selected_provisioning_units(self):
        for root_access in ('enabled', 'disabled'):
            for enabled in (False, True):
                with self.subTest(root_access=root_access, enabled=enabled), tempfile.TemporaryDirectory() as temporary:
                    value = declaration() if enabled else minimal()
                    value['administration']['root_access'] = root_access
                    root = Path(temporary)
                    base = root/'base.tar'
                    base.write_bytes(b'synthetic input')
                    build.assembly(value, base, root/'work', version='0.1.0', sequence=12)
                    tree = root/'work/mkosi.extra'
                    installed = json.loads((tree/'usr/share/lanrith/installed.json').read_bytes())
                    self.assertEqual(installed['credential_catalog_sha256'] is not None, enabled)
                    units = tree/'usr/lib/systemd/system'
                    self.assertEqual((units/'sockets.target.wants/lanrith-credentials.socket').is_symlink(), enabled)
                    self.assertIn(' -I\n', (tree/'usr/bin/lanrith-credentials').read_text())
                    if not enabled:
                        self.assertFalse((units/'lanrith-credentials.socket').exists())
                        continue
                    source = (tree/'usr/share/lanrith/credentials.json').read_bytes()
                    self.assertEqual(credential_store.digest(source), installed['credential_catalog_sha256'])
                    manifest = json.loads(source)
                    endpoint = (units/'lanrith-credentials@.service').read_text()
                    self.assertIn('CollectMode=inactive-or-failed', endpoint)
                    for control in ('NoNewPrivileges=yes', 'CapabilityBoundingSet=\n', 'PrivateNetwork=yes',
                                    'RestrictAddressFamilies=AF_UNIX', 'LimitCORE=0', 'ProtectSystem=strict'):
                        self.assertIn(control, endpoint)
                    for ordinary in ('ssh.service', 'unbound.service', 'chrony.service', 'nftables.service',
                                     'lanrith-policy-guards.service', 'lanrith-image-completion.service'):
                        self.assertFalse((tree/'etc/systemd/system'/ordinary/'50-lanrith-credentials.conf').exists())
                        self.assertFalse((tree/'etc/systemd/system'/(ordinary+'.d')/'50-lanrith-credentials.conf').exists())
                    self.assertIn('lanrith-dns-state.service', manifest['units'])
                    self.assertIn('lanrith-policy-helper-requests.socket', manifest['units'])
                    for unit in manifest['units']:
                        self.assertIn('Requires=lanrith-credential-ready.service',
                            (tree/'etc/systemd/system'/(unit+'.d')/'50-lanrith-credentials.conf').read_text())
                    self.assertNotIn('lanrith-credential-ready', (units/'lanrith-image-completion.service').read_text())


@unittest.skipUnless(os.geteuid() == 0, 'Real credential filesystem custody and peer identities require root.')
class CredentialExecutionTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        (self.root/'var').mkdir(mode=0o700)
        self.value = {'image_id': 'synthetic-router', 'deployment_sequence': 12, 'uki_name': 'synthetic-router_12.efi',
                      'configuration_sha256': 'a'*64, 'state_directory': '/var/lib/lanrith', 'operator': 'operator'}
        self.store = credential_store.Store(self.value, catalog(item('first'), item('second')), root=self.root)
        self.store.setup()
        self.patchers = [patch.object(operation, 'store_for', return_value=self.store),
                         patch.object(image_operation, 'accepted_identity', return_value=None),
                         patch.object(operation, 'control')]
        self.mocks = [p.start() for p in self.patchers]
        for p in self.patchers:
            self.addCleanup(p.stop)

    def stage(self, values=None, **changes):
        return operation.execute(self.value, {'schema': 1, 'action': 'stage', 'configuration_sha256': 'a'*64,
            'credentials': encoded(values or {'first': b'first', 'second': b'second'}), **changes})

    def test_stage_quiesces_only_fixed_consumers_and_commit_starts_observer_without_killing_it(self):
        staged = self.stage()
        self.assertEqual(staged['phase'], 'prepared')
        self.assertFalse(self.store.admitted())
        self.assertEqual(self.mocks[2].call_args_list[0].args, ('stop', [operation.READY, 'alloy.service']))
        result = operation.execute(self.value, {'schema': 1, 'action': 'commit',
                                               'transaction_id': staged['transaction_id']})
        self.assertEqual(result['phase'], 'committed')
        calls = self.mocks[2].call_args_list
        self.assertTrue(any(c.args[0] == 'start' and 'lanrith-image-completion.service' in c.args[1] for c in calls))
        self.assertFalse(any(c.args[0] == 'stop' and any(u in c.args[1] for u in operation.OBSERVERS) for c in calls))
        self.assertNotIn('restart', [c.args[0] for c in calls])

    def test_invalid_values_wrong_image_and_accepted_image_fail_before_stopping_services(self):
        for values, changes in (({'first': b'first', 'second': b'bad\nvalue'}, {}),
                                (None, {'configuration_sha256': 'b'*64})):
            with self.assertRaises(ValueError):
                self.stage(values, **changes)
        self.mocks[1].return_value = self.store.identity
        with self.assertRaisesRegex(ReleaseError, 'accepted image'):
            self.stage()
        self.mocks[2].assert_not_called()

    def test_updated_image_can_add_bindings_without_changing_accepted_fallback_values(self):
        first = self.stage()
        operation.execute(self.value, {'schema': 1, 'action': 'commit', 'transaction_id': first['transaction_id']})
        self.mocks[1].return_value = self.store.identity
        self.mocks[2].reset_mock()
        self.assertEqual(self.stage()['phase'], 'committed')
        self.mocks[2].assert_not_called()
        with self.assertRaises(ValueError):
            self.stage({'first': b'changed', 'second': b'second'})
        candidate = {**self.value, 'deployment_sequence': 13, 'uki_name': 'synthetic-router_13.efi'}
        new_store = credential_store.Store(candidate, catalog(item('first'), item('second'), item('third')), root=self.root)
        new_store.setup()
        self.mocks[0].return_value = new_store
        result = operation.execute(candidate, {'schema': 1, 'action': 'stage', 'configuration_sha256': 'a'*64,
            'credentials': encoded({'first': b'first', 'second': b'second', 'third': b'third'})})
        self.assertEqual(result['phase'], 'prepared')
        self.assertTrue(self.store.admitted())

    def test_service_start_failure_keeps_durable_transaction_for_status_and_retry(self):
        self.mocks[2].side_effect = [None, None, ValueError('synthetic start failure')]
        with self.assertRaises(ValueError):
            self.stage()
        self.assertEqual(self.store.status()['phase'], 'prepared')
        self.mocks[2].side_effect = None
        self.assertEqual(self.stage()['phase'], 'prepared')

    def test_incomplete_set_never_starts_consumer_units(self):
        write = self.store.write
        def fail(path, raw):
            if path == self.store.path(self.store.items['second']['path']):
                raise OSError('synthetic interrupted write')
            write(path, raw)
        with patch.object(self.store, 'write', side_effect=fail), self.assertRaises(OSError):
            self.stage()
        self.assertEqual(self.store.status()['phase'], 'writing')
        self.assertEqual([call.args[0] for call in self.mocks[2].call_args_list], ['stop'])

    def test_kernel_peer_credentials_accept_selected_uid_and_reject_other_user_and_root(self):
        name = '\0lanrith-credential-test-'+os.urandom(12).hex()
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
            listener.bind(name)
            listener.listen(1)
            listener.settimeout(10)
            for uid in (1001, 1002, 0):
                code = ('import socket,sys\ns=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)\n'
                        's.settimeout(10)\ns.connect(sys.argv[1].encode().replace(b"@",b"\\x00",1))\n'
                        's.sendall(b\'{"schema":1,"action":"status"}\\n\')\n'
                        'print(s.recv(65536).decode())\n')
                child = subprocess.Popen([sys.executable, '-I', '-c', code, '@'+name[1:]], user=uid, group=uid,
                                         extra_groups=[], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                try:
                    connection, _ = listener.accept()
                    with connection, patch.object(image_operation, 'policy', return_value=self.value), \
                            patch.object(operation.pwd, 'getpwnam', return_value=SimpleNamespace(pw_uid=1001)):
                        if uid == 1001:
                            operation.serve(connection)
                        else:
                            with patch.object(operation, 'receive') as receive, self.assertRaisesRegex(ReleaseError, 'Caller'):
                                operation.serve(connection)
                            receive.assert_not_called()
                    output, _ = child.communicate(timeout=15)
                    if uid == 1001:
                        self.assertEqual(json.loads(output)['result']['phase'], 'needs-input')
                finally:
                    if child.poll() is None:
                        child.kill()
                        child.communicate(timeout=5)

    def test_catalog_binding_is_required_and_missing_or_changed_manifest_never_disables_checks(self):
        path = self.root/'credentials.json'
        raw = canonical(self.store.catalog)
        path.write_bytes(raw)
        path.chmod(0o644)
        selected = {**self.value, 'credential_catalog_sha256': credential_store.digest(raw)}
        with patch.object(credential_store, 'MANIFEST', path):
            self.assertEqual(operation.catalog(selected), self.store.catalog)
            with self.assertRaises(ValueError):
                operation.catalog(self.value)
            path.write_bytes(canonical(catalog()))
            with self.assertRaisesRegex(ReleaseError, 'identity'):
                operation.catalog(selected)
            path.unlink()
            with self.assertRaises(FileNotFoundError):
                operation.catalog(selected)

    def test_prepared_allows_consumers_but_only_admitted_allows_boot(self):
        with patch.object(operation, 'catalog', return_value=self.store.catalog), \
                patch.object(credential_store, 'Store', return_value=self.store):
            self.assertFalse(operation.ready(self.value, committed=False))
            staged = self.stage()
            self.assertTrue(operation.ready(self.value, committed=False))
            self.assertFalse(operation.ready(self.value))
            operation.execute(self.value, {'schema': 1, 'action': 'commit', 'transaction_id': staged['transaction_id']})
            self.assertTrue(operation.ready(self.value))

    def test_wait_is_bounded_and_does_not_hold_the_provisioning_lock_between_checks(self):
        with patch.object(operation, 'catalog', return_value=self.store.catalog), \
                patch.object(operation, 'ready', return_value=False), \
                patch.object(operation.time, 'monotonic', side_effect=[0, 0, 2]), \
                patch.object(operation.time, 'sleep') as sleep:
            self.assertFalse(operation.wait_ready(self.value, deadline_seconds=1))
        sleep.assert_called_once_with(1)
        with self.store.lock():
            pass

    def test_unadmitted_credentials_fail_health_before_any_other_boot_action(self):
        with patch.object(runtime, 'installed', return_value=self.value), \
                patch.object(operation, 'ready', return_value=False), patch.object(runtime.factory, 'initialize') as init, \
                self.assertRaisesRegex(ReleaseError, 'credentials'):
            runtime.health()
        init.assert_not_called()


if __name__ == '__main__':
    unittest.main()
