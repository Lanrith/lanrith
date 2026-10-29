"""Operator authority and image-specific completion/fallback controls."""

import os
import json
from pathlib import Path
from types import SimpleNamespace
import struct
import tempfile
import unittest
from unittest.mock import patch

from lanrith import build, config, image_operation as operation, release, runtime
from lanrith.release import ReleaseError


def minimal():
    return config.load(Path(__file__).resolve().parents[1]/'examples/minimal.yaml')


class OperatorTests(unittest.TestCase):
    def test_recovery_status_reports_bindings_without_exposing_luks_tokens(self):
        from lanrith import factory
        uuid = 'aaaaaaaa-1234-1234-1234-123456789abc'
        rows = [{'device': '/dev/vda1', 'type': 'c12a7328-f81f-11d2-ba4b-00a0c93ec93b', 'uuid': uuid},
                {'device': '/dev/vda8', 'type': factory.VAR_GUID, 'uuid': 'b'*8+'-1234-1234-1234-123456789abc'}]
        with patch.object(factory, 'state_metadata', return_value=('/dev/vda', '/dev/vda8', {'tokens': 'never-return-this'})), \
                patch.object(operation.update, 'geometry', return_value=rows), \
                patch.object(operation.update, 'command', return_value=uuid), \
                patch.object(Path, 'glob', return_value=[Path('/dev/disk/by-id/synthetic-disk')]), \
                patch.object(Path, 'resolve', return_value=Path('/dev/vda')):
            result = operation.recovery_information({'machine_id': 'a'*32})
        self.assertEqual(result['state_uuid'], uuid)
        self.assertEqual(result['disk_by_ids'], ['/dev/disk/by-id/synthetic-disk'])
        self.assertNotIn('never-return-this', json.dumps(result))

    def setUp(self):
        environment = patch.dict(os.environ, {'INVOCATION_ID': 'd'*32})
        environment.start()
        self.addCleanup(environment.stop)
        accepted = patch.object(operation, 'save_accepted')
        accepted.start()
        self.addCleanup(accepted.stop)
        prune = patch.object(operation, 'prune_inbox')
        prune.start()
        self.addCleanup(prune.stop)

    def fixture(self):
        value = {'image_id': 'lanrith', 'update_image_id': 'lanrith', 'deployment_sequence': 10,
                 'configuration_sha256': 'a'*64, 'uki_name': 'lanrith_10.efi', 'operator': 'admin'}
        candidate = operation.identity({**value, 'deployment_sequence': 11, 'uki_name': 'lanrith_11.efi',
                                         'configuration_sha256': 'b'*64})
        record = {'schema': 1, 'digest': 'c'*64, 'phase': 'rebooting', 'candidate': candidate,
                  'fallback': operation.identity(value), 'error': None, 'executor_id': 'd'*32}
        return value, record

    def test_only_fixed_digest_and_status_requests_are_accepted(self):
        for value in ({'schema': 1, 'action': 'status'},
                      {'schema': 1, 'action': 'trigger', 'digest': 'a'*64}):
            self.assertEqual(operation.request(release.canonical(value)), value)
        bad = [b'', b'{}', b'{}\n'*2, b'x'*513, b'{"schema":1,"schema":1,"action":"status"}\n']
        for selected in ('/tmp/bundle', '../escape', 'a'*63, 'A'*64, 'a'*64+'\n', None, [], 1):
            bad.append(release.canonical({'schema': 1, 'action': 'trigger', 'digest': selected}))
        for action in ('accept', 'reboot', 'recovery', 'command', 'configure', 'stage', 'evidence'):
            bad.append(release.canonical({'schema': 1, 'action': action}))
        bad.append(release.canonical({'schema': 1, 'action': 'status', 'path': '/private'}))
        bad.append(release.canonical({'schema': True, 'action': 'status'}))
        for data in bad:
            with self.subTest(data=data), self.assertRaises(ReleaseError):
                operation.request(data)

    def test_peer_credentials_authorize_before_reading_any_request(self):
        value, _ = self.fixture()
        class Connection:
            def getsockopt(self, *_):
                return struct.pack('3i', 123, 900, 900)
            def settimeout(self, *_):
                raise AssertionError('Unauthorized peer reached request handling')
        with patch.object(operation, 'policy', return_value=value), \
                patch.object(operation.pwd, 'getpwnam', return_value=SimpleNamespace(pw_uid=901)), \
                patch.object(operation, 'trigger') as trigger, self.assertRaises(ReleaseError):
            operation.serve(Connection())
        trigger.assert_not_called()

    def test_descriptor_reads_cannot_follow_a_replaced_upload_directory(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            upload = root/'upload'
            upload.mkdir()
            (upload/'release.json').write_bytes(b'original manifest')
            descriptor = os.open(upload, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                upload.rename(root/'pinned')
                upload.mkdir()
                (upload/'release.json').symlink_to('/etc/passwd')
                self.assertEqual(release.read('release.json', 512, dir_fd=descriptor), b'original manifest')
                with self.assertRaises(OSError):
                    release.read(upload/'release.json', 512)
            finally:
                os.close(descriptor)

    def test_uploaded_identity_and_members_remain_untrusted_until_promotion(self):
        with tempfile.TemporaryDirectory() as temporary:
            value, _ = self.fixture()
            value['upload_directory'] = temporary
            # A digest alone never substitutes for release signature admission.
            folder = Path(temporary)/('a'*64)
            folder.mkdir()
            (folder/'release.json').write_bytes(b'{}')
            with self.assertRaisesRegex(ReleaseError, 'identity'):
                operation.uploaded(value, folder.name)
            for digest in ('../outside', '/tmp/bundle', 'A'*64):
                with self.assertRaises(ReleaseError):
                    operation.uploaded(value, digest)

    def test_completion_promotes_only_the_exact_healthy_candidate(self):
        value, record = self.fixture()
        current = {**value, **record['candidate']}
        with patch.object(operation, 'policy', return_value=current), \
                patch.object(operation, 'load', return_value=record), \
                patch.object(operation, 'operation_lock'), \
                patch.object(operation, 'save') as save, patch.object(runtime, 'accept') as accept:
            operation.complete()
        accept.assert_called_once_with(11)
        self.assertEqual(save.call_args.args[1]['phase'], 'accepted')

    def test_unhealthy_candidate_reboots_without_changing_the_old_default(self):
        value, record = self.fixture()
        current = {**value, **record['candidate']}
        with patch.object(operation, 'policy', return_value=current), \
                patch.object(operation, 'load', return_value=record), patch.object(operation, 'operation_lock'), \
                patch.object(operation, 'fallback_boot') as fallback, \
                patch.object(operation.time, 'monotonic', side_effect=[0, 181]), \
                patch.object(runtime, 'accept', side_effect=ReleaseError('not healthy')), \
                self.assertRaisesRegex(ReleaseError, 'deadline'):
            operation.complete()
        fallback.assert_called_once_with(operation.INSTALLED)

    def test_unqualified_fallback_cannot_change_boot_selectors_or_reboot(self):
        value, record = self.fixture()
        current = {**value, **record['candidate']}
        with patch.object(operation, 'policy', return_value=current), \
                patch.object(operation, 'load', return_value=record), \
                patch.object(operation, 'boot_esp', return_value=Path('/efi')), \
                patch.object(operation, 'select_boot_once') as once, \
                patch.object(operation, 'require_default') as default, \
                patch.object(operation, 'command') as command, patch.object(operation, 'save') as save, \
                self.assertRaisesRegex(ReleaseError, 'pending recovery qualification'):
            operation.fallback_boot()
        once.assert_not_called()
        default.assert_not_called()
        command.assert_not_called()
        save.assert_not_called()

    def test_unknown_boot_identity_is_not_accepted(self):
        value, record = self.fixture()
        with patch.object(operation, 'policy', return_value={**value, 'configuration_sha256': 'e'*64}), \
                patch.object(operation, 'load', return_value=record), patch.object(operation, 'operation_lock'), \
                patch.object(runtime, 'accept') as accept, self.assertRaises(ReleaseError):
            operation.complete()
        accept.assert_not_called()

    def test_failed_candidate_return_marks_fallback_and_remains_repeatable(self):
        value, record = self.fixture()
        with patch.object(operation, 'policy', return_value=value), patch.object(operation, 'operation_lock'), \
                patch.object(operation, 'load', return_value=record), patch.object(operation, 'save') as save, \
                patch.object(runtime, 'accept') as accept:
            operation.complete()
        accept.assert_called_once_with(10)
        self.assertEqual(save.call_args.args[1]['phase'], 'fallback')

    def test_pending_operation_blocks_a_second_trigger_before_upload_inspection(self):
        value, record = self.fixture()
        with patch.object(operation, 'policy', return_value=value), patch.object(operation, 'operation_lock'), \
                patch.object(operation, 'load', return_value=record), patch.object(operation, 'uploaded') as upload, \
                self.assertRaises(ReleaseError):
            operation.trigger('d'*64)
        upload.assert_not_called()

    def test_authorized_trigger_orders_verified_copy_durable_intent_stage_and_reboot(self):
        value, record = self.fixture()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            manifest = {'schema': release.SCHEMA, 'purpose': 'update', 'image_id': 'lanrith',
                        'deployment_sequence': 11, 'platform_version': '0.2.0', 'architecture': 'x86-64',
                        'configuration_sha256': 'b'*64, 'artifacts': [
                            {'role': role, 'name': role+'.raw', 'size': 1, 'sha256': 'a'*64}
                            for role in release.ROLES['update']]}
            (root/'release.json').write_bytes(release.canonical(manifest))
            events = []
            def promoted(*args, **kwargs):
                self.assertEqual(kwargs, {'expected_digest': 'c'*64, 'stage_payload': False})
                events.append('verified-copy')
                return root
            def saved(_, record):
                events.append(record['phase'])
            def stage(*_):
                self.assertEqual(events, ['verified-copy', 'staging'])
                events.append('slot-transfer')
            def command(arguments):
                self.assertEqual(events, ['verified-copy', 'staging', 'slot-transfer', 'rebooting'])
                self.assertEqual(arguments, ['systemctl', '--no-block', 'reboot'])
                events.append('reboot-request')
            with patch.object(operation, 'policy', return_value=value), patch.object(operation, 'operation_lock'), \
                    patch.object(operation, 'load', return_value=None), \
                    patch.object(operation, 'uploaded', return_value=(manifest, root)), \
                    patch.object(operation, 'promote', side_effect=promoted), \
                    patch.object(operation, 'save', side_effect=saved), patch.object(operation, 'stage', side_effect=stage), \
                    patch.object(operation, 'command', side_effect=command):
                self.assertEqual(operation.trigger('c'*64)['phase'], 'rebooting')
            self.assertEqual(events[-1], 'reboot-request')

    def test_executor_cleanup_cannot_cancel_another_invocations_update(self):
        value, record = self.fixture()
        for executor, expected in (('e'*32, False), ('d'*32, True)):
            selected = {**record, 'executor_id': executor}
            with patch.object(operation, 'policy', return_value=value), patch.object(operation, 'operation_lock'), \
                    patch.object(operation, 'load', return_value=selected), \
                    patch.object(operation, 'boot_esp', return_value=Path('/efi')), \
                    patch.object(operation, 'select_boot_once') as once, \
                    patch.object(operation, 'require_default') as default, patch.object(operation, 'save') as save:
                operation.cancel_request()
            self.assertEqual(once.called, expected)
            self.assertEqual(default.called, expected)
            self.assertEqual(save.called, expected)
            if expected:
                self.assertEqual(save.call_args.args[1]['phase'], 'failed')

    def test_real_unix_peer_credentials_allow_only_the_configured_uid(self):
        import socket
        value, _ = self.fixture()
        server, client = socket.socketpair()
        try:
            try:
                client.sendall(release.canonical({'schema': 1, 'action': 'status'}))
            except PermissionError:
                self.skipTest('Local socket I/O is restricted by the execution sandbox.')
            with patch.object(operation, 'policy', return_value=value), \
                    patch.object(operation.pwd, 'getpwnam', return_value=SimpleNamespace(pw_uid=os.getuid())), \
                    patch.object(operation, 'load', return_value=None), \
                    patch.object(operation, 'accepted_identity', return_value=None):
                operation.serve(server)
            response = json.loads(client.recv(32768))
            self.assertTrue(response['ok'])
            with patch.object(operation, 'policy', return_value=value), \
                    patch.object(operation.pwd, 'getpwnam', return_value=SimpleNamespace(pw_uid=os.getuid()+1)), \
                    self.assertRaisesRegex(ReleaseError, 'Caller'):
                operation.serve(server)
        finally:
            server.close()
            client.close()

    def test_root_disabled_build_keeps_operator_transport_and_fixed_executor(self):
        for mode in ('disabled', 'enabled'):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                base = root/'base.tar'
                base.write_bytes(b'synthetic input')
                value = minimal()
                value['administration']['root_access'] = mode
                build.assembly(value, base, root/'assembly', version='0.2.0', sequence=11)
                tree = root/'assembly/mkosi.extra'
                unit = tree/'usr/lib/systemd/system/lanrith-image-operation.socket'
                self.assertIn('SocketUser=admin\nSocketMode=0600', unit.read_text())
                self.assertNotIn('ListenStream=0.', unit.read_text())
                self.assertIn('Accept=yes', unit.read_text())
                self.assertIn(' -I\n', (tree/'usr/bin/lanrith-image').read_text())
                self.assertTrue((tree/'usr/lib/systemd/system/multi-user.target.wants/lanrith-image-completion.service').is_symlink())
                self.assertFalse(any(p.suffix in ('.yml', '.yaml') for p in tree.rglob('*')))
                if mode == 'disabled':
                    ssh = (tree/'etc/systemd/system/ssh.service.d/60-lanrith-rootless.conf').read_text()
                    self.assertIn('ReadWritePaths=/var/tmp/lanrith-update\n', ssh)
                    self.assertIn('PrivateTmp=yes', ssh)
                    self.assertIn('BindPaths=/var/tmp/lanrith-update\n', ssh)
                    self.assertIn('NoNewPrivileges=yes\n', ssh)
                    self.assertIn('SystemCallFilter=~@cpu-emulation @debug @module @mount ', ssh)
                    self.assertIn('SystemCallFilter=chroot\n', ssh)

    def test_root_disabled_build_rejects_serial_login_credential(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            base, credential = root/'base.tar', root/'serial.hash'
            base.write_bytes(b'synthetic input')
            credential.write_text('synthetic credential')
            credential.chmod(0o600)
            value = minimal()
            value['administration']['root_access'] = 'disabled'
            with self.assertRaisesRegex(ReleaseError, 'cannot include a serial-login credential'):
                build.assembly(value, base, root/'assembly', version='0.2.0', sequence=11,
                               serial_hash=credential)
            self.assertFalse((root/'assembly').exists())
