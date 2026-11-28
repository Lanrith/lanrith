"""Exercise operator and manual admission against ordinary, private fixture files."""

from contextlib import ExitStack
import hashlib
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from lanrith import image_operation as operation, release, runtime, update


@unittest.skipUnless(os.getuid() == 0, 'Uses real root-owned files in the native fixture.')
class AdmissionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        keys = tempfile.TemporaryDirectory()
        cls.addClassCleanup(keys.cleanup)
        root = Path(keys.name)
        cls.authorities = []
        for name in ('trusted', 'other'):
            key, cert = root/(name+'.key'), root/(name+'.crt')
            subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
                            '-subj', '/CN=synthetic-'+name, '-keyout', str(key), '-out', str(cert)],
                           check=True, capture_output=True)
            key.chmod(0o600)
            cls.authorities.append((key, cert))

    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.lockdir = self.root/'locks'
        self.lockdir.mkdir(mode=0o700)
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(patch.object(update, 'IMAGE_LOCK_DIR', self.lockdir))
        self.stack.enter_context(patch.object(runtime, 'BOOT_OBSERVATION', self.root/'boot.json'))
        self.value = {'image_id': 'lanrith', 'update_image_id': 'lanrith', 'deployment_sequence': 10,
                      'platform_version': '0.1.0', 'configuration_sha256': 'a'*64,
                      'uki_name': 'lanrith_10.efi', 'operator': 'root', 'certificate': str(self.authorities[0][1]),
                      'state_directory': str(self.root/'state'), 'upload_directory': str(self.root/'upload')}
        self.installed = self.root/'installed.json'
        self.installed.write_bytes(release.canonical(self.value))
        operation.save_accepted(self.value)
        runtime.publish_boot(self.value, Path(self.value['uki_name']), accepted=True)
        self.source = self.root/'upload/bundle'
        self.source.mkdir(parents=True)
        self.files = {role: role+'.raw' for role in release.ROLES['update']}
        for role, name in self.files.items():
            (self.source/name).write_bytes(role.encode())
        self.manifest = release.unsigned_manifest(self.source, purpose='update', version='0.1.0', sequence=11,
                                                  configuration_sha256='b'*64, files=self.files)
        (self.source/'release.json').write_bytes(release.canonical(self.manifest))
        release.sign(self.source, self.authorities[0][0])
        self.digest = hashlib.sha256(release.canonical(self.manifest)).hexdigest()
        self.source = self.source.rename(self.source.with_name(self.digest))
        self.inbox = self.root/'state/update-inbox'
        self.inbox.mkdir(mode=0o700)
        self.stack.enter_context(patch.object(update, 'boot_esp', return_value=self.root))
        self.stack.enter_context(patch.object(Path, 'is_mount', return_value=True))
        self.stack.enter_context(patch.object(update, 'root_disk', return_value=('/dev/fixture', {1, 2})))
        self.stack.enter_context(patch.object(update, 'geometry', return_value=[]))
        self.stack.enter_context(patch.object(update, 'upload_limits'))
        self.stack.enter_context(patch.dict(os.environ, {'INVOCATION_ID': 'c'*32}))

    def test_signature_identity_and_payload_before_publication(self):
        def attempt(certificate, image_id, sequence, digest, message):
            self.installed.write_bytes(release.canonical({**self.value, 'certificate': str(certificate),
                'update_image_id': image_id, 'deployment_sequence': sequence}))
            with patch.object(update, 'copy_member', wraps=update.copy_member) as opened:
                with self.assertRaisesRegex(release.ReleaseError, message):
                    update.promote_locked(self.source, self.installed, expected_digest=digest)
                attempted = [call.args[2] for call in opened.call_args_list]
            self.assertEqual(list(self.inbox.iterdir()), [])
            return attempted
        trusted, other = (item[1] for item in self.authorities)
        for cert, image_id, sequence, digest, message in (
                (other, 'lanrith', 10, self.digest, 'signature'),
                (trusted, 'foreign', 10, self.digest, 'image identity'),
                (trusted, 'lanrith', 11, self.digest, 'not newer'),
                (trusted, 'lanrith', 10, 'f'*64, 'identity differs')):
            with self.subTest(message=message):
                self.assertEqual(attempt(cert, image_id, sequence, digest, message), ['release.json', 'release.json.sig'])
        payload = self.source/self.files['root']
        original = payload.read_bytes()
        payload.write_bytes(b'x'*len(original))
        opened = attempt(trusted, 'lanrith', 10, self.digest, 'digest differs')
        self.assertEqual(set(opened), set(self.files.values()) | {'release.json', 'release.json.sig'})
        payload.write_bytes(original)
        with patch.object(update, 'stage_locked', return_value='staged') as stage:
            self.assertEqual(update.promote(self.source, self.installed), 'staged')
            stage.assert_called_once_with(self.inbox/'11', self.installed)

    def test_manual_and_socket_calls_exclude_each_other_and_leave_status_available(self):
        entries = [('promote', lambda: update.promote(self.source, self.installed)),
                   ('stage', lambda: update.stage(self.inbox/'11', self.installed)),
                   ('trigger', lambda: operation.trigger(self.digest, self.installed))]
        server, client = socket.socketpair()
        self.addCleanup(server.close)
        self.addCleanup(client.close)

        def occupied(*args):
            for name, call in entries:
                with self.subTest(competitor=name), self.assertRaisesRegex(release.ReleaseError, 'already running'):
                    call()
            with patch.object(operation, 'recovery_information', return_value=None):
                client.sendall(release.canonical({'schema': 1, 'action': 'status'}))
                operation.serve(server, self.installed)
                self.assertTrue(json.loads(client.recv(32768))['ok'])
            return 'staged'

        for owner, call in entries:
            with self.subTest(owner=owner), patch.object(update, 'stage_locked', side_effect=occupied), \
                    patch.object(operation, 'stage_locked', side_effect=occupied), patch.object(operation, 'command'):
                result = call()
                self.assertEqual(result['phase'] if owner == 'trigger' else result,
                                 'rebooting' if owner == 'trigger' else 'staged')
        with patch.object(update, 'stage_locked') as stage, patch.object(update, 'promote_locked') as promote, \
                patch.object(operation, 'prune_inbox') as prune:
            for name, call in entries:
                with self.subTest(pending=name), self.assertRaisesRegex(release.ReleaseError, 'pending image operation'):
                    call()
            operation.save(self.value, {**operation.load(self.value), 'phase': 'failed'})
            event = json.loads(runtime.BOOT_OBSERVATION.read_bytes())
            runtime.BOOT_OBSERVATION.write_bytes(release.canonical({**event, 'boot_id': 'stale'}))
            for name, call in entries:
                with self.subTest(stale=name), self.assertRaisesRegex(release.ReleaseError, 'committed boot'):
                    call()
            stage.assert_not_called()
            promote.assert_not_called()
            prune.assert_not_called()

    def test_failure_cleanup_checks_identity_and_reads_back_before_closing(self):
        old = operation.identity(self.value)
        candidate = operation.identity({**self.value, 'deployment_sequence': 11, 'uki_name': 'lanrith_11.efi'})
        pending = {'schema': 1, 'phase': 'staging', 'candidate': candidate, 'fallback': old,
                   'error': None, 'executor_id': 'c'*32, 'digest': self.digest}
        tree = self.root/'EFI/Linux'
        tree.mkdir(parents=True)
        entry = tree/old['uki_name']
        entry.write_bytes(b'accepted predecessor')
        for stop in ('other-executor', 'other-running-image', 'geometry', 'flags', 'entry', 'default', 'oneshot', None):
            with self.subTest(stop=stop), ExitStack() as stack:
                record = {**pending, 'executor_id': 'd'*32} if stop == 'other-executor' else pending
                if stop == 'other-running-image':
                    record = {**pending, 'fallback': {**old, 'configuration_sha256': 'f'*64}}
                operation.save(self.value, record)
                events = []
                def restore(_):
                    events.append('restore')
                    if stop in ('geometry', 'flags'):
                        raise release.ReleaseError(stop)
                    return self.root
                def default(path):
                    self.assertEqual(path, entry)
                    events.append('default')
                    if stop == 'default':
                        raise release.ReleaseError(stop)
                def select(path):
                    self.assertEqual(path, entry)
                    events.append('oneshot')
                    if stop == 'oneshot':
                        raise release.ReleaseError(stop)
                stack.enter_context(patch.object(update, 'restore_esp', restore))
                current = entry.with_name(candidate['uki_name']) if stop == 'entry' else entry
                stack.enter_context(patch.object(operation, 'command', return_value=str(current)))
                stack.enter_context(patch.object(operation, 'require_default', default))
                stack.enter_context(patch.object(operation, 'select_boot_once', select))
                if stop in ('other-executor', 'other-running-image', None):
                    operation.cancel_request(self.installed)
                else:
                    with self.assertRaises(release.ReleaseError):
                        operation.cancel_request(self.installed)
                expected = {
                    'other-executor': [], 'other-running-image': [], 'geometry': ['restore'],
                    'flags': ['restore'], 'entry': ['restore'], 'default': ['restore', 'default'],
                    'oneshot': ['restore', 'default', 'oneshot'], None: ['restore', 'default', 'oneshot']}
                self.assertEqual(events, expected[stop])
                self.assertEqual(operation.load(self.value), record if stop else
                                 {**record, 'phase': 'failed', 'error': 'admission-or-staging-failed'})

    def test_successful_service_stop_preserves_the_committed_reboot_checkpoint(self):
        old = operation.identity(self.value)
        candidate = operation.identity({**self.value, 'deployment_sequence': 11, 'uki_name': 'lanrith_11.efi'})
        record = {'schema': 1, 'phase': 'rebooting', 'candidate': candidate, 'fallback': old,
                  'error': None, 'executor_id': 'c'*32, 'digest': self.digest}
        operation.save(self.value, record)
        with patch.dict(os.environ, {'SERVICE_RESULT': 'success'}), patch.object(operation, 'close_failed_stage') as close:
            operation.cancel_request(self.installed)
            close.assert_not_called()
            operation.save(self.value, {**record, 'phase': 'staging'})
            operation.cancel_request(self.installed)
            close.assert_called_once()

    def test_post_stop_waits_for_admission_and_rechecks_who_owns_the_operation(self):
        old = operation.identity(self.value)
        candidate = operation.identity({**self.value, 'deployment_sequence': 11, 'uki_name': 'lanrith_11.efi'})
        pending = {'schema': 1, 'phase': 'staging', 'candidate': candidate, 'fallback': old,
                   'error': None, 'executor_id': 'c'*32, 'digest': self.digest}
        original_lock = operation.operation_lock
        for superseded in (False, True):
            with self.subTest(superseded=superseded):
                operation.save(self.value, pending)
                waiting = threading.Event()
                errors = []
                def acquire(*, wait):
                    self.assertTrue(wait)
                    waiting.set()
                    return original_lock(wait=wait)
                def cancel():
                    try:
                        operation.cancel_request(self.installed)
                    except Exception as error:
                        errors.append(error)
                with patch.object(operation, 'close_failed_stage') as close, patch.object(operation, 'operation_lock', acquire):
                    with original_lock():
                        thread = threading.Thread(target=cancel)
                        thread.start()
                        self.assertTrue(waiting.wait(timeout=2))
                        if superseded:
                            operation.save(self.value, {**pending, 'executor_id': 'd'*32})
                    thread.join(timeout=2)
                    self.assertFalse(thread.is_alive())
                    self.assertEqual(errors, [])
                    self.assertEqual(close.called, not superseded)

    def test_lock_parent_and_files_remain_protected_across_calls(self):
        with operation.operation_lock():
            lock = self.lockdir/update.OPERATION_LOCK_NAME
            inode = lock.stat().st_ino
        with operation.operation_lock():
            self.assertEqual(lock.stat().st_ino, inode)
        self.lockdir.chmod(0o750)
        with self.assertRaisesRegex(release.ReleaseError, 'directory is unsafe'), operation.operation_lock():
            self.fail()
        self.lockdir.chmod(0o700)
        lock.chmod(0o644)
        with self.assertRaisesRegex(release.ReleaseError, 'file is unsafe'), operation.operation_lock():
            self.fail()

    def test_retirement_resumes_at_every_filesystem_checkpoint(self):
        real_operations = [update.sync_directory, Path.rename, Path.unlink, Path.rmdir]
        steps = []
        def retire(stop):
            cursor = 0
            def wrap(original):
                def step(*args, **kwargs):
                    nonlocal cursor
                    result = original(*args, **kwargs)
                    cursor += 1
                    if stop is None:
                        steps.append((original.__name__, args[0].name))
                    elif cursor == stop:
                        raise InterruptedError('synthetic interruption')
                    return result
                return step
            with ExitStack() as stack:
                for owner, original in zip((update, Path, Path, Path), real_operations):
                    stack.enter_context(patch.object(owner, original.__name__, wrap(original)))
                update.prune_inbox(self.value)
        def prepare():
            shutil.copytree(self.source, self.inbox/'11')
            (self.inbox/'11').chmod(0o700)
        prepare()
        retire(None)
        self.assertEqual([name for op, name in steps if op == 'unlink'][-1], 'release.json')
        for stop in range(1, len(steps)+1):
            with self.subTest(stop=stop, event=steps[stop-1]):
                prepare()
                with self.assertRaises(InterruptedError):
                    retire(stop)
                with patch.object(operation, 'stage_locked'), patch.object(operation, 'command'):
                    self.assertEqual(operation.trigger(self.digest, self.installed)['phase'], 'rebooting')
                self.assertEqual(list(self.inbox.iterdir()), [self.inbox/'11'])
                operation.save(self.value, {**operation.load(self.value), 'phase': 'failed'})
                update.prune_inbox(self.value)

    def test_ambiguous_retirement_preserves_the_entire_inbox(self):
        old = self.inbox/'11'
        shutil.copytree(self.source, old)
        old.chmod(0o700)
        foreign = self.inbox/'ordinary'
        foreign.mkdir()
        with self.assertRaises(release.ReleaseError):
            update.prune_inbox(self.value)
        self.assertTrue(foreign.is_dir())
        foreign.rmdir()
        (old/self.files['root']).unlink()
        with self.assertRaises(release.ReleaseError):
            update.prune_inbox(self.value)
        retired = old.rename(self.inbox/'.retiring-11')
        other = retired/'ordinary'
        other.write_bytes(b'unrelated')
        with self.assertRaises(release.ReleaseError):
            update.prune_inbox(self.value)
        self.assertEqual(other.read_bytes(), b'unrelated')
        (retired/'release.json').unlink()
        with self.assertRaises(release.ReleaseError):
            update.prune_inbox(self.value)
        self.assertTrue(other.is_file())


if __name__ == '__main__':
    unittest.main(module=None, argv=[sys.argv[0], 'test_image_admission', 'test_update',
                                     'test_boot_esp', 'test_release', 'test_image_operation', 'test_image_promotion'])
