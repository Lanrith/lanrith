"""Factory startup, disk selection and installation with disposable ordinary files."""

from contextlib import nullcontext
import io
import json
import os
from pathlib import Path
import signal
import shutil
import socket
import subprocess
import tempfile
import time
import unittest
from unittest.mock import MagicMock, Mock, call, patch

from lanrith import early_unlock, factory, measured_boot
from lanrith.release import ReleaseError


class BootPathTests(unittest.TestCase):
    def test_boot_uses_only_partitions_of_the_verified_disk(self):
        internal = {'name': '/dev/internal', 'type': 'disk', 'tran': 'sata'}
        usb = {'name': '/dev/installer', 'type': 'disk', 'tran': 'usb'}
        payload = {'name': '/dev/installer1', 'type': 'part', 'pkname': usb['name'],
                   'partlabel': 'lanrith-factory-media'}
        profile = {'boot': {}, 'storage': {}, 'tpm_policy': {}}
        for boot, children, branch in ((internal, [payload], 'unlock'), (usb, [payload], 'install'),
                                       (usb, [], 'fail'), (usb, [payload, dict(payload)], 'fail')):
            def inspect(args):
                if args[0] == 'udevadm':
                    return ''
                self.assertEqual(args[-1], boot['name'])
                inventory = [internal, {**usb, 'children': children}]
                return json.dumps({'blockdevices': [row for row in inventory if row['name'] == args[-1]]})

            with self.subTest(children=len(children), branch=branch), patch.object(factory.os, 'geteuid', return_value=0), \
                    patch.object(factory, 'secure_boot'), patch.object(factory, 'verified_root', return_value=(boot['name'], {2, 3})), \
                    patch.object(factory, 'command', side_effect=inspect), patch.object(factory, 'read', return_value=json.dumps(profile)), \
                    patch.object(factory, 'prepare_state', return_value='state') as state, patch.object(early_unlock, 'unlock') as unlock, \
                    patch.object(factory, 'Consoles'), patch.object(factory, 'notify_manager') as manager:
                if branch == 'install':
                    with patch.object(factory, 'install_media', side_effect=SystemExit(0)) as install, self.assertRaises(SystemExit):
                        factory.main(['provision'])
                    self.assertEqual(install.call_args.args[3], [payload])
                else:
                    with patch('sys.stderr', new_callable=io.StringIO):
                        self.assertEqual(factory.main(['provision']), 0 if branch == 'unlock' else 1)
                if branch == 'unlock':
                    state.assert_called_once_with(profile, internal['name'], {2, 3})
                    unlock.assert_called_once_with(profile, 'state')
                    manager.assert_called_once_with('READY=1')
                else:
                    state.assert_not_called()
                    unlock.assert_not_called()
                    manager.assert_not_called()

    def test_expired_console_has_an_independent_deadline_and_restores_the_handler(self):
        previous = signal.getsignal(signal.SIGALRM)
        with patch.object(factory, 'OPERATOR_SECONDS', 0.02), self.assertRaisesRegex(ReleaseError, 'Reboot to retry'), \
                factory.input_deadline():
            time.sleep(3)
        self.assertEqual(signal.getsignal(signal.SIGALRM), previous)
        self.assertEqual(signal.getitimer(signal.ITIMER_REAL), (0, 0))

    def test_enrollment_and_first_partition_creation_get_their_own_grants(self):
        console = MagicMock()
        with patch.object(factory.os, 'geteuid', return_value=0), patch.object(factory, 'Consoles', return_value=nullcontext(console)), \
                patch.object(factory, 'extend_startup') as extend, patch.object(factory, 'command') as command:
            factory.recovery({'boot': {}}, root='/sysroot')
            console.private.assert_called_once()
            self.assertEqual(extend.call_args_list, [call(factory.OPERATOR_SECONDS), call(factory.BOOT_SECONDS)])
            factory.repartition({'machine_id': 'a' * 32, 'boot': {}}, '/synthetic', installed_root=True)
            self.assertEqual(extend.call_args, call(factory.PARTITION_SECONDS))
            self.assertEqual(command.call_args_list[0].kwargs['timeout'], factory.PARTITION_SECONDS)

    def test_manager_receives_relative_grants_and_ready_on_its_socket(self):
        with tempfile.TemporaryDirectory() as directory, socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as manager:
            address = str(Path(directory)/'notify')
            manager.bind(address)
            manager.settimeout(1)
            with patch.dict(os.environ, {'NOTIFY_SOCKET': address}):
                factory.extend_startup(120)
                self.assertEqual(manager.recv(128), b'EXTEND_TIMEOUT_USEC=180000000')
                factory.notify_manager('READY=1')
                self.assertEqual(manager.recv(128), b'READY=1')


class PoweredOff(Exception):
    pass


class MediaTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        release = self.root/'release'
        release.mkdir()
        self.raw = release/'synthetic.raw'
        self.raw.write_bytes(b'abcd' * (256 * 1024))
        self.disk = self.root/'target'
        self.disk.write_bytes(b'original target')
        self.media = [{'pkname': '/dev/installer', 'name': '/dev/payload'}]
        self.profile = {'image_id': 'router', 'boot': {}, 'certificate': '/synthetic.crt',
                        'platform_version': '0.1.0', 'deployment_sequence': 1, 'configuration_sha256': 'a' * 64,
                        'tpm_policy': early_unlock.policy(b'public')}
        self.rows = [{'number': i, 'type': factory.GUIDS[role], 'uuid': role}
                     for i, role in enumerate(('root', 'verity'), 2)]
        self.manifest = {**self.profile, 'artifacts': [
            {'role': role, 'name': 'router_1_'+role+'.part', 'size': 1} for role in ('root', 'verity', 'uki')] +
            [{'role': 'disk', 'name': self.raw.name, 'size': self.raw.stat().st_size}]}
        self.console = Mock()
        self.events = []
        self.failure = None
        self.elapsed = 0
        self.deadline = 300

    def advance(self, seconds):
        self.elapsed += seconds
        self.assertLess(self.elapsed, self.deadline, 'manager would have killed the current phase')

    def grant(self, message):
        self.assertTrue(message.startswith('EXTEND_TIMEOUT_USEC='))
        seconds = int(message.split('=')[1]) // 1_000_000
        self.deadline = max(self.deadline, self.elapsed + seconds)
        self.events.append(('grant', seconds))

    def authenticate(self, _payload, _certificate, *, before_hashing, **options):
        self.events.append('authenticate')
        before_hashing(sum(row['size'] for row in self.manifest['artifacts']))
        return self.manifest

    def confirm(self, *_):
        self.events.append('select-and-confirm')
        self.advance(899)
        return str(self.disk)

    def command(self, args, timeout=30):
        name = args[0]
        self.events.append(name)
        if name == 'tpm2_pcrread':
            self.assertEqual(args[1:4], ['-T', 'device:/dev/tpmrm0', '-o'])
            self.assertEqual(args[-1], 'sha256:7,11,15')
            if self.failure == 'missing-tpm':
                raise ReleaseError('TPM device unavailable')
            Path(args[4]).write_bytes(bytes(64 if self.failure == 'missing-pcr' else 96))
        elif name in ('dd', 'cmp'):
            # Model a device using nearly the full per-command budget, then
            # perform the real copy or comparison on disposable ordinary files.
            self.assertEqual(self.events[-2], ('grant', timeout + 60))
            self.advance(timeout - 1)
            if name == 'dd' and self.failure == name:
                self.disk.write_bytes(self.raw.read_bytes()[:64])
                raise ReleaseError('Synthetic copy interruption')
            if name == 'cmp' and self.failure == name:
                self.disk.write_bytes(b'synthetic read-back mismatch')
            result = subprocess.run(args, capture_output=True, timeout=timeout)
            if result.returncode:
                raise ReleaseError('Synthetic I/O failure')
        elif name == 'systemctl':
            self.assertEqual(args, ['systemctl', '--force', 'poweroff'])
            raise PoweredOff
        else:
            self.assertIn(name, ('mount', 'umount', 'sfdisk', 'sync'))

    def install(self):
        self.deadline = self.elapsed + 300
        ordinary_directory = tempfile.TemporaryDirectory
        def directory(*, prefix, dir=None):
            if prefix == 'lanrith-media.':
                return nullcontext(str(self.root))
            return ordinary_directory(prefix=prefix, dir=self.root)
        with patch.object(factory.tempfile, 'TemporaryDirectory', side_effect=directory), \
                patch.object(factory, 'verify', side_effect=self.authenticate), patch.object(measured_boot, 'verify'), \
                patch.object(factory, 'geometry', return_value=self.rows), patch.object(factory, 'command', side_effect=self.command), \
                patch.object(factory, 'notify_manager', side_effect=self.grant), patch.object(factory, 'target', side_effect=self.confirm):
            factory.install_media(self.profile, '/dev/installer', {2, 3}, self.media, self.console)

    def test_interrupted_copy_requires_fresh_verification_and_confirmation_then_readback(self):
        self.failure = 'dd'
        with self.assertRaisesRegex(ReleaseError, 'interruption'):
            self.install()
        self.assertEqual(self.disk.stat().st_size, 64)
        self.assertNotIn('systemctl', self.events)
        self.failure = None
        with self.assertRaises(PoweredOff):
            self.install()
        self.assertEqual(self.disk.read_bytes(), self.raw.read_bytes())
        self.assertEqual([event for event in self.events if isinstance(event, str)], [
            'mount', 'authenticate', 'tpm2_pcrread', 'select-and-confirm', 'dd', 'umount',
            'mount', 'authenticate', 'tpm2_pcrread', 'select-and-confirm', 'dd', 'cmp', 'sfdisk', 'umount', 'sync', 'systemctl'])

    @unittest.skipUnless(shutil.which('pv'), 'rate-limited source requires pv')
    def test_rate_limited_source_completes_copy_readback_and_poweroff(self):
        run = subprocess.run
        def throttle(args, **options):
            if args[0] == 'dd':
                self.assertEqual(args[1], 'if='+str(self.raw))
                args = [args[0], *args[2:]]
            else:
                self.assertEqual(args[0], 'cmp')
                self.assertEqual(args[-2], str(self.raw))
                args = [*args[:-2], '-', args[-1]]
            with subprocess.Popen(['pv', '--quiet', '--rate-limit', '1M', str(self.raw)], stdout=subprocess.PIPE) as source:
                result = run(args, stdin=source.stdout, **options)
                self.assertEqual(source.wait(timeout=5), 0)
                return result

        with patch.object(subprocess, 'run', side_effect=throttle), self.assertRaises(PoweredOff):
            self.install()
        self.assertEqual(self.disk.read_bytes(), self.raw.read_bytes())
        self.assertEqual(self.events[-3:], ['umount', 'sync', 'systemctl'])

    def test_failed_readback_prohibits_relocation_and_poweroff(self):
        self.failure = 'cmp'
        with self.assertRaisesRegex(ReleaseError, 'I/O failure'):
            self.install()
        for action in ('sfdisk', 'sync', 'systemctl'):
            self.assertNotIn(action, self.events)

    def test_missing_tpm_or_bank_preserves_original_target_before_selection(self):
        for failure in ('missing-tpm', 'missing-pcr'):
            self.failure = failure
            with self.subTest(failure=failure), self.assertRaises(ReleaseError):
                self.install()
            self.assertNotIn('select-and-confirm', self.events)
            self.assertEqual(self.disk.read_bytes(), b'original target')

    def test_manual_profile_does_not_require_tpm_capabilities(self):
        del self.profile['tpm_policy']
        self.profile['boot']['tpm'] = 'disabled'
        with patch.object(factory, 'repartition') as repartition, self.assertRaises(PoweredOff):
            self.install()
        repartition.assert_called_once_with(self.profile, str(self.disk), installed_root=False, console=self.console)
        self.assertNotIn('tpm2_pcrread', self.events)
