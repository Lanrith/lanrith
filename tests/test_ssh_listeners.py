"""Exercise bounded SSH repair and the same-process socket acceptance boundary."""

import importlib.machinery
import importlib.util
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

HELPER = Path(__file__).resolve().parents[1]/'mkosi/base/mkosi.extra/usr/lib/lanrith/verify-ssh-listeners'
loader = importlib.machinery.SourceFileLoader('ssh_listeners', str(HELPER))
spec = importlib.util.spec_from_loader(loader.name, loader)
ssh = importlib.util.module_from_spec(spec)
loader.exec_module(ssh)


class SshListenerTests(unittest.TestCase):
    def setUp(self):
        self.port = 2222
        self.v4 = '192.0.2.1'
        self.v6 = '2001:db8::1'
        self.expected = {self.v4, self.v6}
        self.interfaces = {'lan': list(self.expected)}
        tmp = self.enterContext(tempfile.TemporaryDirectory())
        self.enterContext(patch.object(ssh, 'RETRY', Path(tmp)/'attempts.json'))
        self.enterContext(patch.object(ssh, 'assigned', return_value=self.expected))
        self.unit = self.enterContext(patch.object(ssh.subprocess, 'check_output',
                                                   return_value='MainPID=123\nResult=success\nActiveState=active\n'))
        self.run_unit = self.enterContext(patch.object(ssh.subprocess, 'run'))
        self.owned = self.enterContext(patch.object(ssh, 'listener_sockets', return_value={(self.v4, self.port)}))
        self.can_bind = self.enterContext(patch.object(ssh, 'bindable', return_value=True))
        self.enterContext(patch.object(ssh, 'report'))

    def check(self, repair):
        return ssh.check(self.interfaces, self.expected, self.port, repair)

    def test_reload_failures_are_bounded_and_new_state_resets_attempts(self):
        self.run_unit.side_effect = subprocess.CalledProcessError(1, 'systemctl')
        for _ in range(3):
            with self.assertRaises(subprocess.CalledProcessError):
                self.check(True)
        self.check(True)
        self.assertEqual(self.run_unit.call_count, 3)
        self.can_bind.return_value = False
        self.check(True)
        self.assertFalse(ssh.RETRY.exists())
        self.can_bind.return_value = True
        self.run_unit.side_effect = None
        self.check(True)
        self.assertEqual(self.run_unit.call_count, 4)
        self.owned.return_value = {(address, self.port) for address in self.expected}
        self.assertEqual(self.check(False), 0)
        self.check(True)
        self.assertEqual(self.run_unit.call_count, 4)
        self.owned.return_value.add(('0.0.0.0', self.port))
        self.assertEqual(self.check(False), 1)

    def test_only_an_address_skipped_unit_can_be_started(self):
        for result, state in [('success', 'inactive'), ('exit-code', 'failed'), ('timeout', 'failed')]:
            self.unit.return_value = f'MainPID=0\nResult={result}\nActiveState={state}\n'
            self.check(True)
        self.run_unit.assert_not_called()
        self.unit.return_value = 'MainPID=0\nResult=exec-condition\nActiveState=inactive\n'
        self.can_bind.return_value = False
        self.check(True)
        self.run_unit.assert_not_called()
        self.can_bind.return_value = True
        self.check(True)
        self.run_unit.assert_called_once_with(['/usr/bin/systemctl', '--no-block', 'start', 'ssh.service'],
                                              check=True, timeout=2)

    def test_main_status_255_requires_current_process_bind_failure_evidence(self):
        fields = {'ActiveState': 'failed', 'Result': 'exit-code', 'ExecMainStatus': '255',
                  'ExecMainPID': '44', 'InvocationID': 'abcd'*8}
        self.run_unit.return_value = subprocess.CompletedProcess([], 1, stdout='')
        self.assertFalse(ssh.address_start_failure(fields))
        arguments = self.run_unit.call_args.args[0]
        self.assertIn('_PID=44', arguments)
        self.assertIn('_SYSTEMD_INVOCATION_ID='+'abcd'*8, arguments)
        self.run_unit.return_value = subprocess.CompletedProcess([], 0, stdout='fatal: Cannot bind any address.')
        self.assertTrue(ssh.address_start_failure(fields))
        self.assertFalse(ssh.address_start_failure({**fields, 'ExecMainStatus': '1'}))
