"""Exercise serial supervision with a synthetic monotonic clock and manager."""
import runpy
import subprocess
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch


HELPER = Path(__file__).resolve().parents[1]/'mkosi/base/mkosi.extra/usr/lib/lanrith/serial-idle-watchdog'


class SerialWatchdogTests(unittest.TestCase):
    def setUp(self):
        with patch.object(Path, 'read_text', return_value='{"serial":{"tty":"ttyS1","timeout_seconds":45}}'):
            self.watch = SimpleNamespace(**runpy.run_path(str(HELPER)))
        self.login = self.watch.Sample('a', True, 10)
        self.unavailable = self.watch.Sample(None)
        self.state, expired = self.watch.advance(self.watch.State(), self.login, 100)
        self.assertFalse(expired)

    def test_intermittent_and_persistent_errors_preserve_the_deadline(self):
        watch = self.watch
        unknown, expired = watch.advance(self.state, self.unavailable, 130)
        self.assertEqual(unknown, self.state)
        self.assertFalse(expired)
        for sample in (self.login, watch.Sample('a', False, 10), self.unavailable):
            self.assertTrue(watch.advance(unknown, sample, 145)[1])
        self.assertEqual(watch.advance(unknown, watch.Sample(''), 145), (watch.State(), False))

    def test_fresh_input_and_replacement_have_their_own_deadline(self):
        for sample in (self.watch.Sample('a', True, 11), self.watch.Sample('b', True, 10)):
            fresh, expired = self.watch.advance(self.state, sample, 145)
            self.assertFalse(expired)
            self.assertEqual(fresh.deadline, 190)
            self.assertEqual(fresh.invocation, sample.invocation)

    def test_first_observation_and_missing_rx_have_bounded_deadlines(self):
        watch = self.watch
        unseen, _ = watch.advance(watch.State(), self.unavailable, 100)
        for sample in (self.unavailable, self.login):
            self.assertTrue(watch.advance(unseen, sample, 145)[1])
        missing, _ = watch.advance(watch.State(), watch.Sample('a', True), 100)
        for sample in (watch.Sample('a', True), self.login):
            self.assertTrue(watch.advance(missing, sample, 145)[1])

    def test_unknown_manager_result_is_distinct_from_confirmed_absence(self):
        for error in (FileNotFoundError(), subprocess.TimeoutExpired('systemctl', 2),
                      subprocess.CalledProcessError(1, 'systemctl')):
            with patch.object(subprocess, 'run', side_effect=error):
                self.assertEqual(self.watch.observe(), self.unavailable)
        for text in ('', 'MainPID=unreadable\nControlPID=0\n', 'MainPID=50\nControlPID=0\n'):
            with patch.object(subprocess, 'run', return_value=SimpleNamespace(stdout=text)):
                self.assertEqual(self.watch.observe(), self.unavailable)
        with patch.object(subprocess, 'run', return_value=SimpleNamespace(stdout='MainPID=0\nControlPID=0\n')):
            self.assertEqual(self.watch.observe(), self.watch.Sample(''))

    def test_only_a_readable_prestart_process_earns_its_invocation_permit(self):
        invocation = '3'*32
        with tempfile.TemporaryDirectory() as directory:
            permit = Path(directory)/'getty'
            with patch.dict(self.watch.observe.__globals__, PERMIT=permit):
                for main, control in ((0, 50), (50, 0)):
                    text = f'MainPID={main}\nControlPID={control}\nInvocationID={invocation}\n'
                    with patch.object(subprocess, 'run', return_value=SimpleNamespace(stdout=text)):
                        with patch.object(Path, 'read_text', side_effect=PermissionError()):
                            self.assertEqual(self.watch.observe(), self.unavailable)
                            self.assertFalse(permit.exists())
                        if control:
                            with patch.object(Path, 'read_text', return_value=''):
                                self.assertEqual(self.watch.observe(), self.watch.Sample(''))
                            self.assertEqual(permit.read_text(), invocation+' 50\n')
                            permit.unlink()

    def test_final_observation_controls_enforcement(self):
        for final, restart in ((self.login, True), (self.watch.Sample('b', True, 10), False),
                               (self.watch.Sample('a', True, 11), False), (self.unavailable, False)):
            with self.subTest(final=final):
                now = 100
                def next_poll(_):
                    nonlocal now
                    if now == 145:
                        raise StopIteration
                    now = 145

                manager = SimpleNamespace(run=Mock())
                clock = SimpleNamespace(monotonic=lambda: now, sleep=next_poll)
                observe = Mock(side_effect=[self.login, self.login, final])
                with patch.dict(self.watch.main.__globals__, observe=observe, time=clock, subprocess=manager), \
                        patch('builtins.print'), self.assertRaises(SystemExit if final == self.unavailable else StopIteration):
                    self.watch.main()
                self.assertEqual(observe.call_count, 3)
                self.assertEqual(manager.run.called, restart)
