"""Initial clock readiness waits without opening policy or resetting history."""
import ctypes
import errno
import unittest
from unittest.mock import patch

from lanrith import config, policy_runtime as runtime
from test_radius import declaration


class ClockStartupTests(unittest.TestCase):
    def test_read_only_query_and_error(self):
        def query(pointer):
            self.assertEqual(list(ctypes.cast(pointer, ctypes.POINTER(ctypes.c_long * 64)).contents), [0]*64)
            return 5
        with patch('ctypes.CDLL') as library:
            library.return_value.adjtimex.side_effect = query
            self.assertEqual(runtime.kernel_clock_state(), 5)
            library.return_value.adjtimex.side_effect = lambda _: -1
            with patch('ctypes.get_errno', return_value=errno.EPERM), self.assertRaises(OSError):
                runtime.kernel_clock_state()

    def test_unsynchronized_and_leap_states_wait_then_return(self):
        with patch.object(runtime, 'kernel_clock_state', side_effect=[5, 1, 2, 3, 4, 0]), \
             patch.object(runtime.time, 'sleep') as sleep, patch.object(runtime, 'command') as command:
            runtime.wait_clock()
        self.assertEqual(sleep.call_count, 5)
        command.assert_not_called()

    def test_deadline_does_not_wait_forever_or_change_policy(self):
        with patch.object(runtime, 'kernel_clock_state', return_value=5), \
             patch.object(runtime.time, 'monotonic', side_effect=[10, 100]), \
             patch.object(runtime.time, 'sleep') as sleep, patch.object(runtime, 'command') as command, \
             self.assertRaises(runtime.PolicyRuntimeError):
            runtime.wait_clock()
        sleep.assert_not_called()
        command.assert_not_called()

    def test_helper_waits_inside_its_existing_privilege_boundary(self):
        unit = config.render(declaration())['usr/lib/systemd/system/lanrith-policy-helper.service']
        self.assertIn('ExecStartPre=/usr/lib/lanrith/policy-runtime wait-clock\n', unit)
        self.assertIn('CapabilityBoundingSet=CAP_NET_ADMIN\n', unit)
        self.assertNotIn('CAP_SYS_TIME', unit)
        self.assertIn('TimeoutStartSec=200s\n', unit)
