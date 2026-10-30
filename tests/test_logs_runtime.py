"""An alive exporter with an exited graph component must not bless a boot."""

import os
import signal
import subprocess
import unittest
from unittest import mock

from lanrith import logs_runtime as runtime


def metrics(healthy=9, evaluating='0', **states):
    prefix = 'alloy_component_controller_'
    lines = [prefix+'evaluating{controller_id="",controller_path="/"} '+evaluating]
    for name, number in {'healthy': healthy, **states}.items():
        lines.append(prefix+'running_components{controller_id="",controller_path="/",health_type="'+name+'"} '+str(number))
    return '\n'.join(lines)


class LogSupervisorTests(unittest.TestCase):
    def test_complete_root_graph_is_required(self):
        for value in (metrics(), metrics(12), metrics(exited=0, unknown=0)):
            self.assertTrue(runtime.pipeline_healthy(value))
        for value in (metrics(8), metrics(8, exited=1), metrics(exited=1), metrics(unhealthy=1),
                      metrics(unknown=1), metrics(evaluating='1'), metrics(evaluating='NaN'),
                      metrics(healthy='inf'), metrics(healthy='9.5'), metrics(healthy=5000),
                      metrics()+'\n'+metrics(), metrics().replace('controller_path="/"', 'controller_path="/nested"'),
                      '', 'HTTP/1.1 200 OK'):
            with self.subTest(value=value):
                self.assertFalse(runtime.pipeline_healthy(value))

    def test_exited_component_prevents_readiness_and_is_reaped(self):
        child = mock.Mock()
        child.poll.return_value = None
        with mock.patch.object(runtime.subprocess, 'Popen', return_value=child) as launch, \
                mock.patch.object(runtime, 'health', side_effect=runtime.LogsRuntimeError), \
                mock.patch.object(runtime.time, 'monotonic', side_effect=[0, 2]), \
                mock.patch.object(runtime, 'notify') as notify, \
                mock.patch.dict(os.environ, NOTIFY_SOCKET='@fixture', WATCHDOG_PID='1', WATCHDOG_USEC='1'):
            with self.assertRaises(runtime.LogsRuntimeError):
                runtime.supervise(startup_seconds=1)
            notify.assert_not_called()
            child.terminate.assert_called_once()
            child.wait.assert_called_once_with(timeout=10)
            self.assertEqual(launch.call_args.args[0], runtime.ALLOY)
            for key in ('NOTIFY_SOCKET', 'WATCHDOG_PID', 'WATCHDOG_USEC'):
                self.assertNotIn(key, launch.call_args.kwargs['env'])

    def test_failed_component_after_readiness_exits_for_service_restart(self):
        child = mock.Mock()
        child.poll.return_value = None
        previous = {name: signal.getsignal(name) for name in (signal.SIGTERM, signal.SIGINT)}
        with mock.patch.object(runtime.subprocess, 'Popen', return_value=child), \
                mock.patch.object(runtime, 'health', side_effect=[None, runtime.LogsRuntimeError]), \
                mock.patch.object(runtime.time, 'sleep'), mock.patch.object(runtime, 'notify') as notify:
            with self.assertRaises(runtime.LogsRuntimeError):
                runtime.supervise()
            self.assertEqual(notify.call_args_list, [mock.call('READY=1'), mock.call('WATCHDOG=1')])
            child.terminate.assert_called_once()
        self.assertEqual({name: signal.getsignal(name) for name in previous}, previous)

    def test_unresponsive_child_is_killed_with_bounded_wait(self):
        child = mock.Mock()
        child.poll.return_value = None
        child.wait.side_effect = [subprocess.TimeoutExpired('fixture', 10), 0]
        with mock.patch.object(runtime.subprocess, 'Popen', return_value=child), \
                mock.patch.object(runtime, 'health', side_effect=runtime.LogsRuntimeError), \
                mock.patch.object(runtime.time, 'monotonic', side_effect=[0, 2]):
            with self.assertRaises(runtime.LogsRuntimeError):
                runtime.supervise(startup_seconds=1)
        child.kill.assert_called_once()
        self.assertEqual(child.wait.call_args_list, [mock.call(timeout=10), mock.call(timeout=2)])


if __name__ == '__main__':
    unittest.main()
