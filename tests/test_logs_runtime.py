"""An alive exporter with an exited graph component must not bless a boot."""

import os
import json
from pathlib import Path
import signal
import subprocess
import tempfile
import unittest
from unittest import mock

from lanrith import logs_runtime as runtime


def metrics(healthy=9, evaluating='0', **states):
    prefix = 'alloy_component_controller_'
    lines = [prefix+'evaluating{controller_id="",controller_path="/"} '+evaluating]
    for name, number in {'healthy': healthy, **states}.items():
        lines.append(prefix+'running_components{controller_id="",controller_path="/",health_type="'+name+'"} '+str(number))
    return '\n'.join(lines)


def exporter_metrics():
    return '\n'.join(name+'{component_id="otelcol.exporter.otlphttp.router",data_type="logs"} '+str(number)
        for name, number in (('otelcol_exporter_queue_capacity', 67108864), ('otelcol_exporter_queue_size', 1234),
                              ('otelcol_exporter_enqueue_failed_log_records_total', 42),
                              ('otelcol_exporter_send_failed_log_records_total', 21)))


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
                mock.patch.object(runtime, 'publish_observation'), \
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

    def test_exporter_observation_selects_only_its_log_series_and_bounds_values(self):
        text = exporter_metrics()
        value = runtime.observation(text+'\n'+text.replace('data_type="logs"', 'data_type="traces"'))
        self.assertEqual({name: value[name] for name in runtime.COUNTERS}, {
            'queue_capacity_bytes': 67108864, 'queue_size_bytes': 1234,
            'enqueue_failed_records': 42, 'send_failed_records': 21})
        for changed in (text+'\n'+text, text.replace(' 42', ' NaN'), text.replace(' 42', ' inf'),
                        text.replace(' 42', ' -1'), text.replace(' 42', ' 0.5'),
                        text.replace(' 67108864', ' 1'), text.replace(' 1234', ' 67108865'),
                        text.replace('otelcol_exporter_queue_size', 'unrelated_metric')):
            with self.subTest(changed=changed), self.assertRaises(runtime.LogsRuntimeError):
                runtime.observation(changed)
        zero = runtime.observation('\n'.join(text.splitlines()[:2]))
        self.assertEqual((zero['enqueue_failed_records'], zero['send_failed_records']), (0, 0))

    def test_observation_is_atomic_fresh_same_boot_and_contains_no_unrecognized_fields(self):
        value = runtime.observation(exporter_metrics())
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/'health.json'
            runtime.publish_observation(value, path)
            self.assertEqual(path.stat().st_mode & 0o777, 0o640)
            self.assertEqual(runtime.read_observation(path, owner=os.getuid()), value)
            for changed in ({'boot_id': 'previous-boot'}, {'observed_monotonic_ns': 0},
                            {'observed_monotonic_ns': value['observed_monotonic_ns']+10**12},
                            {'schema': True}, {'queue_size_bytes': 67108865},
                            {'enqueue_failed_records': True}, {'configuration': 'owner.yaml'}):
                path.write_text(json.dumps({**value, **changed}))
                with self.subTest(changed=changed), self.assertRaises(ValueError):
                    runtime.read_observation(path, owner=os.getuid())
            path.write_text(json.dumps(value))
            path.chmod(0o660)
            with self.assertRaises(ValueError):
                runtime.read_observation(path, owner=os.getuid())
            path.chmod(0o640)
            linked = Path(directory)/'alias.json'
            linked.symlink_to(path)
            with self.assertRaises(OSError):
                runtime.read_observation(linked, owner=os.getuid())

    def test_freshness_clock_is_sampled_after_a_concurrent_publication(self):
        value = {**runtime.observation(exporter_metrics()), 'observed_monotonic_ns': 200}
        clock = [100]

        def published(*args, **kwargs):
            clock[0] = 300
            return json.dumps(value).encode()

        with mock.patch.object(runtime, 'read', side_effect=published), \
                mock.patch.object(runtime.time, 'monotonic_ns', side_effect=lambda: clock[0]):
            self.assertEqual(runtime.read_observation(owner=os.getuid()), value)

    def test_local_loss_counters_are_separate_strict_and_optional(self):
        remote = exporter_metrics()
        local = '\n'.join(name+'{component_id="otelcol.exporter.file.router_observations"} '+str(number)
            for name, number in ((runtime.LOCAL_COUNTERS['local_sent_records'], 100),
                                  (runtime.LOCAL_COUNTERS['local_failed_records'], 7)))
        self.assertNotIn('local_sent_records', runtime.observation(remote+local))
        value = runtime.observation(remote+'\n'+local, local=True)
        self.assertEqual((value['local_sent_records'], value['local_failed_records']), (100, 7))
        for text in (local+'\n'+local, local.replace(' 7', ' NaN'), local.replace(' 7', ' -1'),
                     local.replace(' 7', ' 0.5')):
            with self.subTest(text=text), self.assertRaises(runtime.LogsRuntimeError):
                runtime.observation(remote+'\n'+text, local=True)
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary)/'health.json'
            runtime.publish_observation(value, path)
            self.assertEqual(runtime.read_observation(path, owner=os.getuid()), value)
            for change in ({'local_failed_records': True}, {'local_sent_records': -1}):
                path.write_text(json.dumps({**value, **change}))
                with self.subTest(change=change), self.assertRaises(ValueError):
                    runtime.read_observation(path, owner=os.getuid())
            del value['local_sent_records']
            path.write_text(json.dumps(value))
            with self.assertRaises(ValueError):
                runtime.read_observation(path, owner=os.getuid())

    def test_optional_local_health_write_failure_keeps_remote_watchdog(self):
        child = mock.Mock()
        child.poll.side_effect = [None, 0, 0]
        state = runtime.observation(exporter_metrics(), local=True)
        def publish(value, path):
            if path == runtime.LOCAL/'health.json':
                raise PermissionError('synthetic local volume failure')
        with mock.patch.object(runtime.subprocess, 'Popen', return_value=child), \
                mock.patch.object(runtime, 'health', return_value=state) as health, \
                mock.patch.object(runtime, 'publish_observation', side_effect=publish) as output, \
                mock.patch.object(runtime.time, 'sleep'), mock.patch.object(runtime, 'notify') as notify:
            with self.assertRaisesRegex(runtime.LogsRuntimeError, 'exporter exited'):
                runtime.supervise(local=True)
            health.assert_called_once_with(local=True)
            self.assertEqual(output.call_args_list, [mock.call(state, runtime.OBSERVATION),
                                                    mock.call(state, runtime.LOCAL/'health.json')])
            self.assertEqual(notify.call_args_list, [mock.call('READY=1'), mock.call('WATCHDOG=1')])


if __name__ == '__main__':
    unittest.main()
