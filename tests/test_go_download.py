import contextlib
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import unittest
from unittest.mock import patch

from lanrith import go_download


ERROR = ('go: github.com/mattn/go-xmlrpc@v0.0.3: read '
         '"https://proxy.golang.org/github.com/mattn/go-xmlrpc/@v/v0.0.3.zip": '
         'stream error: stream ID 397; INTERNAL_ERROR; received from peer\n')


class GoDownloadTests(unittest.TestCase):
    def result(self, code=1, stdout='', stderr=ERROR):
        return subprocess.CompletedProcess(('go', 'mod', 'download', 'all'), code, stdout, stderr)

    def test_proxy_interruption_retries_identical_download_then_succeeds(self):
        success = self.result(0, stderr='')
        environment = {'GOSUMDB': 'sum.golang.org', 'GOPROXY': 'https://proxy.golang.org'}
        with patch.object(go_download.subprocess, 'run', side_effect=[self.result(), success]) as run, \
                patch.object(go_download.time, 'sleep') as sleep, contextlib.redirect_stderr(io.StringIO()) as log:
            self.assertIs(go_download.download('all', cwd='/fixture', env=environment), success)
        self.assertEqual(run.call_args_list[0], run.call_args_list[1])
        self.assertEqual(run.call_args.args[0], ('go', 'mod', 'download', 'all'))
        self.assertIs(run.call_args.kwargs['env'], environment)
        sleep.assert_called_once_with(2)
        self.assertIn(ERROR, log.getvalue())

    def test_repeated_transport_failure_stops_after_three_attempts(self):
        with patch.object(go_download.subprocess, 'run', return_value=self.result()) as run, \
                patch.object(go_download.time, 'sleep') as sleep, contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(subprocess.CalledProcessError):
                go_download.download('all')
        self.assertEqual(run.call_count, 3)
        self.assertEqual([call.args for call in sleep.call_args_list], [(2,), (5,)])

    def test_checksum_authentication_unknown_modules_and_mixed_errors_never_retry(self):
        for error in ('SECURITY ERROR\nchecksum mismatch\n', 'go: unknown revision v0.0.3\n',
                      'go: https://proxy.golang.org/module: 404 Not Found\n',
                      ERROR+'SECURITY ERROR\n', 'go: updates to go.mod needed\n'):
            with self.subTest(error=error), patch.object(go_download.subprocess, 'run',
                    return_value=self.result(stderr=error)) as run, patch.object(go_download.time, 'sleep') as sleep, \
                    contextlib.redirect_stderr(io.StringIO()), self.assertRaises(subprocess.CalledProcessError):
                go_download.download('all')
            self.assertEqual(run.call_count, 1)
            sleep.assert_not_called()

    def test_json_download_checks_every_error_and_keeps_successful_records(self):
        successful = json.dumps({'Path': 'example.org/a', 'Sum': 'h1:verified'})
        interrupted = json.dumps({'Path': 'example.org/b', 'Error': ERROR.strip()})
        self.assertTrue(go_download.transport_failure(self.result(stdout=successful+'\n'+interrupted, stderr='')))
        security = json.dumps({'Path': 'example.org/c', 'Error': 'checksum mismatch'})
        self.assertFalse(go_download.transport_failure(self.result(stdout=interrupted+'\n'+security, stderr='')))
        mixed = json.dumps({'Error': 'checksum mismatch\n'+ERROR})
        self.assertFalse(go_download.transport_failure(self.result(stdout=mixed, stderr='')))
        self.assertFalse(go_download.transport_failure(self.result(stdout='invalid json', stderr=ERROR)))

    def test_timeout_or_process_kill_is_not_classified_as_download_transport(self):
        self.assertFalse(go_download.transport_failure(self.result(-9)))
        with patch.object(go_download.subprocess, 'run', side_effect=subprocess.TimeoutExpired('go', 600)) as run, \
                patch.object(go_download.time, 'sleep') as sleep, self.assertRaises(subprocess.TimeoutExpired):
            go_download.download('all')
        self.assertEqual(run.call_count, 1)
        sleep.assert_not_called()

    def test_worker_retries_downloads_but_never_compilers_tests_or_scans(self):
        path = Path(__file__).resolve().parents[1]/'scripts/alloy-worker.py'
        spec = importlib.util.spec_from_file_location('alloy_worker', path)
        worker = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(worker)
        with patch.object(worker.go_download, 'download') as download, patch.object(worker.subprocess, 'run') as run:
            worker.run('go', 'mod', 'download', '-json', 'example.org/a@v1.2.3', cwd='/fixture')
            download.assert_called_once_with('-json', 'example.org/a@v1.2.3', cwd='/fixture')
            run.assert_not_called()
        for command in (('go', 'test', './...'), ('go', 'build', '.'), ('go', 'mod', 'verify'), ('/scanner', './...')):
            with self.subTest(command=command), patch.object(worker.go_download, 'download') as download, \
                    patch.object(worker.subprocess, 'run', side_effect=subprocess.CalledProcessError(1, command)) as run, \
                    self.assertRaises(subprocess.CalledProcessError):
                worker.run(*command)
            download.assert_not_called()
            self.assertEqual(run.call_count, 1)


if __name__ == '__main__':
    unittest.main()
