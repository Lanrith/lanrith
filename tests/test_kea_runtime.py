"""Kea startup may tighten only the fixed, live daemon's own control socket."""

from contextlib import redirect_stderr
import io
import os
from pathlib import Path
import socket
import stat
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import time

from lanrith import kea_runtime


class KeaStartupTests(unittest.TestCase):
    def test_cli_has_no_path_override_and_wrong_actor_cannot_prepare_ipc(self):
        for arguments in ([], ['--path', '/other'], ['0'], ['-1'], ['2', '3'], ['not-a-pid']):
            self.assertEqual(kea_runtime.main(arguments), 64)
        with patch.object(kea_runtime.pwd, 'getpwnam', return_value=SimpleNamespace(pw_uid=100, pw_gid=100)), \
                patch.object(kea_runtime.os, 'getuid', return_value=0), \
                patch.object(kea_runtime.os, 'geteuid', return_value=0), \
                patch.object(kea_runtime, 'constrain') as constrain, redirect_stderr(io.StringIO()) as error:
            self.assertEqual(kea_runtime.main(['123']), 1)
            constrain.assert_not_called()
            self.assertEqual(error.getvalue(), 'Kea control readiness failed.\n')
        with patch.object(kea_runtime.pwd, 'getpwnam', return_value=SimpleNamespace(pw_uid=100, pw_gid=100)), \
                patch.object(kea_runtime.os, 'getuid', return_value=100), \
                patch.object(kea_runtime.os, 'geteuid', return_value=100), \
                patch.object(kea_runtime.os, 'getgid', return_value=101), \
                patch.object(kea_runtime.os, 'getegid', return_value=101), \
                patch.object(kea_runtime, 'constrain') as constrain, redirect_stderr(io.StringIO()):
            self.assertEqual(kea_runtime.main(['123']), 1)
            constrain.assert_not_called()

    def test_missing_socket_has_one_bounded_deadline_but_unsafe_input_fails_immediately(self):
        with patch.object(kea_runtime.pwd, 'getpwnam', return_value=SimpleNamespace(pw_uid=100, pw_gid=100)), \
                patch.object(kea_runtime.os, 'getuid', return_value=100), \
                patch.object(kea_runtime.os, 'geteuid', return_value=100), \
                patch.object(kea_runtime.os, 'getgid', return_value=100), \
                patch.object(kea_runtime.os, 'getegid', return_value=100), \
                patch.object(kea_runtime, 'constrain', side_effect=FileNotFoundError(2, 'absent')) as constrain, \
                patch.object(kea_runtime.time, 'monotonic', side_effect=[0, 11]), \
                patch.object(kea_runtime.time, 'sleep') as sleep:
            with self.assertRaises(ValueError):
                kea_runtime.ready(123)
            self.assertEqual(constrain.call_count, 1)
            sleep.assert_not_called()
        with patch.object(kea_runtime.pwd, 'getpwnam', return_value=SimpleNamespace(pw_uid=100, pw_gid=100)), \
                patch.object(kea_runtime.os, 'getuid', return_value=100), \
                patch.object(kea_runtime.os, 'geteuid', return_value=100), \
                patch.object(kea_runtime.os, 'getgid', return_value=100), \
                patch.object(kea_runtime.os, 'getegid', return_value=100), \
                patch.object(kea_runtime, 'constrain', side_effect=ValueError) as constrain:
            with self.assertRaises(ValueError):
                kea_runtime.ready(123)
            self.assertEqual(constrain.call_count, 1)

    @unittest.skipUnless(os.geteuid() == 0, 'Use the native root test environment.')
    def test_live_socket_is_verified_then_tightened_without_sending_an_admin_request(self):
        with tempfile.TemporaryDirectory(prefix='kea-ready-', dir='/run') as temporary:
            Path(temporary).chmod(0o750)
            path = Path(temporary)/'control.sock'
            with socket.socket(socket.AF_UNIX) as server:
                server.bind(str(path))
                path.chmod(0o700)
                server.listen()
                server.settimeout(1)
                kea_runtime.constrain(path, 0, os.getpid(), time.monotonic()+2)
                self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o660)
                connection, _ = server.accept()
                with connection:
                    connection.settimeout(1)
                    self.assertEqual(connection.recv(1), b'')

    @unittest.skipUnless(os.geteuid() == 0, 'Use the native root test environment.')
    def test_wrong_peer_alias_regular_file_or_writable_parent_cannot_be_repaired(self):
        with tempfile.TemporaryDirectory(prefix='kea-ready-', dir='/run') as temporary:
            root = Path(temporary)
            root.chmod(0o750)
            path = root/'control.sock'
            with socket.socket(socket.AF_UNIX) as server:
                server.bind(str(path))
                server.listen()
                path.chmod(0o700)
                with self.assertRaises(ValueError):
                    kea_runtime.constrain(path, 0, os.getpid()+1, time.monotonic()+2)
                self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o700)
                os.chown(path, 0, 65534)
                with self.assertRaises(ValueError):
                    kea_runtime.constrain(path, 0, os.getpid(), time.monotonic()+2)
                self.assertEqual(path.stat().st_gid, 65534)
                os.chown(path, 0, 0)
                alias = root/'alias'
                alias.symlink_to(path)
                regular = root/'file'
                regular.write_text('preserve')
                for selected in (alias, regular):
                    with self.subTest(path=selected.name), self.assertRaises(ValueError):
                        kea_runtime.constrain(selected, 0, os.getpid(), time.monotonic()+2)
                root.chmod(0o777)
                with self.assertRaises(ValueError):
                    kea_runtime.constrain(path, 0, os.getpid(), time.monotonic()+2)
                root.chmod(0o750)
                path.chmod(0o777)
                with self.assertRaises(ValueError):
                    kea_runtime.constrain(path, 0, os.getpid(), time.monotonic()+2)
                self.assertEqual(regular.read_text(), 'preserve')


if __name__ == '__main__':
    unittest.main()
