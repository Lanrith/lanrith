"""A translator cannot forge the supervisor's executable-identity witness."""

import os
from pathlib import Path
import subprocess
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from lanrith import nat64_runtime as runtime
from lanrith.release import ReleaseError


@unittest.skipUnless(os.geteuid() == 0, 'Requires a disposable root process fixture.')
class Nat64ProcessTests(unittest.TestCase):
    def child(self):
        command = ['/usr/bin/sleep', '30']
        child = subprocess.Popen(command, user=65534, group=65534, extra_groups=[],
                                 stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL)
        self.addCleanup(self.stop, child)
        return child

    @staticmethod
    def stop(child):
        if child.poll() is None:
            child.kill()
        child.wait(timeout=3)

    def test_same_uid_worker_attests_the_actual_immutable_elf(self):
        child = self.child()
        result = runtime.process_identity(child, SimpleNamespace(pw_uid=65534, pw_gid=65534))
        pinned = Path(child.args[0]).stat()
        self.assertEqual(result['pid'], child.pid)
        self.assertEqual((result['executable_device'], result['executable_inode']),
                         (pinned.st_dev, pinned.st_ino))
        self.assertLessEqual(result['monotonic'], runtime.kernel_uptime())
        self.assertLess(runtime.kernel_uptime()-result['monotonic'], 2)

    def test_wrong_uid_or_changed_executable_cannot_supply_a_witness(self):
        child = self.child()
        with self.assertRaises(ReleaseError):
            runtime.process_identity(child, SimpleNamespace(pw_uid=65533, pw_gid=65533))
        child.args = ['/usr/bin/true', '30']
        with self.assertRaises(ReleaseError):
            runtime.process_identity(child, SimpleNamespace(pw_uid=65534, pw_gid=65534))

    def test_exited_child_has_no_replayable_identity(self):
        child = self.child()
        self.stop(child)
        with self.assertRaises(ReleaseError):
            runtime.process_identity(child, SimpleNamespace(pw_uid=65534, pw_gid=65534))

    def test_forged_argv_cannot_hide_a_different_executable(self):
        child = subprocess.Popen(['/usr/bin/true', '30'], executable='/usr/bin/sleep',
                                 user=65534, group=65534, extra_groups=[], stdin=subprocess.DEVNULL)
        self.addCleanup(self.stop, child)
        self.assertEqual(Path('/proc', str(child.pid), 'cmdline').read_bytes(), b'/usr/bin/true\0' + b'30\0')
        with self.assertRaises(ReleaseError):
            runtime.process_identity(child, SimpleNamespace(pw_uid=65534, pw_gid=65534))

    def test_stalled_worker_is_bounded_and_reaped(self):
        child = self.child()
        children = Path('/proc/self/task', str(os.getpid()), 'children')
        before = children.read_bytes()
        def stalled_write(*unused):
            time.sleep(10)
            raise AssertionError('Worker timeout did not stop the fork.')
        started = time.monotonic()
        with patch.object(runtime.os, 'write', side_effect=stalled_write), self.assertRaises(ReleaseError):
            runtime.process_identity(child, SimpleNamespace(pw_uid=65534, pw_gid=65534))
        self.assertLess(time.monotonic()-started, 3)
        self.assertEqual(children.read_bytes(), before)


if __name__ == '__main__':
    unittest.main()
