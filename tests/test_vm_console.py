"""Slow qualification operations cannot back up the guest's serial console."""

import socket
import unittest

from vm import SerialReader


class ConsoleTests(unittest.TestCase):
    def test_console_drains_without_an_expect_call_and_retains_bounded_output(self):
        receiving, sending = socket.socketpair()
        receiving.settimeout(0.05)
        sending.settimeout(3)
        console = SerialReader(receiving)
        marker = b'disposable-console-end'
        try:
            # More than a socket buffer or the retained console history. A
            # synchronous reader would block this send during an SSH operation.
            sending.sendall(b'x'*(2*SerialReader.LIMIT)+marker)
            with console.condition:
                self.assertTrue(console.condition.wait_for(lambda: console.data.endswith(marker), timeout=3))
                self.assertLessEqual(len(console.data), SerialReader.LIMIT)
        finally:
            sending.close()
            console.close()
        self.assertFalse(console.thread.is_alive())
        self.assertEqual(console.data, b'')

    def test_console_eof_wakes_waiters_and_cleanup_is_idempotent(self):
        receiving, sending = socket.socketpair()
        receiving.settimeout(0.05)
        console = SerialReader(receiving)
        try:
            sending.shutdown(socket.SHUT_WR)
            with console.condition:
                self.assertTrue(console.condition.wait_for(lambda: console.closed, timeout=3))
        finally:
            sending.close()
            console.close()
        console.close()
        self.assertFalse(console.thread.is_alive())
