"""Real terminal I/O for installer ownership, missing hardware and secret isolation."""

from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
import json
import os
from pathlib import Path
import pty
import select
import subprocess
import sys
import termios
import time
import unittest
from unittest.mock import patch

from lanrith import factory_console
from lanrith.release import ReleaseError


def receive(fd, marker, timeout=3):
    result = b''
    deadline = time.monotonic()+timeout
    while marker not in result:
        if not select.select([fd], [], [], max(0, deadline-time.monotonic()))[0]:
            raise AssertionError('Expected public terminal event did not arrive.')
        result += os.read(fd, 65536)
    return result


@contextmanager
def terminals(count=2):
    pairs = [pty.openpty() for _ in range(count)]
    try:
        yield pairs, [{'tty': os.ttyname(slave).removeprefix('/dev/'), 'baud': None} for _, slave in pairs]
    finally:
        for pair in pairs:
            for fd in pair:
                try:
                    os.close(fd)
                except OSError:
                    pass


class FactoryConsoleTests(unittest.TestCase):
    def test_both_physical_consoles_are_derived_without_hardware_specific_names(self):
        boot = {'console': 'tty0', 'recovery_console': 'ttyS2'}
        self.assertEqual(factory_console.specifications(boot),
                         [{'tty': 'tty1', 'baud': None}, {'tty': 'ttyS2', 'baud': 115200}])
        self.assertEqual(factory_console.specifications({'console': 'ttyS3,57600n8', 'recovery_console': 'ttyS3'}),
                         [{'tty': 'tty1', 'baud': None}, {'tty': 'ttyS3', 'baud': 57600}])
        self.assertIn({'tty': 'ttyUSB4', 'baud': 115200}, factory_console.specifications(
            {'console': 'tty0'}, {'enabled': True, 'tty': 'ttyUSB4'}))
        self.assertEqual(factory_console.specifications({'console': 'tty0'}), [{'tty': 'tty1', 'baud': None}])

    def test_paths_duplicates_and_invalid_baud_rates_are_rejected(self):
        valid = {'tty': 'ttyS0', 'baud': 115200}
        for values in ([], [valid, valid], [{'tty': '../pts/0', 'baud': None}],
                       [{'tty': 'pts/0', 'baud': None}], [{**valid, 'baud': True}],
                       [{**valid, 'baud': 12345}], [{**valid, 'extra': 'value'}]):
            with self.subTest(values=values), self.assertRaises(ReleaseError):
                factory_console.allowed({'boot': {}, 'factory_consoles': values})

    def test_either_console_can_select_but_the_other_cannot_confirm(self):
        for selected in (0, 1):
            with self.subTest(selected=selected), terminals() as (pairs, specs), \
                    patch.object(factory_console, 'allowed', return_value=specs), \
                    factory_console.Consoles({}) as console, ThreadPoolExecutor(1) as pool:
                masters = [item[0] for item in pairs]
                future = pool.submit(console.input, 'Select disk: ')
                for fd in masters:
                    self.assertIn(b'Select disk: ', receive(fd, b'Select disk: '))
                os.write(masters[selected], b'/dev/disk/by-id/synthetic\n')
                self.assertEqual(future.result(3), '/dev/disk/by-id/synthetic')
                future = pool.submit(console.input, 'Confirm erase: ')
                for fd in masters:
                    receive(fd, b'Confirm erase: ')
                os.write(masters[1-selected], b'ERASE-AND-INSTALL wrong-console\n')
                self.assertFalse(future.done())
                os.write(masters[selected], b'ERASE-AND-INSTALL synthetic\n')
                self.assertEqual(future.result(3), 'ERASE-AND-INSTALL synthetic')

    def test_missing_serial_or_monitor_does_not_hide_the_remaining_prompt(self):
        for position in (0, 1):
            with self.subTest(position=position), terminals(1) as (pairs, specs):
                specs.insert(position, {'tty': 'lanrith-nonexistent-console-fixture', 'baud': None})
                with patch.object(factory_console, 'allowed', return_value=specs), \
                        factory_console.Consoles({}) as console, ThreadPoolExecutor(1) as pool:
                    future = pool.submit(console.input, 'Only console: ')
                    receive(pairs[0][0], b'Only console: ')
                    os.write(pairs[0][0], b'yes\n')
                    self.assertEqual(future.result(3), 'yes')

    def test_stale_input_is_discarded_before_a_new_prompt(self):
        with terminals(1) as (pairs, specs), patch.object(factory_console, 'allowed', return_value=specs), \
                factory_console.Consoles({}) as console, ThreadPoolExecutor(1) as pool:
            os.write(pairs[0][0], b'preloaded-confirmation\n')
            # Wait until the terminal has processed the old input before prompting.
            receive(pairs[0][0], b'preloaded-confirmation')
            future = pool.submit(console.input, 'Fresh confirmation: ')
            receive(pairs[0][0], b'Fresh confirmation: ')
            self.assertFalse(future.done())
            os.write(pairs[0][0], b'fresh\n')
            self.assertEqual(future.result(3), 'fresh')

    def test_active_console_disconnect_cancels_instead_of_transferring_confirmation(self):
        with terminals() as (pairs, specs), patch.object(factory_console, 'allowed', return_value=specs), \
                factory_console.Consoles({}) as console, ThreadPoolExecutor(1) as pool:
            future = pool.submit(console.input, 'Choose: ')
            receive(pairs[0][0], b'Choose: ')
            os.write(pairs[0][0], b'disk\n')
            self.assertEqual(future.result(3), 'disk')
            os.close(pairs[0][0])
            with self.assertRaisesRegex(ReleaseError, 'disconnected'):
                console.input('Confirm: ')

    def test_terminal_escape_and_overlong_input_cannot_be_an_installation_answer(self):
        for data in (b'bad\x1b[31m\n', b'x'*1024+b'\n'):
            with self.subTest(length=len(data)), terminals(1) as (pairs, specs), \
                    patch.object(factory_console, 'allowed', return_value=specs), \
                    factory_console.Consoles({}) as console, ThreadPoolExecutor(1) as pool:
                future = pool.submit(console.input, 'Input: ')
                receive(pairs[0][0], b'Input: ')
                os.write(pairs[0][0], data)
                with self.assertRaises(ReleaseError):
                    future.result(3)

    def test_secret_child_has_only_the_selected_terminal_and_never_the_journal_pipe(self):
        program = '''
import getpass,json,os,sys
from unittest.mock import patch
from lanrith import factory_console
specs=json.loads(sys.argv[1])
def private():
    assert os.ttyname(0) == '/dev/'+specs[int(sys.argv[2])]['tty']
    print('synthetic-private-recovery-material', flush=True)
    assert getpass.getpass('Synthetic private passphrase: ') == 'synthetic-secret-input'
    print('PRIVATE-COMPLETE', flush=True)
with patch.object(factory_console, 'allowed', return_value=specs):
    with factory_console.Consoles({}) as console:
        console.private(private)
        console.write('PUBLIC-COMPLETE\\n')
'''
        for selected in (0, 1):
            with self.subTest(selected=selected), terminals() as (pairs, specs):
                process = subprocess.Popen([sys.executable, '-c', program, json.dumps(specs), str(selected)],
                                           stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                try:
                    for master, _ in pairs:
                        receive(master, b'Press Enter on this console')
                    os.write(pairs[selected][0], b'\n')
                    active = receive(pairs[selected][0], b'Synthetic private passphrase: ')
                    self.assertIn(b'synthetic-private-recovery-material', active)
                    os.write(pairs[selected][0], b'synthetic-secret-input\n')
                    active += receive(pairs[selected][0], b'PUBLIC-COMPLETE')
                    inactive = receive(pairs[1-selected][0], b'PUBLIC-COMPLETE')
                    stdout, stderr = process.communicate(timeout=3)
                    self.assertEqual(process.returncode, 0, stderr.decode())
                    self.assertNotIn(b'synthetic-secret-input', active)
                    for output in (inactive, stdout, stderr):
                        self.assertNotIn(b'synthetic-private-recovery-material', output)
                        self.assertNotIn(b'synthetic-secret-input', output)
                    self.assertEqual(stdout, b'')
                    self.assertEqual(stderr, b'')
                finally:
                    if process.poll() is None:
                        process.kill()
                    process.communicate()

    def test_terminal_settings_are_restored(self):
        with terminals(1) as (pairs, specs), patch.object(factory_console, 'allowed', return_value=specs):
            original = termios.tcgetattr(pairs[0][1])
            with factory_console.Consoles({}) as console:
                console.write('Public message.\n')
            self.assertEqual(termios.tcgetattr(pairs[0][1]), original)
