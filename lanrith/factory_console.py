"""Physical installer consoles: shared public output, one input owner, private secrets."""

import errno
import fcntl
import os
import re
import select
import signal
import stat
import sys
import termios

from .release import ReleaseError, require


def specifications(boot, serial=None):
    """Compile supported physical consoles, keeping VGA usable with serial recovery."""
    consoles = {'tty1': None}
    names = [boot.get('console', 'tty0'), boot.get('recovery_console', 'tty0')]
    if serial and serial.get('enabled'):
        names.append(serial.get('tty', 'ttyS0'))
    for name in names:
        tty, _, speed = name.partition(',')
        if tty == 'tty0':
            tty = 'tty1'
        baud = int(speed.removesuffix('n8')) if speed else 115200
        consoles.setdefault(tty, baud if tty.startswith(('ttyS', 'ttyUSB', 'ttyAMA')) else None)
    return [{'tty': tty, 'baud': baud} for tty, baud in consoles.items()]


def allowed(installed):
    values = installed.get('factory_consoles', specifications(installed['boot']))
    require(isinstance(values, list) and 1 <= len(values) <= 4, 'Invalid factory console inventory.')
    seen = set()
    for value in values:
        require(isinstance(value, dict) and set(value) == {'tty', 'baud'} and
                isinstance(value['tty'], str) and re.fullmatch(r'tty1|tty(?:S|USB|AMA)[0-9]+|hvc[0-9]+', value['tty'])
                and value['tty'] not in seen and
                (value['baud'] is None or type(value['baud']) is int and
                 50 <= value['baud'] <= 4000000 and hasattr(termios, 'B'+str(value['baud']))),
                'Invalid factory console device.')
        seen.add(value['tty'])
    return values


def require_physical_input(installed):
    require(os.geteuid() == 0 and os.isatty(0) and
            os.ttyname(0) in {'/dev/'+item['tty'] for item in allowed(installed)},
            'Provisioning secrets require an authorized physical console.')


class Consoles:
    def __init__(self, installed):
        self.specs = allowed(installed)
        self.devices = {}
        self.owner = None

    def __enter__(self):
        try:
            for spec in self.specs:
                path = '/dev/'+spec['tty']
                fd = None
                try:
                    fd = os.open(path, os.O_RDWR | os.O_NOCTTY | os.O_NONBLOCK | os.O_CLOEXEC)
                    require(stat.S_ISCHR(os.fstat(fd).st_mode) and os.isatty(fd), 'Factory console is not a terminal.')
                    previous = termios.tcgetattr(fd)
                    settings = termios.tcgetattr(fd)
                    settings[0] = termios.ICRNL
                    settings[1] = termios.OPOST | termios.ONLCR
                    settings[2] &= ~(termios.CSIZE | termios.PARENB | termios.CSTOPB | termios.CRTSCTS)
                    settings[2] |= termios.CS8 | termios.CREAD | termios.CLOCAL
                    settings[3] = termios.ICANON | termios.ECHO | termios.ECHOE | termios.ECHOK | termios.ISIG
                    if spec['baud'] is not None:
                        settings[4] = settings[5] = getattr(termios, 'B'+str(spec['baud']))
                    termios.tcsetattr(fd, termios.TCSANOW, settings)
                    termios.tcflush(fd, termios.TCIFLUSH)
                    self.devices[fd] = (path, previous)
                except (OSError, termios.error) as error:
                    if fd is not None:
                        os.close(fd)
                    if error.args[0] not in (errno.ENOENT, errno.ENODEV, errno.ENXIO, errno.EIO):
                        raise
            require(self.devices, 'No monitor/keyboard or configured serial console is available.')
            return self
        except BaseException:
            self.__exit__(None, None, None)
            raise

    def __exit__(self, kind, value, trace):
        if kind is not None:
            try:
                self.write('Installation stopped: '+(str(value) if isinstance(value, ReleaseError) else kind.__name__)+'.\n')
            except (OSError, ReleaseError):
                pass
        for fd, (_, previous) in self.devices.items():
            try:
                termios.tcsetattr(fd, termios.TCSANOW, previous)
            except termios.error:
                pass
            os.close(fd)
        self.devices.clear()

    def write(self, text):
        # Public status only. Hardware-provided labels must not inject terminal controls.
        payload = ''.join(c for c in text if c in '\n\t' or c.isprintable()).encode()
        for fd in list(self.devices):
            remaining = payload
            try:
                while remaining:
                    require(select.select([], [fd], [], 2)[1], 'Factory console output stalled.')
                    written = os.write(fd, remaining)
                    require(written > 0, 'Factory console disconnected.')
                    remaining = remaining[written:]
            except (OSError, ReleaseError):
                if fd == self.owner:
                    raise ReleaseError('The active installation console disconnected.') from None
                os.close(fd)
                del self.devices[fd]
        require(self.devices, 'All installation consoles disconnected.')

    def input(self, prompt):
        # Discard type-ahead, including a confirmation entered before its prompt.
        for fd in list(self.devices):
            try:
                termios.tcflush(fd, termios.TCIFLUSH)
            except termios.error:
                require(fd != self.owner, 'The active installation console disconnected.')
                os.close(fd)
                del self.devices[fd]
        self.write(prompt)
        candidates = [self.owner] if self.owner is not None else list(self.devices)
        ready = select.select(candidates, [], [*candidates])[0]
        require(ready, 'No installation input is available.')
        fd = ready[0]
        data = os.read(fd, 1025)
        require(data.endswith(b'\n') and len(data) <= 1024 and data.count(b'\n') == 1,
                'Installation input was disconnected, too long or contained multiple lines.')
        require(all(byte in (9, 10, 13) or 32 <= byte <= 126 for byte in data), 'Invalid installation input.')
        if self.owner is None:
            self.owner = fd
            self.write('\nInstallation input selected on '+self.devices[fd][0]+'. Continue on that console.\n')
        return data.decode('ascii').strip()

    def private(self, operation, *, prompt='Press Enter on this console to record the offline recovery key: '):
        """Run a secret-bearing step with only the selected TTY, never a log pipe."""
        if self.owner is None:
            require(self.input(prompt) == '',
                    'Private console selection was not confirmed.')
        fd = self.owner
        path, previous = self.devices[fd]
        identity = os.fstat(fd).st_rdev
        settings = termios.tcgetattr(fd)
        self.write('Private provisioning continues only on '+self.devices[fd][0]+'. Disable console recording there.\n')
        for stream in (sys.stdout, sys.stderr):
            stream.flush()
        pid = os.fork()
        if pid == 0:
            try:
                os.setsid()
                os.set_blocking(fd, True)
                for number in (0, 1, 2):
                    os.dup2(fd, number)
                for descriptor in self.devices:
                    if descriptor > 2:
                        os.close(descriptor)
                fcntl.ioctl(0, termios.TIOCSCTTY, 0)
                os.tcsetpgrp(0, os.getpgrp())
                sys.stdin = os.fdopen(os.dup(0), 'r')
                sys.stdout = os.fdopen(os.dup(1), 'w', buffering=1)
                sys.stderr = os.fdopen(os.dup(2), 'w', buffering=1)
                operation()
                sys.stdout.flush()
                sys.stderr.flush()
                os._exit(0)
            except BaseException:
                os.write(2, b'Private provisioning failed. No secret was logged.\n')
                os._exit(1)
        try:
            _, status = os.waitpid(pid, 0)
        except BaseException:
            os.kill(pid, signal.SIGTERM)
            os.waitpid(pid, 0)
            raise
        finally:
            # Linux hangs up a real UART when its controlling session exits.
            # Reopen that same device after the private child has been reaped;
            # never transfer ownership to another console on a disconnect.
            fresh = os.open(path, os.O_RDWR | os.O_NOCTTY | os.O_NONBLOCK | os.O_CLOEXEC)
            try:
                require(stat.S_ISCHR(os.fstat(fresh).st_mode) and os.fstat(fresh).st_rdev == identity,
                        'The private provisioning console identity changed.')
                termios.tcsetattr(fresh, termios.TCSANOW, settings)
                termios.tcflush(fresh, termios.TCIFLUSH)
            except BaseException:
                os.close(fresh)
                raise
            os.close(fd)
            del self.devices[fd]
            self.devices[fresh] = (path, previous)
            self.owner = fresh
        require(os.WIFEXITED(status) and os.WEXITSTATUS(status) == 0,
                'Private provisioning did not complete on the selected console.')
