#!/usr/bin/env python3
"""Bounded systemd control for the image's credential activation adapters."""

from pathlib import Path
import subprocess


class Service:
    def __init__(self, unit, error, start_timeout=40):
        self.unit, self.Error, self.start_timeout = unit, error, start_timeout

    @staticmethod
    def run(argv, timeout, payload=None, capture=False, env=None):
        return subprocess.run(argv, input=payload, stdin=subprocess.DEVNULL if payload is None else None,
                              stdout=subprocess.PIPE if capture else subprocess.DEVNULL,
                              stderr=subprocess.DEVNULL, timeout=timeout, check=False, env=env)

    def status(self):
        result = self.run(['/usr/bin/systemctl', 'show', self.unit, '--no-pager',
                           '--property=ActiveState,SubState,MainPID,ControlGroup'], 10, capture=True)
        if result.returncode:
            raise self.Error('Service state could not be inspected.', 70)
        try:
            pairs = [line.split('=', 1) for line in result.stdout.decode('ascii').splitlines()]
            values = dict(pairs)
            if (len(pairs) != 4 or set(values) != {'ActiveState', 'SubState', 'MainPID', 'ControlGroup'}
                    or not values['MainPID'].isascii() or not values['MainPID'].isdigit()
                    or values['ControlGroup'] not in {'', '/system.slice/' + self.unit}):
                raise ValueError
            return values
        except (ValueError, UnicodeError) as error:
            raise self.Error('Service state was malformed or unsupported.', 70) from error

    def stop(self):
        if self.run(['/usr/bin/systemctl', 'stop', self.unit], 40).returncode:
            raise self.Error('Service could not be stopped; credentials were preserved.', 70)
        state = self.status()
        if (state['ActiveState'] not in {'inactive', 'failed'} or state['MainPID'] != '0'
                or state['SubState'] not in {'dead', 'failed'}):
            raise self.Error('Service is not stopped; credentials were preserved.', 70)
        if state['ControlGroup']:
            path = Path('/sys/fs/cgroup') / state['ControlGroup'].lstrip('/') / 'cgroup.events'
            try:
                fields = dict(line.split() for line in path.read_text().splitlines())
                if fields.get('populated') != '0':
                    raise self.Error('Service workers remain; credentials were preserved.', 70)
            except FileNotFoundError:
                pass

    def start(self):
        if self.run(['/usr/bin/systemctl', 'start', self.unit], self.start_timeout).returncode:
            raise self.Error('Service did not start successfully.', 69)
