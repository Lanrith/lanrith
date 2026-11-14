"""Bounded temporary metadata spool shared by optional core observers."""

import json
import os
from pathlib import Path
import re
import stat
import tempfile
import uuid
import time

LIMIT = 1024*1024
LINE = 16384
MAX = 2**63-1


def regular(path, *, maximum=LIMIT):
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(descriptor)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or
                info.st_gid != os.getegid() or info.st_nlink != 1 or
                stat.S_IMODE(info.st_mode) != 0o640 or info.st_size > maximum):
            raise ValueError('Observation file custody differs.')
        return os.read(descriptor, maximum+1)
    finally:
        os.close(descriptor)


class Spool:
    def __init__(self, path, *, boot, counters=None, limit=LIMIT, line=LINE):
        if type(limit) is not int or type(line) is not int or not 1 <= line <= min(limit, LINE) or not limit <= LIMIT:
            raise ValueError('Observation spool capacity differs.')
        self.limit, self.line = limit, line
        for parent in path.parents:
            info = parent.lstat()
            if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
                raise ValueError('Observation ancestor differs.')
        info = path.lstat()
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or
                info.st_gid != os.getegid() or stat.S_IMODE(info.st_mode) != 0o750):
            raise ValueError('Observation directory custody differs.')
        self.path, self.counts = path, {}
        entries = list(path.iterdir())
        if len(entries) > 8:
            raise ValueError('Observation inventory bound.')
        for entry in entries:
            if re.fullmatch(r'\.health\.[a-z0-9_]{8}', entry.name):
                regular(entry, maximum=4096)
                entry.unlink()
            elif entry.name in ('events.jsonl', 'events.jsonl.1', 'events.jsonl.2'):
                data = regular(entry, maximum=self.limit)
                self.counts[entry.name] = data.count(b'\n')
                # A killed writer may have left one incomplete final line. Keep
                # complete records; readers already reject incomplete lines.
                if data and not data.endswith(b'\n'):
                    boundary = data.rfind(b'\n')+1
                    descriptor = os.open(entry, os.O_WRONLY | os.O_NOFOLLOW)
                    try:
                        os.ftruncate(descriptor, boundary)
                    finally:
                        os.close(descriptor)
            elif entry.name == 'health.json':
                regular(entry, maximum=4096)
            else:
                raise ValueError('Unexpected Observation file.')
        names = ('emitted', 'rejected', 'write_failed', 'overwritten', 'disconnects') if counters is None else counters
        if (not isinstance(names, tuple) or len(names) > 12 or
                any(not isinstance(name, str) or re.fullmatch(r'[a-z_]{1,32}', name) is None for name in names) or
                len(names) != len(set(names)) or not {'emitted', 'rejected', 'write_failed', 'overwritten'} <= set(names)):
            raise ValueError('Observation counter contract differs.')
        self.counters = dict.fromkeys(names, 0)
        self.epoch = uuid.uuid4().hex
        self.boot = boot.read_text().strip()
        if re.fullmatch(r'[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}', self.boot) is None:
            raise ValueError('Observation boot identity differs.')

    def bump(self, name, count=1):
        self.counters[name] = min(MAX, self.counters[name]+count)

    def append(self, value):
        if self.counters['emitted'] == MAX:
            raise ValueError('Observation sequence exhausted.')
        value = {**value, 'producer_epoch': self.epoch, 'boot_id': self.boot,
                 'sequence': self.counters['emitted']+1}
        data = json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode()+b'\n'
        if len(data) > self.line:
            self.bump('rejected')
            return
        path = self.path/'events.jsonl'
        if path.exists() and path.stat().st_size+len(data) > self.limit:
            oldest = self.path/'events.jsonl.2'
            self.bump('overwritten', self.counts.pop(oldest.name, 0))
            oldest.unlink(missing_ok=True)
            for src, dst in (('events.jsonl.1', 'events.jsonl.2'), ('events.jsonl', 'events.jsonl.1')):
                if (self.path/src).exists():
                    os.replace(self.path/src, self.path/dst)
                    self.counts[dst] = self.counts.pop(src, 0)
        descriptor = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW, 0o640)
        try:
            info = os.fstat(descriptor)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or
                    info.st_gid != os.getegid() or info.st_nlink != 1 or
                    stat.S_IMODE(info.st_mode) != 0o640 or info.st_size+len(data) > self.limit):
                raise ValueError('Observation output file custody differs.')
            try:
                if os.write(descriptor, data) != len(data):
                    raise OSError('Incomplete Observation metadata write.')
            except OSError:
                os.ftruncate(descriptor, info.st_size)
                raise
        finally:
            os.close(descriptor)
        self.counts[path.name] = self.counts.get(path.name, 0)+1
        self.bump('emitted')

    def health(self):
        value = {'schema': 1, 'producer_epoch': self.epoch, 'boot_id': self.boot,
                 'observed_monotonic_ns': time.monotonic_ns(), **self.counters}
        descriptor, temporary = tempfile.mkstemp(prefix='.health.', dir=self.path)
        try:
            os.fchmod(descriptor, 0o640)
            with os.fdopen(descriptor, 'wb') as stream:
                stream.write(json.dumps(value, sort_keys=True).encode()+b'\n')
            os.replace(temporary, self.path/'health.json')
        finally:
            Path(temporary).unlink(missing_ok=True)


