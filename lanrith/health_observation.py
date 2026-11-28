"""Latest whole-readiness check for the running boot, independent of promotion."""

from contextlib import contextmanager
import fcntl
import json
import os
from pathlib import Path
import re
import stat
import tempfile
import time

from .image_operation import identity
from .release import canonical, require, unique
from .slot_state import BOOT_ID, check_health_directory
from .update import UUID


MAX_AGE_SECONDS = 60


def boot_id():
    current = BOOT_ID.read_text().strip()
    require(re.fullmatch(UUID, current), 'Invalid boot identity.')
    return current


def binding(value):
    return {'schema': 1, 'boot_id': boot_id(), **identity(value)}


def install(stream, path, record):
    stream.write(canonical(record))
    stream.flush()
    os.fchmod(stream.fileno(), 0o644)
    os.fsync(stream.fileno())
    os.replace(stream.name, path)


@contextmanager
def temporary(directory):
    with tempfile.NamedTemporaryFile(prefix='.observation-', dir=directory, delete=False) as stream:
        try:
            yield stream
        finally:
            Path(stream.name).unlink(missing_ok=True)


def publish(path, record):
    with temporary(path.parent) as stream:
        install(stream, path, record)


@contextmanager
def publication_lock(directory):
    check_health_directory(directory)
    lock = os.open(directory/'.boot-publication.lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        fcntl.flock(lock, fcntl.LOCK_EX)
        yield
    finally:
        os.close(lock)


@contextmanager
def attempt(path, value):
    """Retain the writer lock on this attempt's inode until it finishes or dies."""
    directory = path.parent
    directory.mkdir(mode=0o755, exist_ok=True)
    bound = binding(value)
    check_health_directory(directory)
    with temporary(directory) as marker:
        fcntl.lockf(marker, fcntl.LOCK_EX)
        with publication_lock(directory):
            pending = {**bound, 'started_monotonic_ns': time.monotonic_ns(),
                       'finished_monotonic_ns': None, 'result': 'unfinished'}
            install(marker, path, pending)
        result = None
        try:
            yield
        except Exception:
            result = 'failed'
            raise
        else:
            result = 'passed'
        finally:
            # SIGKILL or an interrupted final write leaves an unlocked unfinished
            # inode. A new attempt installs its own inode, even while this one runs.
            if result is not None:
                finished = time.monotonic_ns()
                with publication_lock(directory):
                    if os.path.samestat(os.fstat(marker.fileno()), path.lstat()):
                        publish(path, {**pending, 'finished_monotonic_ns': finished, 'result': result})


def status(path, value):
    summary = {'state': 'missing', 'result': 'unavailable', 'started_monotonic_ns': None,
               'finished_monotonic_ns': None, 'age_seconds': None}
    try:
        check_health_directory(path.parent)
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd, 'rb') as stream:
            info = os.fstat(fd)
            require(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and stat.S_IMODE(info.st_mode) == 0o644 and
                    info.st_nlink == 1 and 0 < info.st_size <= 2048, 'Unsafe health observation.')
            record = json.loads(stream.read(2049), object_pairs_hook=unique)
            bound = binding(value)
            require(isinstance(record, dict) and set(record) == set(bound) | {
                    'started_monotonic_ns', 'finished_monotonic_ns', 'result'} and
                    type(record['schema']) is int and type(record['deployment_sequence']) is int and
                    all(record[k] == v for k, v in bound.items()), 'Health observation identity differs.')
            start, end, result = (record[k] for k in ('started_monotonic_ns', 'finished_monotonic_ns', 'result'))
            now = time.monotonic_ns()
            require(type(start) is int and 0 <= start <= now and (
                    result == 'unfinished' and end is None or
                    result in ('passed', 'failed') and type(end) is int and start <= end <= now),
                    'Invalid health observation.')
            summary.update(started_monotonic_ns=start, finished_monotonic_ns=end, age_seconds=(now-start)//10**9)
            if now-start > MAX_AGE_SECONDS * 10**9:
                return {**summary, 'state': 'stale'}
            if result != 'unfinished':
                return {**summary, 'state': 'complete', 'result': result}
            try:
                fcntl.lockf(fd, fcntl.LOCK_SH | fcntl.LOCK_NB, 0, 0, os.SEEK_SET)
            except BlockingIOError:
                return {**summary, 'state': 'checking'}
            return {**summary, 'state': 'interrupted'}
    except FileNotFoundError:
        return summary
    except (OSError, ValueError, RecursionError):
        return {**summary, 'state': 'invalid'}
