"""Verified slot observations and durable records for the state administrator."""

from contextlib import contextmanager
import fcntl
import json
import os
from pathlib import Path
import re
import stat
import time

from .release import read, require, unique
from .recovery_enrollment import protect, save, sync_directory
from .update import PARTITION_ROLES, UUID

HEALTH = Path('/run/lanrith/slot-health.json')
BOOT_ID = Path('/proc/sys/kernel/random/boot_id')


@contextmanager
def locked_directory(directory, *, private=True):
    fd = os.open(directory, os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        info = os.fstat(fd)
        require(directory.resolve() == directory and info.st_uid == 0 and not info.st_mode & 0o022 and
                (not private or stat.S_IMODE(info.st_mode) == 0o700), 'State administration directory is unsafe.')
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        os.close(fd)


def publish_changed(path, value, previous):
    """Caller holds the directory lock. Keep intent until the rename is durable."""
    intent = path.with_name('.' + path.name + '.pending')
    try:
        info = intent.lstat()
    except FileNotFoundError:
        if previous == value:
            return
        os.close(os.open(intent, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600))
    else:
        require(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and stat.S_IMODE(info.st_mode) == 0o600 and
                info.st_nlink == 1 and info.st_size == 0, 'Unsafe state publication intent.')
    # Also covers retry after interruption during the first directory flush.
    sync_directory(path.parent)
    if previous != value:
        save(path, value)
    intent.unlink()
    sync_directory(path.parent)


def marker(path):
    """Read historical schemas. Incomplete legacy regular files can be repaired."""
    try:
        info = path.lstat()
    except FileNotFoundError:
        return None
    protect(path.parent)
    require(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o022 and info.st_nlink == 1 and
            info.st_size <= 1024, 'Unsafe slot initialization record.')
    if info.st_size == 0:
        return None
    try:
        value = json.loads(read(path, 1024), object_pairs_hook=unique)
    except (json.JSONDecodeError, UnicodeDecodeError):
        return None
    require(isinstance(value, dict) and type(value.get('schema')) is int, 'Invalid slot initialization record.')
    if value['schema'] == 1:
        require(set(value) == {'schema', 'disk'} and isinstance(value['disk'], str) and
                re.fullmatch(r'/dev/[A-Za-z0-9_.-]+', value['disk']), 'Invalid legacy slot initialization record.')
    else:
        require(value['schema'] == 2 and set(value) == {'schema', 'disk_uuid', 'state_partuuid'} and
                all(isinstance(value[key], str) and re.fullmatch(UUID, value[key])
                    for key in ('disk_uuid', 'state_partuuid')) and stat.S_IMODE(info.st_mode) == 0o600,
                'Invalid bound slot initialization record.')
    return value


def remember_marker(directory, state):
    expected = {'schema': 2, 'disk_uuid': state['disk_uuid'], 'state_partuuid': state['uuid']}
    with locked_directory(directory):
        path = directory/'slots-initialized'
        old = marker(path)
        require(not old or old['schema'] == 1 or old == expected,
                'Slot initialization record belongs to another disk or state partition.')
        publish_changed(path, expected, old)


def check_health_directory(directory):
    info = directory.lstat()
    require(directory.resolve() == directory and stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and
            not info.st_mode & 0o022, 'Slot health directory is unsafe.')


def write_health(installed, report, started):
    directory = HEALTH.parent
    directory.mkdir(mode=0o755, exist_ok=True)
    with locked_directory(directory, private=False):
        # An older inspection can finish after a newer one. Preserve the most
        # recent validated sample within the window since this check started.
        age = 1 + (time.monotonic_ns() - started)//10**9
        try:
            current = read_health(installed, max_age_seconds=age)
        except (OSError, ValueError):
            current = None
        if current and current['checked_monotonic_ns'] > started:
            return
        record = {key: installed[key] for key in ('image_id', 'deployment_sequence', 'configuration_sha256')}
        save(HEALTH, {**record, 'schema': 1, 'boot_id': BOOT_ID.read_text().strip(),
                      'checked_monotonic_ns': started, **report})


def read_health(installed, *, max_age_seconds):
    """Read a recent local storage observation for the exact running boot and image."""
    check_health_directory(HEALTH.parent)
    info = HEALTH.lstat()
    require(info.st_uid == 0 and stat.S_IMODE(info.st_mode) == 0o600, 'Slot health is not protected.')
    value = json.loads(read(HEALTH, 4096), object_pairs_hook=unique)
    keys = {'schema', 'boot_id', 'image_id', 'deployment_sequence', 'configuration_sha256',
            'checked_monotonic_ns', 'active_verified', 'active_short', 'standby'}
    require(isinstance(value, dict) and set(value) == keys and type(value['schema']) is int and
            value['schema'] == 1 and value['active_verified'] is True and
            type(value['deployment_sequence']) is int and
            all(value[k] == installed[k] for k in ('image_id', 'deployment_sequence', 'configuration_sha256')) and
            value['boot_id'] == BOOT_ID.read_text().strip() and type(value['checked_monotonic_ns']) is int and
            value['checked_monotonic_ns'] >= 0 and
            type(max_age_seconds) is int and max_age_seconds > 0 and
            0 <= time.monotonic_ns()-value['checked_monotonic_ns'] <= max_age_seconds * 10**9,
            'Current slot health is unavailable.')
    standby = value['standby']
    require(isinstance(standby, dict) and set(standby) == {'available', 'short', 'busy', 'ambiguous'},
            'Invalid standby health.')
    for roles in (value['active_short'], standby['short'], standby['busy'], standby['ambiguous']):
        require(isinstance(roles, list) and all(role in PARTITION_ROLES for role in roles) and
                len(roles) == len(set(roles)), 'Invalid slot health roles.')
    require(standby['available'] is (not any(standby[key] for key in ('short', 'busy', 'ambiguous'))),
            'Invalid standby health result.')
    return value
