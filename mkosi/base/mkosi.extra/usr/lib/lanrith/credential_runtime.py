#!/usr/bin/env python3
"""Private credential activation and recovery on the router's encrypted state.

The journal contains secrets. It must never be logged or copied to the
controller. Only the image entrypoints select operational paths and policy.
"""

from contextlib import contextmanager
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import tempfile

class CredentialError(ValueError):
    def __init__(self, message, code=65):
        super().__init__(message)
        self.code = code


PHASES = {'preparing', 'prepared', 'writing', 'activating', 'restoring',
          'rollback', 'restored', 'committed'}
NAME = re.compile(r'[A-Za-z0-9][A-Za-z0-9._-]{0,199}')
TEMPORARY_PREFIX = '.activation-write.'


def read_json(raw):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError('JSON contains a duplicate field.')
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=unique)


class State:
    """One private state directory, one stable lock, and one bounded journal."""

    Error = CredentialError
    limit = 4097

    def __init__(self, root, owner=0, group=0):
        self.root, self.owner, self.group = Path(root), owner, group
        self.pending = self.root / '.activation-pending'

    def directory(self, path, create=False):
        if path.resolve() != path:
            raise self.Error('Credential activation directory contains a symlink.')
        if create:
            path.mkdir(mode=0o700, parents=True, exist_ok=True)
        info = path.lstat()
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid != self.owner
                or info.st_gid != self.group or stat.S_IMODE(info.st_mode) != 0o700):
            raise self.Error('Credential activation directory is not private and owned by root.')

    def read(self, path, limit=131072):
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(descriptor, 'rb') as stream:
            info = os.fstat(stream.fileno())
            if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                    or info.st_uid != self.owner or info.st_gid != self.group
                    or stat.S_IMODE(info.st_mode) != 0o600 or info.st_size > limit):
                raise self.Error('Credential activation file has unsafe ownership, mode, type, or size.')
            value = stream.read(limit + 1)
            if len(value) > limit:
                raise self.Error('Credential activation file exceeds its size limit.')
            return value

    @staticmethod
    def sync(path):
        descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)

    def write(self, path, value):
        self.directory(path.parent)
        try:
            self.read(path)
        except FileNotFoundError:
            pass
        descriptor, temporary = tempfile.mkstemp(prefix=TEMPORARY_PREFIX, dir=path.parent)
        temporary = Path(temporary)
        try:
            with os.fdopen(descriptor, 'wb') as output:
                output.write(value)
                output.flush()
                os.fsync(output.fileno())
            os.replace(temporary, path)
            self.sync(path.parent)
        finally:
            temporary.unlink(missing_ok=True)

    @contextmanager
    def lock(self):
        self.directory(self.root, create=True)
        path = self.root / '.activation.lock'
        descriptor = os.open(path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
        try:
            info, named = os.fstat(descriptor), path.lstat()
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != self.owner
                    or info.st_gid != self.group or stat.S_IMODE(info.st_mode) != 0o600
                    or info.st_nlink != 1 or (info.st_dev, info.st_ino) != (named.st_dev, named.st_ino)):
                raise self.Error('Credential activation lock is unsafe.')
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as error:
                raise self.Error('Credential activation is busy.', 75) from error
            yield
        finally:
            os.close(descriptor)

    def cleanup_temporaries(self):
        # Only an activation-lock owner calls this. File writes occur in the
        # owner process, so no surviving child can still publish these files.
        paths = list(self.root.glob(TEMPORARY_PREFIX + '*'))
        for path in paths:
            self.read(path)
        for path in paths:
            path.unlink()
        if paths:
            self.sync(self.root)

    @classmethod
    def names(cls, values):
        if (not isinstance(values, list) or not values or len(values) > 32
                or any(not isinstance(name, str) or not NAME.fullmatch(name) for name in values)
                or values != sorted(set(values))):
            raise cls.Error('Credential activation journal has an invalid file set.', 70)
        return values

    def validate(self, raw):
        raise NotImplementedError('Credential format must be selected by the image adapter.')

    def values(self, names):
        values = {}
        for name in self.names(sorted(names)):
            try:
                raw = self.read(self.root / name, self.limit)
                values[name] = self.validate(raw)
            except FileNotFoundError:
                values[name] = None
        return values

    def metadata(self):
        try:
            self.directory(self.pending)
        except FileNotFoundError:
            return None
        try:
            raw = self.read(self.pending / 'metadata.json')
        except FileNotFoundError:
            # Creation may have stopped before the first metadata rename.
            # No credential writes are possible at this boundary.
            for path in self.pending.iterdir():
                if not path.name.startswith(TEMPORARY_PREFIX):
                    raise self.Error('Credential activation journal is incomplete; state was preserved.', 70)
                self.read(path)
            return {'phase': 'preparing', 'names': [], 'before': [], 'after': [], 'schema': 1,
                    'digests': {'before': {}, 'after': {}}}
        try:
            data = read_json(raw)
            if (not isinstance(data, dict) or set(data) != {'schema', 'phase', 'names', 'before', 'after', 'digests'}
                    or type(data['schema']) is not int or data['schema'] != 1 or data['phase'] not in PHASES):
                raise ValueError
            names = self.names(data['names'])
            if not isinstance(data['digests'], dict) or set(data['digests']) != {'before', 'after'}:
                raise ValueError
            for key in ('before', 'after'):
                if (not isinstance(data[key], list) or data[key] != sorted(set(data[key]))
                        or any(name not in names for name in data[key])):
                    raise ValueError
                digests = data['digests'][key]
                if (not isinstance(digests, dict) or set(digests) != set(data[key])
                        or any(not isinstance(value, str) or not re.fullmatch(r'[0-9a-f]{64}', value)
                               for value in digests.values())):
                    raise ValueError
            return data
        except (ValueError, TypeError, KeyError) as error:
            raise self.Error('Credential activation journal is invalid; state was preserved.', 70) from error

    def phase(self, value):
        if value not in PHASES:
            raise self.Error('Invalid Credential activation transition.', 70)
        data = self.metadata()
        if data is None or not data['names']:
            raise self.Error('Credential activation journal is unavailable.', 70)
        data['phase'] = value
        self.write(self.pending / 'metadata.json', json.dumps(data, sort_keys=True).encode() + b'\n')

    def begin(self, before, after):
        names = self.names(sorted(before))
        if set(before) != set(after):
            raise self.Error('Credential activation snapshot file sets differ.', 70)
        self.pending.mkdir(mode=0o700)  # Never replace another journal.
        self.sync(self.root)
        metadata = {'schema': 1, 'phase': 'preparing', 'names': names,
                    'before': [name for name in names if before[name] is not None],
                    'after': [name for name in names if after[name] is not None],
                    'digests': {kind: {name: hashlib.sha256(values[name]).hexdigest() for name in names
                                       if values[name] is not None}
                                for kind, values in (('before', before), ('after', after))}}
        self.write(self.pending / 'metadata.json', json.dumps(metadata, sort_keys=True).encode() + b'\n')
        for kind, values in (('before', before), ('after', after)):
            directory = self.pending / kind
            self.directory(directory, create=True)
            for name in metadata[kind]:
                self.write(directory / name, values[name])
            self.sync(directory)
        self.sync(self.pending)
        self.phase('prepared')

    def snapshot(self, kind):
        if kind not in {'before', 'after'}:
            raise self.Error('Invalid Credential activation snapshot.', 70)
        data = self.metadata()
        self.directory(self.pending / kind)
        # Validate the entire recovery set before replacing any live file.
        result = {}
        for name in data['names']:
            raw = self.read(self.pending / kind / name, self.limit) if name in data[kind] else None
            if raw is not None:
                if hashlib.sha256(raw).hexdigest() != data['digests'][kind][name]:
                    raise self.Error('Credential recovery snapshot digest does not match; live state was preserved.', 70)
                self.validate(raw)
            result[name] = raw
        return result

    def install(self, values):
        for name in self.names(sorted(values)):
            path = self.root / name
            if values[name] is None:
                try:
                    self.read(path, self.limit)
                except FileNotFoundError:
                    continue
                path.unlink()
                self.sync(self.root)
            else:
                self.write(path, values[name])

    def cleanup(self):
        data = self.metadata()
        if data is None:
            return
        files, directories = [], []
        for path in self.pending.iterdir():
            if path.name in {'before', 'after'}:
                self.directory(path)
                directories.append(path)
                for child in path.iterdir():
                    if child.name not in data['names'] and not child.name.startswith(TEMPORARY_PREFIX):
                        raise self.Error('Unowned file in Credential recovery state; cleanup refused.', 70)
                    self.read(child)
                    files.append(child)
            elif path.name == 'metadata.json' or path.name.startswith(TEMPORARY_PREFIX):
                self.read(path)
                files.append(path)
            else:
                raise self.Error('Unowned object in Credential recovery state; cleanup refused.', 70)
        # Keep metadata until all snapshots have gone, so interrupted cleanup
        # can be resumed for committed/restored/preparing transactions.
        metadata = self.pending / 'metadata.json'
        for path in files:
            if path != metadata:
                path.unlink()
        for path in directories:
            self.sync(path)
            path.rmdir()
        metadata.unlink(missing_ok=True)
        self.sync(self.pending)
        self.pending.rmdir()
        self.sync(self.root)


class Activation:
    """The service adapter supplies bounded stop/start and authenticated checks."""

    def __init__(self, state, service, preflight):
        self.state, self.service, self.preflight = state, service, preflight

    def recover(self, boot=False):
        state = self.state
        state.cleanup_temporaries()
        data = state.metadata()
        if data is None:
            return False
        if data['phase'] in {'preparing', 'prepared', 'committed', 'restored'}:
            state.cleanup()
            return True
        before = state.snapshot('before')
        if not boot:
            self.service.stop()
        state.phase('restoring')
        state.install(before)
        state.phase('rollback')
        if not boot:
            self.service.start()
            if not self.service.verify(before):
                raise state.Error('Credential recovery has not passed authenticated acceptance.', 70)
        state.phase('restored')
        state.cleanup()
        return True

    def apply(self, desired):
        state = self.state
        def validated(values):
            if not isinstance(values, dict):
                raise state.Error('Credential activation requires a complete credential set.')
            state.names(sorted(values))
            for value in values.values():
                if value is not None:
                    if not isinstance(value, bytes):
                        raise state.Error('Credential activation value has an invalid type.')
                    state.validate(value)
            return values
        if not callable(desired):
            validated(desired)
        with state.lock():
            recovered = self.recover()
            # The image adapter resolves keep-existing/generate policies only
            # while this lock is held, so a second caller cannot reuse stale
            # values captured before another successful activation.
            desired = validated(desired(state) if callable(desired) else desired)
            disk_before = state.values(desired)
            self.preflight(desired)
            if desired == disk_before and self.service.verify(desired):
                return {'changed': recovered, 'recovered': recovered}
            # A previous failed play may have changed files without restarting
            # the daemon. Preserve credentials checked against it,
            # rather than turning that disk drift into the rollback baseline.
            before = self.service.rollback_values(disk_before)
            state.begin(before, desired)
            try:
                self.service.stop()
                state.phase('writing')
                state.install(desired)
                state.phase('activating')
                self.service.start()
                if not self.service.verify(desired):
                    raise state.Error('Credential activation has not passed authenticated acceptance.', 69)
            except Exception as error:
                try:
                    self.service.stop()
                    state.phase('restoring')
                    state.install(before)
                    state.phase('rollback')
                    self.service.start()
                    if not self.service.verify(before):
                        raise state.Error('Credential rollback has not passed authenticated acceptance.', 70)
                    state.phase('restored')
                    state.cleanup()
                except Exception as recovery_error:
                    raise state.Error('Credential activation failed and recovery remains pending.', 70) from recovery_error
                raise state.Error('Credential activation failed; previous credentials were restored and checked.', 69) from error
            # Acceptance is the commit boundary. Cleanup failure must never
            # roll back an already committed credential set.
            state.phase('committed')
            state.cleanup()
            return {'changed': True, 'recovered': recovered}
