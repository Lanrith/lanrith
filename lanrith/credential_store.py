"""Protected credential staging and admission on encrypted persistent state.

The caller owns authorization and service quiescence. No caller-selected path,
command, format or unit enters this store. Secret-bearing journals never leave
the protected state directory; status exposes neither values nor their hashes.
"""

import base64
from contextlib import contextmanager, ExitStack
import fcntl
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat

from .credential_values import FORMAT_UNITS, validate, validate_catalog
from .release import canonical, require, unique


MANIFEST = Path('/usr/share/lanrith/credentials.json')
CONTROL = PurePosixPath('/var/lib/lanrith/credential-provisioning')
LIMIT = 2*1024*1024
HISTORY_LIMIT = 1024
HEX = re.compile(r'[0-9a-f]{64}\Z')
TRANSACTION = re.compile(r'[0-9a-f]{32}\Z')
RECORDS = {'owned.json', 'admitted.json', 'pending.json', 'receipt.json'}


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def binding(item):
    return digest(canonical(item))


def descriptor(item):
    require(isinstance(item, dict) and isinstance(item.get('format'), str) and item['format'] in FORMAT_UNITS,
            'Credential binding descriptor differs.')
    validate_catalog({'schema': 1, 'credentials': [item], 'units': sorted(FORMAT_UNITS[item['format']])})
    return item


def load_catalog(path=MANIFEST):
    from .policy_runtime import read
    return validate_catalog(json.loads(read(path, 256*1024), object_pairs_hook=unique))


def decoded(text):
    require(isinstance(text, str) and 1 <= len(text) <= 8192 and text.isascii(), 'Encoded credential differs.')
    try:
        raw = base64.b64decode(text, validate=True)
    except ValueError:
        raise ValueError('Encoded credential differs.') from None
    require(base64.b64encode(raw).decode('ascii') == text, 'Encoded credential is not canonical.')
    return raw


class Store:
    def __init__(self, installed, catalog, *, root=Path('/'), extension=None):
        from .image_operation import identity
        require(installed.get('state_directory') == '/var/lib/lanrith', 'Credential control state differs.')
        self.extension = extension
        self.validate_catalog = validate_catalog
        self.validate_value, self.decoded, self.descriptor = validate, decoded, descriptor
        self.value_limit, control = 4097, CONTROL
        if extension is not None:
            from . import extension_credential_values as scoped
            scoped.namespace(extension)
            self.validate_catalog = lambda value: scoped.validate_catalog(extension, value)
            self.validate_value, self.decoded = scoped.validate, scoped.decoded
            self.descriptor = lambda item: scoped.descriptor(extension, item)
            self.value_limit, control = scoped.VALUE_LIMIT, scoped.control_path(extension)
        self.identity = identity(installed)
        self.catalog = self.validate_catalog(json.loads(canonical(catalog), object_pairs_hook=unique))
        self.catalog_digest = digest(canonical(self.catalog))
        self.items = {item['reference']: item for item in self.catalog['credentials']}
        self.root = Path(root)
        require(self.root.is_absolute() and self.root.resolve() == self.root, 'Credential filesystem root differs.')
        self.control = self.path(control)
        self.write_targets = {self.path(i['path']) for i in self.items.values()} | {self.control/name for name in RECORDS}
        self._locked = False

    def path(self, absolute):
        return self.root/str(absolute).lstrip('/')

    def directory(self, path, *, create=False):
        """Pin each directory without following links or leaving the state FS."""
        parts = path.relative_to(self.root).parts
        require(parts and parts[0] == 'var', 'Credential directory is outside persistent state.')
        descriptor_fd = os.open(self.root, os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
        device = None
        try:
            info = os.fstat(descriptor_fd)
            require(info.st_uid == 0 and not stat.S_IMODE(info.st_mode) & 0o022, 'Credential filesystem custody differs.')
            for index, name in enumerate(parts):
                try:
                    child = os.open(name, os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW, dir_fd=descriptor_fd)
                except FileNotFoundError:
                    if not create:
                        raise
                    require(create and index > 0, 'Persistent state is absent.')
                    try:
                        os.mkdir(name, 0o700, dir_fd=descriptor_fd)
                    except FileExistsError:
                        pass
                    child = os.open(name, os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW, dir_fd=descriptor_fd)
                    os.fsync(descriptor_fd)
                info = os.fstat(child)
                try:
                    require(info.st_uid == 0 and not stat.S_IMODE(info.st_mode) & 0o022,
                            'Credential directory custody differs.')
                    if device is None:
                        device = info.st_dev
                    require(info.st_dev == device, 'Credential directory leaves the persistent state filesystem.')
                except BaseException:
                    os.close(child)
                    raise
                os.close(descriptor_fd)
                descriptor_fd = child
            return descriptor_fd
        except BaseException:
            os.close(descriptor_fd)
            raise

    @staticmethod
    def metadata(info, maximum):
        require(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and info.st_nlink == 1 and
                stat.S_IMODE(info.st_mode) == 0o600 and 0 <= info.st_size <= maximum,
                'Credential file metadata differs.')

    def read(self, path, maximum=LIMIT, *, missing=False):
        try:
            parent = self.directory(path.parent)
            try:
                device = os.fstat(parent).st_dev
                fd = os.open(path.name, os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK, dir_fd=parent)
            finally:
                os.close(parent)
            with os.fdopen(fd, 'rb') as stream:
                info = os.fstat(stream.fileno())
                self.metadata(info, maximum)
                require(info.st_dev == device, 'Credential file leaves the persistent state filesystem.')
                raw = stream.read(maximum+1)
                require(len(raw) <= maximum, 'Credential file exceeds its bound.')
                return raw
        except FileNotFoundError:
            if missing:
                return None
            raise

    def record(self, name):
        require(name in RECORDS, 'Credential record name differs.')
        raw = self.read(self.control/name, missing=True)
        return None if raw is None else json.loads(raw, object_pairs_hook=unique)

    def write(self, path, raw):
        require(path in self.write_targets and isinstance(raw, bytes) and len(raw) <= LIMIT,
                'Credential write scope or size differs.')
        self.read(path, missing=True)
        parent = self.directory(path.parent)
        name = '.provisioning-write-'+os.urandom(16).hex()
        fd = None
        try:
            fd = os.open(name, os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW, 0o600, dir_fd=parent)
            with os.fdopen(fd, 'wb') as stream:
                fd = None
                stream.write(raw)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(name, path.name, src_dir_fd=parent, dst_dir_fd=parent)
            os.fsync(parent)
        finally:
            if fd is not None:
                os.close(fd)
            try:
                os.unlink(name, dir_fd=parent)
            except FileNotFoundError:
                pass
            os.close(parent)

    def save(self, name, value):
        require(name in RECORDS, 'Credential record name differs.')
        self.write(self.control/name, canonical(value))

    def remove(self, name):
        require(name == 'pending.json', 'Credential removal scope differs.')
        parent = self.directory(self.control)
        try:
            try:
                os.unlink(name, dir_fd=parent)
            except FileNotFoundError:
                return
            os.fsync(parent)
        finally:
            os.close(parent)

    def setup(self):
        fd = self.directory(self.control, create=True)
        try:
            require(stat.S_IMODE(os.fstat(fd).st_mode) == 0o700, 'Provisioning control directory is not private.')
        finally:
            os.close(fd)
        for item in self.items.values():
            os.close(self.directory(self.path(item['path']).parent, create=True))

    @contextmanager
    def lock(self):
        require(not self._locked, 'Credential provisioning lock is already held.')
        parent = self.directory(self.control)
        try:
            fd = os.open('.lock', os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW|os.O_NONBLOCK, 0o600, dir_fd=parent)
        finally:
            os.close(parent)
        try:
            self.metadata(os.fstat(fd), 0)
            try:
                fcntl.flock(fd, fcntl.LOCK_EX|fcntl.LOCK_NB)
            except BlockingIOError:
                raise ValueError('Credential provisioning is busy.') from None
            self._locked = True
            yield
        finally:
            self._locked = False
            os.close(fd)

    def inventory(self, name, *, admitted=False):
        value = self.record(name)
        if value is None:
            return {}
        require(isinstance(value, dict) and set(value) == {'schema', 'bindings'} and
                type(value['schema']) is int and value['schema'] == 1 and isinstance(value['bindings'], dict) and
                len(value['bindings']) <= HISTORY_LIMIT, 'Credential inventory differs.')
        for key, item in value['bindings'].items():
            if admitted:
                require(isinstance(item, dict) and set(item) == {'descriptor', 'sha256', 'canonical_sha256'} and
                        all(isinstance(item[k], str) and HEX.fullmatch(item[k]) for k in ('sha256', 'canonical_sha256')),
                        'Admitted credential record differs.')
                selected = item['descriptor']
            else:
                selected = item
            self.descriptor(selected)
            require(key == binding(selected), 'Credential binding identity differs.')
        return value['bindings']

    def current(self, item):
        raw = self.read(self.path(item['path']), self.value_limit)
        body = self.validate_value(item, raw)
        return {'descriptor': item, 'sha256': digest(raw), 'canonical_sha256': digest(body)}

    def admitted(self):
        if not self.items:
            return True
        previous = self.inventory('admitted.json', admitted=True)
        for item in self.items.values():
            if binding(item) not in previous:
                return False
            try:
                if previous[binding(item)] != self.current(item):
                    return False
            except FileNotFoundError:
                return False
        return True

    def pending(self):
        value = self.record('pending.json')
        if value is None:
            return None
        require(isinstance(value, dict) and set(value) == {
            'schema', 'identity', 'catalog', 'catalog_sha256', 'transaction_id', 'phase', 'values', 'allow_replace'} and
            type(value['schema']) is int and value['schema'] == 1 and
            isinstance(value['transaction_id'], str) and TRANSACTION.fullmatch(value['transaction_id']) and
            value['phase'] in ('writing', 'prepared') and type(value['allow_replace']) is bool and
            isinstance(value['identity'], dict) and set(value['identity']) == set(self.identity),
            'Pending credential transaction differs.')
        from .image_operation import identity
        identity(value['identity'])
        self.validate_catalog(value['catalog'])
        require(value['catalog_sha256'] == digest(canonical(value['catalog'])) and isinstance(value['values'], dict) and
                set(value['values']) == {item['reference'] for item in value['catalog']['credentials']},
                'Pending credential scope differs.')
        for item in value['catalog']['credentials']:
            self.validate_value(item, self.decoded(value['values'][item['reference']]))
        return value

    def selected_pending(self):
        pending = self.pending()
        return pending if pending is not None and pending['identity'] == self.identity and \
            pending['catalog_sha256'] == self.catalog_digest else None

    def dedicated(self, registry):
        paths = {self.path(item['path']) for item in [*registry.values(), *self.items.values()]}
        parents = {p.parent for p in paths}
        for parent in {self.path(item['path']).parent for item in self.items.values()}:
            fd = self.directory(parent)
            try:
                names = {p.name for p in paths if p.parent == parent}
                names.update(p.relative_to(parent).parts[0] for p in parents if p != parent and parent in p.parents)
                snmp = any(i['format'] == 'snmp-user' and self.path(i['path']).parent == parent for i in self.items.values())
                if snmp:
                    names.add('.activation.lock')
                for name in os.listdir(fd):
                    if name.startswith('.provisioning-write-'):
                        # Only this lock owner can clean abandoned atomic-write
                        # temporaries; validate them before unlinking.
                        self.metadata(os.stat(name, dir_fd=fd, follow_symlinks=False), LIMIT)
                        os.unlink(name, dir_fd=fd)
                    else:
                        require(name in names, 'Credential directory contains unrelated state.')
                os.fsync(fd)
            finally:
                os.close(fd)

    @contextmanager
    def native_locks(self, *, recover=True):
        """Serialize with SNMP's existing recoverable activation protocol."""
        with ExitStack() as stack:
            for item in sorted(self.items.values(), key=lambda i: i['path']):
                if item['format'] != 'snmp-user':
                    continue
                parent = self.path(item['path']).parent
                directory = self.directory(parent)
                try:
                    fd = os.open('.activation.lock', os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW|os.O_NONBLOCK, 0o600, dir_fd=directory)
                finally:
                    os.close(directory)
                stack.callback(os.close, fd)
                self.metadata(os.fstat(fd), 0)
                try:
                    fcntl.flock(fd, fcntl.LOCK_EX|fcntl.LOCK_NB)
                except BlockingIOError:
                    raise ValueError('Native credential activation is busy.') from None
                if (parent/'.activation-pending').exists() or list(parent.glob('.activation-write.*')):
                    require(recover, 'Native credential recovery requires stopped consumers.')
                    from credential_runtime import Activation
                    from snmp_service import State
                    Activation(State(parent, header=item['parameters']['header']), None, None).recover(boot=True)
            yield

    def validate_values(self, values):
        require(isinstance(values, dict) and set(values) == set(self.items), 'Credential input scope differs.')
        supplied = {name: self.decoded(values[name]) for name in self.items}
        for name, item in self.items.items():
            self.validate_value(item, supplied[name])
        return supplied

    def preflight(self, values, *, allow_replace=False):
        supplied = self.validate_values(values)
        previous = self.inventory('admitted.json', admitted=True)
        selected = {}
        for name, item in self.items.items():
            current = self.read(self.path(item['path']), self.value_limit, missing=True)
            protected = [row for row in previous.values() if row['descriptor']['path'] == item['path']]
            require(not protected or current is not None and all(digest(current) == row['sha256'] for row in protected),
                    'Admitted credential integrity differs.')
            if current is not None:
                try:
                    equal = self.validate_value(item, current) == self.validate_value(item, supplied[name])
                except ValueError:
                    equal = False
                if equal:
                    supplied[name] = current  # preserve native file framing
                else:
                    require(allow_replace and not protected, 'Existing fallback credential must be preserved.')
            selected[name] = supplied[name]
        # Reject exhausted history before the caller stops consumers. Consumer
        # names are descriptor-bound, so extension histories can be larger than
        # the fixed core grammars even with the same binding count.
        registry = self.inventory('owned.json')
        registry.update({binding(item): item for item in self.items.values()})
        projected = {**previous, **{binding(item): {'descriptor': item,
            'sha256': '0'*64, 'canonical_sha256': '0'*64} for item in self.items.values()}}
        for records in (registry, projected):
            require(len(records) <= HISTORY_LIMIT and
                    len(canonical({'schema': 1, 'bindings': records})) <= LIMIT,
                    'Credential history exceeds its storage bound.')
        return selected

    def stage(self, values, *, allow_replace=False):
        """Caller holds lock and has stopped the image-owned consumers."""
        require(self._locked and self.items and type(allow_replace) is bool, 'No locked credential staging scope.')
        # Reject the whole input before native recovery can change any file.
        self.validate_values(values)
        with self.native_locks():
            selected = self.preflight(values, allow_replace=allow_replace)
            if self.admitted():
                return self.status()
            registry = self.inventory('owned.json')
            self.dedicated(registry)
            registry.update({binding(item): item for item in self.items.values()})
            require(len(registry) <= HISTORY_LIMIT, 'Credential ownership inventory exceeds its bound.')
            pending = {'schema': 1, 'identity': self.identity, 'catalog': self.catalog,
                'catalog_sha256': self.catalog_digest, 'transaction_id': os.urandom(16).hex(), 'phase': 'writing',
                'values': {name: base64.b64encode(raw).decode('ascii') for name, raw in selected.items()},
                'allow_replace': allow_replace}
            self.save('pending.json', pending)
            self.save('owned.json', {'schema': 1, 'bindings': registry})
            self._write_pending(pending)
        return self.status()

    def _write_pending(self, pending):
        for name, item in self.items.items():
            raw = self.decoded(pending['values'][name])
            if self.read(self.path(item['path']), self.value_limit, missing=True) != raw:
                self.write(self.path(item['path']), raw)
        for item in self.items.values():
            self.current(item)
        self.save('pending.json', {**pending, 'phase': 'prepared'})

    def resume(self):
        """Caller holds lock; another image's journal never replays here."""
        require(self._locked, 'Credential recovery requires its transaction lock.')
        pending = self.selected_pending()
        if pending is None:
            return False
        if self.admitted():
            self.remove('pending.json')
            return True
        with self.native_locks():
            self.preflight(pending['values'], allow_replace=pending['allow_replace'])
            registry = self.inventory('owned.json')
            self.dedicated(registry)
            registry.update({binding(item): item for item in self.items.values()})
            require(len(registry) <= HISTORY_LIMIT, 'Credential ownership inventory exceeds its bound.')
            self.save('owned.json', {'schema': 1, 'bindings': registry})
            self._write_pending(pending)
        return True

    def prepared(self):
        pending = self.selected_pending()
        return pending is not None and pending['phase'] == 'prepared' and all(
            self.read(self.path(item['path']), self.value_limit, missing=True) == self.decoded(pending['values'][name])
            for name, item in self.items.items())

    def commit(self, transaction_id):
        """Caller holds lock and has completed its functional acceptance checks."""
        require(self._locked and isinstance(transaction_id, str) and TRANSACTION.fullmatch(transaction_id),
                'Locked credential confirmation differs.')
        receipt = self.record('receipt.json')
        if self.admitted() and receipt == {'schema': 1, 'identity': self.identity,
                'catalog_sha256': self.catalog_digest, 'transaction_id': transaction_id}:
            pending = self.selected_pending()
            if pending is not None and pending['transaction_id'] == transaction_id:
                self.remove('pending.json')
            return self.status()
        pending = self.selected_pending()
        require(pending is not None and pending['transaction_id'] == transaction_id and self.prepared(),
                'Credential confirmation is stale or the staged set differs.')
        with self.native_locks(recover=False):
            require(self.prepared(), 'Staged credentials changed during native confirmation.')
            previous = self.inventory('admitted.json', admitted=True)
            previous.update({binding(item): self.current(item) for item in self.items.values()})
            require(len(previous) <= HISTORY_LIMIT, 'Admitted credential inventory exceeds its bound.')
            self.save('receipt.json', {'schema': 1, 'identity': self.identity,
                'catalog_sha256': self.catalog_digest, 'transaction_id': transaction_id})
            self.save('admitted.json', {'schema': 1, 'bindings': previous})
            self.remove('pending.json')
        return self.status()

    def status(self):
        try:
            admitted = self.admitted()
            pending = self.selected_pending()
            prepared = self.prepared() if pending is not None else False
        except FileNotFoundError:
            admitted, pending, prepared = False, None, False
        return {'schema': 1, 'required': bool(self.items), 'configuration_sha256': self.identity['configuration_sha256'],
                'phase': 'committed' if admitted else 'prepared' if prepared else 'writing' if pending else 'needs-input',
                'references': sorted(self.items), 'transaction_id': pending['transaction_id'] if pending is not None else None}
