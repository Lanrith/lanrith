"""Build-time secret inputs for private images; never installed on the router."""

import base64
import hashlib
import importlib.util
from functools import lru_cache
import json
import os
from pathlib import Path
import re
import stat

from . import credential_config, credential_values, extension_credential_values
from .release import ReleaseError, canonical, require, unique


LIMIT = 8*1024*1024


def sources(value):
    selected = value.get('credentials', {})
    require(isinstance(selected, dict) and len(selected) <= 512, 'Invalid build credential sources.')
    for name, item in selected.items():
        require(isinstance(name, str) and re.fullmatch(
            r'(?:[a-z][a-z0-9-]{0,47}/)?[a-z][a-z0-9_-]{0,63}', name) and
            isinstance(item, dict) and set(item) == {'file'} and isinstance(item['file'], str),
            'Credential sources require a reference and a file path; inline values are not supported.')
        path = Path(item['file'])
        require(path.is_absolute() and str(path) == item['file'] and '..' not in path.parts and
                re.fullmatch(r'/[A-Za-z0-9_./+-]{1,2047}', item['file']),
                'Build credential source paths must be absolute and canonical.')
    return selected


def inventory(value, integrations):
    from . import extensions
    result = {item['reference']: (item, validate_native)
              for item in credential_config.catalog(value)['credentials']}
    require(set(integrations) == set(value['extensions']), 'Credential extension selections differ.')
    for name, (directory, digest) in integrations.items():
        declaration = extensions.admit(directory, digest)
        require(declaration['id'] == name, 'Credential extension identity differs.')
        active = any(settings.get('enabled') and settings.get('configuration') == name
                     for settings in value['services'].values())
        if active or not declaration['features']:
            catalog = extension_credential_values.declarations(name, declaration.get('credentials', []),
                                                               declaration['files'])
            result.update({name+'/'+item['reference']: (item, extension_credential_values.validate)
                           for item in catalog['credentials']})
    return result


def private_read(path, maximum):
    """No links, devices, shared permissions, oversized input or unstable reads."""
    require(path.resolve() == path, 'Build credential source cannot contain a symlink.')
    parent = os.open('/', os.O_RDONLY | os.O_DIRECTORY)
    try:
        for part in path.parts[1:-1]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
            os.close(parent)
            parent = child
        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
    finally:
        os.close(parent)
    with os.fdopen(fd, 'rb') as stream:
        before = os.fstat(stream.fileno())
        require(stat.S_ISREG(before.st_mode) and (before.st_uid == os.getuid() or os.getuid() == 0) and before.st_nlink == 1 and
                stat.S_IMODE(before.st_mode) in (0o400, 0o600) and 0 < before.st_size <= maximum,
                'Build credential source must be a private caller-owned regular file.')
        raw = stream.read(maximum+1)
        after = os.fstat(stream.fileno())
        require(len(raw) == before.st_size and len(raw) <= maximum and
                (before.st_dev, before.st_ino, before.st_size, before.st_mode, before.st_uid,
                 before.st_mtime_ns, before.st_ctime_ns) ==
                (after.st_dev, after.st_ino, after.st_size, after.st_mode, after.st_uid,
                 after.st_mtime_ns, after.st_ctime_ns), 'Build credential input changed while reading.')
        return raw


def validate(value, integrations, supplied):
    expected = inventory(value, integrations)
    selected_sources(value, expected)
    require(isinstance(supplied, dict) and set(supplied) == set(expected), 'Build credential set is incomplete.')
    for name, (item, check) in expected.items():
        check(item, supplied[name])
    return supplied


def selected_sources(value, expected):
    """Dormant references may remain in intent; only active consumers read files."""
    declared = sources(value)
    require(set(expected) <= declared.keys(),
            'Build credentials must cover the active service and extension references.')
    return {name: declared[name] for name in expected}


def resolve(value, integrations):
    # Check the entire reference set before opening the first private input.
    expected = inventory(value, integrations)
    selected = selected_sources(value, expected)
    result = {}
    try:
        for name, (item, check) in expected.items():
            raw = private_read(Path(selected[name]['file']), 65536 if '/' in name else 4097)
            check(item, raw)
            result[name] = raw
    except (OSError, ValueError, TypeError):
        raise ReleaseError('Build credential '+name+' is unavailable, unsafe or invalid.') from None
    return result


def encode(supplied):
    raw = canonical({name: base64.b64encode(body).decode('ascii') for name, body in sorted(supplied.items())})
    require(len(raw) <= LIMIT, 'Build credential set exceeds its size bound.')
    return raw


def digest(supplied):
    return hashlib.sha256(encode(supplied)).hexdigest() if supplied else None


def load(path, value, integrations):
    data = json.loads(private_read(path, LIMIT), object_pairs_hook=unique)
    require(isinstance(data, dict), 'Private build credential bundle differs.')
    result = {}
    for name, text in data.items():
        require(isinstance(text, str), 'Private build credential encoding differs.')
        raw = base64.b64decode(text, validate=True)
        require(base64.b64encode(raw).decode('ascii') == text, 'Private build credential encoding differs.')
        result[name] = raw
    return validate(value, integrations, result)


def install(overlay, value, supplied, extension_catalogs):
    catalogs = [(None, credential_config.catalog(value))]
    for name in extension_catalogs:
        path = overlay/'usr/share/lanrith/extension-credentials'/ (name+'.json')
        catalogs.append((name, json.loads(path.read_bytes(), object_pairs_hook=unique)))
    for extension, catalog in catalogs:
        for item in catalog['credentials']:
            name = (extension+'/' if extension else '')+item['reference']
            target = overlay/item['path'].lstrip('/')
            require(str(item['path']).startswith('/usr/lib/lanrith/credentials/'),
                    'Image credentials cannot be written to mutable state.')
            target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            target.parent.chmod(0o700)
            with target.open('xb') as stream:
                target.chmod(0o600)
                stream.write(supplied[name])


@lru_cache(maxsize=1)
def snmp_grammar():
    # The same pure grammar is shipped beside the runtime package. Build tools
    # load the maintained source directly, without modifying the import path.
    path = Path(__file__).parents[1]/'mkosi/base/mkosi.extra/usr/lib/lanrith/snmp_credentials.py'
    spec = importlib.util.spec_from_file_location('lanrith_build_snmp_credentials', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def validate_native(item, raw):
    if item['format'] != 'snmp-user':
        return credential_values.validate(item, raw)
    require(isinstance(raw, bytes) and 0 < len(raw) <= 4097, 'SNMP credential size differs.')
    parsed = snmp_grammar().parse(raw, item['parameters']['header'])
    require(parsed['username'] == item['parameters']['username'], 'SNMP credential username differs.')
    return raw
