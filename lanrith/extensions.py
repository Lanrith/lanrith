"""Admit owner-reviewed integration overlays without executing build hooks."""

import json
from pathlib import Path, PurePosixPath
import re
import shutil
import stat

from .release import HEX, canonical, file_record, read, require, unique


PROTECTED = (
    'usr/share/lanrith/', 'usr/lib/lanrith/', 'usr/bin/lanrith-',
    'etc/kernel/', 'etc/crypttab', 'etc/fstab', 'etc/repart.d/',
    'usr/lib/repart.d/', 'boot/', 'efi/', 'etc/systemd/system/boot-complete.target',
    'etc/systemd/system/lanrith-', 'usr/lib/systemd/system/lanrith-',
    'etc/sudoers', 'etc/pam.d/', 'etc/ssh/', 'root/',
    'etc/systemd/system/systemd-', 'usr/lib/systemd/system/systemd-',
    'etc/systemd/system/ssh.', 'usr/lib/systemd/system/ssh.',
    'etc/systemd/system/multi-user.', 'usr/lib/systemd/system/multi-user.',
    'etc/systemd/system/boot-complete.', 'usr/lib/systemd/system/boot-complete.',
)
REPLACEABLE = ('etc/nftables.conf', 'etc/systemd/network/', 'etc/kea/', 'etc/unbound/',
               'etc/chrony/', 'etc/sysctl.d/90-lanrith-routing.conf', 'etc/frr/', 'etc/freeradius/',
               'etc/suricata/', 'etc/snmp/', 'etc/alloy/', 'etc/discovery-bridge/', 'etc/router-policy/',
               'etc/avahi/', 'etc/tayga.conf')


def admit(directory, expected):
    require(directory.is_dir() and not directory.is_symlink() and directory.resolve() == directory.absolute(),
            'Integration directory must be canonical.')
    require(isinstance(expected, str) and HEX.fullmatch(expected) and
            file_record(directory / 'extension.json')['sha256'] == expected,
            'Integration manifest differs from its reviewed digest.')
    value = json.loads(read(directory / 'extension.json', 1024 * 1024), object_pairs_hook=unique)
    require(isinstance(value, dict) and set(value) in (
                {'schema', 'id', 'features', 'health_units', 'files'},
                {'schema', 'id', 'features', 'health_units', 'files', 'replaces'}) and
            value['schema'] == 1 and isinstance(value['id'], str) and
            re.fullmatch(r'[a-z][a-z0-9-]{0,47}', value['id']), 'Invalid integration manifest.')
    require(isinstance(value['features'], list) and len(value['features']) <= 32 and
            all(isinstance(item, str) and re.fullmatch(r'[a-z][a-z0-9-]{0,47}', item)
                for item in value['features']) and len(set(value['features'])) == len(value['features']),
            'Invalid integration features.')
    require(isinstance(value['health_units'], list) and len(value['health_units']) <= 64 and
            all(isinstance(item, str) and re.fullmatch(r'[A-Za-z0-9_@.\\-]+\.(service|target|socket|timer|path)', item)
                for item in value['health_units']), 'Invalid integration health units.')
    require(isinstance(value['files'], dict) and 0 < len(value['files']) <= 4096, 'Invalid integration inventory.')
    replaces = value.get('replaces', [])
    require(isinstance(replaces, list) and len(replaces) == len(set(replaces)) and
            all(isinstance(name, str) and name in value['files'] and
                any(name == prefix or prefix.endswith('/') and name.startswith(prefix) for prefix in REPLACEABLE)
                for name in replaces), 'Invalid explicit compiler configuration replacement.')
    observed = set()
    tree = directory / 'root'
    require(tree.is_dir() and not tree.is_symlink(), 'Integration has no file tree.')
    for path in tree.rglob('*'):
        info = path.lstat()
        require(stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode),
                'Integration links, devices and sockets are prohibited.')
        require(not info.st_mode & 0o7022, 'Integration contains unsafe file permissions.')
        if path.is_file():
            observed.add(path.relative_to(tree).as_posix())
    require(observed == set(value['files']), 'Integration tree differs from its exact inventory.')
    for name, record in value['files'].items():
        path = PurePosixPath(name)
        require(not path.is_absolute() and '..' not in path.parts and path.as_posix() == name and
                path.parts[0] in ('etc', 'usr', 'opt') and
                (name.startswith(('usr/lib/lanrith/integrations/', 'usr/share/lanrith/integrations/')) or
                 not any(name.startswith(prefix) for prefix in PROTECTED)),
                'Integration attempts to replace protected boot, access or update authority.')
        require(isinstance(record, dict) and set(record) == {'sha256', 'size', 'mode'} and
                record['mode'] in (0o644, 0o600, 0o755) and type(record['mode']) is int,
                'Invalid integration file record.')
        actual = file_record(tree / name)
        require({key: actual[key] for key in ('sha256', 'size')} ==
                {key: record[key] for key in ('sha256', 'size')} and
                stat.S_IMODE((tree / name).stat().st_mode) == record['mode'],
                'Integration file differs from the reviewed bytes or mode.')
    return value


def overlay(configuration, selected, destination, base_files=None):
    require(set(selected) == set(configuration['extensions']), 'Integration selections differ from configuration.')
    units, digests, written = [], {}, set()
    for identity in sorted(selected):
        directory, expected = selected[identity]
        value = admit(directory, expected)
        require(value['id'] == identity, 'Integration identity differs from its selection.')
        for feature, settings in configuration['services'].items():
            if settings.get('enabled') and settings.get('configuration') == identity:
                require(feature in value['features'], 'Integration does not implement its selected feature.')
                require(value['health_units'], 'An enabled integration must declare its runtime health requirements.')
        for name, record in value['files'].items():
            require(base_files is None or name not in base_files or name in value.get('replaces', []),
                    'Integration attempts to replace a base package file without an admitted configuration replacement.')
            require(name not in written, 'Integrations conflict on a file.')
            target = destination / name
            require(not target.is_symlink() and (not target.exists() or name in value.get('replaces', [])),
                    'Integration conflicts with the core compiler without an explicit replacement.')
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(directory / 'root' / name, target)
            target.chmod(record['mode'])
            written.add(name)
        units.extend(value['health_units'])
        digests[identity] = expected
    return {'digests': digests, 'health_units': sorted(set(units))}
