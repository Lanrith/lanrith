"""Admit owner-reviewed integration overlays without executing build hooks."""

import json
from pathlib import Path, PurePosixPath
import re
import shutil
import stat

from .release import HEX, canonical, file_record, read, require, unique
from . import extension_network, extension_observations, extension_credential_config, extension_credential_values


PROTECTED = (
    'usr/share/lanrith/', 'usr/lib/lanrith/', 'usr/bin/lanrith-',
    'etc/kernel/', 'etc/crypttab', 'etc/fstab', 'etc/repart.d/',
    'usr/lib/repart.d/', 'boot/', 'efi/', 'etc/systemd/system/boot-complete.target',
    'etc/systemd/system/lanrith-', 'usr/lib/systemd/system/lanrith-',
    'etc/sudoers', 'etc/pam.d/', 'etc/ssh/', 'root/',
    'etc/passwd', 'etc/shadow', 'etc/group', 'etc/gshadow',
    'etc/sysusers.d/', 'usr/lib/sysusers.d/',
    'etc/systemd/system/systemd-', 'usr/lib/systemd/system/systemd-',
    'etc/systemd/system/ssh.', 'usr/lib/systemd/system/ssh.',
    'etc/systemd/system/multi-user.', 'usr/lib/systemd/system/multi-user.',
    'etc/systemd/system/boot-complete.', 'usr/lib/systemd/system/boot-complete.',
    'etc/systemd/system.conf', 'usr/lib/systemd/system.conf.d/',
    'usr/local/lib/systemd/system.conf.d/',
    'usr/lib/kernel/', 'usr/lib/dracut/', 'etc/dracut.conf', 'etc/dracut.conf.d/',
    'usr/share/initramfs-tools/', 'etc/initramfs-tools/',
    'etc/systemd/system-generators/', 'usr/lib/systemd/system-generators/',
    'etc/ld.so.preload',
)
REPLACEABLE = ('etc/nftables.conf', 'etc/systemd/network/', 'etc/kea/', 'etc/unbound/',
               'etc/chrony/', 'etc/sysctl.d/90-lanrith-routing.conf', 'etc/frr/', 'etc/freeradius/',
               'etc/suricata/', 'etc/snmp/', 'etc/alloy/', 'etc/discovery-bridge/', 'etc/router-policy/',
               'etc/avahi/', 'etc/tayga.conf')

CORE_MOUNTS = {'-', 'var', 'efi', 'boot', 'boot-efi', 'sysroot', 'usr', 'etc', 'home', 'root',
               'run', 'dev', 'proc', 'sys', 'tmp'}


def health_unit(value):
    if not isinstance(value, str) or not re.fullmatch(
            r'[A-Za-z0-9_@.\\-]+\.(service|target|socket|timer|path|mount|automount)', value):
        return False
    stem, suffix = value.rsplit('.', 1)
    return suffix not in ('mount', 'automount') or stem not in CORE_MOUNTS


def admit(directory, expected):
    require(directory.is_dir() and not directory.is_symlink() and directory.resolve() == directory.absolute(),
            'Integration directory must be canonical.')
    require(isinstance(expected, str) and HEX.fullmatch(expected) and
            file_record(directory / 'extension.json')['sha256'] == expected,
            'Integration manifest differs from its reviewed digest.')
    value = json.loads(read(directory / 'extension.json', 1024 * 1024), object_pairs_hook=unique)
    required = {'schema', 'id', 'features', 'health_units', 'files'}
    require(isinstance(value, dict) and required <= set(value) <= required | {
                'replaces', 'identities', 'health_units_by_feature', 'start_units', 'network', 'observations',
                'credentials'} and
            value['schema'] == 1 and isinstance(value['id'], str) and
            re.fullmatch(r'[a-z][a-z0-9-]{0,47}', value['id']), 'Invalid integration manifest.')
    require(isinstance(value['features'], list) and len(value['features']) <= 32 and
            all(isinstance(item, str) and re.fullmatch(r'[a-z][a-z0-9-]{0,47}', item)
                for item in value['features']) and len(set(value['features'])) == len(value['features']),
            'Invalid integration features.')
    require(isinstance(value['health_units'], list) and len(value['health_units']) <= 64 and
            all(health_unit(item) for item in value['health_units']), 'Invalid integration health units.')
    by_feature = value.get('health_units_by_feature', {})
    require(isinstance(by_feature, dict) and set(by_feature) <= set(value['features']) and
            all(isinstance(units, list) and len(units) <= 64 and
                all(health_unit(unit) for unit in units) for units in by_feature.values()),
            'Invalid per-feature health units.')
    require(isinstance(value['files'], dict) and 0 < len(value['files']) <= 4096, 'Invalid integration inventory.')
    identities = identity_declarations(value.get('identities', {}))
    extension_network.declarations(value.get('network', {}), identities)
    extension_observations.declarations(value.get('observations', []), identities)
    extension_credential_values.declarations(value['id'], value.get('credentials', []), value['files'])
    start_units = value.get('start_units', [])
    require(isinstance(start_units, list) and len(start_units) <= 64 and
            all(isinstance(unit, str) and re.fullmatch(
                r'[A-Za-z0-9_][A-Za-z0-9_.@-]{0,127}\.(service|socket|timer|target)', unit) and
                '@.' not in unit and
                'usr/lib/systemd/system/'+unit in value['files'] for unit in start_units) and
            len(set(start_units)) == len(start_units), 'Invalid integration start units.')
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
        if name.startswith(('etc/systemd/system/', 'usr/lib/systemd/system/')):
            unit = path.parts[4] if name.startswith('usr/') else path.parts[3]
            unit = unit.removesuffix('.d')
            require(not unit.endswith(('.mount', '.automount')) or health_unit(unit),
                    'Integration attempts to replace a core storage mount.')
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
    units, digests, written, identities, starts, declarations, replaced = [], {}, set(), [], [], [], set()
    observations, credentials = [], []
    for identity in sorted(selected):
        directory, expected = selected[identity]
        value = admit(directory, expected)
        identities.append(identity_declarations(value.get('identities', {})))
        require(value['id'] == identity, 'Integration identity differs from its selection.')
        active = []
        for feature, settings in configuration['services'].items():
            if settings.get('enabled') and settings.get('configuration') == identity:
                require(feature in value['features'], 'Integration does not implement its selected feature.')
                feature_units = value.get('health_units_by_feature', {}).get(feature, [])
                require(value['health_units'] or feature_units,
                        'An enabled integration must declare its runtime health requirements.')
                active.append(feature)
                units.extend(feature_units)
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
        if active or not value['features']:
            units.extend(value['health_units'])
            starts.extend(value.get('start_units', []))
            declarations.append(extension_network.declarations(value.get('network', {}), identities[-1]))
            observations.append(extension_observations.declarations(value.get('observations', []), identities[-1]))
            credentials.append((identity, extension_credential_values.declarations(
                identity, value.get('credentials', []), value['files']), bool(active or value['health_units'])))
        replaced.update(value.get('replaces', []))
        digests[identity] = expected
    extension_observations.install(configuration, observations, destination)
    credential_catalogs = extension_credential_config.install(credentials, destination,
        configuration.get('administration', {}).get('username', 'admin'))
    plan = extension_network.resolve(configuration, declarations)
    if any(plan.values()):
        require('etc/nftables.conf' not in replaced,
                'Typed integration networking cannot combine with a whole-firewall replacement.')
        from . import firewall, service_plane
        (destination/'etc/nftables.conf').write_text(firewall.render(configuration, extension_rules=plan))
        if plan['services']:
            (destination/'etc/lanrith/services.nft').write_text(service_plane.namespace_firewall(
                configuration, service_plane.topology(configuration), extension_rules=plan))
    return {'digests': digests, 'health_units': sorted(set(units)), 'identities': identities,
            'start_units': sorted(set(starts)), 'credential_catalogs': credential_catalogs}


def identity_declarations(value):
    """Owner services can add locked identities without replacing core accounts."""
    require(isinstance(value, dict) and set(value) <= {'users', 'groups'}, 'Invalid integration identities.')
    result = {'users': value.get('users', []), 'groups': value.get('groups', [])}
    for kind, entries in result.items():
        require(isinstance(entries, list) and len(entries) <= 64, 'Integration identity count exceeds its bound.')
        for item in entries:
            required = {'name', 'gid'} | ({'uid'} if kind == 'users' else set())
            optional = {'home'} if kind == 'users' else {'members'}
            require(isinstance(item, dict) and required <= set(item) <= required | optional and
                    isinstance(item['name'], str) and re.fullmatch(r'[a-z_][a-z0-9_-]{0,31}', item['name']) and
                    item['name'] != 'lanrith-dns-observer' and
                    all(type(item[field]) is int and 100 <= item[field] <= 59999
                        for field in ('uid', 'gid') if field in required), 'Invalid locked integration identity.')
            if kind == 'users':
                home = item.get('home', '/nonexistent')
                require(isinstance(home, str) and (home == '/nonexistent' or
                        re.fullmatch(r'/var/lib/[A-Za-z0-9_./-]+', home) and '..' not in Path(home).parts),
                        'Integration service home must be bounded persistent state.')
            else:
                members = item.get('members', [])
                require(isinstance(members, list) and len(members) == len(set(members)) and
                        all(isinstance(name, str) and re.fullmatch(r'[a-z_][a-z0-9_-]{0,31}', name)
                            for name in members), 'Invalid integration group members.')
    return result


def account_overlay(accounts, declarations, destination, reserved_name='admin'):
    from . import dns_observations
    declarations = [*declarations, *dns_observations.account_declarations(accounts, declarations, destination)]
    if not any(value['users'] or value['groups'] for value in declarations):
        return
    require(set(accounts) == {'passwd', 'group'}, 'Admitted base account registry is missing.')
    rows = {name: text.decode().splitlines() for name, text in accounts.items()}
    users = {parts[0]: (int(parts[2]), int(parts[3])) for line in rows['passwd'] if (parts := line.split(':'))}
    groups = {parts[0]: int(parts[2]) for line in rows['group'] if (parts := line.split(':'))}
    uids, gids = {uid for uid, _ in users.values()}, set(groups.values())
    added = {'users': [], 'groups': []}
    for value in declarations:
        for item in value['groups']:
            require(item['name'] not in groups and item['gid'] not in gids,
                    'Integration group collides with a core or another integration identity.')
            groups[item['name']] = item['gid']
            gids.add(item['gid'])
            added['groups'].append(item)
    for value in declarations:
        for item in value['users']:
            require(item['name'] not in users and item['name'] != reserved_name and item['uid'] not in uids and
                    item['gid'] in gids, 'Integration user collides with an identity or lacks a declared primary group.')
            users[item['name']] = (item['uid'], item['gid'])
            uids.add(item['uid'])
            rows['passwd'].append(f'{item["name"]}:*:{item["uid"]}:{item["gid"]}:Lanrith integration service:'+
                                  item.get('home', '/nonexistent')+':/usr/sbin/nologin')
            added['users'].append(item)
    for item in added['groups']:
        require(set(item.get('members', [])) <= users.keys(), 'Integration group names an undeclared user.')
        rows['group'].append(f'{item["name"]}:x:{item["gid"]}:'+','.join(item.get('members', [])))
    for name, lines in rows.items():
        path = destination/'etc'/name
        require(not path.exists() and not path.is_symlink(), 'Integration conflicts with protected account generation.')
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text('\n'.join(lines)+'\n')
        path.chmod(0o644)
    metadata = destination/'usr/share/lanrith/integration-identities.json'
    metadata.parent.mkdir(parents=True, exist_ok=True)
    metadata.write_bytes(canonical(added))
    metadata.chmod(0o644)
