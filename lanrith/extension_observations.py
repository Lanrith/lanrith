"""Admit a fixed read-only observation endpoint, never policy mutation IPC."""

from .release import require


def declarations(value, identities):
    require(isinstance(value, list) and len(value) <= 1,
            'Integration observations must select at most one supported endpoint.')
    users = {entry['name']: entry for entry in identities['users']}
    groups = {entry['gid'] for entry in identities['groups']}
    result = []
    for entry in value:
        require(isinstance(entry, dict) and set(entry) == {'service', 'user'} and
                entry['service'] == 'policy' and isinstance(entry['user'], str) and
                entry['user'] in users, 'Invalid integration observation declaration.')
        user = users[entry['user']]
        require(user['gid'] in groups,
                'Observation reader needs an extension-owned primary group.')
        result.append({key: user[key] for key in ('name', 'uid', 'gid')})
    return result


def resolve(configuration, declarations):
    readers = [entry for declaration in declarations for entry in declaration]
    require(len(readers) <= 1, 'Only one admitted policy observation reader is supported.')
    if not readers:
        return None
    require(configuration.get('identity', {}).get('policy', {}).get('enabled', False),
            'Policy observations require the selected policy component.')
    reader = readers[0]
    return {'user': reader['name'], 'uid': reader['uid'], 'gid': reader['gid']}


def install(configuration, declarations, destination):
    observer = resolve(configuration, declarations)
    if observer is None:
        return
    # Core-owned generation is the only writer of this wiring. Extensions may
    # select a reader, but cannot supply a helper unit, command, path or parser.
    from . import policy_agent
    files = policy_agent.render(configuration, observer=observer)
    for name in ('etc/router-policy-agent/runtime/runtime.json',
                 'usr/lib/systemd/system/lanrith-policy-helper.service'):
        path = destination/name
        require(path.is_file() and not path.is_symlink(), 'Core policy runtime wiring is missing.')
        path.write_text(files[name])
