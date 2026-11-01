"""Admit fixed read-only observation endpoints, never mutation or journal access."""

from .release import require


def declarations(value, identities):
    require(isinstance(value, list) and len(value) <= 2,
            'Integration observations must select at most two supported endpoints.')
    users = {entry['name']: entry for entry in identities['users']}
    groups = {entry['gid'] for entry in identities['groups']}
    result = []
    for entry in value:
        require(isinstance(entry, dict) and set(entry) == {'service', 'user'} and
                entry['service'] in ('policy', 'logs') and isinstance(entry['user'], str) and
                entry['user'] in users, 'Invalid integration observation declaration.')
        user = users[entry['user']]
        require(user['gid'] in groups,
                'Observation reader needs an extension-owned primary group.')
        require(not any(item['service'] == entry['service'] for item in result),
                'An observation endpoint may be selected only once.')
        result.append({'service': entry['service'], **{key: user[key] for key in ('name', 'uid', 'gid')}})
    return result


def resolve(configuration, declarations, *, service='policy'):
    require(service in ('policy', 'logs'), 'Unsupported observation endpoint.')
    readers = [entry for declaration in declarations for entry in declaration if entry['service'] == service]
    require(len(readers) <= 1, 'Only one admitted reader per observation endpoint is supported.')
    if not readers:
        return None
    selected = (configuration.get('identity', {}).get('policy', {}) if service == 'policy' else
                configuration.get('observability', {}).get('logs', {}))
    require(selected.get('enabled', False), 'Observations require the selected component.')
    reader = readers[0]
    return {'user': reader['name'], 'uid': reader['uid'], 'gid': reader['gid']}


def install(configuration, declarations, destination):
    observer = resolve(configuration, declarations)
    log_observer = resolve(configuration, declarations, service='logs')
    # Core-owned generation is the only writer of this wiring. Extensions may
    # select a reader, but cannot supply a helper unit, command, path or parser.
    if observer is not None:
        from . import policy_agent
        files = policy_agent.render(configuration, observer=observer)
        for name in ('etc/router-policy-agent/runtime/runtime.json',
                     'usr/lib/systemd/system/lanrith-policy-helper.service'):
            path = destination/name
            require(path.is_file() and not path.is_symlink(), 'Core policy runtime wiring is missing.')
            path.write_text(files[name])
    if log_observer is not None:
        from . import logs
        files = logs.render(configuration, observer=log_observer)
        for name in ('usr/share/lanrith/logs.json', 'etc/alloy/config.alloy',
                     'etc/systemd/system/alloy.service.d/60-lanrith.conf'):
            path = destination/name
            require(path.is_file() and not path.is_symlink(), 'Core log runtime wiring is missing.')
            path.write_text(files[name])
