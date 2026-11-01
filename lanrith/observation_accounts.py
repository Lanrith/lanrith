"""Build-only allocation of locked core observation identities."""

from .release import require


def allocate(accounts, declarations, destination, *, name, manifest):
    if not (destination/manifest).exists():
        return []
    require(set(accounts) == {'passwd', 'group'}, 'observation collector needs admitted base accounts.')
    rows = {kind: [line.split(':') for line in text.decode().splitlines() if line]
            for kind, text in accounts.items()}
    require(all(row[0] != name for entries in rows.values() for row in entries),
            'Base already has an unreviewed observation collector identity.')
    used = {int(row[2]) for entries in rows.values() for row in entries}
    for declaration in declarations:
        for kind in ('users', 'groups'):
            for entry in declaration[kind]:
                require(entry['name'] != name, 'Integration collides with the observation collector.')
                used.add(entry['gid'])
                if kind == 'users':
                    used.add(entry['uid'])
    selected = next((uid for uid in range(100, 1000) if uid not in used), None)
    require(selected is not None, 'No unused system identity for the observation collector.')
    return [{'users': [{'name': name, 'uid': selected, 'gid': selected}],
             'groups': [{'name': name, 'gid': selected}]}]
