"""Compile explicitly release-owned RRsets and a private migration primary."""

from . import integrations, intent
from .release import canonical, require


def managed_rrsets(zones, records):
    plan = {}
    count = 0
    for zone, entry in zones.items():
        owners = entry.get('managed_rrsets', {})
        require(isinstance(owners, dict) and (not owners or entry.get('persistent')),
                'Managed DNS RRsets require a persistent zone.')
        targets = {name.lower(): rr for name, rr in records[zone].items()}
        seen = set()
        for label, rr in owners.items():
            integrations.domain(label)
            require(not label.endswith('.') and len(label+'.'+zone) <= 253 and label.lower() not in seen,
                    'Invalid or duplicate managed DNS owner name.')
            seen.add(label.lower())
            intent.fields(rr, {'A', 'AAAA', 'CNAME'})
            require(rr and not ('CNAME' in rr and len(rr) != 1), 'Conflicting managed DNS types.')
            name = (label+'.'+zone+'.').lower()
            for kind, transition in rr.items():
                count += 1
                require(count <= 128, 'Too many managed DNS RRsets.')
                intent.fields(transition, {'previous', 'remove'}, {'previous'})
                previous = []
                for item in intent.sequence(transition['previous'], 16):
                    if kind == 'CNAME':
                        integrations.domain(item)
                        require(item.endswith('.') and not item.endswith('..'), 'Invalid previous CNAME.')
                        previous.append(item.lower())
                    else:
                        previous.append(str(intent.address(item, 4 if kind == 'A' else 6)))
                require(len(set(previous)) == len(previous) and (kind != 'CNAME' or len(previous) <= 1),
                        'Invalid previous DNS RRset.')
                remove = transition.get('remove', False)
                intent.boolean(remove)
                desired = targets.get(label.lower(), {}).get(kind)
                require((desired is None and remove and previous) or (desired is not None and not remove),
                        'Managed DNS RRset must reference seed data or explicitly remove a previous RRset.')
                plan.setdefault(zone, []).append({'name': name, 'type': kind, 'previous': sorted(previous),
                                                   'desired': [desired.lower()] if desired is not None else []})
    for changes in plan.values():
        changes.sort(key=lambda r: (r['name'], r['type']))
        # One RFC 2136 transaction per zone. Bound uncompressed names and RDATA
        # for both prerequisites and changes, including an extra CNAME check.
        require(sum((len(r['name']) + 20) * (4 + len(r['previous'])) +
                    sum(map(len, r['previous'] + r['desired'])) for r in changes) < 60000,
                'Managed DNS transaction exceeds the DNS message bound.')
    return plan


def publisher_denials(key, changes):
    rules = []
    for name in sorted({r['name'] for r in changes}):
        kinds = {r['type'] for r in changes if r['name'] == name}
        protected = 'ANY' if 'CNAME' in kinds else ' '.join(sorted(kinds | {'CNAME'}))
        rules.append(f'  deny "{key}" name {name} {protected};')
    return rules


def render(plan):
    lines = [
        'options { directory "/var/lib/bind"; listen-on port 1053 { 127.0.0.1; };',
        ' listen-on-v6 { none; }; recursion no; dnssec-validation no; notify no;',
        ' empty-zones-enable no; allow-query { localhost; }; allow-transfer { none; };',
        ' pid-file none; };', 'controls {};',
        'include "/var/lib/bind/migration.key";',
    ]
    for zone, changes in plan.items():
        lines += [f'zone "{zone}" {{ type primary; file "/var/cache/bind/db.{zone}";', ' update-policy {']
        lines += [f'  grant "lanrith-migration" name {r["name"]} {r["type"]};' for r in changes]
        lines += [' };', '};']
    return {
        'etc/bind/lanrith-migration.conf': '\n'.join(lines)+'\n',
        'usr/share/lanrith/dns-migration.json': canonical(plan).decode(),
        'etc/systemd/system/named.service.d/59-lanrith-migration.conf':
            '[Unit]\nRequires=lanrith-dns-migrate.service\nAfter=lanrith-dns-migrate.service\n',
        'usr/lib/systemd/system/lanrith-dns-migrate.service':
            '[Unit]\nDescription=Apply declared authoritative DNS RRset transitions\n'
            'Requires=lanrith-dns-state.service\nAfter=lanrith-dns-state.service\nBefore=named.service\n'
            '[Service]\nType=oneshot\nRemainAfterExit=yes\nUser=bind\nGroup=bind\nUMask=0077\n'
            'RuntimeDirectory=lanrith-dns-migrate\nRuntimeDirectoryMode=0700\n'
            'BindPaths=/run/lanrith-dns-migrate:/var/lib/bind\nWorkingDirectory=/var/lib/bind\n'
            'PrivateNetwork=yes\nRestrictAddressFamilies=AF_UNIX AF_INET AF_NETLINK\n'
            'ProtectSystem=strict\nReadWritePaths=/var/cache/bind\nProtectHome=yes\nPrivateTmp=yes\n'
            'NoNewPrivileges=yes\nCapabilityBoundingSet=\nTimeoutStartSec=180\n'
            'ExecStart=/usr/bin/python3 /usr/lib/lanrith/lanrith/dns_migration.py\n',
    }
