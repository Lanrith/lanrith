"""Generate authoritative zones, source-and-key admission and durable seeds."""

import hashlib
import ipaddress as ip

from . import authoritative_migration, integrations, intent
from . import bindings as runtime_bindings
from .release import canonical, require


def settings(value):
    return value['services']['dns'].get('authoritative', {})


def active(value):
    return value['services']['dns']['enabled'] and settings(value).get('enabled', False)


def writers(value):
    return settings(value).get('writers', {}) if active(value) else {}


def attached_sources(value, source):
    """Authority admission requires a known ingress, not just a routable address."""
    from .routing import routed_sources
    result = []
    for selector in integrations.endpoints(value, source):
        require(set(selector) == {'network', 'addresses'} and selector['network'] in value['networks'],
                'DNS authority access needs explicit addresses and an attachment network.')
        require(value['networks'][selector['network']].get('forwarding', True),
                'DNS authority clients cannot attach through management.')
        network = value['networks'][selector['network']]
        owned = [ip.ip_interface(a).network for a in network['addresses'] +
                 network.get('additional_subnets', []) + network.get('routed_prefixes', []) +
                 routed_sources(value, selector['network'])]
        require(all(any(ip.ip_network(a).version == prefix.version and ip.ip_network(a).subnet_of(prefix)
                        for prefix in owned) for a in selector['addresses']),
                'DNS authority client is outside its attachment.')
        result.append(selector)
    return result


def qualified_clients(value, sources):
    clients = [item for source in sources for item in attached_sources(value, source)]
    # A DNS server sees the source address after host ingress filtering. Overlapping
    # permissions on different interfaces would erase the reader or writer's attachment.
    attachments = {}
    for client in clients:
        scopes = attachments.setdefault(client['network'], [])
        scopes.extend(ip.ip_network(address) for address in client['addresses'])
    local = intent.service_networks(value)
    for network, scopes in attachments.items():
        others = [prefix for other, prefixes in attachments.items() if other != network for prefix in prefixes]
        require(not any(a.overlaps(b) for a in scopes for b in others + local if a.version == b.version),
                'DNS authority clients must have unambiguous external attachments.')
    return clients


def direct_clients(value):
    readers = intent.sequence(settings(value).get('direct_readers', []), 64)
    return qualified_clients(value, [*readers, *(writer['sources'] for writer in writers(value).values())])


def validate(value):
    if not active(value):
        return
    configuration = settings(value)
    zones = configuration['zones']
    normalized = [z.lower().rstrip('.') for z in zones]
    require(len(set(normalized)) == len(zones) and all(not z.endswith('.') for z in zones),
            'Authoritative zones must be distinct relative DNS names.')
    blocked = [name.lower().rstrip('.') for name in value['services']['dns'].get('blocked_domains', [])]
    require(not any(zone == name or zone.endswith('.'+name) for zone in normalized for name in blocked),
            'An authoritative zone cannot override a blocked domain.')
    direct_clients(value)
    keys = set()
    for writer in writers(value).values():
        require(zones[writer['zone']].get('persistent', False),
                'Dynamic DNS writers require a persistent zone.')
        key = writer['key_name'].lower().rstrip('.')
        require(key not in keys, 'DNS writer key names must be unique.')
        keys.add(key)
    for zone, records in integrations.dns_records(value).items():
        require(all(not label.endswith('.') and
                    len(label)+len(zone)+1 <= 253 for label in records),
                'Zone records must use relative in-zone labels.')
        require(len({label.lower() for label in records}) == len(records),
                'DNS record labels must be unique ignoring case.')
    authoritative_migration.managed_rrsets(zones, zone_records(value))


def service_records(value):
    records = {}
    for name, feature in (('ns1', 'authoritative'), ('dns', 'dns'), ('ntp', 'ntp'), ('metrics', 'metrics')):
        if feature == 'ntp' and not value['services']['ntp']['enabled']:
            continue
        if feature == 'metrics' and not value.get('observability', {}).get('metrics', {}).get('enabled'):
            continue
        addresses = intent.service_addresses(value, feature)
        records[name] = {'A': addresses[0], 'AAAA': addresses[1]}
    from . import snmp
    if snmp.active(value):
        records['snmp'] = {'AAAA': snmp.listener(value)}
    return records


def zone_records(value):
    records = integrations.dns_records(value)
    primary = settings(value)['primary_zone']
    services = service_records(value)
    require(not services.keys() & {label.lower() for label in records[primary]},
            'Configured DNS record conflicts with a generated service record.')
    records[primary].update(services)
    for zone, entry in settings(value)['zones'].items():
        if 'discovery_delegation' in entry:
            add_delegation(value, zone, entry, records[zone])
    return records


def add_delegation(value, zone, entry, records):
    from . import discovery
    service = value['services'].get('discovery', {})
    require(discovery.active(value) and 'configuration' not in service and
            service['domain'].rstrip('.').lower() == zone.lower() and not entry.get('persistent'),
            'Discovery delegation needs the matching immutable parent and built-in discovery service.')
    publication = entry['discovery_delegation']
    intent.fields(publication, {'views', 'publish_browse'}, {'views'})
    selected = intent.sequence(publication['views'], 64, 1)
    views, default = discovery.views(value)
    require(all(isinstance(v, str) and v in views for v in selected) and len(set(selected)) == len(selected),
            'Discovery delegation requires distinct declared views.')
    manifest = discovery.dns_manifest(value)
    ns = manifest['nameservers'][0]
    suffix = '.'+zone.lower()+'.'
    require(ns.lower().endswith(suffix) and len(ns) <= 254,
            'Discovery nameserver must fit inside its published parent.')
    target = ns.lower().removesuffix(suffix)
    owners = {name.lower(): name for name in records}
    subzones = [name.lower() for name in settings(value)['zones'] if name.lower().endswith('.'+zone.lower())]

    def within(name, origin):
        return name == origin or name.endswith('.'+origin)

    for view in selected:
        cut = view+'.'+zone.lower()
        require(len(cut) <= 253 and not any(within(name, cut) for name in subzones)
                and not any(within(name, view) for name in [*owners, target]),
                'Discovery delegation conflicts with an authoritative zone or parent record.')
        records[view] = {'NS': ns}
    target_name = owners.get(target, target)
    addresses = {'A': [], 'AAAA': []}
    for listener in manifest['listeners']:
        address = listener['host']
        addresses['AAAA' if ':' in address else 'A'].append(address)
    require(all(answer in addresses.get(kind, []) for kind, answer in records.get(target_name, {}).items()),
            'Discovery nameserver record conflicts with its listener addresses.')
    require(not any(within(ns.lower().rstrip('.'), child) for child in subzones),
            'Discovery nameserver is below another authoritative zone.')
    records[target_name] = addresses
    if intent.boolean(publication.get('publish_browse', False)):
        for name, targets in discovery.browse_records(zone+'.', selected, default).items():
            owner = name+'.'+zone.lower()
            require(len(owner) <= 253 and name not in owners and not any(within(owner, child) for child in subzones),
                    'Discovery browse publication conflicts with an authoritative zone or parent record.')
            records[name] = {'PTR': targets}


def zone_text(value, zone, records):
    primary = settings(value)['primary_zone']
    # A content-derived serial changes immutable zones when intent changes.
    # Existing persistent zones retain their own serials and journals.
    serial = int.from_bytes(hashlib.sha256(canonical(records)).digest()[:4], 'big') or 1
    text = (f'$ORIGIN {zone}.\n$TTL 300\n'
            f'@ IN SOA ns1.{primary}. hostmaster.{primary}. ({serial} 3600 600 1209600 300)\n'
            f'@ IN NS ns1.{primary}.\n')
    for label, rr in sorted(records.items()):
        for kind, answer in sorted(rr.items()):
            for item in answer if isinstance(answer, list) else [answer]:
                text += f'{label} IN {kind} {item}\n'
    return text


def render(value):
    if not active(value):
        return {}
    from .service_plane import NAMESPACE
    configuration = settings(value)
    endpoints = intent.service_addresses(value, 'authoritative')
    query_sources = sorted({a for client in direct_clients(value) for a in client['addresses']} |
                           set(intent.service_addresses(value, 'dns')))
    has_state = any(zone.get('persistent') for zone in configuration['zones'].values())
    directory = '/var/cache/bind' if has_state else '/run/named'
    lines = ['options {', f' directory "{directory}";',
             ' pid-file "/run/named/named.pid";', ' recursion no;', ' dnssec-validation no;',
             ' notify no;', ' empty-zones-enable no;', ' allow-transfer { none; };',
             ' listen-on { '+endpoints[0]+'; };',
             ' listen-on-v6 { '+' '.join(a+';' for a in endpoints[1:])+' };',
             ' allow-query { '+' '.join(a+';' for a in query_sources)+' };',
             ' version none;', ' hostname none;', ' server-id none;', '};',
             'controls {};']
    if writers(value):
        lines.append('include "/run/lanrith-dns/keys.conf";')
    credentials = {}
    for index, writer in enumerate(writers(value).values()):
        addresses = [a for s in attached_sources(value, writer['sources']) for a in s['addresses']]
        # BIND nested ACL negative matches continue in the outer list. This
        # conjunction admits a writer only with its own source AND TSIG key.
        lines.append(f'acl "writer-{index}" {{ !{{ !{{ '+
                     ' '.join(a+';' for a in addresses)+
                     f' }}; any; }}; key "{writer["key_name"]}"; }};')
        credentials[writer['key_name']] = writer['credential']
    seeds, files = [], {}
    records = zone_records(value)
    plan = authoritative_migration.managed_rrsets(configuration['zones'], records)
    if writers(value):
        # A signed publisher must pass its own source ACL before any zone
        # can evaluate its update-policy. Unsigned readers use allow-query.
        match = [f'"writer-{i}";' for i in range(len(writers(value)))]
        match += [f'!key "{key}";' for key in credentials]
        lines += ['view "authority" {', ' match-clients { '+' '.join(match)+' any; };']
    for zone, entry in configuration['zones'].items():
        seed = 'usr/share/lanrith/zones/db.'+zone
        files[seed] = zone_text(value, zone, records[zone])
        persistent = entry.get('persistent', False)
        target = '/var/cache/bind/db.'+zone if persistent else '/'+seed
        if persistent:
            seeds.append({'source': '/'+seed, 'target': target})
        publishers = [w for w in writers(value).values() if w['zone'] == zone and w['grants']]
        transfers = [f'"writer-{i}";' for i, w in enumerate(writers(value).values())
                     if w['zone'] == zone and w.get('zone_transfer', False)]
        lines += [f'zone "{zone}" {{ type primary; file "{target}";']
        if publishers:
            lines.append(' update-policy {')
            for writer in publishers:
                key = writer['key_name']
                lines.extend(authoritative_migration.publisher_denials(key, plan.get(zone, [])))
                for grant in writer['grants']:
                    rule = 'name' if 'name' in grant else 'subdomain'
                    owner = grant.get('name', grant.get('subtree'))
                    name = zone+'.' if owner == '@' else owner+'.'+zone+'.'
                    lines.append(f'  grant "{key}" {rule} {name} ' + ' '.join(grant['types']) + ';')
            lines.append(' };')
        else:
            lines.append(' allow-update { none; };')
        lines += [' allow-transfer { '+(' '.join(transfers) if transfers else 'none;')+' };',
                  '};']
    if writers(value):
        lines.append('};')
    if plan:
        files.update(authoritative_migration.render(plan))
    files['etc/bind/named.conf'] = '\n'.join(lines)+'\n'
    files['usr/share/lanrith/authoritative.json'] = canonical({
        'schema': 1, 'seeds': seeds, 'credentials': credentials}).decode()
    files['usr/lib/systemd/system/lanrith-dns-state.service'] = (
        '[Unit]\nDescription=Prepare authoritative DNS state without replacing journals\n'
        'Before=named.service\nAfter=var.mount\nRequiresMountsFor=/var/cache/bind\n'
        '[Service]\nType=oneshot\nRemainAfterExit=yes\nGroup=bind\nUMask=0027\n'
        'RuntimeDirectory=lanrith-dns\nRuntimeDirectoryMode=0750\n'
        'ProtectSystem=strict\nReadWritePaths=/var/cache/bind\nProtectHome=yes\nPrivateTmp=yes\n'
        'NoNewPrivileges=yes\nRestrictAddressFamilies=AF_UNIX\n'
        + ''.join(f'LoadCredential={name}:{runtime_bindings.credential_path(value, name)}\n'
                  for name in sorted(set(credentials.values())))
        + 'ExecStart=/usr/bin/python3 /usr/lib/lanrith/lanrith/dns_runtime.py\n')
    files['etc/systemd/system/named.service.d/60-lanrith-services.conf'] = (
        '[Unit]\nRequires=lanrith-services.service lanrith-dns-state.service\n'
        'After=lanrith-services.service lanrith-dns-state.service\n'
        'BindsTo=lanrith-services.service nftables.service lanrith-dns-state.service\n'
        # The command channel is intentionally disabled by controls {} above.
        # Use named's native signals instead of the package's rndc commands.
        '[Service]\nExecStop=\nExecReload=\nExecReload=/usr/bin/kill -HUP $MAINPID\n'
        'KillSignal=SIGTERM\nNetworkNamespacePath=/run/netns/'+NAMESPACE+'\n'
        'User=bind\nGroup=bind\nNoNewPrivileges=yes\n'
        'CapabilityBoundingSet=CAP_NET_BIND_SERVICE\nAmbientCapabilities=CAP_NET_BIND_SERVICE\n'
        'ProtectSystem=strict\nProtectHome=yes\nReadWritePaths=/run/named\n'
        + ('ReadWritePaths=/var/cache/bind\n' if has_state else ''))
    return files


def resolver_path(value):
    # Select a locally usable stub transport under the resolver's upstream-family policy.
    ipv4_only = value['uplink'].get('ipv6') == 'disabled' and value['uplink'].get('ipv4') != 'disabled'
    index = 0 if ipv4_only else 1
    return intent.service_addresses(value, 'dns')[index], intent.service_addresses(value, 'authoritative')[index]


def resolver_zones(value):
    if not active(value):
        return '', ''
    _, target = resolver_path(value)
    server = ''.join(f'  local-zone: "{zone}." transparent\n  domain-insecure: "{zone}."\n'
                     for zone in settings(value)['zones'])
    stubs = ''.join(f'stub-zone:\n  name: "{zone}."\n  stub-addr: {target}\n'
                    '  stub-first: no\n' for zone in settings(value)['zones'])
    return server, stubs
