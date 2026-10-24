"""Generate authoritative zones, source-and-key admission and durable seeds."""

import hashlib
import ipaddress as ip

from . import integrations, intent
from . import bindings as runtime_bindings
from .release import canonical, require


def settings(value):
    return value['services']['dns'].get('authoritative', {})


def active(value):
    return settings(value).get('enabled', False)


def writers(value):
    return settings(value).get('writers', {}) if active(value) else {}


def writer_sources(value, writer):
    """Writer admission requires a known ingress, not just a routable address."""
    from .routing import routed_sources
    result = []
    for selector in integrations.endpoints(value, writer['sources']):
        require(set(selector) == {'network', 'addresses'} and selector['network'] in value['networks'],
                'DNS writer needs explicit addresses and an attachment network.')
        require(value['networks'][selector['network']].get('forwarding', True),
                'DNS writer cannot attach through management.')
        network = value['networks'][selector['network']]
        owned = [ip.ip_interface(a).network for a in network['addresses'] +
                 network.get('additional_subnets', []) + network.get('routed_prefixes', []) +
                 routed_sources(value, selector['network'])]
        require(all(any(ip.ip_network(a).version == prefix.version and ip.ip_network(a).subnet_of(prefix)
                        for prefix in owned) for a in selector['addresses']),
                'DNS writer source is outside its attachment.')
        result.append(selector)
    return result


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
    keys = set()
    for writer in writers(value).values():
        writer_sources(value, writer)
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
    zone_records(value)


def zone_records(value):
    records = integrations.dns_records(value)
    primary = settings(value)['primary_zone']
    for name, feature in (('ns1', 'authoritative'), ('dns', 'dns'), ('ntp', 'ntp'), ('metrics', 'metrics')):
        if feature == 'ntp' and not value['services']['ntp']['enabled']:
            continue
        if feature == 'metrics' and not value.get('observability', {}).get('metrics', {}).get('enabled'):
            continue
        addresses = intent.service_addresses(value, feature)
        rr = {'A': addresses[0], 'AAAA': addresses[1]}
        require(name not in {n.lower() for n in records[primary]},
                'Configured DNS record conflicts with a generated service record.')
        records[primary][name] = rr
    from . import snmp
    if snmp.active(value):
        require('snmp' not in {n.lower() for n in records[primary]},
                'Configured DNS record conflicts with a generated service record.')
        records[primary]['snmp'] = {'AAAA': snmp.listener(value)}
    return records


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
            text += f'{label} IN {kind} {answer}\n'
    return text


def render(value):
    if not active(value):
        return {}
    from .service_plane import clients, NAMESPACE
    configuration = settings(value)
    endpoints = intent.service_addresses(value, 'authoritative')
    query_sources = sorted(set(a for client in clients(value, 'dns') for a in client['addresses']) |
                           set(intent.service_addresses(value, 'dns')) |
                           {a for w in writers(value).values() for s in writer_sources(value, w)
                            for a in s['addresses']})
    lines = ['options {', ' directory "/var/cache/bind";',
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
        addresses = [a for s in writer_sources(value, writer) for a in s['addresses']]
        # BIND nested ACL negative matches continue in the outer list. This
        # conjunction admits a writer only with its own source AND TSIG key.
        lines.append(f'acl "writer-{index}" {{ !{{ !{{ '+
                     ' '.join(a+';' for a in addresses)+
                     f' }}; any; }}; key "{writer["key_name"]}"; }};')
        credentials[writer['key_name']] = writer['credential']
    seeds, files = [], {}
    records = zone_records(value)
    for zone, entry in configuration['zones'].items():
        seed = 'usr/share/lanrith/zones/db.'+zone
        files[seed] = zone_text(value, zone, records[zone])
        persistent = entry.get('persistent', False)
        target = '/var/cache/bind/db.'+zone if persistent else '/'+seed
        if persistent:
            seeds.append({'source': '/'+seed, 'target': target})
        allowed = [f'"writer-{i}";' for i, w in enumerate(writers(value).values()) if w['zone'] == zone]
        transfers = [f'"writer-{i}";' for i, w in enumerate(writers(value).values())
                     if w['zone'] == zone and w.get('zone_transfer', False)]
        lines += [f'zone "{zone}" {{ type primary; file "{target}";',
                  ' allow-update { '+(' '.join(allowed) if allowed else 'none;')+' };',
                  ' allow-transfer { '+(' '.join(transfers) if transfers else 'none;')+' };',
                  '};']
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
        '[Service]\nNetworkNamespacePath=/run/netns/'+NAMESPACE+'\n')
    return files


def resolver_zones(value):
    if not active(value):
        return '', ''
    # ULA is always present inside the namespace, independent of client RA/GUA.
    target = intent.service_addresses(value, 'authoritative')[1]
    server = ''.join(f'  local-zone: "{zone}." transparent\n  domain-insecure: "{zone}."\n'
                     for zone in settings(value)['zones'])
    stubs = ''.join(f'stub-zone:\n  name: "{zone}."\n  stub-addr: {target}\n'
                    '  stub-first: no\n' for zone in settings(value)['zones'])
    return server, stubs
