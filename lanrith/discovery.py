"""Compile controlled LAN discovery, authoritative views and publication paths."""

import ipaddress as ip

from . import authoritative, dns64, integrations, intent, routing, translation
from .release import canonical, require


COLLECTOR = 'discovery-bridge-collector'
PUBLISHER = 'discovery-bridge-publisher'
DNS_USER = 'discovery-bridge-dns'
NATIVE_SOCKET = '/run/discovery-bridge-native/query.sock'


def _prefix_key(value):
    network = ip.ip_network(value)
    return network.version, int(network.network_address), network.prefixlen


def active(value):
    return value['services'].get('discovery', {}).get('enabled', False)


def _native_prefixes(network, *, additional=True):
    result = [str(ip.ip_interface(address).network) for address in network['addresses']]
    if additional:
        result += network.get('additional_subnets', [])
    return list(dict.fromkeys(result))


def _additional(value, key):
    return [ip.ip_network(prefix) for selector in value['services']['discovery'].get('additional_sources', [])
            for item in integrations.endpoints(value, selector) if item.get('network') == key
            for prefix in item['addresses']]


def _survivors(prefix, excluded):
    remaining = [prefix]
    for cut in excluded:
        if not prefix.overlaps(cut):
            continue
        remaining = [part for item in remaining if not item.subnet_of(cut)
                     for part in (item.address_exclude(cut) if cut.subnet_of(item) else [item])]
    return remaining


def _outermost(prefixes):
    roots = []
    for prefix in sorted(set(prefixes), key=lambda p: (p.version, p.prefixlen, int(p.network_address))):
        if not any(prefix.subnet_of(other) for other in roots if prefix.version == other.version):
            roots.append(prefix)
    return roots


def _source_ranges(value, key, excluded):
    configured = [ip.ip_network(raw) for raw in _native_prefixes(value['networks'][key], additional=False)]
    additional = _additional(value, key)
    declared = []
    for prefix in dict.fromkeys(configured + additional):
        if _survivors(prefix, excluded):
            declared.append(prefix)
        elif prefix in additional:
            covers = ', '.join(str(item) for item in excluded if prefix.overlaps(item))
            require(False, f'Discovery additional source {prefix} on {key} is wholly excluded by {covers}.')
    # IPv4 network and broadcast checks use the original subnet boundaries.
    # Native query selection and the firewall use their surviving CIDRs.
    require(declared, f'Discovery link {key} has no surviving source prefix.')
    effective = [part for prefix in _outermost(declared) for part in _survivors(prefix, excluded)]
    require(len(declared) <= 128 and len(effective) <= 128,
            f'Discovery link {key} exceeds 128 effective source prefixes.')
    return declared, effective


def _exclusions(value):
    return [ip.ip_network(raw) for raw in _forbidden(value, _publisher(value))]


def _view_prefixes(value, key):
    # These DNS delegations contain only source-qualified records from the collector.
    # Keep a containing delegation when an interior address is excluded.
    declared, _ = _source_ranges(value, key, _exclusions(value))
    aligned = []
    for prefix in _outermost(declared):
        width = 8 if prefix.version == 4 else 4
        extra_bits = -prefix.prefixlen % width
        require(len(aligned) + (1 << extra_bits) <= 8,
                f'Discovery DNS view {key} exceeds eight source reverse prefixes.')
        aligned.extend(prefix.subnets(prefixlen_diff=extra_bits))
    return [str(prefix) for prefix in aligned]


def selected(value):
    settings = value['services']['discovery']
    return [(key, value['networks'][key]) for key in settings['networks']]


def views(value):
    settings = value['services']['discovery']
    configured = settings.get('views') or {key: key for key in settings['networks']}
    default = settings.get('default_view', next(iter(configured)))
    return configured, default


def _publisher(value):
    publishers = value['services']['discovery'].get('external_publishers', {})
    require(len(publishers) <= 1,
            'The admitted discovery bridge supports one explicitly named external publisher.')
    if not publishers:
        return None
    name, settings = next(iter(publishers.items()))
    clients = sorted({str(prefix) for prefix in integrations.prefixes(value, settings['clients'])}, key=_prefix_key)
    sources = sorted({str(prefix) for prefix in integrations.prefixes(value, settings['addresses'])}, key=_prefix_key)
    families = {ip.ip_network(prefix).version for prefix in clients}
    require(len(families) == 1, 'A discovery publisher needs one client address family.')
    family = next(iter(families))
    network = value['networks'][settings['network']]
    reachable = [ip.ip_interface(address).network for address in network['addresses']]
    reachable += [ip.ip_network(prefix) for prefix in network.get('additional_subnets', [])]
    reachable += [ip.ip_network(prefix) for prefix in routing.routed_sources(value, settings['network'])]
    require(all(any(ip.ip_network(client).version == scope.version and
                        ip.ip_network(client).subnet_of(scope) for scope in reachable)
                for client in clients),
            'Discovery publisher clients must use their declared attachment or an admitted routed source.')
    hosts = [str(ip.ip_interface(address).ip) for address in network['addresses']
             if ip.ip_interface(address).version == family]
    require(hosts, 'A discovery publisher needs a gateway address in its client family.')
    return {'name': name, 'network': settings['network'], 'interface': network['name'],
            'host': hosts[0], 'clients': clients, 'sources': sources}


def _forbidden(value, publisher):
    settings = value['services']['discovery']
    selected_keys = set(settings['networks'])
    result = list(settings.get('exclude', []))
    for key, network in value['networks'].items():
        if key not in selected_keys and network.get('forwarding', True):
            result += _native_prefixes(network)
    if publisher:
        result += publisher['clients']
    for component in intent.translations(value).values():
        result += [component['prefix'], component['pool']]
    return list(dict.fromkeys(str(ip.ip_network(prefix)) for prefix in result))


def _translators(value, retained_allocations, access_backend):
    components = {item['interface']: item for item in translation.manifests(value, retained_allocations)}
    if 'nat46' not in components or 'nat64-internal' not in components:
        return None
    nat46, nat64 = components['nat46'], components['nat64-internal']
    return {
        'nat64_prefix': nat64['prefix'],
        'nat46_pool': nat46['pool'],
        'reserved': [nat46['ipv4']],
        'ip': ['/usr/sbin/ip'],
        'systemctl': ['/usr/bin/systemctl'],
        'nat46': {
            'interface': nat46['interface'], 'unit': nat46['unit'], 'config': nat46['config'],
            'binary': '/usr/lib/lanrith/tayga-internal' if access_backend == 'tun' else '/usr/sbin/tayga',
            'ipv4': nat46['ipv4'], 'ipv6': nat46['ipv6'],
            'prefix': nat46['prefix'], 'data_directory': '/var/lib/tayga-nat46',
        },
        'nat64': {
            'interface': nat64['interface'], 'unit': nat64['unit'], 'config': nat64['config'],
            'binary': '/usr/lib/lanrith/tayga-internal', 'ipv4': nat64['ipv4'], 'ipv6': nat64['ipv6'],
            'prefix': nat64['prefix'], 'data_directory': nat64['state_directory'],
            'dynamic_pool': nat64['pool'],
        },
    }


def router_manifest(value, retained_allocations=None, *, access_backend='tun'):
    settings = value['services']['discovery']
    publisher = _publisher(value)
    excluded = _exclusions(value)
    require(len(excluded) <= 128, 'Discovery supports up to 128 excluded prefixes.')
    sources = {network['name']: [str(p) for p in _source_ranges(value, key, excluded)[0]]
               for key, network in selected(value)}
    browse = sorted({kind.lower() for kind in settings.get('browse', [])})
    pairs = sum(len({ip.ip_network(prefix).version for prefix in prefixes}) for prefixes in sources.values())
    require(pairs <= 12, 'Discovery supports up to 12 selected interface/family pairs.')
    require(pairs * (1 + len(browse)) <= 512,
            'Discovery configured browse watches exceed the 512 permanent browser budget.')
    manifest = {
        'enabled': True,
        'interfaces': [{'interface': network['name'], 'source': network['name'],
                        'families': sorted({ip.ip_network(prefix).version for prefix in sources[network['name']]})}
                       for _, network in selected(value)],
        'sources': sources,
        'forbidden': [str(prefix) for prefix in excluded],
        'alias_prefix': settings['alias_prefix'],
        'state': '/var/lib/discovery-bridge/identities.db',
        'bus_socket': '/run/dbus/system_bus_socket',
        'publisher_socket': '/run/discovery-bridge/publisher.sock',
        'producer_user': COLLECTOR,
        'bootstrap': [{'name': kind+'.local.', 'type': 'PTR'} for kind in browse],
    }
    configured_views, _ = views(value)
    manifest['native'] = {'socket': NATIVE_SOCKET, 'user': DNS_USER,
                          'sources': [value['networks'][key]['name'] for key in configured_views.values()]}
    if publisher:
        manifest['sources'][publisher['name']] = publisher['sources']
        manifest['gateway'] = {'host': publisher['host'], 'port': 9443, 'clients': publisher['clients']}
        manifest['publication'] = {'host': publisher['host'], 'port': 9444,
                                   'clients': publisher['clients'], 'source': publisher['name']}
    translators = _translators(value, retained_allocations, access_backend)
    if translators:
        manifest['translators'] = translators
    return manifest


def direct_clients(value):
    readers = intent.sequence(value['services']['discovery'].get('direct_readers', []), 64)
    return authoritative.qualified_clients(value, readers)


def dns_manifest(value):
    settings = value['services']['discovery']
    configured_views, default = views(value)
    domain = settings['domain'].rstrip('.')+'.'
    # The pinned DNS frontend reserves local. for mDNS and arpa. for reverse mappings.
    require(not ('.'+domain.lower()).endswith(('.local.', '.arpa.')),
            'Discovery DNS requires a forward domain outside local. and arpa.')
    require(len(configured_views) <= 12 and len(set(configured_views.values())) == len(configured_views),
            'Discovery DNS supports up to 12 views with a distinct collected link for each.')
    links = []
    for name, key in configured_views.items():
        links.append({'source': value['networks'][key]['name'],
                      'service_domain': name+'.'+domain, 'host_domain': name+'.'+domain,
                      'prefixes': _view_prefixes(value, key)})
    reverse_scopes = [ip.ip_network(raw) for link in links for raw in link['prefixes']]
    require(not any(a.overlaps(b) for i, a in enumerate(reverse_scopes) for b in reverse_scopes[i+1:]),
            'Discovery DNS views require distinct source reverse delegations.')
    clients = {str(ip.ip_network(address)) for address in intent.service_addresses(value, 'dns')}
    clients.update(address for client in direct_clients(value) for address in client['addresses'])
    require(len(clients) <= 128, 'Discovery DNS supports up to 128 client prefixes.')
    return {
        'schema': 1, 'enabled': True,
        'listeners': [{'host': address, 'port': 53} for address in intent.service_addresses(value, 'discovery')],
        'clients': sorted(clients, key=_prefix_key),
        'native_socket': NATIVE_SOCKET, 'collector_user': COLLECTOR,
        'nameservers': ['discovery-proxy.'+domain],
        'mailbox': 'hostmaster.'+'.'.join(domain.split('.')[1:]),
        'default_source': value['networks'][configured_views[default]]['name'],
        'links': links,
    }


def reverse_zone(prefix):
    network = ip.ip_network(prefix)
    width = 8 if network.version == 4 else 4
    require(network.prefixlen % width == 0,
            'Discovery DNS views require octet- or nibble-aligned network prefixes.')
    labels = network.network_address.reverse_pointer.rstrip('.').split('.')
    keep = network.prefixlen // width
    return '.'.join(labels[(4 if network.version == 4 else 32)-keep:])+'.'


def browse_records(domain, view_names, default):
    domains = [name+'.'+domain for name in view_names]
    records = {'b._dns-sd._udp': domains}
    if default in view_names:
        records['db._dns-sd._udp'] = [default+'.'+domain]
    records['lb._dns-sd._udp'] = domains
    return records


def resolver_budget(value, *, private=False):
    # Both DNS64 instances can perform a native AAAA lookup followed by A.
    # The outer budget covers four native windows, with slack at the three boundaries.
    cold_ms = 6000
    margin_ms = 2000
    direct_ms = cold_ms + margin_ms
    chained = dns64.private_active(value) and not private
    upstream_ms = 4 * cold_ms + 3 * margin_ms if chained else direct_ms
    reply_ms = 2 * direct_ms if private else upstream_ms
    # Unbound may shorten the TCP deadline after a fast metadata reply unless
    # this RTT floor matches the 376ms unknown-server threshold.
    return ['  infra-cache-min-rtt: 376', f'  tcp-auth-query-timeout: {upstream_ms}',
            f'  discard-timeout: {reply_ms}']


def resolver_configuration(value, *, private=False):
    chained = dns64.private_active(value) and not private
    settings = value['services']['discovery']
    configured_views, default = views(value)
    domain = settings['domain'].rstrip('.')+'.'
    lines = ['server:', *resolver_budget(value, private=private)]
    if private:
        lines.append('  qname-minimisation: no')
    else:
        parents = {domain}
        dns = value['services']['dns']
        if dns.get('domain'):
            parents.add(dns['domain'].rstrip('.')+'.')
        authority = dns.get('authoritative', {})
        if authority.get('enabled') and authority.get('primary_zone'):
            parents.add(authority['primary_zone'].rstrip('.')+'.')
        for parent in sorted(parents):
            for owner, names in browse_records(domain, configured_views, default).items():
                name = owner+'.'+parent
                lines.append('  local-zone: "'+name+'" static')
                lines += ['  local-data: "'+name+' 10 IN PTR '+target+'"' for target in names]
    zones = []
    for name, key in configured_views.items():
        child = name+'.'+domain
        zones.append(child)
        if chained:
            lines.append(f'  private-domain: "{child}"')
        for prefix in _view_prefixes(value, key):
            reverse = reverse_zone(prefix)
            zones.append(reverse)
    targets = intent.service_addresses(value, 'discovery')
    for zone in zones:
        lines += [f'  local-zone: "{zone}" transparent', f'  domain-insecure: "{zone}"']
    kind = 'stub' if private else 'forward'
    if chained:
        loop = '::1' if value['uplink'].get('ipv4') == 'disabled' else '127.0.0.1'
        targets = [f'{loop}@{dns64.PORT}']
    for zone in zones:
        lines += [kind+'-zone:', f'  name: "{zone}"', *(f'  {kind}-addr: {target}' for target in targets),
                  f'  {kind}-first: no', f'  {kind}-tcp-upstream: yes']
        if private:
            lines.append('  stub-prime: no')
    return '\n'.join(lines)+'\n'


def avahi_bus_policy(value):
    # Debian includes /etc/dbus-1/system.d after both packages' policies.
    # Restrict method calls at each level with an inherited Avahi grant.
    destination = 'send_destination="org.freedesktop.Avahi" send_type="method_call"'
    deny = f'    <deny {destination}/>'
    lines = ['<busconfig>', '  <policy context="default">', deny, '  </policy>',
             '  <policy group="netdev">', deny, '  </policy>']
    methods = {
        'status': (),
        'browse': ('Server2.RecordBrowserPrepare', 'RecordBrowser.Start', 'RecordBrowser.Free'),
        'publish': ('Server.EntryGroupNew', 'EntryGroup.AddRecord', 'EntryGroup.Commit',
                    'EntryGroup.Reset', 'EntryGroup.Free'),
    }
    clients = {'root': 'status', COLLECTOR: 'browse', PUBLISHER: 'publish',
               **value['services']['discovery'].get('local_clients', {})}
    for user, role in sorted(clients.items()):
        lines += [f'  <policy user="{user}">', deny]
        for method in ('Server.GetState', *methods[role]):
            interface, member = method.split('.')
            lines.append(f'    <allow {destination} send_interface="org.freedesktop.Avahi.{interface}" '
                         f'send_member="{member}"/>')
        lines.append('  </policy>')
    return '\n'.join([*lines, '</busconfig>', ''])


def avahi_configuration(value):
    interfaces = ','.join(network['name'] for _, network in selected(value))
    return ('[server]\nuse-ipv4=yes\nuse-ipv6=yes\nenable-dbus=yes\n'
            'ratelimit-interval-usec=1000000\nratelimit-burst=1000\n'
            'entries-per-entry-group-max=4096\nallow-interfaces='+interfaces+'\n'
            '[wide-area]\nenable-wide-area=no\n[publish]\npublish-addresses=no\n'
            'publish-hinfo=no\npublish-workstation=no\npublish-domain=no\n'
            '[reflector]\nenable-reflector=no\n')


def firewall_rules(value, direction):
    """Return exact local mDNS and external publication admission rules."""
    from .firewall import values
    result = []
    if not active(value):
        return result
    excluded = _exclusions(value)
    for key, network in selected(value):
        _, effective = _source_ranges(value, key, excluded)
        interface = network['name']
        for family, spelling, multicast, ttl in ((4, 'ip', '224.0.0.251', 'ttl'),
                                                  (6, 'ip6', 'ff02::fb', 'hoplimit')):
            sources = [str(prefix) for prefix in effective if prefix.version == family]
            local = [str(ip.ip_interface(address).ip) for address in intent.gateway_addresses(network)
                     if any(ip.ip_interface(address).ip in prefix for prefix in effective if prefix.version == family)]
            if not sources:
                continue
            if family == 6:
                link_local = [str(prefix) for prefix in _survivors(ip.ip_network('fe80::/10'), excluded)]
                require(len(link_local) <= 128, f'Discovery link {key} exceeds 128 IPv6 link-local source prefixes.')
                sources.extend(link_local)
                local.extend(link_local)
            require(local, f'Discovery link {key} needs a surviving IPv{family} local address.')
            if direction == 'input':
                result.append(f'  iifname "{interface}" {spelling} saddr {values(sources)} '
                              f'{spelling} daddr {values([multicast, *local])} {spelling} {ttl} 255 '
                              'udp dport 5353 accept')
                if family == 4:
                    result.append(f'  iifname "{interface}" ip daddr 224.0.0.0/4 ip ttl 1 '
                                  'ip protocol igmp accept')
            else:
                result.append(f'  meta skuid {{ "{COLLECTOR}", "avahi" }} oifname "{interface}" '
                              f'{spelling} saddr {values(local)} {spelling} daddr '
                              f'{values([multicast, *sources])} {spelling} {ttl} 255 udp sport 5353 accept')
                # The publisher's raw UDP socket emits multicast announcements and goodbyes.
                link_sources = [str(ip.ip_interface(a).ip) for a in intent.gateway_addresses(network)
                                if ip.ip_interface(a).version == family]
                if family == 6:
                    link_sources.append('fe80::/10')
                result.append(f'  meta skuid "{PUBLISHER}" oifname "{interface}" fib saddr type local '
                              f'{spelling} saddr {values(link_sources)} {spelling} daddr {multicast} {spelling} {ttl} 255 '
                              'udp sport 5353 udp dport 5353 accept')
    publisher = _publisher(value)
    if direction == 'input' and publisher:
        family = ip.ip_address(publisher['host']).version
        spelling = 'ip' if family == 4 else 'ip6'
        result.append(f'  iifname "{publisher["interface"]}" {spelling} saddr {values(publisher["clients"])} '
                      f'{spelling} daddr {publisher["host"]} tcp dport {{ 9443, 9444 }} accept')
    return result


def render(value, retained_allocations=None, *, access_backend='tun'):
    if not active(value):
        return {}
    router = router_manifest(value, retained_allocations, access_backend=access_backend)
    dns = dns_manifest(value)
    interfaces = ' '.join('--interface='+network['name']+':routable' for _, network in selected(value))
    collector_after = ['avahi-daemon.service', 'nftables.service', 'systemd-networkd.service']
    if router.get('translators'):
        collector_after += [router['translators'][name]['unit'] for name in ('nat46', 'nat64')]
    collector = ('[Unit]\nRequires=avahi-daemon.service nftables.service systemd-networkd.service\n'
                 'After='+' '.join(collector_after)+'\nBindsTo=nftables.service\n'
                 '[Service]\nExecStartPre=/usr/lib/systemd/systemd-networkd-wait-online '+interfaces+' --timeout=90\n')
    dns_clients = dns['clients']
    dns_unit = ('[Unit]\nRequires=lanrith-services.service discovery-bridge-collector.service\n'
                'After=lanrith-services.service discovery-bridge-collector.service\n'
                'BindsTo=lanrith-services.service nftables.service\n[Service]\n'
                'NetworkNamespacePath=/run/netns/lanrith-services\nIPAddressDeny=any\n'+
                ''.join('IPAddressAllow='+prefix+'\n' for prefix in dns_clients))
    files = {
        'etc/discovery-bridge/router.json': canonical(router).decode(),
        'etc/discovery-bridge/dns.json': canonical(dns).decode(),
        'etc/avahi/avahi-daemon.conf': avahi_configuration(value),
        'etc/dbus-1/system.d/lanrith-avahi.conf': avahi_bus_policy(value),
        # Type=dbus orders Avahi against the socket, not the bus daemon.
        # Keep the bus alive until Avahi and its ordered consumers have stopped.
        'etc/systemd/system/avahi-daemon.service.d/60-lanrith.conf': (
            '[Unit]\nRequires=dbus.service\nAfter=dbus.service\n'),
        'etc/unbound/unbound.conf.d/61-lanrith-discovery.conf': resolver_configuration(value),
        'etc/systemd/system/discovery-bridge-collector.service.d/60-lanrith.conf': collector,
        'etc/systemd/system/discovery-bridge-publisher.service.d/60-lanrith.conf': (
            '[Unit]\nRequires=avahi-daemon.service nftables.service systemd-networkd.service\n'
            'After=avahi-daemon.service nftables.service systemd-networkd.service\nBindsTo=nftables.service\n'),
        'etc/systemd/system/discovery-bridge-dns.service.d/60-lanrith.conf': dns_unit,
    }
    if router.get('translators', {}).get('nat46'):
        files['usr/lib/tmpfiles.d/80-lanrith-discovery.conf'] = 'd /var/lib/tayga-nat46 0750 root root -\n'
    return files
