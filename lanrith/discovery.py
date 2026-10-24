"""Compile controlled LAN discovery, authoritative views and publication paths."""

import ipaddress as ip

from . import integrations, intent, routing, translation
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


def _discovery_prefixes(value, key):
    result = _native_prefixes(value['networks'][key], additional=False)
    for selector in value['services']['discovery'].get('additional_sources', []):
        for item in integrations.endpoints(value, selector):
            if item.get('network') == key:
                result += item['addresses']
    return list(dict.fromkeys(str(ip.ip_network(prefix)) for prefix in result))


def _discovery_gateways(value, key):
    network = value['networks'][key]
    result = list(network['addresses'])
    native = set(_native_prefixes(network, additional=False))
    for prefix in _discovery_prefixes(value, key):
        if prefix not in native:
            parsed = ip.ip_network(prefix)
            result.append(str(parsed.network_address+1)+'/'+str(parsed.prefixlen))
    return result


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


def _translators(value, retained_allocations):
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
            'binary': '/usr/sbin/tayga', 'ipv4': nat46['ipv4'], 'ipv6': nat46['ipv6'],
            'prefix': nat46['prefix'], 'data_directory': '/var/lib/tayga-nat46',
        },
        'nat64': {
            'interface': nat64['interface'], 'unit': nat64['unit'], 'config': nat64['config'],
            'binary': '/usr/lib/lanrith/tayga-internal', 'ipv4': nat64['ipv4'], 'ipv6': nat64['ipv6'],
            'prefix': nat64['prefix'], 'data_directory': nat64['state_directory'],
            'dynamic_pool': nat64['pool'],
        },
    }


def router_manifest(value, retained_allocations=None):
    settings = value['services']['discovery']
    publisher = _publisher(value)
    sources = {network['name']: _discovery_prefixes(value, key) for key, network in selected(value)}
    manifest = {
        'enabled': True,
        'interfaces': [{'interface': network['name'], 'source': network['name'],
                        'families': sorted({ip.ip_network(prefix).version for prefix in sources[network['name']]})}
                       for _, network in selected(value)],
        'sources': sources,
        'forbidden': _forbidden(value, publisher),
        'alias_prefix': settings['alias_prefix'],
        'state': '/var/lib/discovery-bridge/identities.db',
        'bus_socket': '/run/dbus/system_bus_socket',
        'publisher_socket': '/run/discovery-bridge/publisher.sock',
        'producer_user': COLLECTOR,
        'bootstrap': [{'name': kind+'.local.', 'type': 'PTR'} for kind in settings.get('browse', [])],
    }
    configured_views, _ = views(value)
    manifest['native'] = {'socket': NATIVE_SOCKET, 'user': DNS_USER,
                          'sources': [value['networks'][key]['name'] for key in configured_views.values()]}
    if publisher:
        manifest['sources'][publisher['name']] = publisher['sources']
        manifest['gateway'] = {'host': publisher['host'], 'port': 9443, 'clients': publisher['clients']}
        manifest['publication'] = {'host': publisher['host'], 'port': 9444,
                                   'clients': publisher['clients'], 'source': publisher['name']}
    translators = _translators(value, retained_allocations)
    if translators:
        manifest['translators'] = translators
    return manifest


def dns_manifest(value):
    settings = value['services']['discovery']
    configured_views, default = views(value)
    domain = settings['domain'].rstrip('.')+'.'
    links = []
    for name, key in configured_views.items():
        links.append({'source': value['networks'][key]['name'],
                      'service_domain': name+'.'+domain, 'host_domain': name+'.'+domain,
                      'prefixes': _native_prefixes(value['networks'][key], additional=False)})
    clients = {'127.0.0.0/8', '::1/128', *(str(prefix) for prefix in intent.service_networks(value))}
    for key, network in value['networks'].items():
        if not network.get('forwarding', True):
            continue
        clients.update(_native_prefixes(network))
        clients.update(routing.routed_sources(value, key))
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


def resolver_configuration(value):
    settings = value['services']['discovery']
    configured_views, default = views(value)
    domain = settings['domain'].rstrip('.')+'.'
    parents = {domain}
    dns = value['services']['dns']
    if dns.get('domain'):
        parents.add(dns['domain'].rstrip('.')+'.')
    authoritative = dns.get('authoritative', {})
    if authoritative.get('enabled') and authoritative.get('primary_zone'):
        parents.add(authoritative['primary_zone'].rstrip('.')+'.')
    lines = ['server:']
    domains = [name+'.'+domain for name in configured_views]
    for parent in sorted(parents):
        for owner, names in (('b._dns-sd._udp.', domains),
                             ('db._dns-sd._udp.', [default+'.'+domain]),
                             ('lb._dns-sd._udp.', domains)):
            lines.append('  local-zone: "'+owner+parent+'" static')
            lines += ['  local-data: "'+owner+parent+' 10 IN PTR '+target+'"' for target in names]
    zones = []
    for name, key in configured_views.items():
        child = name+'.'+domain
        lines.append('  local-zone: "'+child+'" transparent')
        zones.append(child)
        for prefix in _native_prefixes(value['networks'][key], additional=False):
            reverse = reverse_zone(prefix)
            lines.append('  local-zone: "'+reverse+'" transparent')
            zones.append(reverse)
    targets = intent.service_addresses(value, 'discovery')
    for zone in zones:
        lines += ['forward-zone:', '  name: "'+zone+'"',
                  *('  forward-addr: '+target for target in targets),
                  '  forward-first: no', '  forward-tcp-upstream: yes']
    return '\n'.join(lines)+'\n'


def avahi_configuration(value):
    interfaces = ','.join(network['name'] for _, network in selected(value))
    return ('[server]\nuse-ipv4=yes\nuse-ipv6=yes\nenable-dbus=yes\n'
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
    for key, network in selected(value):
        interface = network['name']
        for family, spelling, multicast, ttl in ((4, 'ip', '224.0.0.251', 'ttl'),
                                                  (6, 'ip6', 'ff02::fb', 'hoplimit')):
            sources = [prefix for prefix in _discovery_prefixes(value, key)
                       if ip.ip_network(prefix).version == family]
            local = [str(ip.ip_interface(address).ip) for address in _discovery_gateways(value, key)
                     if ip.ip_interface(address).version == family]
            if not sources or not local:
                continue
            if family == 6:
                sources.append('fe80::/10')
                local.append('fe80::/10')
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
    publisher = _publisher(value)
    if direction == 'input' and publisher:
        family = ip.ip_address(publisher['host']).version
        spelling = 'ip' if family == 4 else 'ip6'
        result.append(f'  iifname "{publisher["interface"]}" {spelling} saddr {values(publisher["clients"])} '
                      f'{spelling} daddr {publisher["host"]} tcp dport {{ 9443, 9444 }} accept')
    return result


def render(value, retained_allocations=None):
    if not active(value):
        return {}
    router = router_manifest(value, retained_allocations)
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
