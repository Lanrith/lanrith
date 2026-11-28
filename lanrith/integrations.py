"""Typed optional integration contracts and cross-component references."""

import hashlib
import ipaddress as ip
from pathlib import PurePosixPath
import re
from urllib.parse import urlsplit

from . import bindings, directory_settings, intent
from .release import ReleaseError, canonical, require


def text(value, maximum=512):
    require(isinstance(value, str) and 0 < len(value) <= maximum and value.isprintable(),
            'Invalid integration text.')
    return value


def domain(value):
    text(value, 253)
    require(all(re.fullmatch(r'[a-zA-Z0-9_](?:[a-zA-Z0-9_-]{0,61}[a-zA-Z0-9_])?', label)
                for label in value.rstrip('.').split('.')), 'Invalid DNS name.')
    return value


def zone_owner(label, zone):
    """Return an absolute lowercase owner for a relative label or the apex."""
    if label == '@':
        return zone.lower()+'.'
    domain(label)
    require(not label.endswith('.') and len(label+'.'+zone) <= 253,
            'Zone records must use relative in-zone labels.')
    return (label+'.'+zone+'.').lower()


def credential(value):
    require(isinstance(value, str) and intent.NAME.fullmatch(value), 'Invalid credential reference.')


def integer(value, low, high):
    require(type(value) is int and low <= value <= high, 'Invalid integration integer.')


def enabled(settings):
    require(isinstance(settings, dict), 'Invalid integration settings.')
    return intent.boolean(settings.get('enabled', False))


def selected_network(value, key):
    require(isinstance(key, str) and key in value['networks'] and
            value['networks'][key].get('forwarding', True), 'Integration requires an ordinary LAN network.')
    return value['networks'][key]


def endpoints(value, selector):
    from . import access
    resolved = intent.expand(value, selector)
    for item in resolved:
        access.selector(item, value['networks'], value['hardware']['interfaces'], value['uplink'], source=True)
    return resolved


def prefixes(value, selector):
    result = endpoints(value, selector)
    require(result and all(set(item) == {'addresses'} for item in result),
            'This integration needs unqualified address groups.')
    return [ip.ip_network(a) for item in result for a in item['addresses']]


def routing(value):
    settings = value.get('routing', {})
    intent.fields(settings, {'static_routes', 'bgp', 'asymmetric_replies'})
    for route in intent.sequence(settings.get('static_routes', [])):
        intent.fields(route, {'to', 'network', 'on_link'}, {'to', 'network', 'on_link'})
        selected_network(value, route['network'])
        require(intent.boolean(route['on_link']), 'Static routes must explicitly declare on-link delivery.')
        prefixes(value, route['to'])
    bgp = settings.get('bgp', {})
    intent.fields(bgp, {'enabled', 'asn', 'network', 'peer_groups', 'import_ownership'})
    active = enabled(bgp)
    if active:
        integer(bgp.get('asn'), 1, 4294967294)
        selected_network(value, bgp.get('network'))
    seen = set()
    for group in intent.named(bgp.get('peer_groups', {}), 64).values():
        intent.fields(group, {'remote_asn', 'network', 'import', 'maximum_prefixes', 'peers', 'dynamic',
                              'credential', 'hold_seconds', 'services'}, {'remote_asn', 'import'})
        integer(group['remote_asn'], 1, 4294967294)
        selected = selected_network(value, group.get('network', bgp.get('network')))
        for clause in intent.sequence(group['import'], 64, 1):
            intent.fields(clause, {'group', 'prefix_length', 'exact', 'purpose', 'reply_mode', 'fallback'},
                          {'group', 'purpose'})
            require(clause.get('fallback', 'routing_table') in ('routing_table', 'bgp_only'),
                    'Unknown BGP import fallback.')
            require(clause['purpose'] in ('network', 'service'), 'Unknown route purpose.')
            require(('prefix_length' in clause) != ('exact' in clause), 'Specify exact imports or a prefix length.')
            if 'exact' in clause:
                require(intent.boolean(clause['exact']), 'Exact imports cannot be false.')
            for prefix in prefixes(value, {'group': clause['group']}):
                require(prefix.prefixlen > 0, 'Default route imports are prohibited.')
                if 'prefix_length' in clause:
                    integer(clause['prefix_length'], prefix.prefixlen, prefix.max_prefixlen)
                if 'reply_mode' in clause:
                    require(clause['reply_mode'] == 'dsr' and clause['purpose'] == 'service' and
                            prefix.version == 6 and clause.get('prefix_length', prefix.prefixlen) == 128,
                            'DSR is limited to imported IPv6 service host routes.')
        integer(group.get('maximum_prefixes', 65), 1, 65536)
        hold = group.get('hold_seconds', 90)
        integer(hold, 3, 65535)
        require(hold % 3 == 0, 'BGP hold time must support the one-third keepalive interval.')
        if 'credential' in group:
            credential(group['credential'])
        for a in intent.named(group.get('peers', {}), 256).values():
            peer = intent.address(a)
            require(peer not in seen and any(peer in ip.ip_interface(p).network for p in selected['addresses']) and
                    all(peer != ip.ip_interface(p).ip for p in intent.gateway_addresses(selected)),
                    'Duplicate BGP peer or peer outside its attachment network.')
            seen.add(peer)
        dynamic = group.get('dynamic', {})
        intent.fields(dynamic, {'enabled', 'range', 'maximum_peers'})
        if enabled(dynamic):
            require('credential' in group, 'Dynamic BGP peers require authentication.')
            scope = intent.network(dynamic.get('range'))
            require(any(scope.version == ip.ip_interface(p).version and scope.subnet_of(ip.ip_interface(p).network)
                        for p in selected['addresses']), 'Dynamic BGP range is outside its network.')
            require(not any(ip.ip_interface(p).ip in scope for p in intent.gateway_addresses(selected)) and
                    not any(peer in scope for peer in seen), 'Dynamic BGP range includes a router or pinned peer.')
            integer(dynamic.get('maximum_peers'), 1, 256)
        for service in intent.sequence(group.get('services', []), 2):
            require(service in ('dns', 'ntp') and value['services'][service]['enabled'],
                    'BGP peer service references a disabled or unknown component.')
    for entry in intent.sequence(settings.get('asymmetric_replies', []), 64):
        intent.fields(entry, {'name', 'mode', 'from', 'to'}, {'mode', 'from', 'to'})
        if 'name' in entry:
            text(entry['name'], 96)
        require(entry['mode'] in ('tcp_dsr', 'icmp_echo_reply'), 'Unsupported asymmetric reply mode.')
        for key in ('from', 'to'):
            resolved = endpoints(value, entry[key])
            require(all('network' in item and 'addresses' in item and
                        all(ip.ip_network(a).version == 6 for a in item['addresses']) for item in resolved),
                    'Asymmetric replies require explicit IPv6 addresses and attachment networks.')


def dns_records(value):
    """Resolve address references once, sharing aliases with packet translation."""
    dns = value['services']['dns']
    authoritative = dns.get('authoritative', {})
    intent.fields(authoritative, {'enabled', 'primary_zone', 'writers', 'direct_readers', 'zones'})
    active = enabled(authoritative) and dns['enabled']
    if active:
        domain(authoritative.get('primary_zone'))
    zones = authoritative.get('zones', {})
    require(isinstance(zones, dict) and len(zones) <= 64, 'Invalid authoritative zones.')
    if active:
        require(authoritative['primary_zone'] in zones, 'Primary zone is not declared.')
    result = {}
    for zone, settings in zones.items():
        domain(zone)
        intent.fields(settings, {'persistent', 'records', 'records_from', 'fixed_records', 'managed_rrsets', 'discovery_delegation'})
        intent.boolean(settings.get('persistent', False))
        records = settings.get('records', {})
        require(isinstance(records, dict), 'Invalid DNS records.')
        resolved = {}
        for label, rr in records.items():
            zone_owner(label, zone)
            intent.fields(rr, {'A', 'AAAA', 'CNAME'})
            require(rr and not ('CNAME' in rr and (len(rr) != 1 or label == '@')),
                    'CNAME conflicts with address records or zone apex authority.')
            resolved[label] = {}
            for kind, entry in rr.items():
                if kind == 'CNAME':
                    domain(entry)
                    require(entry.endswith('.'), 'CNAME target must be absolute.')
                    answer = entry
                elif isinstance(entry, dict):
                    intent.fields(entry, {'alias', 'network'})
                    require(len(entry) == 1, 'Ambiguous DNS address reference.')
                    family = 4 if kind == 'A' else 6
                    if 'alias' in entry:
                        maps = intent.translations(value).get('nat46', {}).get('mappings', {})
                        require(isinstance(entry['alias'], str) and entry['alias'] in maps,
                                'DNS references unknown alias or disabled NAT46.')
                        answer = maps[entry['alias']]['ipv'+str(family)]
                    else:
                        require(isinstance(entry['network'], str) and entry['network'] in value['networks'],
                                'DNS references an unknown network.')
                        addresses = [ip.ip_interface(a).ip for a in value['networks'][entry['network']]['addresses']
                                     if ip.ip_interface(a).version == family]
                        require(len(addresses) == 1, 'DNS network reference needs one unambiguous address.')
                        answer = str(addresses[0])
                else:
                    answer = str(intent.address(entry, 4 if kind == 'A' else 6))
                resolved[label][kind] = answer
        for source in intent.sequence(settings.get('records_from', []), 64):
            intent.fields(source, {'bgp_peers', 'suffix'}, {'bgp_peers', 'suffix'})
            domain(source['suffix'])
            bgp = value.get('routing', {}).get('bgp', {})
            require(enabled(bgp) and source['bgp_peers'] in bgp.get('peer_groups', {}),
                    'DNS references disabled or unknown BGP peers.')
            for name, target in bgp['peer_groups'][source['bgp_peers']].get('peers', {}).items():
                label = name+'.'+source['suffix']
                require(label not in resolved, 'Generated DNS record conflicts with an explicit record.')
                resolved[label] = {'AAAA' if intent.address(target).version == 6 else 'A': target}
        result[zone] = resolved
    for writer in intent.named(authoritative.get('writers', {}), 64).values():
        intent.fields(writer, {'zone', 'sources', 'key_name', 'credential', 'zone_transfer', 'grants'},
                      {'zone', 'sources', 'key_name', 'credential'})
        require(writer['zone'] in zones, 'DNS writer references an undeclared zone.')
        grants = writer.get('grants', [])
        require(isinstance(grants, list), 'DNS writer grants must be a list.')
        require(not active or 'grants' not in writer or grants or writer.get('zone_transfer') is True,
                'DNS writer needs grants or transfer access.')
        for grant in grants:
            intent.fields(grant, {'name', 'subtree', 'types'}, {'types'})
            require(('name' in grant) != ('subtree' in grant), 'DNS grant requires one name or subtree.')
            owner = grant.get('name', grant.get('subtree'))
            if owner != '@':
                domain(owner)
                require(not owner.endswith('.') and len(owner+'.'+writer['zone']) <= 253,
                        'DNS grant requires an in-zone relative owner.')
            kinds = intent.sequence(grant['types'], 16, 1)
            require(all(kind in ('A', 'AAAA', 'CAA', 'CNAME', 'HTTPS', 'MX', 'NAPTR', 'NS', 'PTR',
                                 'SRV', 'SVCB', 'TLSA', 'TXT') for kind in kinds) and
                    len(set(kinds)) == len(kinds), 'Invalid or duplicate DNS grant type.')
        endpoints(value, writer['sources'])
        domain(writer['key_name'])
        require(not writer['key_name'].endswith('..'), 'Invalid DNS writer key name.')
        credential(writer['credential'])
        intent.boolean(writer.get('zone_transfer', False))
    return result


def validate_admission_binding(radius, directory, vlan):
    admission = radius['admission']
    provider = admission.get('provider_policy')
    require(isinstance(provider, dict), 'Directory admission requires a trusted provider policy export.')
    intent.fields(provider, {'provider', 'revision', 'binding_sha256'}, {'provider', 'revision', 'binding_sha256'})
    text(provider['provider'], 128)
    require(isinstance(provider['revision'], str) and re.fullmatch(r'[0-9a-f]{64}', provider['revision']),
            'Directory admission requires an immutable provider policy revision (SHA-256).')
    # Independently pinned by the release owner from the provider's effective flow.
    # The declaration supplies expected values; it must never synthesize the pin.
    binding = {'schema': 1, 'provider': provider['provider'], 'revision': provider['revision'],
               'endpoint': str(intent.address(radius['proxy']['address'])),
               'directory': admission['directory'], 'directory_url': directory['url'],
               'directory_base_dn': directory['base_dn'], 'group_dn': admission['group_dn'], 'vlan': vlan}
    require(hashlib.sha256(canonical(binding)).hexdigest() == provider['binding_sha256'],
            'RADIUS admission differs from the trusted provider policy binding.')


def identity(value):
    from . import routing as routing_model

    identity = value.get('identity', {})
    intent.fields(identity, {'directories', 'radius', 'policy'})
    directories = intent.named(identity.get('directories', {}), 16)
    for name, directory in directories.items():
        intent.fields(directory, {'enabled', 'url', 'addresses', 'base_dn', 'bind_dn', 'credential', 'ca_file',
                                  'source_service', 'search_mode', 'mapping'},
                      {'url', 'base_dn', 'bind_dn', 'credential', 'ca_file'})
        if 'source_service' in directory:
            radius = identity.get('radius', {})
            require(directory['source_service'] == 'radius' and isinstance(radius, dict) and
                    radius.get('enabled') is True and isinstance(radius.get('admission'), dict) and
                    radius['admission'].get('directory') == name,
                    'A directory source service must be an enabled RADIUS service using that directory.')
        enabled(directory)
        url = urlsplit(text(directory['url']))
        require(url.scheme in ('ldap+starttls', 'ldaps') and url.hostname and not url.username and
                not url.password and not url.query and not url.fragment and url.path in ('', '/'),
                'Directory requires verified StartTLS or LDAPS without embedded credentials.')
        integer(url.port if url.port is not None else (636 if url.scheme == 'ldaps' else 389), 1, 65535)
        from .directory_config import endpoint
        endpoint(directory)
        try:
            directory_settings.reader_options(directory)
        except ValueError as error:
            raise ReleaseError(str(error)) from error
        text(directory['base_dn'])
        text(directory['bind_dn'])
        credential(directory['credential'])
        path = PurePosixPath(text(directory['ca_file']))
        require(not path.is_absolute() and path.parts[0] == 'trust' and '..' not in path.parts and
                re.fullmatch(r'trust/[a-zA-Z0-9_.-]+\.pem', str(path)), 'CA must reference a protected trust file.')

    def directory_reference(key):
        require(isinstance(key, str) and key in directories and enabled(directories[key]),
                'Integration references an unknown or disabled directory.')

    policy = identity.get('policy', {})
    intent.fields(policy, {'enabled', 'directory', 'networks'})
    if enabled(policy):
        directory_reference(policy.get('directory'))
        for key in intent.sequence(policy.get('networks'), 64, 1):
            selected_network(value, key)
    if any(rule.get('authorization') == 'directory' for rule in value.get('access', {}).get('rules', [])):
        require(enabled(policy), 'Directory-authorized rules require an enabled identity policy.')
    radius = identity.get('radius', {})
    intent.fields(radius, {'enabled', 'network', 'clients', 'admission', 'proxy', 'fallback'})
    if enabled(radius):
        radius_network = selected_network(value, radius.get('network'))
        admission = radius.get('admission')
        intent.fields(admission, {'directory', 'group_dn', 'network', 'provider_policy'}, {'network'})
        admitted = selected_network(value, admission['network'])
        require(('directory' in admission) == ('group_dn' in admission),
                'Directory admission requires both a directory and group DN.')
        require('provider_policy' not in admission or 'directory' in admission,
                'A provider policy export requires directory admission.')
        if 'directory' in admission:
            directory_reference(admission['directory'])
            text(admission['group_dn'])
            require(enabled(policy) and policy['directory'] == admission['directory'] and
                    admission['network'] in policy.get('networks', []),
                    'RADIUS directory admission requires its selected identity policy.')
            require('dhcp4' in admitted and any(ip.ip_interface(a).version == 4 for a in admitted['addresses']),
                    'RADIUS directory admission requires a DHCPv4 network.')
        require(1 <= admitted.get('vlan', 0) <= 4094, 'RADIUS admission requires a tagged network.')
        require('proxy' in radius, 'The RADIUS MAC proxy backend requires an upstream proxy.')
    clients = intent.named(radius.get('clients', {}), 64)
    require(not enabled(radius) or bool(clients), 'RADIUS requires at least one configured NAS client.')
    for client in clients.values():
        intent.fields(client, {'address', 'kind', 'port', 'transport', 'credential'}, {'address', 'kind'})
        intent.network(client['address'])
        require(client['kind'] in ('wired_mab', 'wireless_mac'), 'Unknown RADIUS client kind.')
        require(client.get('transport', 'udp') == 'udp', 'The RADIUS MAC backend currently supports UDP transport.')
        require('credential' in client, 'A RADIUS UDP NAS client requires a shared-secret credential reference.')
        credential(client['credential'])
        if 'port' in client:
            integer(client['port'], 1, 65535)
        if enabled(radius):
            scope = intent.network(client['address'])
            attachments = [ip.ip_interface(a).network for a in radius_network['addresses']]
            attachments += [ip.ip_network(a) for a in radius_network.get('additional_subnets', [])]
            attachments += [ip.ip_network(a) for a in radius_network.get('routed_prefixes', [])]
            attachments += [ip.ip_network(a) for a in routing_model.routed_sources(value, radius['network'])]
            require(any(scope.version == attached.version and scope.subnet_of(attached) for attached in attachments),
                    'RADIUS client is outside its declared attachment network.')
    if 'proxy' in radius:
        proxy = radius['proxy']
        intent.fields(proxy, {'address', 'transport', 'credential'}, {'address'})
        intent.address(proxy['address'])
        require(proxy.get('transport', 'udp') == 'udp', 'The RADIUS MAC backend currently supports UDP transport.')
        require('credential' in proxy, 'A RADIUS UDP proxy requires a shared-secret credential reference.')
        credential(proxy['credential'])
        if enabled(radius):
            target = intent.address(proxy['address'])
            attachments = [ip.ip_interface(a).network for a in radius_network['addresses']]
            attachments += [ip.ip_network(a) for a in radius_network.get('additional_subnets', [])]
            attachments += [ip.ip_network(a) for a in radius_network.get('routed_prefixes', [])]
            attachments += [ip.ip_network(a) for a in routing_model.routed_sources(value, radius['network'])]
            require(any(target.version == attached.version and target in attached for attached in attachments),
                    'RADIUS proxy is outside its declared attachment network.')
    if enabled(radius) and 'directory' in admission:
        validate_admission_binding(radius, directories[admission['directory']], admitted['vlan'])
    fallback = radius.get('fallback', {})
    intent.fields(fallback, {'enabled', 'clients', 'provider_response_seconds', 'nas_retry_seconds'})
    if enabled(fallback) and enabled(radius):
        response = fallback.get('provider_response_seconds')
        retry = fallback.get('nas_retry_seconds')
        require(type(response) is int and 1 <= response <= 26 and
                type(retry) is int and response + 3 <= retry <= 120,
                'RADIUS fallback requires a qualified provider response bound and compatible NAS retry interval.')
        for key in intent.sequence(fallback.get('clients'), 64, 1):
            require(key in clients and clients[key]['kind'] == 'wired_mab' and 'port' in clients[key] and
                    intent.network(clients[key]['address']).num_addresses == 1,
                    'Outage fallback requires an exact wired NAS and port.')


def validate_dns_forwarding(value):
    dns = value['services']['dns']
    upstreams = []
    if 'tls_forwarding' in dns:
        tls = dns['tls_forwarding']
        intent.fields(tls, {'trust', 'upstreams'}, {'trust', 'upstreams'})
        require(dns['enabled'] and 'upstreams' not in dns and tls['trust'] == 'system',
                'TLS forwarding requires an enabled resolver, system trust and no plain upstreams.')
        for peer in intent.sequence(tls['upstreams'], 16, 1):
            intent.fields(peer, {'address', 'authentication_name'}, {'address', 'authentication_name'})
            addr = intent.address(peer['address'])
            name = domain(peer['authentication_name']).removesuffix('.')
            require(not addr.is_link_local and '_' not in name and not name.endswith('.') and
                    not name.rsplit('.', 1)[-1].isdigit(),
                    'TLS forwarding requires a routed address and certificate DNS name.')
            upstreams.append(addr)
    else:
        upstreams = [intent.address(raw) for raw in intent.sequence(dns.get('upstreams', []), 16)]
    if upstreams:
        require(any(value['uplink'].get('ipv'+str(addr.version)) != 'disabled' for addr in upstreams),
                'DNS forwarding requires an upstream on an enabled address family.')


def validate_ntp(value):
    settings = value['services']['ntp']
    sources = intent.ntp_upstreams(value)
    require(not settings['enabled'] or sources, 'Enabled NTP requires explicit site upstreams.')
    bootstrap = False
    total = 0
    for source in sources:
        intent.fields(source, {'type', 'address', 'family', 'maxsources'}, {'type', 'address'})
        kind, host = source['type'], source['address']
        require(kind in ('pool', 'server'), 'NTP source type must be pool or server.')
        family = source.get('family')
        require('family' not in source or family in ('ipv4', 'ipv6'), 'Invalid NTP address family.')
        require(isinstance(host, str), 'Invalid NTP source address.')
        try:
            literal = ip.ip_address(host)
        except ValueError:
            domain(host)
            require(not re.fullmatch(r'[0-9.]+', host) and not host.endswith('..'), 'Invalid NTP hostname.')
            literal = None
        else:
            intent.address(host)
            require(not literal.is_link_local and family in (None, 'ipv'+str(literal.version)),
                    'NTP address must be routable and match its declared family.')
            if value['uplink'].get('ipv'+str(literal.version)) != 'disabled':
                bootstrap = True
        if 'maxsources' in source:
            require(kind == 'pool', 'NTP maxsources applies only to pools.')
            integer(source['maxsources'], 1, 1 if literal else 16)
        total += 1 if kind == 'server' or literal else source.get('maxsources', 4)
    if 'total_sources' in settings:
        integer(settings['total_sources'], 1, 256)
        require(total == settings['total_sources'], 'NTP total_sources must equal the configured member targets.')
    require(not intent.boolean(settings.get('require_numeric_source', False)) or bootstrap,
            'DNS-independent NTP bootstrap requires a numeric site upstream on an enabled uplink family.')
    if 'ratelimit' in settings:
        limits = settings['ratelimit']
        ranges = {'interval': (-19, 12), 'burst': (1, 255), 'leak': (1, 4)}
        intent.fields(limits, ranges)
        for key, number in limits.items():
            integer(number, *ranges[key])


def validate(value):
    for key, group in intent.named(value.get('groups', {})).items():
        intent.sequence(group, 256, 1)
        endpoints(value, {'group': key})
    routing(value)
    from .routing import validate as validate_routes
    validate_routes(value)
    identity(value)
    validate_dns_forwarding(value)
    validate_ntp(value)
    dns = value['services']['dns']
    if 'domain' in dns:
        domain(dns['domain'])
    for blocked in intent.sequence(dns.get('blocked_domains', []), 1024):
        domain(blocked)
    dns_records(value)
    if 'private_dns64_startup' in dns:
        from . import dns64
        require(dns64.private_active(value) and dns['private_dns64_startup'] in ('required', 'independent'),
                'Select required or independent startup for an enabled private DNS64 handler.')
    discovery = value['services'].get('discovery', {})
    clients = discovery.get('local_clients', {})
    require(isinstance(clients, dict) and len(clients) <= 64 and
            all(isinstance(name, str) and bindings.ACCOUNT.fullmatch(name) and
                name not in ('root', 'avahi', 'discovery-bridge-collector', 'discovery-bridge-publisher') and
                role in ('status', 'browse', 'publish') for name, role in clients.items()),
            'Local Avahi clients require distinct Unix accounts and a status, browse or publish role.')
    if 'configuration' not in discovery:
        intent.fields(discovery, {'enabled', 'domain', 'alias_prefix', 'networks', 'additional_sources', 'browse',
                                  'external_publishers', 'exclude', 'views', 'default_view', 'direct_readers', 'local_clients'})
        if enabled(discovery):
            require(value['services']['dns']['enabled'], 'Discovery DNS requires the generated DNS service.')
            domain(discovery.get('domain'))
            require(isinstance(discovery.get('alias_prefix'), str) and
                    re.fullmatch(r'[a-z][a-z0-9-]{0,7}', discovery['alias_prefix']), 'Invalid discovery alias prefix.')
            for key in intent.sequence(discovery.get('networks'), 64, 1):
                selected_network(value, key)
        for source in intent.sequence(discovery.get('additional_sources', []), 64):
            resolved = endpoints(value, source)
            require(all(set(item) == {'network', 'addresses'} and
                        item['network'] in discovery.get('networks', []) for item in resolved),
                    'Discovery additional sources require explicit selected LAN attachments.')
        for browse in intent.sequence(discovery.get('browse', []), 64):
            require(isinstance(browse, str) and re.fullmatch(r'_[a-zA-Z0-9_-]{1,63}\._(?:tcp|udp)', browse),
                    'Invalid discovery browse type.')
        for publisher in intent.named(discovery.get('external_publishers', {}), 64).values():
            intent.fields(publisher, {'network', 'clients', 'addresses'}, {'network', 'clients', 'addresses'})
            selected_network(value, publisher['network'])
            endpoints(value, publisher['clients'])
            endpoints(value, publisher['addresses'])
        for prefix in intent.sequence(discovery.get('exclude', []), 64):
            intent.network(prefix)
        views = intent.named(discovery.get('views', {}), 64)
        require(all(key in discovery.get('networks', []) for key in views.values()) and
                ('default_view' not in discovery or discovery['default_view'] in (views or discovery.get('networks', []))),
                'Invalid discovery views.')
    from .authoritative import validate as validate_authoritative
    validate_authoritative(value)
    observability = value.get('observability', {})
    intent.fields(observability, {'metrics', 'logs', 'snmp', 'ids', 'journal'})
    for key, settings in observability.items():
        if key == 'journal':
            from . import journal
            journal.validate(settings, value['hardware']['storage']['state_mib'])
            continue
        allowed = {'clients'} if key == 'metrics' else {'clients', 'username', 'credential'} if key == 'snmp' else {
            'endpoint', 'tls_server_name', 'authentication', 'username', 'credential'} if key == 'logs' else {'forward_alerts'}
        intent.fields(settings, allowed | {'enabled'})
        active = enabled(settings)
        if active:
            required = {'endpoint', 'tls_server_name'} if key == 'logs' else set() if key == 'ids' else allowed
            require(required <= set(settings), 'Enabled observability integration is missing configuration.')
        if key == 'ids' and 'forward_alerts' in settings:
            intent.boolean(settings['forward_alerts'])
            require(not settings['forward_alerts'] or active and observability.get('logs', {}).get('enabled'),
                    'Forwarding IDS alerts requires enabled IDS and log delivery.')
        if key == 'logs':
            from .logs import authentication
            authentication(settings)
        if 'clients' in settings:
            intent.sequence(settings['clients'], 64, 1)
            endpoints(value, settings['clients'])
        if 'credential' in settings:
            credential(settings['credential'])
        if 'username' in settings:
            require(re.fullmatch(r'[a-zA-Z0-9_-]{1,64}', text(settings['username'], 64)), 'Invalid telemetry username.')
        if 'endpoint' in settings:
            url = urlsplit(text(settings['endpoint']))
            require(url.scheme == 'https' and url.hostname and not url.username and not url.password and
                    not url.fragment and not url.query and url.port in (None, 443),
                    'Log delivery requires HTTPS on port 443 without embedded secrets.')
            try:
                intent.address(url.hostname)
            except ValueError:
                require(False, 'Log delivery requires an address literal to avoid a DNS bootstrap dependency.')
            domain(settings['tls_server_name'])
    limits = value.get('access', {}).get('delegation_limits', {})
    from .metrics import sources as metrics_sources
    metrics_sources(value)
    from .snmp import validate as validate_snmp
    validate_snmp(value)
    intent.fields(limits, {'networks', 'endpoints'})
    for selector in intent.sequence(limits.get('networks', [])):
        prefixes(value, selector)
    for entry in intent.sequence(limits.get('endpoints', [])):
        intent.fields(entry, {'name', 'addresses', 'ports', 'protocol'}, {'addresses', 'ports', 'protocol'})
        if 'name' in entry:
            text(entry['name'], 96)
        endpoints(value, {'addresses': entry['addresses']})
        require(entry['protocol'] in ('tcp', 'udp'), 'Delegation endpoint requires TCP or UDP.')
        for port in intent.sequence(entry['ports'], 64, 1):
            integer(port, 1, 65535)


def require_runtime(value, target_facts=None):
    """Keep contracts from being mistaken for admitted runtime implementations."""
    missing = []
    if value.get('identity', {}).get('policy', {}).get('enabled', False):
        from . import service_plane
        # The pinned helper rejects an empty post-NAT source projection. Do
        # not let validate/render claim that such a profile can be assembled.
        dynamic_clients = any(not path['addresses'] for path in intent.uplink_nat(value))
        dynamic_services = any(path['masquerade'] and not path.get('translated_addresses')
                               for path in service_plane.egress(value))
        if dynamic_clients or dynamic_services:
            missing.append('directory policy with dynamic uplink source translation '
                           '(select static addresses for translated uplink families)')
    if (value.get('routing', {}).get('asymmetric_replies') and
            not value.get('identity', {}).get('policy', {}).get('enabled', False)):
        missing.append('asymmetric replies without the policy guard runtime')
    if any(interface.get('owner') == 'vpp' for interface in value['hardware']['interfaces'].values()):
        if target_facts is None:
            missing.append('verified VPP hardware binding')
        else:
            from .hardware_config import ownership_manifest
            ownership_manifest(value, target_facts)
    if any(enabled(s) for name, s in value.get('observability', {}).items()
           if name not in ('ids', 'metrics', 'snmp', 'logs', 'journal')):
        missing.append('observability integration')
    require(not missing, 'Runtime implementation is not admitted for: '+', '.join(missing)+'.')
