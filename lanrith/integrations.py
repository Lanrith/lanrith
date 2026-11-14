"""Typed optional integration contracts and cross-component references."""

import ipaddress as ip
from pathlib import PurePosixPath
import re
from urllib.parse import urlsplit

from . import intent
from .release import require


def text(value, maximum=512):
    require(isinstance(value, str) and 0 < len(value) <= maximum and value.isprintable(),
            'Invalid integration text.')
    return value


def domain(value):
    text(value, 253)
    require(all(re.fullmatch(r'[a-zA-Z0-9_](?:[a-zA-Z0-9_-]{0,61}[a-zA-Z0-9_])?', label)
                for label in value.rstrip('.').split('.')), 'Invalid DNS name.')
    return value


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
    intent.fields(bgp, {'enabled', 'asn', 'network', 'peer_groups'})
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
            intent.fields(clause, {'group', 'prefix_length', 'exact', 'purpose', 'reply_mode'}, {'group', 'purpose'})
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
    intent.fields(authoritative, {'enabled', 'primary_zone', 'writers', 'zones'})
    active = enabled(authoritative)
    require(not active or dns['enabled'], 'Authoritative DNS requires the DNS service.')
    if active:
        domain(authoritative.get('primary_zone'))
    zones = authoritative.get('zones', {})
    require(isinstance(zones, dict) and len(zones) <= 64, 'Invalid authoritative zones.')
    if active:
        require(authoritative['primary_zone'] in zones, 'Primary zone is not declared.')
    result = {}
    for zone, settings in zones.items():
        domain(zone)
        intent.fields(settings, {'persistent', 'records', 'records_from'})
        intent.boolean(settings.get('persistent', False))
        records = settings.get('records', {})
        require(isinstance(records, dict) and len(records) <= 4096, 'Invalid DNS records.')
        resolved = {}
        for label, rr in records.items():
            domain(label)
            intent.fields(rr, {'A', 'AAAA', 'CNAME'})
            require(rr and not ('CNAME' in rr and len(rr) != 1), 'CNAME conflicts with address records.')
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
        intent.fields(writer, {'zone', 'sources', 'key_name', 'credential', 'zone_transfer'},
                      {'zone', 'sources', 'key_name', 'credential'})
        require(writer['zone'] in zones, 'DNS writer references an undeclared zone.')
        endpoints(value, writer['sources'])
        domain(writer['key_name'])
        credential(writer['credential'])
        intent.boolean(writer.get('zone_transfer', False))
    return result


def identity(value):
    from . import routing as routing_model

    identity = value.get('identity', {})
    intent.fields(identity, {'directories', 'radius', 'policy'})
    directories = intent.named(identity.get('directories', {}), 16)
    for directory in directories.values():
        intent.fields(directory, {'enabled', 'url', 'addresses', 'base_dn', 'bind_dn', 'credential', 'ca_file'},
                      {'url', 'base_dn', 'bind_dn', 'credential', 'ca_file'})
        enabled(directory)
        url = urlsplit(text(directory['url']))
        require(url.scheme in ('ldap+starttls', 'ldaps') and url.hostname and not url.username and
                not url.password and not url.query and not url.fragment and url.path in ('', '/'),
                'Directory requires verified StartTLS or LDAPS without embedded credentials.')
        integer(url.port if url.port is not None else (636 if url.scheme == 'ldaps' else 389), 1, 65535)
        from .directory_config import endpoint
        endpoint(directory)
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
        intent.fields(admission, {'directory', 'group_dn', 'network'}, {'directory', 'group_dn', 'network'})
        directory_reference(admission['directory'])
        text(admission['group_dn'])
        admitted = selected_network(value, admission['network'])
        require(admission['network'] in policy.get('networks', []),
                'RADIUS admission must be enforced by the selected identity policy.')
        require('dhcp4' in admitted and any(ip.ip_interface(a).version == 4 for a in admitted['addresses']) and
                1 <= admitted.get('vlan', 0) <= 4094,
                'RADIUS admission requires a tagged DHCPv4 network.')
    clients = intent.named(radius.get('clients', {}), 64)
    for client in clients.values():
        intent.fields(client, {'address', 'kind', 'port', 'credential'}, {'address', 'kind', 'credential'})
        intent.network(client['address'])
        require(client['kind'] in ('wired_mab', 'wireless_mac'), 'Unknown RADIUS client kind.')
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
        intent.fields(proxy, {'address', 'credential'}, {'address', 'credential'})
        intent.address(proxy['address'])
        credential(proxy['credential'])
        if enabled(radius):
            target = intent.address(proxy['address'])
            attachments = [ip.ip_interface(a).network for a in radius_network['addresses']]
            attachments += [ip.ip_network(a) for a in radius_network.get('additional_subnets', [])]
            attachments += [ip.ip_network(a) for a in radius_network.get('routed_prefixes', [])]
            attachments += [ip.ip_network(a) for a in routing_model.routed_sources(value, radius['network'])]
            require(any(target.version == attached.version and target in attached for attached in attachments),
                    'RADIUS proxy is outside its declared attachment network.')
    fallback = radius.get('fallback', {})
    intent.fields(fallback, {'enabled', 'clients'})
    if enabled(fallback):
        require(enabled(radius), 'RADIUS fallback requires RADIUS.')
        for key in intent.sequence(fallback.get('clients'), 64, 1):
            require(key in clients and clients[key]['kind'] == 'wired_mab' and 'port' in clients[key] and
                    intent.network(clients[key]['address']).num_addresses == 1,
                    'Outage fallback requires an exact wired NAS and port.')


def validate(value):
    for key, group in intent.named(value.get('groups', {})).items():
        intent.sequence(group, 256, 1)
        endpoints(value, {'group': key})
    routing(value)
    from .routing import validate as validate_routes
    validate_routes(value)
    identity(value)
    for feature in ('dns', 'ntp'):
        settings = value['services'][feature]
        for upstream in intent.sequence(settings.get('upstreams', []), 16):
            if feature == 'dns':
                intent.address(upstream)
                continue
            try:
                intent.address(upstream)
            except ValueError:
                domain(upstream)
    dns = value['services']['dns']
    if 'domain' in dns:
        domain(dns['domain'])
    for blocked in intent.sequence(dns.get('blocked_domains', []), 1024):
        domain(blocked)
    dns_records(value)
    from .authoritative import validate as validate_authoritative
    validate_authoritative(value)
    discovery = value['services'].get('discovery', {})
    if 'configuration' not in discovery:
        intent.fields(discovery, {'enabled', 'domain', 'alias_prefix', 'networks', 'additional_sources', 'browse',
                                  'external_publishers', 'exclude', 'views', 'default_view'})
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
                ('default_view' not in discovery or discovery['default_view'] in views), 'Invalid discovery views.')
    observability = value.get('observability', {})
    intent.fields(observability, {'metrics', 'logs', 'snmp', 'ids'})
    for key, settings in observability.items():
        allowed = {'clients'} if key == 'metrics' else {'clients', 'username', 'credential'} if key == 'snmp' else {
            'endpoint', 'tls_server_name', 'username', 'credential'} if key == 'logs' else set()
        intent.fields(settings, allowed | {'enabled'})
        active = enabled(settings)
        if active:
            require(allowed <= set(settings), 'Enabled observability integration is missing configuration.')
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
           if name not in ('ids', 'metrics', 'snmp', 'logs')):
        missing.append('observability integration')
    require(not missing, 'Runtime implementation is not admitted for: '+', '.join(missing)+'.')
