"""Generate isolated core DNS/NTP networking and service configuration."""

import ipaddress as ip
from urllib.parse import urlsplit

from . import intent, routing, authoritative, dns64, metrics, snmp, integrations, discovery
from .release import canonical, require


NAMESPACE = 'lanrith-services'
HOST_LINK = 'lr-services'
SERVICE_LINK = 'lr-host'


def attached(value):
    return (any(value['services'][name]['enabled'] for name in ('dns', 'ntp')) or
            value.get('identity', {}).get('radius', {}).get('enabled', False) or
            value.get('observability', {}).get('logs', {}).get('enabled', False) or
            discovery.active(value) or
            metrics.active(value) or snmp.active(value))


def destination_network(value, address):
    """Resolve one internal dependency to exactly one routed attachment."""
    target = ip.ip_address(address)
    matches = []
    for key, network in value['networks'].items():
        scopes = [ip.ip_interface(item).network for item in network['addresses']]
        scopes += [ip.ip_network(item) for item in network.get('additional_subnets', [])]
        scopes += [ip.ip_network(item) for item in routing.routed_sources(value, key)]
        for route in value.get('routing', {}).get('static_routes', []):
            if route['network'] == key:
                scopes += integrations.prefixes(value, route['to'])
        if any(target.version == scope.version and target in scope for scope in scopes):
            matches.append(key)
    require(len(matches) == 1, 'Internal service target needs one unambiguous attachment route.')
    return matches[0]


def clients(value, feature):
    if feature == 'authoritative':
        return clients(value, 'dns') + [
            source for writer in authoritative.writers(value).values()
            for source in authoritative.writer_sources(value, writer)]
    if feature == 'radius':
        radius = value.get('identity', {}).get('radius', {})
        if not radius.get('enabled', False):
            return []
        return [{'network': radius['network'], 'addresses': list(dict.fromkeys(
            str(ip.ip_network(client['address'])) for client in radius.get('clients', {}).values()))}]
    if feature == 'discovery':
        return [{'network': key, 'addresses': [
            str(ip.ip_interface(address).network) for address in network['addresses']] +
            network.get('additional_subnets', []) + routing.routed_sources(value, key)}
            for key, network in value['networks'].items() if network.get('forwarding', True)]
    result = [{'network': key, 'addresses': [
        str(ip.ip_interface(a).network)
        for a in n['addresses'] + n.get('routed_prefixes', []) + n.get('additional_subnets', [])]}
        for key, n in value['networks'].items() if n.get(feature)]
    return result + routing.service_clients(value, feature)


def egress(value):
    """Fixed service dependencies, with exact static post-NAT source geometry.

    An empty translated-address list records dynamic uplink addressing. Native
    enforcement must obtain qualified live address evidence before activation.
    """
    plane = topology(value)
    result = []
    for kind in ('dns', 'ntp', 'ntp_dns'):
        component = 'ntp' if kind == 'ntp_dns' else kind
        if component not in plane['endpoints'] or kind == 'ntp_dns' and 'dns' in plane['endpoints']:
            continue
        for address in plane['endpoints'][component]:
            family = 'ipv6' if ':' in address else 'ipv4'
            upstream = value['uplink'].get(family, 'ra' if family == 'ipv6' else 'dhcp')
            if upstream == 'disabled':
                continue
            destinations = ['::/0' if family == 'ipv6' else '0.0.0.0/0']
            if kind == 'ntp_dns':
                destinations = [str(ip.ip_network(resolver)) for resolver in
                    value['services']['dns'].get('upstreams', ['9.9.9.9', '2620:fe::fe'])
                    if (':' in resolver) == (family == 'ipv6')]
                if not destinations:
                    continue
            masquerade = family == 'ipv4' or not value['uplink'].get('downstream_prefix')
            entry = {'kind': kind, 'interface': plane['host_link'], 'address': address,
                     'destinations': sorted(set(destinations)), 'masquerade': masquerade}
            if masquerade and upstream == 'static':
                entry['translated_addresses'] = [str(ip.ip_interface(configured).ip)
                    for configured in value['uplink']['addresses']
                    if (':' in configured) == (family == 'ipv6')]
            result.append(entry)
    radius = value.get('identity', {}).get('radius', {})
    if radius.get('enabled', False):
        destination = ip.ip_address(radius['proxy']['address'])
        source = next(address for address in intent.service_addresses(value, 'radius')
                      if ip.ip_address(address).version == destination.version)
        result.append({'kind': 'radius_proxy', 'interface': plane['host_link'], 'address': source,
                       'destinations': [str(ip.ip_network(destination))], 'masquerade': False,
                       'destination_interface': value['networks'][radius['network']]['name']})
    logs = value.get('observability', {}).get('logs', {})
    if logs.get('enabled', False):
        destination = ip.ip_address(urlsplit(logs['endpoint']).hostname)
        source = next(address for address in intent.service_addresses(value, 'logs')
                      if ip.ip_address(address).version == destination.version)
        network = destination_network(value, destination)
        result.append({'kind': 'logs', 'interface': plane['host_link'], 'address': source,
                       'destinations': [str(ip.ip_network(destination))], 'masquerade': False,
                       'destination_interface': value['networks'][network]['name']})
    return result


def topology(value):
    active = [name for name in ('dns', 'ntp') if value['services'][name]['enabled']]
    if authoritative.active(value):
        active.append('authoritative')
    if metrics.active(value):
        active.append('metrics')
    if value.get('identity', {}).get('radius', {}).get('enabled', False):
        active.append('radius')
    if value.get('observability', {}).get('logs', {}).get('enabled', False):
        active.append('logs')
    if discovery.active(value):
        active.append('discovery')
    pools = intent.service_networks(value)
    dependency_routes = []
    for feature, raw in (('radius', value.get('identity', {}).get('radius', {}).get('proxy', {}).get('address')),
                         ('logs', urlsplit(value.get('observability', {}).get('logs', {}).get('endpoint', '')).hostname)):
        if raw is None or feature not in active:
            continue
        target = ip.ip_address(raw)
        source = next(a for a in intent.service_addresses(value, feature)
                      if ip.ip_address(a).version == target.version)
        gateway = str(next(p for p in pools if p.version == target.version).network_address+1)
        dependency_routes.append({'to': str(ip.ip_network(target)), 'via': gateway, 'source': source})
    return {'schema': 1, 'namespace': NAMESPACE, 'host_link': HOST_LINK, 'service_link': SERVICE_LINK,
            'host_addresses': [str(p.network_address+1)+'/'+str(p.prefixlen) for p in pools],
            'peer_addresses': [str(p.network_address+2)+'/'+str(p.prefixlen) for p in pools],
            'endpoints': {name: intent.service_addresses(value, name) for name in active},
            'defaults': [str(p.network_address+1) for p in pools[:2]],
            'default_sources': [next(a for a in reversed(intent.service_addresses(value, active[0]))
                                     if ip.ip_address(a).version == family) for family in (4, 6)] if active else
                               [str(p.network_address+2) for p in pools[:2]] if snmp.active(value) else [],
            'dependency_routes': dependency_routes,
            'wan': value['hardware']['interfaces'][value['uplink']['interface']]['name'],
            'proxy': ([a for name in active for a in intent.service_addresses(value, name)[2:]] +
                      ([snmp.listener(value)] if snmp.active(value) and len(pools) > 2 else []))
                     if value['uplink'].get('delivery') == 'on_link' else []}


def render(value):
    active = [name for name in ('dns', 'ntp') if value['services'][name]['enabled']]
    if not attached(value):
        return {}
    plane = topology(value)
    files = {'usr/share/lanrith/service-plane.json': canonical(plane).decode()}
    files['usr/lib/systemd/system/lanrith-services.service'] = (
        '[Unit]\nDescription=Create isolated core service networking\n'
        'Requires=nftables.service\nAfter=nftables.service systemd-networkd.service\n'
        'BindsTo=nftables.service\nBefore=unbound.service chrony.service discovery-bridge-dns.service\n'
        '[Service]\nType=oneshot\nRemainAfterExit=yes\n'
        'ExecStart=/usr/bin/python3 /usr/lib/lanrith/lanrith/service_runtime.py start\n'
        'ExecStop=/usr/bin/python3 /usr/lib/lanrith/lanrith/service_runtime.py stop\n'
        'TimeoutStartSec=30s\nTimeoutStopSec=30s\n')
    for feature, unit in (('dns', 'unbound.service'), ('ntp', 'chrony.service')):
        if feature not in active:
            continue
        files['etc/systemd/system/'+unit+'.d/60-lanrith-services.conf'] = (
            '[Unit]\nRequires=lanrith-services.service\nAfter=lanrith-services.service\n'
            'BindsTo=lanrith-services.service nftables.service\n'
            '[Service]\nNetworkNamespacePath=/run/netns/'+NAMESPACE+'\n')
    if 'dns' in active:
        dns = value['services']['dns']
        text = ('server:\n  ip-freebind: yes\n  interface: 127.0.0.1\n  interface: ::1\n'
                '  access-control: 127.0.0.0/8 allow\n  access-control: ::1/128 allow\n'
                '  access-control: 0.0.0.0/0 refuse\n  access-control: ::/0 refuse\n')
        for endpoint in plane['endpoints']['dns']:
            text += '  interface: '+endpoint+'\n'
        for client in clients(value, 'dns'):
            for raw in client['addresses']:
                text += '  access-control: '+raw+' allow\n'
        for blocked in dns.get('blocked_domains', []):
            text += '  local-zone: "'+blocked.rstrip('.')+'." always_nxdomain\n'
        server, stubs = authoritative.resolver_zones(value)
        text += server + dns64.server(value)
        if dns64.private_active(value):
            stubs = dns64.forwards(value)
        for family in (4, 6):
            chosen = next(a for a in reversed(plane['endpoints']['dns']) if ip.ip_address(a).version == family)
            text += '  outgoing-interface: '+chosen+'\n'
        if value['uplink'].get('ipv6', 'ra') == 'disabled':
            # Keep IPv6 LAN listeners while using IPv4 recursive transport.
            text += '  do-not-query-address: ::/0\n'
        if value['uplink'].get('ipv4', 'dhcp') == 'disabled':
            text += '  do-not-query-address: 0.0.0.0/0\n'
        if dns.get('upstreams'):
            text += 'forward-zone:\n  name: "."\n'
            for upstream in dns['upstreams']:
                # Address literals avoid a bootstrap resolver dependency.
                intent.address(upstream)
                text += '  forward-addr: '+upstream+'\n'
        text += stubs
        files['etc/unbound/unbound.conf.d/lanrith.conf'] = text
    if 'ntp' in active:
        ntp = value['services']['ntp']
        text = ''.join('pool '+server+' iburst\n' for server in ntp.get('upstreams', ['2.pool.ntp.org']))
        text += 'driftfile /var/lib/chrony/chrony.drift\nrtcsync\nmakestep 1 3\ncmdport 0\n'
        for endpoint in plane['endpoints']['ntp'][:2]:
            text += 'bindaddress '+endpoint+'\n'
        for family in (4, 6):
            endpoint = next(a for a in reversed(plane['endpoints']['ntp']) if ip.ip_address(a).version == family)
            text += 'bindacqaddress '+endpoint+'\n'
        for client in clients(value, 'ntp'):
            for raw in client['addresses']:
                text += 'allow '+raw+'\n'
        files['etc/chrony/chrony.conf'] = text
        # Namespace DNS is explicit; disabling DNS still leaves numeric NTP upstreams usable.
        if 'dns' in active:
            # Both daemons share this isolated namespace. Managed addresses
            # admit declared LAN clients; local resolver requests use the
            # loopback listener and its explicit localhost ACL instead.
            files['etc/lanrith/chrony-resolv.conf'] = 'nameserver 127.0.0.1\n'
            files['etc/systemd/system/chrony.service.d/60-lanrith-services.conf'] += (
                'BindReadOnlyPaths=/etc/lanrith/chrony-resolv.conf:/etc/resolv.conf\n')
        else:
            # DNS disabled globally: NTP resolves its pool names through explicit numeric resolvers.
            resolvers = value['services']['dns'].get('upstreams', ['9.9.9.9', '2620:fe::fe'])
            for resolver in resolvers:
                intent.address(resolver)
            files['etc/lanrith/chrony-resolv.conf'] = ''.join('nameserver '+a+'\n' for a in resolvers)
            files['etc/systemd/system/chrony.service.d/60-lanrith-services.conf'] += (
                'BindReadOnlyPaths=/etc/lanrith/chrony-resolv.conf:/etc/resolv.conf\n')
    files.update(dns64.render(value))
    if dns64.private_active(value):
        files['etc/systemd/system/unbound.service.d/61-lanrith-dns64.conf'] = (
            '[Unit]\nRequires=lanrith-dns64-private.service\nAfter=lanrith-dns64-private.service\n')
    files['etc/lanrith/services.nft'] = namespace_firewall(value, plane)
    return files


def namespace_firewall(value, plane):
    from .firewall import values
    lines = ['flush ruleset', 'table inet services {',
             'chain input { type filter hook input priority filter; policy drop;',
             'iifname "lo" accept', 'ct state invalid drop', 'ct state established,related accept',
             'ip6 hoplimit 255 icmpv6 type { nd-neighbor-solicit, nd-neighbor-advert } accept',
             'icmpv6 type { destination-unreachable, packet-too-big, time-exceeded, parameter-problem } accept']
    for feature, port in (('dns', 53), ('ntp', 123), ('authoritative', 53), ('discovery', 53),
                          ('radius', 1812)):
        if feature not in plane['endpoints']:
            continue
        for family, spelling in ((4, 'ip'), (6, 'ip6')):
            sources = [a for c in clients(value, feature) for a in c['addresses']
                       if ip.ip_network(a).version == family]
            if sources:
                targets = [a for a in plane['endpoints'][feature] if ip.ip_address(a).version == family]
                for protocol in ('tcp', 'udp') if feature not in ('ntp', 'radius') else ('udp',):
                    lines.append(f'{spelling} saddr {values(sources)} {spelling} daddr {values(targets)} '
                                 f'{protocol} dport {port} accept')
                    if feature == 'radius':
                        lines.append(f'{spelling} saddr {values(sources)} {spelling} daddr {values(targets)} '
                                     f'{protocol} dport 1813 accept')
    lines += metrics.client_rules(value, namespace=True)
    lines += ['}', 'chain forward { type filter hook forward priority filter; policy drop; }',
              'chain output { type filter hook output priority filter; policy drop;',
              'ct state invalid drop', *local_output(value, plane),
              'jump socket_identity', 'ct state established,related accept',
              'ip6 hoplimit 255 icmpv6 type { nd-neighbor-solicit, nd-neighbor-advert } accept',
              'icmpv6 type { destination-unreachable, packet-too-big, time-exceeded, parameter-problem } accept']
    for feature, uid, port in (('dns', 'unbound', 53), ('ntp', '_chrony', 123)):
        if feature not in plane['endpoints']:
            continue
        for family, spelling in ((4, 'ip'), (6, 'ip6')):
            sources = [a for a in plane['endpoints'][feature] if ip.ip_address(a).version == family]
            for protocol in ('tcp', 'udp') if feature == 'dns' else ('udp',):
                lines.append(f'meta skuid "{uid}" {spelling} saddr {values(sources)} {protocol} dport {port} accept')
    if 'ntp' in plane['endpoints'] and 'dns' not in plane['endpoints']:
        for resolver in value['services']['dns'].get('upstreams', ['9.9.9.9', '2620:fe::fe']):
            spelling = 'ip6' if ':' in resolver else 'ip'
            for protocol in ('tcp', 'udp'):
                lines.append(f'meta skuid "_chrony" {spelling} daddr {resolver} {protocol} dport 53 accept')
    lines += metrics.backend_rule(value, namespace=True)
    radius = value.get('identity', {}).get('radius', {})
    if radius.get('enabled', False):
        proxy = radius['proxy']['address']
        spelling = 'ip6' if ':' in proxy else 'ip'
        source = next(a for a in plane['endpoints']['radius'] if (':' in a) == (':' in proxy))
        lines.append(f'meta skuid "freerad" {spelling} saddr {source} {spelling} daddr {proxy} '
                     'udp dport 1812 accept')
    logs = value.get('observability', {}).get('logs', {})
    if logs.get('enabled', False):
        from urllib.parse import urlsplit
        target = urlsplit(logs['endpoint']).hostname
        spelling = 'ip6' if ':' in target else 'ip'
        source = next(a for a in plane['endpoints']['logs'] if (':' in a) == (':' in target))
        lines.append(f'meta skuid "alloy" {spelling} saddr {source} {spelling} daddr {target} '
                     'tcp dport 443 accept')
    return '\n'.join(lines+['}', *socket_identity(plane), '}'])+'\n'


SERVICE_ACCOUNTS = {'dns': 'unbound', 'ntp': '_chrony', 'authoritative': 'bind',
                    'discovery': 'discovery-bridge-dns',
                    'metrics': 'lanrith-metrics', 'radius': 'freerad', 'logs': 'alloy'}


def socket_identity(plane):
    """Check every socket packet, including an already tracked original tuple.

    Privileged root sockets and kernel control packets retain their authority.
    An established tuple never substitutes for an unprivileged account's own
    assigned source. In particular another service cannot reuse a closed UDP
    socket's still-live conntrack entry.
    """
    from .firewall import values
    lines = ['chain socket_identity {', 'meta skuid 0 return']
    accounts = [SERVICE_ACCOUNTS[name] for name in plane['endpoints']]
    for feature, addresses in plane['endpoints'].items():
        uid = SERVICE_ACCOUNTS[feature]
        for family, spelling in ((4, 'ip'), (6, 'ip6')):
            selected = [a for a in addresses if ip.ip_address(a).version == family]
            if selected:
                lines.append(f'meta skuid "{uid}" {spelling} saddr {values(selected)} return')
    # Missing socket metadata must fall through for kernel-generated errors.
    # Both known-but-wrong sources and any other socket owner are denied.
    lines += [f'meta skuid "{uid}" drop' for uid in accounts]
    lines += ['meta skuid != '+values(['0', *('"'+a+'"' for a in accounts)])+' drop', 'return', '}']
    return lines


def local_output(value, plane):
    """Permit explicit local service dependencies rather than all loopback use."""
    from .firewall import values
    endpoints = plane['endpoints']
    lines = ['oifname "lo" meta skuid 0 accept']
    if 'logs' in endpoints:
        # The supervisor observes Alloy's local component graph. The API is
        # neither a LAN listener nor a dependency available to other services.
        lines += [
            'oifname "lo" meta skuid "alloy" ip saddr 127.0.0.1 ip daddr 127.0.0.1 tcp dport 12345 accept',
            'oifname "lo" meta skuid "alloy" ip saddr 127.0.0.1 ip daddr 127.0.0.1 '
            'ct direction reply ct state { established, related } tcp sport 12345 accept',
        ]
    if 'dns' in endpoints and 'ntp' in endpoints:
        for family, spelling, target in ((4, 'ip', '127.0.0.1'), (6, 'ip6', '::1')):
            for protocol in ('tcp', 'udp'):
                lines.append(f'oifname "lo" meta skuid "_chrony" {spelling} daddr {target} {protocol} dport 53 accept')
    for dependency in ('authoritative', 'discovery'):
        if dependency not in endpoints:
            continue
        for family, spelling in ((4, 'ip'), (6, 'ip6')):
            targets = [a for a in endpoints[dependency] if ip.ip_address(a).version == family]
            for protocol in ('tcp', 'udp'):
                lines.append(f'oifname "lo" meta skuid "unbound" {spelling} daddr {values(targets)} {protocol} dport 53 accept')
    if dns64.private_active(value):
        for spelling, target in (('ip', '127.0.0.1'), ('ip6', '::1')):
            for protocol in ('tcp', 'udp'):
                lines.append(f'oifname "lo" meta skuid "unbound" {spelling} daddr {target} {protocol} dport {dns64.PORT} accept')

        # A private CNAME which leaves its authoritative zone returns to the
        # public resolver's managed endpoint, using the same unbound account.
        for family, spelling in ((4, 'ip'), (6, 'ip6')):
            targets = [a for a in endpoints['dns'] if ip.ip_address(a).version == family]
            for protocol in ('tcp', 'udp'):
                lines.append(f'oifname "lo" meta skuid "unbound" {spelling} daddr {values(targets)} {protocol} dport 53 accept')
    for feature, addresses in endpoints.items():
        uid = SERVICE_ACCOUNTS[feature]
        ports = ([53] if feature in ('dns', 'authoritative', 'discovery') else [123] if feature == 'ntp' else
                 [1812, 1813] if feature == 'radius' else [443] if feature == 'logs' else [9100])
        if feature == 'dns' and dns64.private_active(value):
            ports.append(dns64.PORT)
        for family, spelling, loop in ((4, 'ip', '127.0.0.1'), (6, 'ip6', '::1')):
            sources = [a for a in addresses if ip.ip_address(a).version == family]
            if feature == 'dns':
                sources.append(loop)
            for protocol in ('tcp', 'udp') if feature in ('dns', 'authoritative', 'discovery') else ('udp',) if feature in ('ntp', 'radius') else ('tcp',):
                lines.append(f'oifname "lo" meta skuid "{uid}" {spelling} saddr {values(sources)} '
                             f'ct direction reply ct state {{ established, related }} {protocol} sport {values(ports)} accept')
    accounts = ['0', *('"'+SERVICE_ACCOUNTS[name]+'"' for name in endpoints)]
    # Any socket-backed local packet not admitted above is denied. A missing
    # skuid breaks each match, leaving only kernel control traffic below.
    lines += ['oifname "lo" meta skuid '+values(accounts)+' drop',
              'oifname "lo" meta skuid != '+values(accounts)+' drop',
              'oifname "lo" ct state related meta l4proto { icmp, ipv6-icmp } accept',
              'oifname "lo" ct direction reply ct state { established, related } tcp flags & rst == rst accept',
              'oifname "lo" drop']
    return lines
