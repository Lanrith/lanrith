"""Generate bounded native routing and its control-plane connectivity."""

import hashlib
import ipaddress as ip

from . import integrations, intent
from . import bindings as runtime_bindings
from .release import canonical, require


def groups(value):
    bgp = value.get('routing', {}).get('bgp', {})
    if not bgp.get('enabled', False):
        return {}
    return bgp.get('peer_groups', {})


def attachment(value, group):
    return group.get('network', value['routing']['bgp']['network'])


def imports(value, group):
    for clause in group['import']:
        for prefix in integrations.prefixes(value, {'group': clause['group']}):
            yield prefix, clause.get('prefix_length', prefix.prefixlen), clause


def routed_sources(value, network):
    """BGP import scopes, never forwarding permissions or static-route trust."""
    result = []
    for group in groups(value).values():
        if attachment(value, group) == network:
            result.extend(str(p) for p, _, _ in imports(value, group))
    return list(dict.fromkeys(result))


def service_clients(value, feature):
    result = []
    for group in groups(value).values():
        if feature not in group.get('services', []):
            continue
        result.append({'network': attachment(value, group), 'addresses': [
            str(p) for p, _, clause in imports(value, group) if clause['purpose'] == 'network']})
    return result


def peers(value, group):
    result = list(group.get('peers', {}).values())
    if group.get('dynamic', {}).get('enabled'):
        result.append(group['dynamic']['range'])
    return result


def control_rules(value, direction):
    """Exact peer addresses/ranges, ingress/egress network and router address."""
    from .firewall import values
    result = []
    for group in groups(value).values():
        network = value['networks'][attachment(value, group)]
        for family, spelling in ((4, 'ip'), (6, 'ip6')):
            remote = [p for p in peers(value, group) if ip.ip_network(p).version == family]
            local = [str(ip.ip_interface(a).ip) for a in network['addresses']
                     if ip.ip_interface(a).version == family]
            if not remote or not local:
                continue
            if direction == 'input':
                result.append(f'  iifname "{network["name"]}" {spelling} saddr {values(remote)} '
                              f'{spelling} daddr {values(local)} tcp dport 179 accept')
            else:
                result.append(f'  meta skuid "frr" oifname "{network["name"]}" '
                              f'{spelling} saddr {values(local)} {spelling} daddr {values(remote)} '
                              'tcp dport 179 accept')
    return result


def static_routes(value, network):
    text = ''
    for route in value.get('routing', {}).get('static_routes', []):
        if route['network'] == network:
            for prefix in integrations.prefixes(value, route['to']):
                text += f'\n[Route]\nDestination={prefix}\n'
                # IPv6 direct routes have no gateway; networkd ignores Scope.
                if ip.ip_network(prefix).version == 4:
                    text += 'Scope=link\n'
    return text


def fallback_pools(value):
    pools = {'bgp_only': set(), 'routing_table': set()}
    for group in groups(value).values():
        for prefix, _, clause in imports(value, group):
            pools[clause.get('fallback', 'routing_table')].add(prefix)
    return pools


def validate_fallback(value):
    pools = fallback_pools(value)
    if not pools['bgp_only']:
        return
    direct = [ip.ip_interface(a).network for network in value['networks'].values()
              for a in network['addresses'] + network.get('additional_subnets', [])]
    direct += [ip.ip_interface(a).network for a in value['uplink'].get('addresses', [])]
    for route in value.get('routing', {}).get('static_routes', []):
        direct.extend(integrations.prefixes(value, route['to']))
    for pool in pools['bgp_only']:
        require(not any(pool.overlaps(p) for p in pools['routing_table'] if p.version == pool.version),
                'Overlapping BGP import pools must agree on their fallback.')
        require(not any(pool.overlaps(p) for p in direct if p.version == pool.version),
                'BGP-only fallback overlaps an explicitly on-link or connected allocation.')


def validate_import_ownership(value):
    bgp = value.get('routing', {}).get('bgp', {})
    rows = intent.sequence(bgp.get('import_ownership', []), 4096)
    if not rows:
        return
    # Validate declared policy even when temporarily disabling the daemon.
    # Peers of either transport family can carry the advertised address family.
    policies = [(list(imports(value, group)), {ip.ip_network(p) for p in peers(value, group)})
                for group in bgp.get('peer_groups', {}).values()]
    seen = set()
    for row in rows:
        intent.fields(row, {'prefix', 'origins'}, {'prefix', 'origins'})
        prefix = intent.network(row['prefix'])
        require(prefix not in seen, 'Duplicate BGP import ownership prefix.')
        seen.add(prefix)
        expected = {intent.network(p) for p in intent.sequence(row['origins'], 1024)}
        actual = set()
        for clauses, origins in policies:
            if any(prefix.version == pool.version and prefix.prefixlen == length and prefix.subnet_of(pool)
                   for pool, length, _ in clauses):
                actual.update(origins)
        for family in (4, 6):
            expected_scope = ip.collapse_addresses(p for p in expected if p.version == family)
            actual_scope = ip.collapse_addresses(p for p in actual if p.version == family)
            require(list(expected_scope) == list(actual_scope),
                    f'BGP import origins differ from allocation for {prefix}.')


def validate(value):
    """Reject route ownership that would weaken another attachment's guard."""
    require(not value.get('routing', {}).get('bgp', {}).get('enabled') or bool(groups(value)),
            'Enabled BGP requires at least one declared peer group.')
    connected = [(key, ip.ip_interface(a).network) for key, network in value['networks'].items()
                 for a in network['addresses'] + network.get('additional_subnets', [])]
    protected = intent.service_networks(value)
    protected += [ip.ip_network(c['prefix']) for c in intent.translations(value).values()]
    protected += [ip.ip_network(c['pool']) for c in intent.translations(value).values()]
    owners = []
    for key in value['networks']:
        allocations = routed_sources(value, key) + [
            str(p) for route in value.get('routing', {}).get('static_routes', []) if route['network'] == key
            for p in integrations.prefixes(value, route['to'])]
        for raw in allocations:
            prefix = ip.ip_network(raw)
            require(any(ip.ip_interface(a).version == prefix.version for a in value['networks'][key]['addresses']),
                    'Routed allocation needs the same address family on its attachment.')
            require(not any(prefix.version == p.version and prefix.overlaps(p) for p in protected),
                    'Routed allocation overlaps a managed service or translator.')
            require(not any(key != other and prefix.version == p.version and prefix.overlaps(p)
                            for other, p in connected + owners),
                    'Routed allocation belongs to another attachment.')
            require(not any(prefix.version == ip.ip_interface(a).version and ip.ip_interface(a).ip in prefix
                            for network in value['networks'].values() for a in network['addresses']),
                    'Routed allocation includes a router control address.')
            owners.append((key, prefix))
    validate_fallback(value)
    validate_import_ownership(value)
    dynamic = [g for g in groups(value).values() if g.get('dynamic', {}).get('enabled')]
    # FRR's listen limit is per router instance, not per peer group.
    require(len(dynamic) <= 1, 'One bounded dynamic BGP peer group is supported per router.')
    for group in groups(value).values():
        require(peers(value, group), 'BGP peer group requires pinned peers or a dynamic range.')
        require(not any(ip.ip_interface(a).ip in prefix for prefix, _, _ in imports(value, group)
                        for network in value['networks'].values() for a in intent.gateway_addresses(network)),
                'BGP imports include a router control address.')
        dynamic = group.get('dynamic', {})
        if dynamic.get('enabled'):
            scope = ip.ip_network(dynamic['range'])
            require(not any(ip.ip_address(peer) in scope for other in groups(value).values()
                            for peer in other.get('peers', {}).values()),
                    'Dynamic BGP range overlaps a pinned peer.')


def frr_config(value):
    bgp = value['routing']['bgp']
    # A stable router ID is required on IPv6-only routers too. Prefer an
    # existing gateway; derive an ID (not an interface address) otherwise.
    addresses = [str(ip.ip_interface(a).ip) for n in value['networks'].values()
                 for a in n['addresses'] if ip.ip_interface(a).version == 4]
    router_id = addresses[0] if addresses else '10.'+'.'.join(
        str(b) for b in hashlib.sha256(value['hostname'].encode()).digest()[:3])
    lines = ['frr defaults traditional', 'hostname '+value['hostname'],
             'log syslog informational', 'service integrated-vtysh-config']
    bindings = {}
    for index, group in enumerate(groups(value).values()):
        name = 'LR'+str(index)
        for family, spelling in ((4, 'ip'), (6, 'ipv6')):
            selected = [(p, length) for p, length, _ in imports(value, group) if p.version == family]
            for seq, (prefix, length) in enumerate(selected, 1):
                bounds = '' if prefix.prefixlen == length else f' ge {length} le {length}'
                lines.append(f'{spelling} prefix-list {name}-{family} seq {seq*10} permit {prefix}{bounds}')
            if selected:
                lines += [f'route-map {name}-IN-{family} permit 10',
                          f' match {spelling} address prefix-list {name}-{family}']
            lines.append(f'route-map {name}-IN-{family} deny 65535')
        lines.append(f'route-map {name}-OUT deny 10')
    lines += [f'router bgp {bgp["asn"]}', f' bgp router-id {router_id}',
              ' no bgp default ipv4-unicast', ' bgp ebgp-requires-policy',
              ' no bgp graceful-restart notification']
    for index, group in enumerate(groups(value).values()):
        name = 'LR'+str(index)
        network = value['networks'][attachment(value, group)]
        hold = group.get('hold_seconds', 90)
        lines += [f' neighbor {name} peer-group', f' neighbor {name} remote-as {group["remote_asn"]}',
                  f' neighbor {name} update-source {network["name"]}',
                  f' neighbor {name} timers {hold//3} {hold}']
        if 'credential' in group:
            marker = '@LANRITH_BGP_'+str(index)+'@'
            lines.append(f' neighbor {name} password {marker}')
            bindings[marker] = group['credential']
        for peer in group.get('peers', {}).values():
            lines.append(f' neighbor {peer} peer-group {name}')
        dynamic = group.get('dynamic', {})
        if dynamic.get('enabled'):
            lines += [f' bgp listen limit {dynamic["maximum_peers"]}',
                      f' bgp listen range {dynamic["range"]} peer-group {name}']
    for family in (4, 6):
        lines.append(f' address-family ipv{family} unicast')
        for index, group in enumerate(groups(value).values()):
            if not any(p.version == family for p, _, _ in imports(value, group)):
                continue
            name = 'LR'+str(index)
            lines += [f'  neighbor {name} activate',
                      f'  neighbor {name} route-map {name}-IN-{family} in',
                      f'  neighbor {name} route-map {name}-OUT out',
                      f'  neighbor {name} maximum-prefix {group.get("maximum_prefixes", 65)}']
        lines.append(' exit-address-family')
    return '\n'.join(lines)+'\n', bindings


def render(value):
    if not groups(value):
        return {}
    text, bindings = frr_config(value)
    files = {
        'etc/frr/frr.conf': text,
        'etc/frr/daemons': ('zebra=yes\nbgpd=yes\nvtysh_enable=yes\n'
            'zebra_options=" -A 127.0.0.1"\nbgpd_options=" -A 127.0.0.1"\n'),
    }
    unit = ('[Unit]\nRequires=nftables.service\nAfter=nftables.service systemd-networkd.service\n'
            'BindsTo=nftables.service\n')
    # Each activation uses the selected image's complete FRR configuration.
    service = '[Service]\nExecReload=\n'
    pools = fallback_pools(value)['bgp_only']
    if pools:
        # Route ownership follows loopback, so a disconnected peer LAN cannot
        # remove the reject. A high-byte distance of 255 lets zebra prefer BGP.
        text_routes = '[Match]\nName=lo\n\n[Link]\nRequiredForOnline=no\n\n[Network]\nKeepConfiguration=yes\n'
        for family in (4, 6):
            # A contained pool needs no second reject hijacking a covering BGP path.
            selected = sorted((p for p in pools if p.version == family),
                              key=lambda p: (p.network_address, p.prefixlen))
            cover = None
            for prefix in selected:
                if cover is None or not prefix.subnet_of(cover):
                    text_routes += f'\n[Route]\nDestination={prefix}\nType=unreachable\nMetric={255 << 24}\n'
                    cover = prefix
        files['etc/systemd/network/10-bgp-fallback.network'] = text_routes
    if bindings:
        files['usr/share/lanrith/routing.json'] = canonical({
            'schema': 1, 'template': text, 'credentials': bindings}).decode()
        files['usr/lib/systemd/system/lanrith-routing-credentials.service'] = (
            '[Unit]\nDescription=Prepare authenticated routing configuration\n'
            'Before=frr.service\nAfter=nftables.service\nRequires=nftables.service\n'
            '[Service]\nType=oneshot\nRemainAfterExit=yes\nGroup=frr\nUMask=0027\n'
            'RuntimeDirectory=lanrith-routing\nRuntimeDirectoryMode=0750\n'
            'ProtectSystem=strict\nProtectHome=yes\nPrivateTmp=yes\nNoNewPrivileges=yes\n'
            'RestrictAddressFamilies=AF_UNIX\n'
            + ''.join(f'LoadCredential={key}:{runtime_bindings.credential_path(value, key)}\n'
                      for key in sorted(set(bindings.values())))
            + 'ExecStart=/usr/bin/python3 /usr/lib/lanrith/lanrith/routing_runtime.py\n')
        unit += (
            'Requires=lanrith-routing-credentials.service\nAfter=lanrith-routing-credentials.service\n'
            'BindsTo=lanrith-routing-credentials.service\n')
        service += 'BindReadOnlyPaths=/run/lanrith-routing/frr.conf:/etc/frr/frr.conf\n'
    files['etc/systemd/system/frr.service.d/60-lanrith-routing.conf'] = unit+'\n'+service
    return files
