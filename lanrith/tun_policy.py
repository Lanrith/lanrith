"""Compile ordered access at the client-facing boundary of each translator.

TAYGA owns translation and native allocation. This build-time module emits
policy and selector data; it never observes, allocates or supervises clients.
The client-facing family retains the original client on both requests and
replies. The other family supplies guarded transit through the trusted daemon.
"""

import hashlib
import ipaddress as ip

from . import access, integrations, intent, routing, translation
from .release import canonical, require


OWNER = 0x4c520001
DIRECTORY = 0x4c520002
TRANSIT = 0x4c520003


def quote(value):
    require(isinstance(value, str) and access.IFNAME.fullmatch(value), 'Invalid policy interface.')
    return '"'+value+'"'


def intersection(left, right):
    if left.version != right.version or not left.overlaps(right):
        return None
    return left if left.subnet_of(right) else right


def encoded(component, network):
    prefix = ip.ip_network(component['prefix'])
    require(prefix.prefixlen == 96 and network.version == 4, 'Expected a /96 translation prefix.')
    return ip.IPv6Network((int(prefix.network_address)+int(network.network_address), 96+network.prefixlen))


def route_scopes(value, family):
    """Partition declared route space, preserving longest-prefix attachment.

    Import pools bind dynamic BGP reachability to its configured attachment.
    Withdrawal must not make an internal destination eligible for WAN transit.
    """
    wan = value['hardware']['interfaces'][value['uplink']['interface']]['name']
    routes = []
    for key, network in value['networks'].items():
        prefixes = [ip.ip_interface(a).network for a in network['addresses']]
        prefixes += [ip.ip_network(a) for a in network.get('additional_subnets', [])]
        prefixes += [ip.ip_network(a) for a in network.get('routed_prefixes', [])]
        prefixes += [ip.ip_network(a) for a in routing.routed_sources(value, key)]
        for route in value.get('routing', {}).get('static_routes', []):
            if route['network'] == key:
                prefixes += integrations.prefixes(value, route['to'])
        routes += [(prefix, network['name']) for prefix in prefixes if prefix.version == family]
    seen = {}
    for prefix, interface in routes:
        require(prefix not in seen or seen[prefix] == interface, 'Ambiguous destination attachment.')
        seen[prefix] = interface
    maximum = (1 << (32 if family == 4 else 128))-1
    intervals = [(0, maximum, wan)]
    for prefix, interface in sorted(seen.items(), key=lambda item: (item[0].prefixlen, int(item[0].network_address))):
        first, last = int(prefix.network_address), int(prefix.broadcast_address)
        updated = []
        for low, high, previous in intervals:
            if high < first or last < low:
                updated.append((low, high, previous))
                continue
            if low < first:
                updated.append((low, first-1, previous))
            updated.append((max(low, first), min(high, last), interface))
            if last < high:
                updated.append((last+1, high, previous))
        intervals = updated
    address = ip.IPv4Address if family == 4 else ip.IPv6Address
    return [(prefix, interface) for first, last, interface in intervals
            for prefix in ip.summarize_address_range(address(first), address(last))]


class Compiler:
    def __init__(self, value, retained_allocations=None):
        self.value = value
        self.components = intent.translations(value)
        self.allocations = translation.allocate(value, retained_allocations)
        self.physical = sorted({value['hardware']['interfaces'][value['uplink']['interface']]['name'],
                                *(n['name'] for n in value['networks'].values())})
        self.clients = {family: [(ip.ip_network(prefix), network['name'])
                                 for key, network in value['networks'].items()
                                 if network.get('forwarding', True)
                                 for prefix in [*[str(ip.ip_interface(a).network) for a in network['addresses']],
                                                *network.get('additional_subnets', []),
                                                *network.get('routed_prefixes', []),
                                                *routing.routed_sources(value, key)]
                                 if ip.ip_network(prefix).version == family]
                        for family in (4, 6)}
        self.routes = {family: route_scopes(value, family) for family in (4, 6)}
        self.sets = {}
        self.rules = []

    def endpoint(self, selected, source):
        return access.selector(selected, self.value['networks'], self.value['hardware']['interfaces'],
                               self.value['uplink'], source=source)

    def targets(self, endpoint, family):
        """Native targets and the equivalent client-facing translator view."""
        addresses = endpoint['addresses']
        selected = endpoint['interface']
        result = set()
        all_network = ip.ip_network('0.0.0.0/0' if family == 4 else '::/0')
        native = [a for a in addresses or [all_network] if a.version == family]
        for interface in self.physical if selected is None else [selected]:
            if interface in self.physical:
                result.update((interface, prefix) for prefix in native)
        for component in self.components.values():
            device = component['interface']
            client_family = 6 if component['component'] == 'nat64' else 4
            if family != client_family:
                continue
            direct = ip.ip_network(component['prefix' if family == 6 else 'pool'])
            if selected in (None, device):
                for prefix in addresses or [direct]:
                    common = intersection(prefix, direct)
                    if common is not None:
                        result.add((device, common))
            if component['component'] == 'nat64':
                for scope, interface in self.routes[4]:
                    if selected not in (None, interface):
                        continue
                    for prefix in addresses or [scope]:
                        common = intersection(prefix, scope)
                        if common is not None:
                            result.add((device, encoded(component, common)))
            else:
                for mapping in component['mappings'].values():
                    target = ip.ip_address(mapping['ipv6'])
                    interface = next(interface for scope, interface in self.routes[6] if target in scope)
                    if selected in (None, interface) and (addresses is None or any(target in a for a in addresses)):
                        result.add((device, ip.ip_network(mapping['ipv4'])))
        return result

    def sources(self, endpoint, family):
        addresses = endpoint['addresses']
        selected = endpoint['interface']
        all_network = ip.ip_network('0.0.0.0/0' if family == 4 else '::/0')
        result = set()
        for interface in self.physical if selected is None else [selected]:
            if interface in self.physical:
                result.update((interface, prefix, endpoint['mac'])
                              for prefix in addresses or [all_network] if prefix.version == family)
        # On a translated callback the client-facing side still carries the
        # original client, while its peer is represented by a component prefix
        # (NAT64) or a configured alias (NAT46).
        for component in self.components.values():
            device = component['interface']
            if component['component'] == 'nat64' and family == 6:
                if endpoint['mac'] is not None:
                    continue  # Physical MAC predicates cannot be inferred from an IP packet.
                for scope, interface in self.routes[4]:
                    if selected not in (None, interface):
                        continue
                    for prefix in addresses or [scope]:
                        common = intersection(prefix, scope)
                        if common is not None:
                            result.add((device, encoded(component, common), None))
            elif component['component'] == 'nat46' and family == 4:
                if endpoint['mac'] is not None:
                    continue
                for mapping in component['mappings'].values():
                    target = ip.ip_address(mapping['ipv6'])
                    interface = next(interface for scope, interface in self.routes[6] if target in scope)
                    if selected in (None, interface) and (addresses is None or any(target in a for a in addresses)):
                        result.add((device, ip.ip_network(mapping['ipv4']), None))
        return result

    def selector_set(self, family, rows, source, mac=False):
        groups = {}
        for row in rows:
            key = (row[0], row[2] if source else None)
            groups.setdefault(key, []).append(row[1])
        compact = []
        for (interface, address_mac), prefixes in groups.items():
            compact += [(interface, prefix, address_mac) if source else (interface, prefix)
                        for prefix in ip.collapse_addresses(prefixes)]
        ordered = sorted(compact)
        key = (family, source, mac, tuple(ordered))
        if key not in self.sets:
            name = 'tp_'+hashlib.sha256(repr(key).encode()).hexdigest()[:16]
            self.sets[key] = name
        return self.sets[key]

    def compile(self):
        raw = self.value.get('access', {})
        require(not ({'internet', 'between_networks'} & set(raw)), 'TUN policy requires ordered access intent.')
        # Validation is shared with the public contract; names are metadata.
        normalized = intent.access(self.value)
        for index, rule in enumerate(normalized['rules']):
            sources = [self.endpoint(e, True) for e in rule['from']]
            targets = [self.endpoint(e, False) for e in rule['to']]
            access.render({'rules': [{**rule, 'from': 'any', 'to': 'any'}]},
                          self.value['networks'], self.value['hardware']['interfaces'], self.value['uplink'])
            for family in (4, 6):
                if rule.get('family') not in (None, 'ipv'+str(family)):
                    continue
                protocol = rule['protocol']
                if protocol in ('icmp', 'icmpv6') and family != (4 if protocol == 'icmp' else 6):
                    continue
                destination_rows = set().union(*(self.targets(e, family) for e in targets))
                source_rows = set().union(*(self.sources(e, family) for e in sources))
                for endpoint in sources:
                    if endpoint['mac'] is None:
                        continue
                    virtual = self.sources({**endpoint, 'mac': None}, family)
                    relevant = any(interface == attachment and intersection(prefix, scope) is not None
                                   for interface, prefix in destination_rows
                                   for scope, attachment in self.clients[family])
                    require(not relevant or not any(row[0] in self.components for row in virtual),
                            'A MAC-qualified translated callback needs original physical ingress evidence.')
                if not source_rows or not destination_rows:
                    continue
                # Each selector retains its interface/address/MAC conjunction.
                # Ordinary address lists become set entries, never rule copies.
                for mac in (False, True):
                    subset = {row for row in source_rows if (row[2] is not None) == mac}
                    if not subset:
                        continue
                    src = self.selector_set(family, subset, True, mac)
                    dst = self.selector_set(family, destination_rows, False)
                    spelling = 'ip' if family == 4 else 'ip6'
                    match = f'meta nfproto ipv{family} iifname . {spelling} saddr'
                    if mac:
                        match += ' . ether saddr'
                    match += f' @{src} oifname . {spelling} daddr @{dst}'
                    if protocol != 'any':
                        match += ' meta l4proto '+('ipv6-icmp' if protocol == 'icmpv6' else protocol)
                    if rule.get('ports'):
                        match += ' '+protocol+' dport { '+', '.join(map(str, sorted(rule['ports'])))+' }'
                    if rule.get('states'):
                        match += ' ct state { '+', '.join(sorted(rule['states']))+' }'
                    if rule.get('direction'):
                        match += ' ct direction '+rule['direction']
                    if rule.get('tcp_flags'):
                        flags = '('+' | '.join(sorted(rule['tcp_flags']))+')'
                        match += ' tcp flags & '+flags+' == '+flags
                    for field, suffix in (('icmp_types', 'type'), ('icmp_codes', 'code')):
                        if rule.get(field):
                            match += ' '+protocol+' '+suffix+' { '+', '.join(map(str, rule[field]))+' }'
                    if rule['action'] == 'deny':
                        verdict = 'drop'
                    else:
                        verdict = 'goto tp_'+{'owner': 'owner', 'directory': 'directory', 'inherit': 'inherit'}[rule['authorization']]
                    self.rules.append('  '+match+' '+verdict)
        return self

    def declarations(self):
        lines = []
        for (family, source, mac, rows), name in self.sets.items():
            types = f'ifname . ipv{family}_addr'+(' . ether_addr' if mac else '')
            entries = [quote(row[0])+' . '+str(row[1])+(' . '+row[2] if mac else '') for row in rows]
            lines.append(f' set {name} {{ type {types}; flags interval; auto-merge; elements = {{ '+', '.join(entries)+' }; }')
        return lines


def compile(value, retained_allocations=None):
    """Return a build-time fragment, without changing backend admission."""
    compiler = Compiler(value, retained_allocations).compile()
    return {'declarations': compiler.declarations(), 'rules': compiler.rules,
            'access_rules': len(compiler.rules), 'selector_sets': len(compiler.sets),
            'selector_entries': sum(len(key[3]) for key in compiler.sets),
            'client_facing_families': {name: 6 if c['component'] == 'nat64' else 4
                                       for name, c in compiler.components.items()},
            'allocations_sha256': hashlib.sha256(canonical(compiler.allocations)).hexdigest(),
            'source_sha256': hashlib.sha256(canonical(value)).hexdigest()}


def definitions(value, retained_allocations=None):
    """Compile the immutable program and initially empty delegated data sets.

    This fragment is not an independent admission decision. Its caller must
    install physical source validation, router/service protection and management
    isolation before calling forward(). Runtime writers update only set data.
    """
    compiler = Compiler(value, retained_allocations).compile()
    lines = compiler.declarations()
    client_families = {6 if c['component'] == 'nat64' else 4 for c in compiler.components.values()}
    transit_families = {4 if c['component'] == 'nat64' else 6 for c in compiler.components.values()}
    for family in (4, 6):
        lines += [f' set tp_grants{family} {{ type ipv{family}_addr . ipv{family}_addr . inet_proto . inet_service; '
                  'flags timeout; timeout 90s; size 16384; }',
                  f' set tp_echo{family} {{ type ipv{family}_addr . ipv{family}_addr; '
                  'flags timeout; timeout 90s; size 16384; }']
        if family in client_families:
            clients = sorted((interface, prefix) for prefix, interface in compiler.clients[family])
            entries = ', '.join(quote(interface)+' . '+str(prefix) for interface, prefix in clients)
            lines.append(f' set tp_clients{family} {{ type ifname . ipv{family}_addr; flags interval; auto-merge; '
                         +(f'elements = {{ {entries} }}; ' if entries else '')+'}')
        if family not in transit_families:
            continue
        # The partition is data shared by all components. Each physical
        # attachment has one two-rule check, independent of access/alias count.
        routes = compiler.routes[family]
        interfaces = sorted({interface for _, interface in routes})
        for index, interface in enumerate(interfaces):
            lines += [f' chain tp_route{family}_{index} {{',
                      f'  oifname != {quote(interface)} drop', '  return', ' }']
        rows = ', '.join(str(prefix)+f' : jump tp_route{family}_{interfaces.index(interface)}'
                         for prefix, interface in routes)
        lines += [f' map tp_routes{family} {{ type ipv{family}_addr : verdict; flags interval; '
                  f'elements = {{ {rows} }}; }}']
    lines += [' chain tp_fresh {',
              '  meta nfproto ipv4 ct protocol icmp ct original ip saddr . ct original ip daddr @tp_echo4 accept',
              '  meta nfproto ipv6 ct protocol ipv6-icmp ct original ip6 saddr . ct original ip6 daddr @tp_echo6 accept',
              '  meta nfproto ipv4 ct original ip saddr . ct original ip daddr . ct protocol . ct original proto-dst @tp_grants4 accept',
              '  meta nfproto ipv6 ct original ip6 saddr . ct original ip6 daddr . ct protocol . ct original proto-dst @tp_grants6 accept',
              '  drop', ' }',
              f' chain tp_owner {{ ct mark set {OWNER} accept; }}',
              f' chain tp_directory {{ ct mark set {DIRECTORY} goto tp_fresh; }}',
              ' chain tp_inherit {']
    policy = value.get('identity', {}).get('policy', {})
    managed = policy.get('networks', []) if policy.get('enabled', False) else []
    for key in managed:
        interface = value['networks'][key]['name']
        lines.append(f'  iifname {quote(interface)} goto tp_directory')
        for family in (4, 6):
            source = compiler.endpoint({'network': key}, True)
            for device, prefix, _ in sorted(compiler.sources(source, family)):
                if device in compiler.components:
                    spelling = 'ip' if family == 4 else 'ip6'
                    lines.append(f'  iifname {quote(device)} {spelling} saddr {prefix} goto tp_directory')
            endpoint = compiler.endpoint({'network': key}, False)
            for device, prefix in sorted(compiler.targets(endpoint, family)):
                spelling = 'ip' if family == 4 else 'ip6'
                lines.append(f'  oifname {quote(device)} {spelling} daddr {prefix} goto tp_directory')
    lines += ['  goto tp_owner', ' }', ' chain tp_boundary {']
    for component in compiler.components.values():
        device = quote(component['interface'])
        family = 6 if component['component'] == 'nat64' else 4
        spelling = 'ip' if family == 4 else 'ip6'
        # An alias/prefix is a LAN client facility. Neither WAN nor management
        # traffic becomes a translator client through a wildcard owner rule.
        lines += [f'  oifname {device} meta nfproto ipv{family} iifname . {spelling} saddr != @tp_clients{family} drop',
                  f'  iifname {device} meta nfproto ipv{family} oifname . {spelling} daddr != @tp_clients{family} drop']
        if component['component'] == 'nat64':
            # Dynamic allocations support outbound flows and stateful replies.
            # New callbacks use explicit active stable identities. An orphaned
            # connection in the other family cannot expose a dynamic client.
            stable = sorted(compiler.allocations['active']) if component['interface'] == 'nat64-internal' else []
            condition = (' ip6 daddr != { '+', '.join(stable)+' }') if stable else ''
            lines.append(f'  iifname {device} meta nfproto ipv6 ct mark != {{ {OWNER}, {DIRECTORY} }}{condition} drop')
        other, payload = (4, 'ip') if family == 6 else (6, 'ip6')
        lines += [f'  iifname {device} meta nfproto ipv{other} {payload} daddr vmap @tp_routes{other}']
    lines += [' }', ' chain tp_transit {']
    for component in compiler.components.values():
        device = quote(component['interface'])
        if component['component'] == 'nat64':
            lines += [f'  iifname {device} meta nfproto ipv4 ip saddr {component["pool"]} ct mark set {TRANSIT} accept',
                      f'  oifname {device} meta nfproto ipv4 ip daddr {component["pool"]} '
                      f'ct state established,related ct mark {TRANSIT} accept']
            stable = sorted(compiler.allocations['active'].values(), key=ip.ip_address) if component['interface'] == 'nat64-internal' else []
            if stable:
                lines.append(f'  oifname {device} ip daddr {{ '+', '.join(stable)+f' }} ct mark set {TRANSIT} accept')
            lines.append(f'  oifname {device} meta nfproto ipv4 drop')
        else:
            targets = ', '.join(m['ipv6'] for m in component['mappings'].values())
            lines += [f'  iifname {device} ip6 saddr {component["prefix"]} ip6 daddr {{ {targets} }} ct mark set {TRANSIT} accept',
                      f'  oifname {device} ip6 saddr {{ {targets} }} ip6 daddr {component["prefix"]} ct mark set {TRANSIT} accept']
    lines += [' }', ' chain tp_access {', *compiler.rules, '  drop', ' }']
    return lines


def forward():
    """Run after mandatory source, destination and service guards."""
    return ['  ct status & 512 != 0 drop', '  jump tp_boundary', f'  ct mark {DIRECTORY} goto tp_fresh',
            f'  ct state established,related ct direction reply ct mark {OWNER} accept',
            '  jump tp_transit', '  goto tp_access']
