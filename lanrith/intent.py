"""Expand concise owner intent into the shared, deterministic configuration model.

This module never reads a reference image, host hardware, or credentials. Private
migration bindings and verified hardware observations enter assembly separately.
"""

import copy
import hashlib
import ipaddress as ip
import re

from .release import ReleaseError, require


NAME = re.compile(r'[a-z][a-z0-9_-]{0,47}\Z')
SERVICE_OFFSETS = {'dns': (10, 0x10), 'authoritative': (11, 0x11), 'discovery': (12, 0x12),
                   'radius': (30, 0x30), 'ntp': (40, 0x40), 'metrics': (50, 0x50),
                   'logs': (60, 0x60)}


def fields(value, allowed, required=()):
    require(isinstance(value, dict) and set(required) <= set(value) <= set(allowed),
            'Unknown, missing or invalid intent fields.')


def sequence(value, maximum=256, minimum=0):
    require(isinstance(value, list) and minimum <= len(value) <= maximum,
            'Invalid or excessive intent list.')
    return value


def named(value, maximum=256):
    require(isinstance(value, dict) and len(value) <= maximum and
            all(isinstance(key, str) and NAME.fullmatch(key) for key in value),
            'Invalid or excessive named intent entries.')
    return value


def boolean(value):
    require(type(value) is bool, 'Feature flags must be booleans.')
    return value


def network(value, version=None, prefixlen=None):
    require(isinstance(value, str) and '%' not in value, 'Invalid IP prefix.')
    try:
        result = ip.ip_network(value, strict=True)
    except ValueError:
        raise ReleaseError('Invalid aligned IP prefix.') from None
    require((version is None or result.version == version) and
            (prefixlen is None or result.prefixlen == prefixlen) and
            not (result.is_multicast or result.is_loopback or result.is_link_local or
                 result.network_address.is_unspecified), 'Invalid IP allocation.')
    return result


def address(value, version=None):
    require(isinstance(value, str) and '%' not in value, 'Invalid IP address.')
    try:
        result = ip.ip_address(value)
    except ValueError:
        raise ReleaseError('Invalid IP address.') from None
    require((version is None or result.version == version) and
            not (result.is_multicast or result.is_loopback or result.is_unspecified),
            'Invalid unicast IP address.')
    return result


def subnet(prefix, identifier, length=64):
    prefix = network(prefix, 6, 48)
    require(type(identifier) is int and 0 <= identifier <= 65535, 'Invalid IPv6 subnet identifier.')
    return ip.IPv6Network((int(prefix.network_address) | identifier << 64, length))


def disjoint(allocations):
    for index, item in enumerate(allocations):
        require(all(item.version != other.version or not item.overlaps(other)
                    for other in allocations[:index]), 'Address allocations overlap.')


def prepare(value):
    """Expand only shorthand; repeated normalization is byte-for-byte stable."""
    fields(value, {'schema', 'hostname', 'hardware', 'uplink', 'networks', 'access', 'services',
                   'administration', 'release', 'extensions', 'addressing', 'groups', 'routing',
                   'translation', 'identity', 'observability', 'runtime'},
           {'schema', 'hostname', 'hardware', 'uplink', 'networks', 'administration'})
    value = copy.deepcopy(value)
    hardware = value['hardware']
    require(isinstance(hardware, dict), 'Invalid hardware configuration.')
    if isinstance(hardware.get('watchdog'), str):
        hardware['watchdog'] = {'mode': hardware['watchdog']}
    for interface in named(hardware.get('interfaces', {}), 64).values():
        require(isinstance(interface, dict), 'Invalid hardware interface.')
        require(interface.get('owner', 'linux') in ('linux', 'vpp') and
                interface.get('state', 'up') in ('up', 'down'), 'Invalid interface ownership or state.')
        require(interface.get('name') not in ('lr-services', 'lr-host'), 'Interface name is reserved for core services.')
        if interface.get('owner') == 'vpp':
            require(interface.get('state') == 'down', 'Active VPP transit is not yet qualified.')
            require(set(interface.get('match', {})) == {'mac'}, 'VPP ownership needs an exact MAC selector.')

    addressing = value.setdefault('addressing', {})
    fields(addressing, {'ula_prefix', 'services'})
    if 'ula_prefix' not in addressing:
        # Stable across recompiles, including hosts without an assembly identity yet.
        seed = hardware.get('machine_id', value['hostname'])
        require(isinstance(seed, str), 'Invalid ULA identity seed.')
        identifier = int.from_bytes(hashlib.sha256(seed.encode()).digest()[:5], 'big')
        addressing['ula_prefix'] = str(ip.IPv6Network(((0xfd << 120) | (identifier << 80), 48)))
    ula = network(addressing['ula_prefix'], 6, 48)
    require(ula.subnet_of(ip.IPv6Network('fd00::/8')), 'ULA must use a locally assigned /48.')
    service_ranges = addressing.setdefault('services', {})
    fields(service_ranges, {'ipv4', 'ipv6'})
    service_ranges.setdefault('ipv4', '10.255.254.0/24')
    service_ranges.setdefault('ipv6', str(subnet(str(ula), 0xfe02)))
    pool4 = network(service_ranges['ipv4'], 4)
    pool6 = network(service_ranges['ipv6'], 6, 64)
    require(pool4.prefixlen <= 26 and pool4.is_private and pool6.subnet_of(ula),
            'Managed service ranges need private IPv4 capacity and a /64 under the ULA.')

    uplink = value['uplink']
    require(isinstance(uplink, dict), 'Invalid uplink.')
    for family in (4, 6):
        key = 'ipv'+str(family)
        entry = uplink.get(key)
        if isinstance(entry, dict):
            fields(entry, {'address', 'gateway'} | ({'downstream_prefix', 'delivery'} if family == 6 else set()),
                   {'address', 'gateway'})
            require(not any(ip.ip_interface(a).version == family for a in uplink.get('addresses', [])),
                    'Duplicate uplink addressing syntax.')
            require(ip.ip_interface(entry['address']).version == family and
                    address(entry['gateway']).version == family, 'Uplink address family mismatch.')
            uplink.setdefault('addresses', []).append(entry['address'])
            uplink.setdefault('gateways', []).append(entry['gateway'])
            uplink[key] = 'static'
            for option in ('downstream_prefix', 'delivery'):
                if option in entry:
                    require(option not in uplink, 'Duplicate downstream prefix or delivery mode.')
                    uplink[option] = entry[option]
    downstream = uplink.get('downstream_prefix')
    if downstream is not None:
        network(downstream, 6, 48)
        require(uplink.get('ipv6', 'ra') != 'disabled', 'GUA delegation requires an IPv6 uplink.')
    require('delivery' not in uplink or downstream is not None and
            uplink['delivery'] in ('routed', 'on_link'), 'Invalid downstream delivery mode.')
    if 'upload_mbps' in uplink:
        require('upload_shaping' not in uplink, 'Duplicate upload shaping configuration.')
        uplink['upload_shaping'] = {'mbps': uplink.pop('upload_mbps')}
    uplink.setdefault('masquerade', True)
    for entry in sequence(uplink.get('private_services', []), 64):
        require(address(entry).is_private, 'Upstream private service must be a private IP address.')

    services = value.setdefault('services', {})
    require(isinstance(services, dict), 'Invalid services configuration.')
    for feature in ('dns', 'ntp', 'dhcp4'):
        entry = services.setdefault(feature, {})
        require(isinstance(entry, dict), 'Invalid service configuration.')
        entry.setdefault('enabled', any('dhcp4' in n for n in value.get('networks', {}).values())
                         if feature == 'dhcp4' else True)
        boolean(entry['enabled'])
    networks = named(value['networks'], 64)
    for key, item in networks.items():
        require(isinstance(item, dict), 'Invalid network.')
        require(item.get('role', 'lan') in ('lan', 'management'), 'Invalid network role.')
        require(item.get('name') not in ('lr-services', 'lr-host') and item.get('namespace') != 'lanrith-services',
                'Network name or namespace conflicts with managed services.')
        management = item.get('role') == 'management'
        if 'ipv4' in item or 'ipv6' in item:
            require('addresses' not in item, 'Do not combine shorthand and gateway addresses.')
            item['addresses'] = []
            v4 = item.pop('ipv4', None)
            if v4 is not None:
                v4 = {'subnet': v4} if isinstance(v4, str) else v4
                fields(v4, {'subnet', 'address'}, {'subnet'})
                prefix = network(v4['subnet'], 4)
                gateway = address(v4.get('address', str(prefix.network_address+1)), 4)
                require(gateway in prefix and gateway not in (prefix.network_address, prefix.broadcast_address),
                        'IPv4 gateway is not a usable subnet address.')
                item['addresses'].append(f'{gateway}/{prefix.prefixlen}')
            v6 = item.pop('ipv6', None)
            if v6 is not None:
                fields(v6, {'subnet_id', 'ra', 'gua'}, {'subnet_id'})
                require('ra' not in item, 'Duplicate RA configuration.')
                item['ra'] = boolean(v6.get('ra', True))
                gua = boolean(v6.get('gua', downstream is not None))
                require(not gua or downstream is not None, 'GUA requires a downstream prefix.')
                for prefix in [str(ula)] + ([downstream] if gua else []):
                    selected = subnet(prefix, v6['subnet_id'])
                    item['addresses'].append(str(selected.network_address+1)+'/64')
        if management:
            require(not item.get('forwarding', False) and not item.get('ra', False) and
                    not any(item.get(feature, False) for feature in ('dns', 'ntp')) and
                    not item.get('dhcp4'), 'Management networks cannot enable LAN services or forwarding.')
            item.update(forwarding=False, dns=False, ntp=False, ra=False)
        for feature in ('dns', 'ntp'):
            # Global disable is authoritative; a per-network flag can further restrict it.
            enabled = boolean(item.get(feature, not management)) and services[feature]['enabled']
            item[feature] = enabled
        if 'dhcp4' in item:
            dhcp = item['dhcp4']
            fields(dhcp, {'enabled', 'pool', 'pools', 'reservations'})
            enabled = boolean(dhcp.get('enabled', True)) and services['dhcp4']['enabled']
            if not enabled:
                del item['dhcp4']
            else:
                dhcp.pop('enabled', None)
                if 'pool' in dhcp:
                    require('pools' not in dhcp, 'Duplicate DHCP pool syntax.')
                    sequence(dhcp['pool'], 2, 2)
                    dhcp['pools'] = ['-'.join(dhcp.pop('pool'))]
                validate_dhcp(dhcp, item['addresses'])
        for entry in sequence(item.get('additional_subnets', []), 32):
            prefix = network(entry)
            require(prefix.prefixlen <= (30 if prefix.version == 4 else 126),
                    'Additional attachment subnet needs room for a gateway and clients.')
            require(any(ip.ip_interface(a).version == prefix.version for a in item['addresses']),
                    'Additional attachment needs the same address family on its network.')
        require(item.get('interface') in hardware.get('interfaces', {}) and
                hardware['interfaces'][item['interface']].get('owner', 'linux') == 'linux' and
                hardware['interfaces'][item['interface']].get('state', 'up') == 'up',
                'LAN networks require an active Linux-owned interface.')
    require(uplink.get('interface') in hardware.get('interfaces', {}) and
            hardware['interfaces'][uplink['interface']].get('owner', 'linux') == 'linux' and
            hardware['interfaces'][uplink['interface']].get('state', 'up') == 'up',
            'The uplink requires an active Linux-owned interface.')

    entries = value.get('extensions', [])
    if isinstance(entries, list) and any(isinstance(entry, dict) for entry in entries):
        result = []
        seen = set()
        for entry in entries:
            fields(entry, {'id', 'enabled'}, {'id'})
            require(isinstance(entry['id'], str) and entry['id'] not in seen,
                    'Duplicate extension identity.')
            seen.add(entry['id'])
            if boolean(entry.get('enabled', True)):
                result.append(entry['id'])
        value['extensions'] = result
    return value


def validate_dhcp(dhcp, gateways):
    sequence(dhcp.get('pools', []), 64, 1)
    gateways = [ip.ip_interface(a) for a in gateways if ip.ip_interface(a).version == 4]
    require(len(gateways) == 1, 'DHCPv4 requires one IPv4 subnet.')
    gateway = gateways[0]
    allocated = []
    for pool in dhcp['pools']:
        require(isinstance(pool, str) and pool.count('-') == 1, 'Invalid DHCP pool.')
        first, last = (address(part.strip(), 4) for part in pool.split('-'))
        require(first <= last and first in gateway.network and last in gateway.network and
                first != gateway.network.network_address and last != gateway.network.broadcast_address and
                not first <= gateway.ip <= last, 'DHCP pool conflicts with its subnet or gateway.')
        require(all(last < low or first > high for low, high in allocated), 'DHCP pools overlap.')
        allocated.append((first, last))
    identities, reserved = set(), set()
    for reservation in sequence(dhcp.get('reservations', []), 256):
        fields(reservation, {'mac', 'address', 'hostname'}, {'mac', 'address'})
        mac = reservation['mac']
        require(isinstance(mac, str) and re.fullmatch(r'(?:[0-9a-f]{2}:){5}[0-9a-f]{2}', mac) and
                mac not in identities, 'Invalid or duplicate DHCP reservation identity.')
        target = address(reservation['address'], 4)
        require(target in gateway.network and target not in (gateway.ip, gateway.network.network_address,
                gateway.network.broadcast_address) and target not in reserved and
                not any(first <= target <= last for first, last in allocated),
                'DHCP reservation conflicts with the gateway, pool, or another reservation.')
        require('hostname' not in reservation or isinstance(reservation['hostname'], str) and
                re.fullmatch(r'[a-z0-9][a-z0-9-]{0,62}', reservation['hostname']), 'Invalid reservation hostname.')
        identities.add(mac)
        reserved.add(target)


def service_networks(value):
    """All managed service ranges, including the mirrored provider subnet."""
    ranges = value['addressing']['services']
    result = [network(ranges['ipv4'], 4), network(ranges['ipv6'], 6)]
    if value['uplink'].get('downstream_prefix'):
        identifier = (int(result[1].network_address) >> 64) & 65535
        result.append(subnet(value['uplink']['downstream_prefix'], identifier))
    return result


def service_addresses(value, feature):
    offset4, offset6 = SERVICE_OFFSETS[feature]
    return [str(pool.network_address+(offset4 if pool.version == 4 else offset6)) for pool in service_networks(value)]


def gateway_addresses(network):
    """Additional on-link attachment ranges also need a local gateway."""
    return network['addresses'] + [
        str(ip.ip_network(prefix).network_address+1)+'/'+str(ip.ip_network(prefix).prefixlen)
        for prefix in network.get('additional_subnets', [])]


def uplink_nat(value):
    """Generated IPv4 source translation supplies connectivity, never access."""
    uplink, networks = value['uplink'], value['networks']
    if uplink.get('ipv4', 'dhcp') == 'disabled' or 'masquerade' in uplink and not uplink['masquerade']:
        return []
    selected = networks if uplink.get('masquerade') else value['access'].get('internet', [])
    addresses = [str(ip.ip_interface(address).ip) for address in uplink.get('addresses', [])
                 if ip.ip_interface(address).version == 4]
    result = []
    for key in selected:
        network = networks[key]
        if not network.get('forwarding', True):
            continue
        sources = [str(ip.ip_interface(address).network) for address in network['addresses']
                   if ip.ip_interface(address).version == 4]
        sources += [prefix for prefix in network.get('routed_prefixes', []) + network.get('additional_subnets', [])
                    if ip.ip_network(prefix).version == 4]
        if sources:
            result.append({'interface': network['name'], 'sources': list(dict.fromkeys(sources)),
                           'addresses': addresses.copy()})
    return result


def translations(value):
    """Return independent translator manifests; no manifest grants permission."""
    declarations = value.get('translation', {})
    fields(declarations, {'nat64', 'nat46'})
    result = {}
    ula = value['addressing']['ula_prefix']
    for name, settings in declarations.items():
        fields(settings, {'enabled', 'internet_pool', 'private_pool'} if name == 'nat64' else
               {'enabled', 'pool', 'mappings'})
        enabled = boolean(settings.get('enabled', False))
        if name == 'nat64':
            for label, default, interface, prefix, endpoint in (
                ('internet_pool', '10.255.224.0/20', 'nat64', '64:ff9b::/96',
                 str(subnet(ula, 0xfd64).network_address+1)),
                ('private_pool', '10.255.208.0/20', 'nat64-internal', str(subnet(ula, 0xfd65, 96)),
                 str(subnet(ula, 0xfd65).network_address+(0xffff << 48)+1))):
                pool = network(settings.get(label, default), 4)
                require(pool.is_private and 16 <= pool.prefixlen <= 28, 'Invalid NAT64 source pool.')
                if enabled:
                    result[interface] = {'component': name, 'interface': interface, 'pool': str(pool),
                        'prefix': prefix, 'ipv4': str(pool.network_address+1), 'ipv6': endpoint, 'mappings': {}}
        else:
            pool = network(settings.get('pool', '10.255.200.0/24'), 4)
            require(pool.is_private and 16 <= pool.prefixlen <= 29, 'Invalid NAT46 alias pool.')
            mappings = named(settings.get('mappings', {}))
            seen4, seen6 = set(), set()
            for entry in mappings.values():
                fields(entry, {'ipv4', 'ipv6'}, {'ipv4', 'ipv6'})
                a4, a6 = address(entry['ipv4'], 4), address(entry['ipv6'], 6)
                require(a4 in pool and a4 not in (pool.network_address, pool.network_address+1, pool.broadcast_address)
                        and a4 not in seen4 and a6 not in seen6 and not a6.is_link_local and a6.ipv4_mapped is None,
                        'Duplicate, reserved, or out-of-pool NAT46 mapping.')
                seen4.add(a4)
                seen6.add(a6)
            if enabled:
                require(mappings, 'Enabled NAT46 needs explicit destination mappings.')
                result[name] = {'component': name, 'interface': name, 'pool': str(pool),
                    'prefix': str(subnet(ula, 0xfd46, 96)), 'ipv4': str(pool.network_address+1),
                    'ipv6': str(subnet(ula, 0xfd46).network_address+(0xffff << 48)+1),
                    'mappings': copy.deepcopy(mappings)}
    return result


def expand(value, selected, *, stack=()):
    """Resolve group conjunctions without dropping interface or address scope."""
    groups = named(value.get('groups', {}))
    result = []
    for entry in selected if isinstance(selected, list) else [selected]:
        require(len(stack) <= 16, 'Access group nesting exceeds its bound.')
        if isinstance(entry, str):
            entry = {'network': entry} if entry in value['networks'] or entry in ('uplink', 'any') else {'addresses': entry}
        fields(entry, {'network', 'interface', 'addresses', 'mac', 'group', 'translation', 'alias_target'})
        special = set(entry) & {'group', 'translation', 'alias_target'}
        require(len(special) <= 1, 'Ambiguous endpoint reference.')
        scope = {k: v for k, v in entry.items() if k not in special}
        if 'group' in entry:
            key = entry['group']
            require(isinstance(key, str) and key in groups and key not in stack,
                    'Unknown or cyclic access group.')
            for child in expand(value, groups[key], stack=(*stack, key)):
                require(all(k not in child or child[k] == v for k, v in scope.items()),
                        'Group qualifier conflicts with its endpoint scope.')
                result.append({**child, **scope})
        elif 'translation' in entry:
            require(set(entry) == {'translation'}, 'Translation selectors cannot override component scope.')
            components = translations(value)
            require(entry['translation'] in ('nat64', 'nat46'), 'Unknown translation component.')
            matches = [c for c in components.values() if c['component'] == entry['translation']]
            require(matches, 'Access references a disabled translation component.')
            for component in matches:
                result.append({'interface': component['interface'], 'addresses': [component[
                    'pool' if entry['translation'] == 'nat46' else 'prefix']]})
        elif 'alias_target' in entry:
            require('addresses' not in scope, 'An alias target already selects an address.')
            mappings = translations(value).get('nat46', {}).get('mappings', {})
            require(isinstance(entry['alias_target'], str) and entry['alias_target'] in mappings,
                    'Unknown alias target or disabled NAT46 component.')
            result.append({**scope, 'addresses': [str(ip.ip_network(mappings[entry['alias_target']]['ipv6']))]})
        else:
            require(scope, 'Empty access selector.')
            if 'addresses' in scope:
                entries = [scope['addresses']] if isinstance(scope['addresses'], str) else sequence(scope['addresses'], 256, 1)
                addresses = []
                for raw in entries:
                    require(isinstance(raw, str), 'Invalid endpoint address.')
                    if '-' in raw:
                        require(raw.count('-') == 1, 'Invalid endpoint address range.')
                        first, last = (address(a) for a in raw.split('-'))
                        require(first.version == last.version and first <= last, 'Invalid endpoint address range.')
                        addresses.extend(str(n) for n in ip.summarize_address_range(first, last))
                    else:
                        try:
                            require('%' not in raw, 'Scoped endpoint addresses are not supported.')
                            addresses.append(str(ip.ip_network(raw)))
                        except ValueError:
                            raise ReleaseError('Invalid endpoint prefix.') from None
                require(len(addresses) <= 256, 'Expanded endpoint exceeds its address bound.')
                scope['addresses'] = addresses
            result.append(scope)
        require(len(result) <= 256, 'Expanded group exceeds its endpoint bound.')
    return result


def access(value):
    declaration = value.get('access', {})
    if not ({'default', 'rules'} & set(declaration)):
        return declaration
    fields(declaration, {'default', 'rules', 'delegation_limits'})
    result = {'default': declaration.get('default', 'deny'), 'rules': []}
    for rule in sequence(declaration.get('rules', [])):
        require(isinstance(rule, dict), 'Invalid access rule.')
        for endpoint in ('from', 'to'):
            require(endpoint in rule, 'Missing access endpoint.')
        authorization = rule.get('authorization', 'inherit')
        require(authorization in ('owner', 'directory', 'inherit'), 'Unknown authorization mode.')
        require(rule.get('action') == 'allow' or 'authorization' not in rule,
                'Authorization modes apply only to allow rules.')
        protocols = rule.get('protocol', 'any')
        protocols = protocols if isinstance(protocols, list) else [protocols]
        sequence(protocols, 8, 1)
        require(all(isinstance(p, str) for p in protocols) and len(set(protocols)) == len(protocols),
                'Invalid or duplicate protocols.')
        sources, destinations = expand(value, rule['from']), expand(value, rule['to'])
        possible = {4, 6}
        for entries in (sources, destinations):
            possible &= set().union(*({ip.ip_network(a).version for a in entry['addresses']}
                                      if 'addresses' in entry else {4, 6} for entry in entries))
        if not possible and translations(value):
            # The renderer must still prove that a declared mapping supports the
            # cross-family selector. This only keeps ICMP available for that check.
            possible = ({4} if translations(value).get('nat46') else set()) | ({6} if translations(value).get('nat64') else set())
        emitted = 0
        for protocol in protocols:
            for native in ('icmp', 'icmpv6') if protocol == 'icmp' and 'family' not in rule else (protocol,):
                if protocol == 'icmp' and native in ('icmp', 'icmpv6') and (4 if native == 'icmp' else 6) not in possible:
                    continue
                expanded = {**rule, 'from': sources,
                    'to': destinations, 'protocol': native, 'authorization': authorization}
                if emitted:
                    expanded.pop('name', None)
                result['rules'].append(expanded)
                emitted += 1
        require(emitted, 'Access rule has no supported address family.')
    return result


def validate_allocations(value):
    connected = [ip.ip_interface(a).network for n in value['networks'].values() for a in n['addresses']]
    additional = [network(a) for n in value['networks'].values() for a in n.get('additional_subnets', [])]
    services = service_networks(value)
    components = translations(value)
    interface_names = {n['name'] for n in value['networks'].values()} | {
        n['name'] for n in value['hardware']['interfaces'].values()}
    require(not set(components) & interface_names, 'Translator interface name conflicts with a declared attachment.')
    translated = [network(c[key]) for c in components.values() for key in ('pool', 'prefix')]
    # Translator control addresses can be outside their translation prefixes.
    endpoints = [network(c['ipv6']) for c in components.values()]
    disjoint(connected+additional+services+translated+endpoints)
    for a in value['uplink'].get('addresses', []):
        wan = ip.ip_interface(a)
        for candidate in connected+additional+services+translated+endpoints:
            if candidate.version == wan.version and candidate.overlaps(wan.network):
                downstream = value['uplink'].get('downstream_prefix')
                require(candidate.version == 6 and downstream and candidate.subnet_of(network(downstream)) and
                        wan.network == network(downstream) and value['uplink'].get('delivery') == 'on_link' and
                        wan.ip not in candidate and all(address(g) not in candidate for g in
                            value['uplink'].get('gateways', []) if address(g).version == 6),
                        'Internal and uplink allocations overlap.')
    for component in components.values():
        for entry in component['mappings'].values():
            target = address(entry['ipv6'])
            require(not any(target in prefix for prefix in services+translated+endpoints if prefix.version == 6),
                    'NAT46 cannot target generated services or another translator.')
            require(all(target != ip.ip_interface(a).ip for n in value['networks'].values()
                        for a in gateway_addresses(n)) and all(target != ip.ip_interface(a).ip
                        for a in value['uplink'].get('addresses', [])),
                    'NAT46 cannot target a router control address.')
            require(not any(target in ip.ip_interface(a).network for n in value['networks'].values()
                    if not n.get('forwarding', True) for a in n['addresses'] if ':' in a),
                    'NAT46 cannot target an isolated management network.')
