"""Compile narrow, owner-admitted extension access behind the core guards."""

import ipaddress as ip

from . import intent, routing, service_plane
from .release import require


def declarations(value, identities):
    require(isinstance(value, dict) and set(value) <= {'listeners', 'services'},
            'Invalid integration network declaration.')
    users = {entry['name']: entry['uid'] for entry in identities['users']}
    result = {}
    for kind, fields in (('listeners', {'user', 'network', 'address', 'sources', 'protocol', 'port'}),
                         ('services', {'user', 'service', 'family'})):
        entries = value.get(kind, [])
        require(isinstance(entries, list) and len(entries) <= 64,
                'Integration network count exceeds its bound.')
        result[kind] = []
        for entry in entries:
            require(isinstance(entry, dict) and set(entry) == fields and
                    isinstance(entry['user'], str) and entry['user'] in users,
                    'Integration network access requires its own declared service identity.')
            if kind == 'listeners':
                require(isinstance(entry['network'], str) and isinstance(entry['address'], str) and
                        isinstance(entry['protocol'], str) and entry['protocol'] in ('tcp', 'udp') and
                        type(entry['port']) is int and 1024 <= entry['port'] <= 65535 and
                        isinstance(entry['sources'], list) and 0 < len(entry['sources']) <= 64 and
                        all(isinstance(source, str) for source in entry['sources']),
                        'Invalid integration listener scope.')
                try:
                    address = ip.ip_address(entry['address'])
                    sources = [ip.ip_network(source, strict=True) for source in entry['sources']]
                except ValueError:
                    require(False, 'Invalid integration listener address.')
                require(str(address) == entry['address'] and len(set(sources)) == len(sources) and
                        all(source.version == address.version and source.prefixlen > 0 and
                            str(source) == raw for source, raw in zip(sources, entry['sources'])),
                        'Integration listener needs canonical, same-family bounded sources.')
            else:
                # Start with the read-only managed metrics API. Other service
                # contracts need their own consumer ACL and protocol validation.
                require(entry['service'] == 'metrics' and type(entry['family']) is int and
                        entry['family'] in (4, 6), 'Unsupported integration service dependency.')
            result[kind].append({**entry, 'uid': users[entry['user']]})
    return result


def resolve(value, declarations):
    result = {'listeners': [], 'services': []}
    bindings = {}
    for selected in declarations:
        for entry in selected['listeners']:
            network = value['networks'].get(entry['network'])
            require(network is not None and 'namespace' not in network,
                    'Integration listener needs a declared host attachment.')
            address = ip.ip_address(entry['address'])
            local = [ip.ip_interface(raw).ip for raw in intent.gateway_addresses(network)]
            require(address in local and entry['port'] != value['administration'].get('ssh_port', 22),
                    'Integration listener must use its attachment address and cannot claim SSH.')
            pools = [ip.ip_interface(raw).network for raw in intent.gateway_addresses(network)]
            pools += [ip.ip_network(raw) for raw in network.get('routed_prefixes', []) +
                      routing.routed_sources(value, entry['network'])]
            invalid = [ip.ip_network(raw) for raw in (
                ('0.0.0.0/8', '127.0.0.0/8', '169.254.0.0/16', '224.0.0.0/3') if address.version == 4 else
                ('::/128', '::1/128', 'fe80::/10', 'ff00::/8'))]
            for raw in entry['sources']:
                source = ip.ip_network(raw)
                require(any(source.version == pool.version and source.subnet_of(pool) for pool in pools) and
                        not any(source.overlaps(pool) for pool in invalid),
                        'Integration listener source is outside its validated attachment.')
            binding = (entry['address'], entry['protocol'], entry['port'])
            require(binding not in bindings or bindings[binding] == entry['uid'],
                    'Integration listeners conflict on a local socket.')
            bindings[binding] = entry['uid']
            result['listeners'].append({**entry, 'interface': network['name']})
        for entry in selected['services']:
            plane = service_plane.topology(value)
            require(entry['service'] in plane['endpoints'],
                    'Integration references a disabled managed service.')
            targets = [raw for raw in plane['endpoints'][entry['service']]
                       if ip.ip_address(raw).version == entry['family']]
            sources = [str(ip.ip_interface(raw).ip) for raw in plane['host_addresses']
                       if ip.ip_interface(raw).version == entry['family']]
            require(targets and len(sources) == 1, 'Integration service address family is unavailable.')
            result['services'].append({**entry, 'source': sources[0], 'targets': targets,
                                      'interface': plane['host_link'], 'protocol': 'tcp', 'port': 9100})
    require(sum(len(entries) for entries in result.values()) <= 256,
            'Combined integration network declarations exceed their bound.')
    return result


def input_rules(plan):
    from .firewall import values
    result = []
    for entry in (plan or {}).get('listeners', []):
        spelling = 'ip6' if ':' in entry['address'] else 'ip'
        result.append(f'  iifname "{entry["interface"]}" {spelling} saddr {values(entry["sources"])} '
                      f'{spelling} daddr {entry["address"]} {entry["protocol"]} dport {entry["port"]} '
                      'ct state new accept')
    return result


def output_chain(plan):
    """Check external socket packets before conntrack can substitute for a UID."""
    from .firewall import values
    if not plan or not any(plan.values()):
        return []
    lines = [' chain extension_output {']
    users = set()
    for entry in plan['listeners']:
        users.add(entry['uid'])
        spelling = 'ip6' if ':' in entry['address'] else 'ip'
        lines.append(f'  meta skuid {entry["uid"]} oifname "{entry["interface"]}" '
                     f'{spelling} saddr {entry["address"]} {spelling} daddr {values(entry["sources"])} '
                     f'{entry["protocol"]} sport {entry["port"]} ct direction reply '
                     'ct state established,related accept')
    for entry in plan['services']:
        users.add(entry['uid'])
        spelling = 'ip6' if entry['family'] == 6 else 'ip'
        lines.append(f'  meta skuid {entry["uid"]} oifname "{entry["interface"]}" '
                     f'{spelling} saddr {entry["source"]} {spelling} daddr {values(entry["targets"])} '
                     f'{entry["protocol"]} dport {entry["port"]} ct direction original '
                     'ct state new,established,related accept')
    # Another unprivileged UID must not reuse a closed extension socket's
    # still-tracked tuple. Root retains the platform's existing authority.
    for entry in plan['listeners']:
        spelling = 'ip6' if ':' in entry['address'] else 'ip'
        lines.append(f'  meta skuid != 0 oifname "{entry["interface"]}" '
                     f'{spelling} saddr {entry["address"]} {entry["protocol"]} sport {entry["port"]} drop')
    for entry in plan['services']:
        spelling = 'ip6' if entry['family'] == 6 else 'ip'
        lines.append(f'  meta skuid != 0 oifname "{entry["interface"]}" '
                     f'{spelling} daddr {values(entry["targets"])} {entry["protocol"]} dport {entry["port"]} drop')
    return lines + ['  meta skuid '+values(sorted(users))+' drop', ' }']


def namespace_rules(plan):
    from .firewall import values
    result = []
    for entry in (plan or {}).get('services', []):
        spelling = 'ip6' if entry['family'] == 6 else 'ip'
        result.append(f'  iifname "{service_plane.SERVICE_LINK}" {spelling} saddr {entry["source"]} '
                      f'{spelling} daddr {values(entry["targets"])} '
                      f'{entry["protocol"]} dport {entry["port"]} accept')
    return list(dict.fromkeys(result))
