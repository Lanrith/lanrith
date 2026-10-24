"""Validate and render ordinary routed allow/deny rules without topology roles."""

import ipaddress
import re

from .release import require


IFNAME = re.compile(r'[a-zA-Z0-9_.:-]{1,15}')
MAC = re.compile(r'(?:[0-9a-f]{2}:){5}[0-9a-f]{2}')
STATES = {'new', 'established', 'related'}
FLAGS = {'fin', 'syn', 'rst', 'psh', 'ack', 'urg', 'ece', 'cwr'}
ICMP = {
    'icmp': {'echo-request', 'echo-reply', 'destination-unreachable', 'time-exceeded',
             'parameter-problem', 'redirect'},
    'icmpv6': {'echo-request', 'echo-reply', 'destination-unreachable', 'packet-too-big',
               'time-exceeded', 'parameter-problem', 'nd-router-solicit', 'nd-router-advert',
               'nd-neighbor-solicit', 'nd-neighbor-advert'},
}
MAX_GENERATED = 4096


def fields(value, allowed, required=()):
    require(isinstance(value, dict) and set(required) <= set(value) <= set(allowed),
            'Unknown, missing or invalid access fields.')


def bounded_list(value, maximum, label):
    require(isinstance(value, list) and 1 <= len(value) <= maximum, label)
    return value


def selector(value, networks, interfaces, uplink, *, source):
    """A network name is enough; explicit selectors add interface/host scope."""
    if isinstance(value, str):
        value = {'network': value} if value in networks or value in ('any', 'uplink') else {'addresses': value}
    fields(value, {'network', 'interface', 'addresses', 'mac'})
    require(value and not ('network' in value and 'interface' in value), 'Declare one access interface selector.')
    interface = None
    if 'network' in value:
        network = value['network']
        require(isinstance(network, str) and network in {*networks, 'any', 'uplink'},
                'Access rule references an unknown network.')
        if network != 'any':
            interface = interfaces[uplink['interface']]['name'] if network == 'uplink' else networks[network]['name']
    if 'interface' in value:
        require(isinstance(value['interface'], str) and IFNAME.fullmatch(value['interface']),
                'Invalid access interface name.')
        interface = value['interface']
    addresses = None
    if 'addresses' in value:
        entries = [value['addresses']] if isinstance(value['addresses'], str) else value['addresses']
        bounded_list(entries, 256, 'Declare bounded access addresses.')
        addresses = []
        for entry in entries:
            require(isinstance(entry, str), 'Access addresses must be IP addresses or CIDRs.')
            try:
                address = ipaddress.ip_network(entry, strict=True)
            except ValueError:
                require(False, 'Access addresses must be aligned IP addresses or CIDRs.')
            require('%' not in entry, 'Access addresses must not contain zone identifiers.')
            addresses.append(address)
        require(len(addresses) == len(set(addresses)), 'Duplicate access address.')
    mac = value.get('mac')
    require('mac' not in value or source and isinstance(mac, str) and MAC.fullmatch(mac),
            'A source MAC must be a lower-case Ethernet address.')
    return {'interface': interface, 'addresses': addresses, 'mac': mac}


def endpoints(value, networks, interfaces, uplink, *, source):
    entries = bounded_list(value, 256, 'Declare bounded access endpoints.') if isinstance(value, list) else [value]
    return [selector(entry, networks, interfaces, uplink, source=source) for entry in entries]


def render(access, networks, interfaces, uplink, *, translated=None):
    """Return ordered forward rules; mandatory safety and return handling are separate."""
    fields(access, {'default', 'rules'})
    require(access.get('default', 'deny') == 'deny', 'The routed access default must remain deny.')
    require(not {'any', 'uplink'} & set(networks), 'Network names conflict with reserved access endpoints.')
    rules = access.get('rules', [])
    require(isinstance(rules, list) and len(rules) <= 256, 'Declare bounded access rules.')
    result = []
    names = set()
    for rule in rules:
        fields(rule, {'action', 'from', 'to', 'protocol', 'ports', 'family', 'states',
                      'direction', 'tcp_flags', 'icmp_types', 'icmp_codes', 'name', 'description', 'authorization'}, {'action', 'from', 'to'})
        if 'name' in rule:
            name = rule['name']
            require(isinstance(name, str) and 1 <= len(name) <= 96 and
                    name == name.strip() and name.isprintable(),
                    'Access rule names must contain 1–96 printable characters without surrounding whitespace.')
            require(name.casefold() not in names, 'Access rule names must be unique, ignoring case.')
            names.add(name.casefold())
        require(rule.get('authorization', 'inherit') in ('owner', 'directory', 'inherit'),
                'Unknown access authorization mode.')
        require(rule['action'] in ('allow', 'deny'), 'Access action must be allow or deny.')
        protocol = rule.get('protocol', 'any')
        require(protocol in ('any', 'tcp', 'udp', 'sctp', 'icmp', 'icmpv6', 'gre', 'esp', 'ah'),
                'Unsupported access protocol.')
        require('family' not in rule or rule['family'] in ('ipv4', 'ipv6'), 'Invalid access address family.')
        families = {4, 6} if 'family' not in rule else {4 if rule['family'] == 'ipv4' else 6}
        if protocol in ICMP:
            families &= {4 if protocol == 'icmp' else 6}
        ports = rule.get('ports')
        if 'ports' in rule:
            bounded_list(ports, 64, 'Declare bounded destination ports.')
            require(protocol in ('tcp', 'udp', 'sctp') and
                    all(type(port) is int and 1 <= port <= 65535 for port in ports) and
                    len(ports) == len(set(ports)), 'Destination ports require a transport protocol and unique valid ports.')
        states = rule.get('states', ['new', 'established', 'related'])
        bounded_list(states, 5, 'Declare bounded connection states.')
        require(all(isinstance(state, str) and state in STATES for state in states) and
                len(states) == len(set(states)), 'Invalid or duplicate connection state.')
        require('direction' not in rule or rule['direction'] in ('original', 'reply'), 'Invalid connection direction.')
        flags = rule.get('tcp_flags')
        if 'tcp_flags' in rule:
            bounded_list(flags, 8, 'Declare bounded TCP flags.')
            require(protocol == 'tcp' and all(isinstance(flag, str) and flag in FLAGS for flag in flags) and
                    len(flags) == len(set(flags)), 'TCP flags require TCP and unique supported flags.')
        types = rule.get('icmp_types')
        if 'icmp_types' in rule:
            bounded_list(types, 32, 'Declare bounded ICMP types.')
            require(protocol in ICMP and all(type(kind) is int and 0 <= kind <= 255 or
                    isinstance(kind, str) and kind in ICMP[protocol] for kind in types) and
                    len(types) == len(set(types)), 'ICMP types require the matching ICMP protocol.')
        codes = rule.get('icmp_codes')
        if 'icmp_codes' in rule:
            bounded_list(codes, 32, 'Declare bounded ICMP codes.')
            require(protocol in ICMP and all(type(code) is int and 0 <= code <= 255 for code in codes) and
                    len(codes) == len(set(codes)), 'ICMP codes require the matching ICMP protocol.')
        require('description' not in rule or isinstance(rule['description'], str) and
                len(rule['description']) <= 160 and not any(character in rule['description'] for character in '\r\n\x00'),
                'Invalid access description.')
        sources = endpoints(rule['from'], networks, interfaces, uplink, source=True)
        destinations = endpoints(rule['to'], networks, interfaces, uplink, source=False)
        emitted = 0
        for source in sources:
            for destination in destinations:
                possible = families.copy()
                for endpoint in (source, destination):
                    if endpoint['addresses'] is not None:
                        possible &= {address.version for address in endpoint['addresses']}
                if not possible:
                    continue
                # A family-neutral rule needs no duplicated IPv4/IPv6 form.
                versions = [None] if possible == {4, 6} and all(endpoint['addresses'] is None
                    for endpoint in (source, destination)) else sorted(possible)
                for version in versions:
                    conditions = []
                    if version is not None:
                        conditions.append('meta nfproto '+('ipv4' if version == 4 else 'ipv6'))
                    for endpoint, direction in ((source, 'i'), (destination, 'o')):
                        if endpoint['interface'] is not None:
                            conditions.append(f'{direction}ifname "{endpoint["interface"]}"')
                        if endpoint['addresses'] is not None:
                            values = ', '.join(str(address) for address in endpoint['addresses'] if address.version == version)
                            conditions.append(('ip' if version == 4 else 'ip6') +
                                              (' saddr' if direction == 'i' else ' daddr')+' { '+values+' }')
                    if source['mac'] is not None:
                        conditions.append('ether saddr '+source['mac'])
                    if protocol != 'any':
                        conditions.append('meta l4proto '+('ipv6-icmp' if protocol == 'icmpv6' else protocol))
                    if ports:
                        conditions.append(protocol+' dport { '+', '.join(str(port) for port in sorted(ports))+' }')
                    if flags:
                        value = '('+' | '.join(sorted(flags))+')'
                        conditions.append('tcp flags & '+value+' == '+value)
                    if types:
                        conditions.append(('icmp' if protocol == 'icmp' else 'icmpv6')+
                                          ' type { '+', '.join(str(kind) for kind in types)+' }')
                    if codes:
                        conditions.append(('icmp' if protocol == 'icmp' else 'icmpv6')+
                                          ' code { '+', '.join(str(code) for code in codes)+' }')
                    conditions.append('ct state { '+', '.join(states)+' }')
                    if rule.get('direction') is not None:
                        conditions.append('ct direction '+rule['direction'])
                    # A directory match is terminal when no fresh grant is present.
                    # The chain is populated only by the admitted policy agent.
                    conditions.append('jump directory_grants' if rule['action'] == 'allow' and
                        rule.get('authorization') == 'directory' else
                        'accept' if rule['action'] == 'allow' else 'drop')
                    result.append('  '+' '.join(conditions))
                    emitted += 1
                    require(len(result) <= MAX_GENERATED, 'Access policy exceeds its generated rule bound.')
        require(emitted or translated is not None and translated(rule),
                'An access rule must select at least one supported packet family.')
    return result
