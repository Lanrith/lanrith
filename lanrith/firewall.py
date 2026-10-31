"""Generate baseline guards and service rules from declared router intent."""

import ipaddress

from . import access, intent, service_plane, routing, nat46, nat64, metrics, snmp, discovery, extension_network


ERRORS6 = 'destination-unreachable, packet-too-big, time-exceeded, parameter-problem'
NEIGHBOURS = 'nd-neighbor-solicit, nd-neighbor-advert'
POLICY_FORWARD_MARKS = (
    '0xb1000000', '0xb2000000', '0xb3000000',
    '0xd1000000', '0xd2000000', '0xd3000000', '0xd4000000', '0xd5000000', '0xd6000000',
    '0xf1000000', '0xf2000000', '0xf3000000', '0xf4000000', '0xf5000000', '0xf6000000',
)


def sysctls():
    lines = ['net.ipv4.ip_forward=1', 'net.ipv6.conf.all.forwarding=1']
    for family in ('ipv4', 'ipv6'):
        # Defaults protect later links; globs also fix already-present links,
        # including names with dots. IPv6 zero still permits type-2 headers.
        for scope in ('all', 'default', '*'):
            lines.append(f'net/{family}/conf/{scope}/accept_source_route={-1 if family == "ipv6" else 0}')
            lines.append(f'net/{family}/conf/{scope}/accept_redirects=0')
            if family == 'ipv4':
                lines.extend(f'net/ipv4/conf/{scope}/{option}=0' for option in ('secure_redirects', 'send_redirects'))
    lines += ['net.ipv4.tcp_syncookies=1', 'net.ipv4.icmp_echo_ignore_broadcasts=1',
              'net.ipv4.icmp_ignore_bogus_error_responses=1']
    return '\n'.join(lines)+'\n'


def addresses(network, family):
    return [ipaddress.ip_interface(address) for address in network['addresses']
            if ipaddress.ip_interface(address).version == family]


def prefixes(network, family, value=None):
    routed = [] if value is None else routing.routed_sources(
        value, next(key for key, entry in value['networks'].items() if entry is network))
    return [str(address.network) for address in addresses(network, family)] + [
        prefix for prefix in network.get('routed_prefixes', []) + network.get('additional_subnets', []) + routed
        if ipaddress.ip_network(prefix).version == family]


def values(items):
    return '{ '+', '.join(dict.fromkeys(str(item) for item in items))+' }'


def render(value, *, extension_rules=None):
    networks, interfaces, uplink = value['networks'], value['hardware']['interfaces'], value['uplink']
    wan = interfaces[uplink['interface']]['name']
    dhcp = uplink.get('ipv4', 'dhcp') == 'dhcp'
    ra = uplink.get('ipv6', 'ra') == 'ra'
    ipv6_names = [network['name'] for network in networks.values() if addresses(network, 6)]
    if uplink.get('ipv6', 'ra') != 'disabled':
        ipv6_names.append(wan)
    plane = service_plane.topology(value)
    policy_managed = value.get('identity', {}).get('policy', {}).get('enabled', False)
    if service_plane.attached(value):
        ipv6_names.append(plane['host_link'])
    ipv6_set = values('"'+name+'"' for name in ipv6_names)
    translator_chains = [] if policy_managed else nat46.chains(value) + nat64.chains(value)
    # The policy agent's NAT64 zone hook is fixed at -300. The immutable source
    # boundary must run first, with an unambiguous priority, in managed mode.
    source_priority = -310 if policy_managed else -300
    lines = ['#!/usr/sbin/nft -f', 'flush ruleset', 'table inet lanrith {',
             *translator_chains,
             f' chain source_guard {{ type filter hook prerouting priority {source_priority}; policy accept;',
             '  iifname "lo" accept']
    ingress = [wan, *(network['name'] for network in networks.values())]
    if nat46.component(value):
        ingress.append('nat46')
    if service_plane.attached(value):
        ingress.append(plane['host_link'])
    ingress.extend(item['interface'] for item in nat64.components(value))
    lines.append('  iifname != '+values('"'+name+'"' for name in ingress)+' drop')
    lines += nat46.source_guard(value) + nat64.source_guard(value)
    for family, spelling in ((4, 'ip'), (6, 'ip6')):
        local = [str(ipaddress.ip_interface(a).ip) for network in networks.values()
                 for a in intent.gateway_addresses(network) if ipaddress.ip_interface(a).version == family]
        local += [str(ipaddress.ip_interface(a).ip) for a in uplink.get('addresses', [])
                  if ipaddress.ip_interface(a).version == family]
        if local:
            physical = values('"'+name+'"' for name in [wan, *(n['name'] for n in networks.values())])
            lines.append(f'  iifname {physical} {spelling} saddr {values(local)} drop')
    if uplink.get('ipv6', 'ra') != 'disabled':
        lines.append(f'  iifname "{wan}" ip6 saddr :: ip6 daddr ff02::1:ff00:0/104 ip6 hoplimit 255 '
                     'icmpv6 type nd-neighbor-solicit icmpv6 code 0 accept')
        lines.append(f'  iifname "{wan}" ip6 saddr :: ip6 daddr ff02::/16 ip6 hoplimit 1 '
                     'icmpv6 type { 131, 132, 143 } accept')
    # Static attachment routes supply reachability, not blanket source trust.
    # A configured collector outside connected ranges gets only its listener.
    lines += metrics.client_rules(value, ingress=True) + snmp.client_rules(value, ingress=True)
    for network in networks.values():
        name = network['name']
        if 'dhcp4' in network:
            targets = ['255.255.255.255', *(address.ip for address in addresses(network, 4))]
            lines.append(f'  iifname "{name}" ip saddr 0.0.0.0 ip daddr {values(targets)} udp sport 68 udp dport 67 accept')
        if addresses(network, 6):
            lines.append(f'  iifname "{name}" ip6 saddr :: ip6 daddr ff02::1:ff00:0/104 ip6 hoplimit 255 '
                         'icmpv6 type nd-neighbor-solicit icmpv6 code 0 accept')
            if network.get('ra'):
                lines.append(f'  iifname "{name}" ip6 saddr :: ip6 daddr ff02::2 ip6 hoplimit 255 '
                             'icmpv6 type nd-router-solicit icmpv6 code 0 accept')
            lines.append(f'  iifname "{name}" ip6 saddr :: ip6 daddr ff02::/16 ip6 hoplimit 1 '
                         'icmpv6 type { 131, 132, 143 } accept')
        for family, spelling in ((4, 'ip'), (6, 'ip6')):
            allowed = prefixes(network, family, value)
            if family == 6 and allowed:
                allowed.append('fe80::/10')
            lines.append(f'  iifname "{name}" '+(f'{spelling} saddr != {values(allowed)} drop' if allowed else
                         f'meta nfproto {"ipv4" if family == 4 else "ipv6"} drop'))
    if service_plane.attached(value):
        for family, spelling in ((4, 'ip'), (6, 'ip6')):
            allowed = [a for addresses in plane['endpoints'].values() for a in addresses
                       if ipaddress.ip_address(a).version == family]
            allowed += [str(ipaddress.ip_interface(a).ip) for a in plane['peer_addresses']
                        if ipaddress.ip_interface(a).version == family]
            if family == 6:
                allowed.append('fe80::/10')
            lines.append(f'  iifname "{plane["host_link"]}" {spelling} saddr != {values(allowed)} drop')
    # Source-address validity is independent of an owner's forwarding grants.
    lines += ['  ip saddr { 0.0.0.0/8, 127.0.0.0/8, 224.0.0.0/3 } drop',
              '  ip6 saddr { ::/128, ::1/128, ff00::/8 } drop']
    for family, spelling in ((4, 'ip'), (6, 'ip6')):
        owned = [prefix for network in networks.values() for prefix in prefixes(network, family, value)]
        if service_plane.attached(value):
            owned += [str(ipaddress.ip_interface(a).network) for a in plane['host_addresses']
                      if ipaddress.ip_interface(a).version == family]
        if owned:
            lines.append(f'  iifname "{wan}" {spelling} saddr {values(owned)} drop')
    lines += [' }', ' chain input { type filter hook input priority filter; policy drop;',
              '  iifname "lo" accept',
              *[f'  iifname "{item["interface"]}" drop' for item in nat64.components(value)],
              '  ct state invalid drop', *snmp.input_rules(value), '  ct state established,related accept']
    if ipv6_names:
        lines.append(f'  iifname {ipv6_set} meta l4proto ipv6-icmp icmpv6 type {{ {ERRORS6} }} accept')
        lines.append(f'  iifname {ipv6_set} ip6 hoplimit 255 icmpv6 type {{ {NEIGHBOURS} }} icmpv6 code 0 accept')
        lines.append(f'  iifname {ipv6_set} ip6 saddr {{ ::/128, fe80::/10 }} ip6 daddr ff02::/16 '
                     'ip6 hoplimit 1 icmpv6 type { 130, 131, 132, 143 } accept')
    if dhcp:
        lines.append(f'  iifname "{wan}" udp sport 67 udp dport 68 accept')
    if ra:
        lines.append(f'  iifname "{wan}" ip6 saddr fe80::/10 ip6 hoplimit 255 '
                     'icmpv6 type nd-router-advert icmpv6 code 0 accept')
    lines += metrics.backend_rule(value) + discovery.firewall_rules(value, 'input')
    lines += routing.control_rules(value, 'input')
    lines += extension_network.input_rules(extension_rules)
    for key, network in networks.items():
        name = network['name']
        for family, spelling in ((4, 'ip'), (6, 'ip6')):
            local = addresses(network, family)
            if not local:
                continue
            source = values(prefixes(network, family))
            target = values(address.ip for address in local)
            scope = f'iifname "{name}" {spelling} saddr {source} {spelling} daddr {target}'
            if key in value['administration']['networks']:
                lines.append(f'  {scope} tcp dport {value["administration"].get("ssh_port", 22)} accept')

        if 'dhcp4' in network:
            source = values(['0.0.0.0', *prefixes(network, 4)])
            target = values(['255.255.255.255', *(address.ip for address in addresses(network, 4))])
            lines.append(f'  iifname "{name}" ip saddr {source} ip daddr {target} udp sport 68 udp dport 67 accept')
        if network.get('ra'):
            lines.append(f'  iifname "{name}" ip6 saddr {{ ::/128, fe80::/10 }} ip6 hoplimit 255 '
                         'icmpv6 type nd-router-solicit icmpv6 code 0 accept')
    lines += [' }', ' chain forward { type filter hook forward priority filter; policy drop;',
              '  ip saddr { 0.0.0.0/8, 127.0.0.0/8, 169.254.0.0/16, 224.0.0.0/3 } drop',
              '  ip daddr { 0.0.0.0/8, 127.0.0.0/8, 169.254.0.0/16, 224.0.0.0/24, 255.255.255.255 } drop',
              '  ip6 saddr { ::/128, ::1/128, fe80::/10 } drop',
              '  ip6 daddr { ::/128, ::1/128, fe80::/10, ff01::/16, ff02::/16 } drop']
    for network in networks.values():
        if not network.get('forwarding', True):
            lines += [f'  iifname "{network["name"]}" drop', f'  oifname "{network["name"]}" drop']
    lines.append('  ct state invalid,untracked drop')
    lines += core_forward(value, plane)
    translators = list(intent.translations(value))
    if len(translators) > 1:
        names = values('"'+name+'"' for name in translators)
        lines.append(f'  iifname {names} oifname {names} drop')
    if policy_managed:
        # These marks are produced only after the helper's early checks. Its
        # later confirmation and physical-egress hooks still revalidate the
        # exact tuple, epoch, source ownership, and translated geometry.
        lines.append('  meta mark & 0xff000000 '+values(POLICY_FORWARD_MARKS)+' accept')
    else:
        lines += nat46.forward(value) + nat64.forward(value)
        if 'rules' in value['access'] or 'default' in value['access']:
            lines += access.render(intent.access(value), networks, interfaces, uplink,
                                   translated=lambda rule: nat46.supports(value, rule) or nat64.supports(value, rule))
        lines.append('  ct state established,related accept')
        for key in value['access'].get('internet', []):
            lines.append(f'  iifname "{networks[key]["name"]}" oifname "{wan}" accept')
        for rule in value['access'].get('between_networks', []):
            ports = values(sorted(set(rule['ports'])))
            lines.append(f'  iifname "{networks[rule["from"]]["name"]}" oifname "{networks[rule["to"]]["name"]}" '
                         f'{rule["protocol"]} dport {ports} accept')
    translation_errors = [] if policy_managed else nat46.local_errors(value) + nat64.local_errors(value)
    lines += [' }', ' chain output { type filter hook output priority filter; policy drop;',
              '  oifname "lo" accept',
              *(['  jump extension_output'] if extension_rules and any(extension_rules.values()) else []),
              *translation_errors, '  ct state invalid drop',
              *snmp.output_rules(value), '  ct state established,related accept']
    declared = values('"'+name+'"' for name in [network['name'] for network in networks.values()]+[wan])
    lines.append(f'  oifname {declared} icmp type {{ destination-unreachable, time-exceeded, parameter-problem }} accept')
    if dhcp:
        lines.append(f'  oifname "{wan}" udp sport 68 udp dport 67 accept')
    if ipv6_names:
        lines.append(f'  oifname {ipv6_set} meta l4proto ipv6-icmp icmpv6 type {{ {ERRORS6} }} accept')
        lines.append(f'  oifname {ipv6_set} ip6 hoplimit 255 icmpv6 type {{ {NEIGHBOURS} }} icmpv6 code 0 accept')
        lines.append(f'  oifname {ipv6_set} ip6 hoplimit 1 icmpv6 type {{ 130, 131, 132, 143 }} accept')
    if ra:
        lines.append(f'  oifname "{wan}" ip6 hoplimit 255 icmpv6 type nd-router-solicit icmpv6 code 0 accept')
    lines += routing.control_rules(value, 'output')
    lines += discovery.firewall_rules(value, 'output')
    from .directory_config import output_rules as directory_output
    lines += directory_output(value)
    for network in networks.values():
        if network.get('ra'):
            lines.append(f'  oifname "{network["name"]}" ip6 saddr fe80::/10 ip6 hoplimit 255 '
                         'icmpv6 type nd-router-advert icmpv6 code 0 accept')
        if 'dhcp4' in network:
            lines.append(f'  oifname "{network["name"]}" ip saddr {values(address.ip for address in addresses(network, 4))} '
                         f'ip daddr {values(["255.255.255.255", *prefixes(network, 4)])} udp sport 67 udp dport 68 accept')
    lines += [' }', *extension_network.output_chain(extension_rules), '}', 'table ip lanrith_nat {',
              ' chain postrouting { type nat hook postrouting priority srcnat; policy accept;']
    if plane['endpoints'] and uplink.get('ipv4', 'dhcp') != 'disabled':
        sources = [a for addresses in plane['endpoints'].values() for a in addresses if ':' not in a]
        lines.append(f'  iifname "{plane["host_link"]}" ip saddr {values(sources)} oifname "{wan}" masquerade')
    for path in intent.uplink_nat(value):
        lines.extend(f'  ip saddr {prefix} oifname "{wan}" masquerade' for prefix in path['sources'])
    for manifest in nat64.components(value):
        for network in networks.values():
            if network.get('forwarding', True):
                for prefix in prefixes(network, 4):
                    lines.append(f'  iifname "{manifest["interface"]}" ip saddr {manifest["pool"]} '
                                 f'oifname "{network["name"]}" ip daddr {prefix} masquerade')
        if uplink.get('ipv4', 'dhcp') != 'disabled':
            lines.append(f'  iifname "{manifest["interface"]}" ip saddr {manifest["pool"]} '
                         f'oifname "{wan}" masquerade')
    result = '\n'.join(lines + [' }', '}'])+'\n'
    if plane['endpoints'] and uplink.get('ipv6', 'ra') != 'disabled' and not uplink.get('downstream_prefix'):
        sources = [a for addresses in plane['endpoints'].values() for a in addresses if ':' in a]
        result += 'table ip6 lanrith_service_nat {\n chain postrouting { type nat hook postrouting priority srcnat; policy accept;\n'
        result += f'  iifname "{plane["host_link"]}" ip6 saddr {values(sources)} oifname "{wan}" masquerade\n'
        result += ' }\n}\n'
    if 'ntp' in plane['endpoints']:
        result += 'table inet lanrith_time {\n chain time_redirect { type nat hook prerouting priority dstnat; policy accept;\n'
        for network in networks.values():
            if network.get('ntp'):
                for family, spelling in ((4, 'ip'), (6, 'ip6')):
                    allowed = prefixes(network, family)
                    if allowed:
                        target = plane['endpoints']['ntp'][0 if family == 4 else 1]
                        result += f'  iifname "{network["name"]}" {spelling} saddr {values(allowed)} udp dport 123 dnat {spelling} to {target}\n'
        result += ' }\n}\n'
    return result


def core_forward(value, plane):
    if not plane['endpoints']:
        return []
    host = plane['host_link']
    lines = [f'  iifname "{host}" ct state established,related ct direction reply accept',
             f'  oifname "{host}" ct state established,related ct direction reply accept']
    for feature, port in (('dns', 53), ('ntp', 123), ('authoritative', 53)):
        if feature not in plane['endpoints']:
            continue
        for family, spelling in ((4, 'ip'), (6, 'ip6')):
            targets = [a for a in plane['endpoints'][feature] if ipaddress.ip_address(a).version == family]
            for client in service_plane.clients(value, feature):
                network = value['networks'][client['network']]
                sources = [a for a in client['addresses'] if ipaddress.ip_network(a).version == family]
                if sources:
                    for protocol in ('tcp', 'udp') if feature != 'ntp' else ('udp',):
                        lines.append(f'  iifname "{network["name"]}" oifname "{host}" {spelling} saddr {values(sources)} '
                                     f'{spelling} daddr {values(targets)} {protocol} dport {port} accept')
    for path in service_plane.egress(value):
        spelling = 'ip6' if ':' in path['address'] else 'ip'
        protocols, port = ((('udp',), 123) if path['kind'] == 'ntp' else
                           (('udp',), 1812) if path['kind'] == 'radius_proxy' else
                           (('tcp',), 443) if path['kind'] == 'logs' else (('tcp', 'udp'), 53))
        outgoing = path.get('destination_interface', plane['wan'])
        for destination in path['destinations']:
            target = '' if ipaddress.ip_network(destination).prefixlen == 0 else f'{spelling} daddr {ipaddress.ip_network(destination).network_address} '
            for protocol in protocols:
                lines.append(f'  iifname "{host}" oifname "{outgoing}" {spelling} saddr {values([path["address"]])} '
                             f'{target}{protocol} dport {port} accept')
    # Mandatory component boundaries precede all owner rules.
    lines += metrics.client_rules(value)
    lines += [f'  iifname "{host}" drop', f'  oifname "{host}" drop']
    return lines
