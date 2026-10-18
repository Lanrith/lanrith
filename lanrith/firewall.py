"""Generate baseline guards and service rules from declared router intent."""

import ipaddress

from . import access


ERRORS6 = 'destination-unreachable, packet-too-big, time-exceeded, parameter-problem'
NEIGHBOURS = 'nd-neighbor-solicit, nd-neighbor-advert'


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


def prefixes(network, family):
    return [str(address.network) for address in addresses(network, family)] + [
        prefix for prefix in network.get('routed_prefixes', []) if ipaddress.ip_network(prefix).version == family]


def values(items):
    return '{ '+', '.join(dict.fromkeys(str(item) for item in items))+' }'


def render(value):
    networks, interfaces, uplink = value['networks'], value['hardware']['interfaces'], value['uplink']
    wan = interfaces[uplink['interface']]['name']
    dhcp = uplink.get('ipv4', 'dhcp') == 'dhcp'
    ra = uplink.get('ipv6', 'ra') == 'ra'
    ipv6_names = [network['name'] for network in networks.values() if addresses(network, 6)]
    if uplink.get('ipv6', 'ra') != 'disabled':
        ipv6_names.append(wan)
    ipv6_set = values('"'+name+'"' for name in ipv6_names)
    lines = ['#!/usr/sbin/nft -f', 'flush ruleset', 'table inet lanrith {',
             ' chain source_guard { type filter hook prerouting priority -300; policy accept;',
             '  iifname "lo" accept']
    if uplink.get('ipv6', 'ra') != 'disabled':
        lines.append(f'  iifname "{wan}" ip6 saddr :: ip6 daddr ff02::1:ff00:0/104 ip6 hoplimit 255 '
                     'icmpv6 type nd-neighbor-solicit icmpv6 code 0 accept')
        lines.append(f'  iifname "{wan}" ip6 saddr :: ip6 daddr ff02::/16 ip6 hoplimit 1 '
                     'icmpv6 type { 131, 132, 143 } accept')
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
            allowed = prefixes(network, family)
            if family == 6 and allowed:
                allowed.append('fe80::/10')
            lines.append(f'  iifname "{name}" '+(f'{spelling} saddr != {values(allowed)} drop' if allowed else
                         f'meta nfproto {"ipv4" if family == 4 else "ipv6"} drop'))
    # Source-address validity is independent of an owner's forwarding grants.
    lines += ['  ip saddr { 0.0.0.0/8, 127.0.0.0/8, 224.0.0.0/3 } drop',
              '  ip6 saddr { ::/128, ::1/128, ff00::/8 } drop']
    for family, spelling in ((4, 'ip'), (6, 'ip6')):
        owned = [prefix for network in networks.values() for prefix in prefixes(network, family)]
        if owned:
            lines.append(f'  iifname "{wan}" {spelling} saddr {values(owned)} drop')
    lines += [' }', ' chain input { type filter hook input priority filter; policy drop;',
              '  iifname "lo" accept', '  ct state invalid drop', '  ct state established,related accept']
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
            if network.get('dns'):
                lines.extend(f'  {scope} {protocol} dport 53 accept' for protocol in ('tcp', 'udp'))
            if value['services'].get('ntp', {}).get('enabled'):
                lines.append(f'  {scope} udp dport 123 accept')
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
    if 'rules' in value['access'] or 'default' in value['access']:
        lines += access.render(value['access'], networks, interfaces, uplink)
    lines.append('  ct state established,related accept')
    for key in value['access'].get('internet', []):
        lines.append(f'  iifname "{networks[key]["name"]}" oifname "{wan}" accept')
    for rule in value['access'].get('between_networks', []):
        ports = values(sorted(set(rule['ports'])))
        lines.append(f'  iifname "{networks[rule["from"]]["name"]}" oifname "{networks[rule["to"]]["name"]}" '
                     f'{rule["protocol"]} dport {ports} accept')
    lines += [' }', ' chain output { type filter hook output priority filter; policy drop;',
              '  oifname "lo" accept', '  ct state invalid drop', '  ct state established,related accept']
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
    for network in networks.values():
        if network.get('ra'):
            lines.append(f'  oifname "{network["name"]}" ip6 saddr fe80::/10 ip6 hoplimit 255 '
                         'icmpv6 type nd-router-advert icmpv6 code 0 accept')
        if 'dhcp4' in network:
            lines.append(f'  oifname "{network["name"]}" ip saddr {values(address.ip for address in addresses(network, 4))} '
                         f'ip daddr {values(["255.255.255.255", *prefixes(network, 4)])} udp sport 67 udp dport 68 accept')
    # These package accounts are resolved by nft on the assembled target.
    # Local service configuration never grants arbitrary daemon egress.
    if value['services'].get('dns', {}).get('enabled'):
        lines.extend(f'  oifname "{wan}" meta skuid "unbound" {protocol} dport 53 accept'
                     for protocol in ('tcp', 'udp'))
    if value['services'].get('ntp', {}).get('enabled'):
        lines.append(f'  oifname "{wan}" meta skuid "_chrony" udp dport 123 accept')
    lines += [' }', '}', 'table ip lanrith_nat {',
              ' chain postrouting { type nat hook postrouting priority srcnat; policy accept;']
    masqueraded = networks if uplink.get('masquerade') else value['access'].get('internet', [])
    if 'masquerade' in uplink and not uplink['masquerade']:
        masqueraded = []
    for key in masqueraded:
        if networks[key].get('forwarding', True):
            lines.extend(f'  ip saddr {prefix} oifname "{wan}" masquerade'
                         for prefix in prefixes(networks[key], 4))
    return '\n'.join(lines + [' }', '}'])+'\n'
