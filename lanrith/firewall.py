"""Generate baseline guards and service rules from declared router intent."""

import ipaddress

from . import access, intent, networkd, service_plane, routing, nat46, nat64, metrics, snmp, discovery, extension_network, tun_policy
from . import public_nat64
from .release import require


ERRORS6 = 'destination-unreachable, packet-too-big, time-exceeded, parameter-problem'
NEIGHBOURS = 'nd-neighbor-solicit, nd-neighbor-advert'
POLICY_FORWARD_MARKS = (
    '0xb1000000', '0xb2000000', '0xb3000000',
    '0xd1000000', '0xd2000000', '0xd3000000', '0xd4000000', '0xd5000000', '0xd6000000',
    '0xf1000000', '0xf2000000', '0xf3000000', '0xf4000000', '0xf5000000', '0xf6000000',
)
NAT64_TARGET_MARKS = ('0xd7000000', '0xd8000000', '0xd9000000', '0xda000000')


def sysctls():
    lines = []
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


def activation(value):
    from .firewall_activation import FLOOR, FORWARDING, HARDENING
    rescue = [value['networks'][key] for key in value['administration']['networks']
              if value['networks'][key].get('role') == 'management' and 'namespace' not in value['networks'][key]]
    port = value['administration'].get('ssh_port', 22)
    incoming = ['iifname "lo" accept']
    outgoing = [*metrics.local_backend_drop(value), 'oifname "lo" accept']
    for network in rescue:
        name = network['name']
        for gateway in map(ipaddress.ip_interface, network['addresses']):
            family = 'ip' if gateway.version == 4 else 'ip6'
            incoming.append(f'iifname "{name}" {family} saddr {gateway.network} {family} daddr {gateway.ip} '
                            f'tcp dport {port} ct state {{ new, established }} accept')
            outgoing.append(f'oifname "{name}" {family} saddr {gateway.ip} {family} daddr {gateway.network} '
                            f'tcp sport {port} ct direction reply ct state established accept')
        if addresses(network, 6):
            for rules, direction in ((incoming, 'iifname'), (outgoing, 'oifname')):
                rules.append(f'{direction} "{name}" ip6 hoplimit 255 icmpv6 type {{ {NEIGHBOURS} }} '
                             'icmpv6 code 0 accept')
    floor = ['destroy table inet lanrith_recovery', 'table inet lanrith_recovery {',
             'chain input { type filter hook input priority filter - 1; policy drop;', *incoming, '}',
             'chain forward { type filter hook forward priority filter - 1; policy drop; }',
             'chain output { type filter hook output priority filter - 1; policy drop;', *outgoing, '}', '}']
    forwarding = []
    for family, key in ((4, 'net.ipv4.ip_forward'), (6, 'net.ipv6.conf.all.forwarding')):
        # A disabled WAN family can still route between internal attachments.
        enabled = (value['uplink'].get(f'ipv{family}') != 'disabled' or bool(intent.translations(value)) or
                   any(network.get('forwarding', True) and prefixes(network, family, value)
                       for network in value['networks'].values()))
        forwarding.append(f'{key}={int(enabled)}')
    prerequisite = ('[Unit]\nRequires=lanrith-firewall-floor.service\n'
                    'After=lanrith-firewall-floor.service\n')
    files = {
        FLOOR.lstrip('/'): '\n'.join(floor)+'\n',
        HARDENING.lstrip('/'): sysctls(),
        FORWARDING.lstrip('/'): '\n'.join(forwarding)+'\n',
        'usr/lib/systemd/system/lanrith-firewall-floor.service': (
            '[Unit]\nDescription=Install the host recovery firewall before networking\n'
            'DefaultDependencies=no\nRefuseManualStop=yes\nBefore=network-pre.target shutdown.target\n'
            'Conflicts=shutdown.target\n[Service]\nType=oneshot\nRemainAfterExit=yes\n'
            f'ExecStart=/usr/sbin/nft -f {FLOOR}\n'),
        'etc/systemd/system/systemd-networkd.service.d/60-lanrith-firewall-floor.conf': prerequisite,
        'etc/systemd/system/nftables.service.d/60-lanrith-activation.conf': (
            prerequisite+'Requires=systemd-sysctl.service\nAfter=systemd-sysctl.service\n'
            '[Service]\nRuntimeDirectory=lanrith-firewall\nRuntimeDirectoryMode=0700\nRuntimeDirectoryPreserve=yes\n'
            f'ExecStartPre=/usr/sbin/nft -f {FLOOR}\nExecStart=\n'
            'ExecStart=/usr/bin/python3 /usr/lib/lanrith/lanrith/firewall_activation.py\n'
            f'ExecReload=\nExecStop=\nExecStopPost=/usr/sbin/nft -f {FLOOR}\n')}
    if rescue:
        # With a dedicated rescue attachment SSH can start under the floor
        # even when the general host policy cannot load.
        files['etc/systemd/system/ssh.service.d/10-lanrith-firewall.conf'] = prerequisite
    return files


def render(value, *, extension_rules=None, access_backend='tun', retained_allocations=None):
    # The default and all deployed builds use client-facing TUN enforcement.
    # Explicit legacy rendering remains available for migration comparisons.
    require(access_backend in ('legacy', 'tun'), 'Unknown access compiler.')
    tun = access_backend == 'tun'
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
    translator_chains = (tun_policy.definitions(value, retained_allocations) if tun else
                         [] if policy_managed else nat46.chains(value) + nat64.chains(value))
    public = intent.translations(value).get('nat64')
    public_guard = []
    if public and public['prefix'] == str(public_nat64.WELL_KNOWN_PREFIX):
        blocked = values(public_nat64.embedded(network, public_nat64.WELL_KNOWN_PREFIX)
                         for network in public_nat64.BLOCKED)
        translator_chains += [
            f' set nat64_non_global {{ type ipv6_addr; flags interval; elements = {blocked}; }}',
            ' counter nat64_non_global_drops {}',
        ]
        public_guard = [f'  oifname "{public["interface"]}" ip6 daddr @nat64_non_global '
                        'counter name nat64_non_global_drops drop']
    # The policy agent's NAT64 zone hook is fixed at -300. The immutable source
    # boundary must run first, with an unambiguous priority, in managed mode.
    source_priority = -310 if policy_managed and not tun else -300
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
              *[f'  iifname "{name}" drop' for name in
                (intent.translations(value) if tun else [item['interface'] for item in nat64.components(value)])],
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
    lines += [' }', ' chain forward { type filter hook forward priority filter; policy drop;', *public_guard,
              '  ip saddr { 0.0.0.0/8, 127.0.0.0/8, 169.254.0.0/16, 224.0.0.0/3 } drop',
              '  ip daddr { 0.0.0.0/8, 127.0.0.0/8, 169.254.0.0/16, 224.0.0.0/24, 255.255.255.255 } drop',
              '  ip6 saddr { ::/128, ::1/128, fe80::/10 } drop',
              '  ip6 daddr { ::/128, ::1/128, fe80::/10, ff01::/16, ff02::/16 } drop']
    for network in networks.values():
        if not network.get('forwarding', True):
            lines += [f'  iifname "{network["name"]}" drop', f'  oifname "{network["name"]}" drop']
    # Topology limits native IPv6 transit even when an access rule covers both families.
    for network in networks.values():
        sources = prefixes(network, 6, value)
        if not sources or not network.get('forwarding', True):
            continue
        guard = f'  iifname "{network["name"]}" oifname "{wan}" meta nfproto ipv6'
        if networkd.routed(value, network):
            guard += ' ip6 saddr != ' + values(networkd.provider_sources(value, network, sources))
        destinations = networkd.upstream_routes(value, network)
        if destinations:
            guard += ' ip6 daddr != ' + values(destinations)
        lines.append(guard + ' drop')
    if tun and value.get('routing', {}).get('asymmetric_replies'):
        lines.append('  jump tp_asymmetric')
    lines.append('  ct state invalid,untracked drop')
    lines += core_forward(value, plane)
    translators = list(intent.translations(value))
    if len(translators) > 1:
        names = values('"'+name+'"' for name in translators)
        lines.append(f'  iifname {names} oifname {names} drop')
    if tun:
        lines += tun_policy.forward(value)
    elif policy_managed:
        # These marks are produced only after the helper's early checks. Its
        # later confirmation and physical-egress hooks still revalidate the
        # exact tuple, epoch, source ownership, and translated geometry.
        marks = POLICY_FORWARD_MARKS
        if 'nat64' in translators:
            marks += NAT64_TARGET_MARKS
        lines.append('  meta mark & 0xff000000 '+values(marks)+' accept')
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
    translation_errors = [] if tun or policy_managed else nat46.local_errors(value) + nat64.local_errors(value)
    lines += [' }', ' chain output { type filter hook output priority filter; policy drop;', *public_guard,
              *metrics.local_backend_drop(value), '  oifname "lo" accept',
              *(['  jump extension_output'] if extension_rules and any(extension_rules.values()) else []),
              *translation_errors, '  ct state invalid drop',
              *snmp.output_rules(value), '  ct state established,related accept']
    lines += ['  '+rule for rule in service_plane.host_dns_rules(plane, namespace=False)]
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
    from . import directory_config
    directory_output, directory_source = directory_config.firewall_rules(value)
    lines += directory_output
    for network in networks.values():
        if network.get('ra'):
            lines.append(f'  oifname "{network["name"]}" ip6 saddr fe80::/10 ip6 hoplimit 255 '
                         'icmpv6 type nd-router-advert icmpv6 code 0 accept')
        if 'dhcp4' in network:
            lines.append(f'  oifname "{network["name"]}" ip saddr {values(address.ip for address in addresses(network, 4))} '
                         f'ip daddr {values(["255.255.255.255", *prefixes(network, 4)])} udp sport 67 udp dport 68 accept')
    lines += [' }', *extension_network.output_chain(extension_rules), *directory_source, '}', 'table ip lanrith_nat {',
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
    intercepted = [network for network in networks.values() if network.get('ntp_intercept')]
    if intercepted:
        result += 'table inet lanrith_time {\n chain time_redirect { type nat hook prerouting priority dstnat; policy accept;\n'
        for network in intercepted:
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
    for feature, port in (('dns', 53), ('ntp', 123), ('authoritative', 53), ('discovery', 53), ('radius', 1812)):
        if feature not in plane['endpoints']:
            continue
        for family, spelling in ((4, 'ip'), (6, 'ip6')):
            targets = [a for a in plane['endpoints'][feature] if ipaddress.ip_address(a).version == family]
            for client in service_plane.clients(value, feature):
                network = value['networks'][client['network']]
                sources = [a for a in client['addresses'] if ipaddress.ip_network(a).version == family]
                if sources:
                    for protocol in ('tcp', 'udp') if feature not in ('ntp', 'radius') else ('udp',):
                        ports = '{ 1812, 1813 }' if feature == 'radius' else str(port)
                        lines.append(f'  iifname "{network["name"]}" oifname "{host}" {spelling} saddr {values(sources)} '
                                     f'{spelling} daddr {values(targets)} {protocol} dport {ports} accept')
    for path in service_plane.egress(value):
        spelling = 'ip6' if ':' in path['address'] else 'ip'
        protocols, port = service_plane.EGRESS_TRANSPORT[path['kind']]
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
