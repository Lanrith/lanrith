"""Mapped IPv4-to-IPv6 forwarding with ordered intent and short-lived tuple guards.

The TUN is a second packet ingress, not an authorization boundary. Each output
tuple needs a recent admitted input tuple, including the embedded client address.
Native source validation and router/service isolation still run first.
"""

import copy
import ipaddress as ip

from . import access, integrations, intent, routing, translation
from .release import canonical, require


def component(value):
    return intent.translations(value).get('nat46')


def attachment(value, address):
    """Resolve the declared longest-prefix attachment, rejecting equal ambiguity."""
    address = ip.ip_address(address)
    candidates = []
    for key, network in value['networks'].items():
        prefixes = [str(ip.ip_interface(a).network) for a in network['addresses']]
        prefixes += network.get('additional_subnets', []) + routing.routed_sources(value, key)
        prefixes += [str(p) for route in value.get('routing', {}).get('static_routes', [])
                     if route['network'] == key for p in integrations.prefixes(value, route['to'])]
        for prefix in prefixes:
            parsed = ip.ip_network(prefix)
            if address in parsed:
                candidates.append((parsed.prefixlen, network['name']))
    if not candidates:
        return value['hardware']['interfaces'][value['uplink']['interface']]['name']
    length = max(length for length, _ in candidates)
    matches = {name for size, name in candidates if size == length}
    require(len(matches) == 1, 'Ambiguous NAT46 destination attachment.')
    return matches.pop()


def destinations(value, rule, entry):
    """Test both the alias and the mapped destination without widening a qualifier."""
    target, alias = ip.ip_address(entry['ipv6']), ip.ip_address(entry['ipv4'])
    logical = attachment(value, entry['ipv6'])
    for selected in intent.expand(value, rule['to']):
        item = access.selector(selected, value['networks'], value['hardware']['interfaces'],
                               value['uplink'], source=False)
        interface, addresses = item['interface'], item['addresses']
        # An attachment and its address are one alternative. Mixing the native
        # address with the translator's interface would widen a partial rule.
        if interface in (None, 'nat46') and (addresses is None or any(alias in p for p in addresses)):
            return True
        if interface in (None, logical) and (addresses is None or any(target in p for p in addresses)):
            return True
    return False


def original_rules(value, entry):
    """Project one mapped destination while preserving source, transport and order."""
    result = []
    for rule in value.get('access', {}).get('rules', []):
        if rule.get('family') == 'ipv6' or not destinations(value, rule, entry):
            continue
        sources = []
        for source in intent.expand(value, rule['from']):
            source = copy.deepcopy(source)
            if 'addresses' in source:
                source['addresses'] = [a for a in source['addresses'] if ip.ip_network(a).version == 4]
                if not source['addresses']:
                    continue
            sources.append(source)
        if not sources:
            continue
        protocols = rule.get('protocol', 'any')
        for protocol in protocols if isinstance(protocols, list) else [protocols]:
            if protocol not in ('any', 'tcp', 'udp', 'icmp'):
                continue
            selected = {**rule, 'from': sources,
                        'to': {'interface': 'nat46', 'addresses': entry['ipv4']},
                        'protocol': protocol, 'family': 'ipv4'}
            # Names are metadata, including when a protocol list expands.
            selected.pop('name', None)
            result.extend(access.render({'rules': [selected]}, value['networks'],
                                        value['hardware']['interfaces'], value['uplink']))
    return result


def supports(value, rule):
    settings = component(value)
    selected = {**value, 'access': {'rules': [rule]}}
    return settings is not None and any(original_rules(selected, entry)
                                        for entry in settings['mappings'].values())


def source_guard(value):
    settings = component(value)
    if not settings:
        return []
    return [
        f'  iifname != "nat46" ip saddr {settings["pool"]} drop',
        f'  iifname != "nat46" ip6 saddr {settings["prefix"]} drop',
        f'  iifname "nat46" ip saddr != {settings["pool"]} drop',
        f'  iifname "nat46" ip6 saddr != {{ {settings["prefix"]}, {settings["ipv6"]} }} drop',
    ]


def forward(value):
    if not component(value):
        return []
    return ['  iifname "nat46" jump nat46_output',
            '  oifname "nat46" jump nat46_input']


def key(family, direction, protocol, *, error=False):
    # Raw IPv4 bytes use the same nft integer type as the embedded IPv4 bytes.
    offset = {(4, 'from'): 96, (4, 'to'): 128, (6, 'from'): 160, (6, 'to'): 288}[family, direction]
    address = f'@nh,{offset},32'
    if error and protocol == 'icmp':
        transport = '@th,'+('256' if family == 4 else '416')+',32'
    elif error:
        transport = 'ct original proto-src . ct original proto-dst'
    elif protocol == 'icmp':
        transport = '@th,32,32'  # Echo identifier and sequence survive SIIT.
    elif direction == 'from':
        transport = f'{protocol} sport . {protocol} dport'
    else:
        transport = f'{protocol} dport . {protocol} sport'
    return address+' . '+transport


def chains(value):
    settings = component(value)
    if not settings:
        return []
    result, incoming, outgoing = [], [], []
    for index, entry in enumerate(settings['mappings'].values()):
        base = f'n46_{index}'
        alias, target = entry['ipv4'], entry['ipv6']
        destination = attachment(value, target)
        # Both directions need a new proof after a reload; no persistent set or
        # old conntrack entry can create one. A bounded timeout tolerates batches
        # and reordering without retaining an authorization lease.
        for protocol in ('tcp', 'udp', 'icmp'):
            for direction in ('initial', 'local_reply'):
                result.append(f' set {base}_{protocol}_{direction}_error {{ typeof @nh,96,32 . @nh,96,32 . @th,0,32; '
                              'flags dynamic,timeout; timeout 2s; size 1024; }')
            for direction in ('forward', 'reply'):
                name = f'{base}_{protocol}_{direction}'
                result.append(f' set {name} {{ typeof {key(4, "from", protocol)}; '
                              'flags dynamic,timeout; timeout 2s; size 1024; }')
            for direction in ('forward', 'reply'):
                result.append(f' set {base}_{protocol}_{direction}_error {{ '
                              f'typeof {key(4, "from", protocol, error=True)}; '
                              'flags dynamic,timeout; timeout 2s; size 1024; }')
        incoming += [f'  meta nfproto ipv4 ip daddr {alias} jump {base}_policy',
                     f'  iifname "{destination}" meta nfproto ipv6 ip6 saddr {target} '
                     f'ip6 daddr {settings["prefix"]} ct state established ct direction reply jump {base}_reply']
        outgoing += [
            f'  oifname "{destination}" meta nfproto ipv6 ip6 saddr {settings["prefix"]} '
            f'ip6 daddr {target} jump {base}_forward',
            f'  meta nfproto ipv4 ip saddr {alias} ct state established ct direction reply jump {base}_return']
        result += [f' chain {base}_policy {{']
        for line in original_rules(value, entry):
            result.append(line.removesuffix('accept')+f'jump {base}_admit' if line.endswith('accept') else line)
        result += ['  drop', ' }', f' chain {base}_admit {{']
        for protocol in ('tcp', 'udp', 'icmp'):
            match = 'icmp type echo-request' if protocol == 'icmp' else f'meta l4proto {protocol}'
            result.append(f'  {match} update @{base}_{protocol}_forward '
                          f'{{ {key(4, "from", protocol)} }} update @{base}_{protocol}_initial_error '
                          f'{{ @nh,96,32 . @nh,96,32 . @th,{32 if protocol == "icmp" else 0},32 }} accept')
        for protocol in ('tcp', 'udp', 'icmp'):
            result.append('  icmp type { destination-unreachable, time-exceeded, parameter-problem } '
                          f'ct state related ct direction original ct original ip daddr {alias} '
                          f'ct protocol {protocol} '+('@th,64,8 0x45 ' if protocol == 'icmp' else '')+
                          f'update @{base}_{protocol}_forward_error '
                          f'{{ {key(4, "from", protocol, error=True)} }} accept')
        result += ['  drop', ' }']
        for stage, family, direction, proof, update in (
                ('forward', 6, 'from', 'forward', False),
                ('reply', 6, 'to', 'reply', True),
                ('return', 4, 'to', 'reply', False)):
            result.append(f' chain {base}_{stage} {{')
            for protocol in ('tcp', 'udp', 'icmp'):
                match = (f'icmp{"v6" if family == 6 else ""} type '
                         f'echo-{"request" if stage == "forward" else "reply"}' if protocol == 'icmp'
                         else f'meta l4proto {protocol}')
                expression = key(family, direction, protocol)
                operation = f'update @{base}_{protocol}_{proof} {{ {expression} }}' if update else \
                            f'{expression} @{base}_{protocol}_{proof}'
                result.append(f'  {match} {operation} accept')
            result += ['  drop', ' }']
        # Correlated error packets carry a different outer source. Conntrack must
        # identify the original TCP/UDP flow to this mapping; the tuple is then
        # carried across the translation as a separate short-lived proof.
        for protocol in ('tcp', 'udp', 'icmp'):
            for family, direction, hook, identity, stage, update in (
                    (6, 'from', outgoing, f'oifname "{destination}" ip6 daddr {target}', 'forward', False),
                    (6, 'to', incoming, f'iifname "{destination}" ip6 daddr {settings["prefix"]}', 'reply', True),
                    (4, 'to', outgoing, f'ip saddr {{ {alias}, {settings["ipv4"]} }}', 'reply', False)):
                spelling = 'ip' if family == 4 else 'ip6'
                errors = ('destination-unreachable, time-exceeded, parameter-problem' if family == 4 else
                          'destination-unreachable, packet-too-big, time-exceeded, parameter-problem')
                match = (f'  meta nfproto ipv{family} {identity} '
                         f'icmp{"v6" if family == 6 else ""} type {{ {errors} }} ct state related '
                         f'ct direction {"original" if stage == "forward" else "reply"} '
                         f'ct original {spelling} daddr {alias if family == 4 else target} '
                         f'ct protocol {"ipv6-icmp" if protocol == "icmp" and family == 6 else protocol}')
                if protocol == 'icmp':
                    match += ' @th,64,8 0x45' if family == 4 else ' @th,64,4 6 @th,112,8 58'
                expression = key(family, direction, protocol, error=True)
                operation = (f'update @{base}_{protocol}_{stage}_error {{ {expression} }}' if update else
                             f'{expression} @{base}_{protocol}_{stage}_error')
                # Error handling must precede the normal chains' terminal drops.
                hook.insert(0, match+' '+operation+' accept')
            # TAYGA can itself reject an admitted packet, without a remote error
            # leg. Its control address still needs the recent original proof.
            match = (f'  ip saddr {settings["ipv4"]} icmp type {{ destination-unreachable, time-exceeded, parameter-problem }} '
                     f'ct state related ct direction reply ct original ip daddr {alias} ct protocol {protocol}')
            if protocol == 'icmp':
                match += ' @th,64,8 0x45'
            outgoing.insert(0, match+f' {key(4, "to", protocol, error=True)} @{base}_{protocol}_forward accept')
            # Errors emitted before an IPv6 forward reaches conntrack confirm
            # use the quoted tuple proof installed at the IPv4 admission point.
            quoted = 256 if protocol == 'icmp' else 224
            outgoing.insert(0,
                f'  ip saddr {{ {alias}, {settings["ipv4"]} }} icmp type '
                '{ destination-unreachable, time-exceeded, parameter-problem } '
                f'ct state related ct direction reply ct original ip daddr {alias} ct protocol {protocol} '
                f'@th,64,8 0x45 @nh,128,32 . @th,160,32 . @th,{quoted},32 '
                f'@{base}_{protocol}_local_reply_error accept')
    result += [' chain nat46_input {', *incoming, '  drop', ' }',
               ' chain nat46_output {', *outgoing, '  drop', ' }']
    require(len(result) <= 16384, 'NAT46 enforcement exceeds its generated rule bound.')
    return result


def local_errors(value):
    """Router-generated errors need the same original and return proofs."""
    settings = component(value)
    if not settings:
        return []
    result = []
    for index, entry in enumerate(settings['mappings'].values()):
        for protocol in ('tcp', 'udp', 'icmp'):
            # The kernel may reject an oversize packet before confirming its new
            # IPv6 conntrack entry. Bound these local errors to a literal mapped
            # destination, the embedded client and a just-admitted quoted tuple.
            number = {'tcp': 6, 'udp': 17, 'icmp': 58}[protocol]
            quoted = 416 if protocol == 'icmp' else 384
            expression = f'@nh,288,32 . @th,224,32 . @th,{quoted},32'
            result.append(
                f'  oifname "nat46" ip6 daddr {settings["prefix"]} '
                'icmpv6 type { destination-unreachable, packet-too-big, time-exceeded, parameter-problem } '
                f'@th,64,4 6 @th,112,8 {number} '
                f'@th,128,96 0x{int(ip.ip_network(settings["prefix"]).network_address) >> 32:x} '
                f'@th,256,128 0x{int(ip.ip_address(entry["ipv6"])):x} '
                f'{expression} @n46_{index}_{protocol}_initial_error '
                f'update @n46_{index}_{protocol}_local_reply_error {{ {expression} }} accept')
            match = (f'  oifname "nat46" ip6 daddr {settings["prefix"]} '
                     'icmpv6 type { destination-unreachable, packet-too-big, time-exceeded, parameter-problem } '
                     f'ct state related ct direction reply ct original ip6 daddr {entry["ipv6"]} '
                     f'ct protocol {"ipv6-icmp" if protocol == "icmp" else protocol}')
            if protocol == 'icmp':
                match += ' @th,64,4 6 @th,112,8 58'
            expression = key(6, 'to', protocol, error=True)
            result.append(match+f' {expression} @n46_{index}_{protocol}_forward '
                          f'update @n46_{index}_{protocol}_reply_error {{ {expression} }} accept')
    return result+['  oifname "nat46" drop']


def render(value):
    if not component(value):
        return {}
    manifest = next(c for c in translation.manifests(value) if c['component'] == 'nat46')
    policy_dependency = (' lanrith-policy-guards.service'
                         if value.get('identity', {}).get('policy', {}).get('enabled', False) else '')
    return {
        'etc/tayga-nat46.conf': manifest['text'],
        'usr/share/lanrith/nat46.json': canonical(manifest).decode(),
        'usr/lib/sysusers.d/80-lanrith-nat46.conf': 'u lanrith-nat46 - "Mapped translation" /\n',
        'usr/lib/systemd/system/lanrith-nat46-network.service':
            '[Unit]\nDescription=Configure mapped translation routes\n'
            'Requires=nftables.service systemd-networkd.service\n'
            'After=nftables.service systemd-networkd.service systemd-sysusers.service systemd-tmpfiles-setup.service\n'
            'BindsTo=nftables.service\nBefore=lanrith-nat46.service\n'
            '[Service]\nType=oneshot\nRemainAfterExit=yes\n'
            'Environment=PYTHONPATH=/usr/lib/lanrith\n'
            'ExecStart=/usr/bin/python3 -m lanrith.translation_runtime start\n'
            'ExecStop=/usr/bin/python3 -m lanrith.translation_runtime stop\n'
            'NoNewPrivileges=yes\nProtectSystem=strict\nProtectHome=yes\nPrivateTmp=yes\n'
            'CapabilityBoundingSet=CAP_NET_ADMIN\nRestrictAddressFamilies=AF_NETLINK AF_UNIX AF_INET AF_INET6\n',
        'usr/lib/systemd/system/lanrith-nat46.service':
            '[Unit]\nDescription=Mapped IPv4 to IPv6 translation\n'
            f'Requires=lanrith-nat46-network.service nftables.service{policy_dependency}\n'
            f'After=lanrith-nat46-network.service nftables.service{policy_dependency}\n'
            'BindsTo=lanrith-nat46-network.service nftables.service\n'
            '[Service]\nUser=lanrith-nat46\nGroup=lanrith-nat46\n'
            'ExecStart=/usr/sbin/tayga --nodetach --config /etc/tayga-nat46.conf\n'
            'Restart=on-failure\nRestartSec=2s\nNoNewPrivileges=yes\n'
            'CapabilityBoundingSet=\nProtectSystem=strict\nProtectHome=yes\nPrivateTmp=yes\n'
            'RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6\n'
            'DevicePolicy=closed\nDeviceAllow=/dev/net/tun rw\n'
            '[Install]\nWantedBy=multi-user.target\n',
    }
