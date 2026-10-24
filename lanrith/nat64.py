"""IPv6-to-IPv4 policy projection with an independent proof for each egress."""

import copy
import ipaddress as ip

from . import access, intent, translation
from .nat64_packets import forward_key, label, match, return_key, transport
from .release import canonical, require


def components(value):
    return [item for item in intent.translations(value).values() if item['component'] == 'nat64']


def attachments(value):
    return [value['hardware']['interfaces'][value['uplink']['interface']]['name'],
            *(network['name'] for network in value['networks'].values() if network.get('forwarding', True))]


def targets(value, rule, manifest, destination):
    """Translate logical IPv4 and encoded IPv6 selectors without losing interface scope."""
    prefix = ip.ip_network(manifest['prefix'])
    result = []
    for selected in intent.expand(value, rule['to']):
        item = access.selector(selected, value['networks'], value['hardware']['interfaces'],
                               value['uplink'], source=False)
        if item['interface'] not in (None, manifest['interface'], destination):
            continue
        for network in item['addresses'] or [prefix]:
            if network.version == 4 and item['interface'] in (None, destination):
                result.append(str(ip.IPv6Network((int(prefix.network_address)+int(network.network_address),
                                                 96+network.prefixlen))))
            elif network.version == 6 and item['interface'] in (None, manifest['interface']) and network.overlaps(prefix):
                result.append(str(network if network.subnet_of(prefix) else prefix))
        if item['addresses'] is None and item['interface'] == destination:
            # An unqualified logical egress covers its IPv4 destinations. The
            # encoded IPv6 representation still belongs to the translator.
            result.append(str(prefix))
    return list(dict.fromkeys(result))


def original_rules(value, manifest, destination):
    result = []
    for rule in value.get('access', {}).get('rules', []):
        if rule.get('family') == 'ipv4':
            continue
        selected = targets(value, rule, manifest, destination)
        if not selected:
            continue
        sources = []
        for source in intent.expand(value, rule['from']):
            source = copy.deepcopy(source)
            if 'addresses' in source:
                source['addresses'] = [a for a in source['addresses'] if ip.ip_network(a).version == 6]
                if not source['addresses']:
                    continue
            sources.append(source)
        if not sources:
            continue
        protocols = rule.get('protocol', 'any')
        for protocol in protocols if isinstance(protocols, list) else [protocols]:
            if protocol not in ('any', 'tcp', 'udp', 'icmp', 'icmpv6'):
                continue
            projected = {**rule, 'from': sources, 'family': 'ipv6',
                         'to': {'interface': manifest['interface'], 'addresses': selected},
                         'protocol': 'icmpv6' if protocol == 'icmp' else protocol}
            projected.pop('name', None)
            result.extend(access.render({'rules': [projected]}, value['networks'],
                                        value['hardware']['interfaces'], value['uplink']))
    return result


def supports(value, rule):
    selected = {**value, 'access': {'rules': [rule]}}
    return any(original_rules(selected, manifest, destination)
               for manifest in components(value) for destination in attachments(value))


def source_guard(value):
    result = []
    for manifest in components(value):
        device = manifest['interface']
        result += [f'  iifname != "{device}" ip saddr {manifest["pool"]} drop',
                   f'  iifname != "{device}" ip6 saddr {manifest["prefix"]} drop',
                   f'  iifname "{device}" ip saddr != {manifest["pool"]} drop',
                   f'  iifname "{device}" ip6 saddr != {{ {manifest["prefix"]}, {manifest["ipv6"]} }} drop']
    return result


def forward(value):
    result = []
    for manifest in components(value):
        name, device = label(manifest), manifest['interface']
        result += [f'  iifname "{device}" jump {name}_output',
                   f'  oifname "{device}" jump {name}_input']
    return result


def chains(value):
    result = []
    for manifest in components(value):
        name, device = label(manifest), manifest['interface']
        result += [f' map {name}_clients {{ type ipv4_addr : verdict; }}',
                   f' set {name}_ready {{ type ipv6_addr; size 65534; }}',
                   f' set {name}_pending {{ type ipv6_addr; flags dynamic,timeout; timeout 30s; size 4096; }}']
        for protocol in ('tcp', 'udp', 'icmp'):
            for index, _ in enumerate(attachments(value)):
                result.append(f' set {name}_{protocol}_forward_{index} {{ typeof ip6 saddr . @nh,288,32 . {transport(protocol)}; '
                              'flags dynamic,timeout; timeout 2s; size 16384; }')
                result.append(f' set {name}_{protocol}_initial_error_{index} {{ typeof ip6 saddr . @nh,288,32 . @th,0,32; '
                              'flags dynamic,timeout; timeout 2s; size 16384; }')
            result.append(f' set {name}_{protocol}_local_reply_error {{ typeof ip6 saddr . @nh,288,32 . @th,0,32; '
                          'flags dynamic,timeout; timeout 2s; size 16384; }')
            for direction in ('reply', 'reply_error'):
                expression = return_key('ip6 daddr', '@nh,160,32', protocol, error=direction == 'reply_error')
                result.append(f' set {name}_{protocol}_{direction} {{ typeof {expression}; '
                              'flags dynamic,timeout; timeout 2s; size 16384; }')
        destinations = attachments(value)
        for index, destination in enumerate(destinations):
            for stage in ('first', 'more'):
                result.append(f' chain {name}_{stage}_p{index} {{')
                for line in original_rules(value, manifest, destination):
                    if line.endswith('accept'):
                        line = line.removesuffix('accept')+f'goto {name}_{stage}_a{index}'
                    elif line.endswith('drop'):
                        line = line.removesuffix('drop')+'return'
                    result.append(line)
                result += ['  return', ' }', f' chain {name}_{stage}_a{index} {{']
                for protocol in ('tcp', 'udp', 'icmp'):
                    expression = f'ip6 saddr . @nh,288,32 . {transport(protocol)}'
                    raw = f'ip6 saddr . @nh,288,32 . @th,{32 if protocol == "icmp" else 0},32'
                    result.append(f'  {match(protocol, 6)} update @{name}_{protocol}_forward_{index} {{ {expression} }} '
                                  f'update @{name}_{protocol}_initial_error_{index} {{ {raw} }}')
                if stage == 'first':
                    result += [f'  jump {name}_more_p{next_index}'
                               for next_index in range(index+1, len(destinations))]
                    for protocol in ('tcp', 'udp', 'icmp'):
                        result += [f'  {match(protocol, 6)} ip6 saddr @{name}_ready accept',
                                   f'  {match(protocol, 6)} update @{name}_pending {{ ip6 saddr }} drop']
                    result.append('  drop')
                else:
                    result.append('  return')
                result += [' }']
        result += [f' chain {name}_input {{',
                   f'  meta nfproto ipv4 ip daddr vmap @{name}_clients',
                   '  meta nfproto != ipv6 drop', f'  ip6 daddr != {manifest["prefix"]} drop']
        # The first permitted egress records its proof, visits the remaining
        # egress policies, and admits this packet. No surviving proof from an
        # earlier packet can substitute for that current policy decision.
        result += [f'  jump {name}_first_p{index}' for index, _ in enumerate(destinations)]
        result += ['  drop', ' }', f' chain {name}_output {{',
                   f'  meta nfproto ipv4 ip saddr vmap @{name}_clients']
        for protocol in ('tcp', 'udp', 'icmp'):
            expression = return_key('ip6 daddr', '@nh,160,32', protocol)
            result.append(f'  ip6 saddr {manifest["prefix"]} ct state established ct direction reply '
                          f'{match(protocol, 6, True)} {expression} @{name}_{protocol}_reply accept')
            expression = return_key('ct original ip6 saddr', '@th,352,32', protocol, error=True)
            result.append(f'  ct state related ct direction reply ct original ip6 daddr {manifest["prefix"]} '
                          f'ct protocol {"ipv6-icmp" if protocol == "icmp" else protocol} '
                          'icmpv6 type { destination-unreachable, packet-too-big, time-exceeded, parameter-problem } '
                          f'@th,64,4 6 {expression} @{name}_{protocol}_reply_error accept')
            raw = f'ct original ip6 saddr . @th,352,32 . @th,{416 if protocol == "icmp" else 384},32'
            number = {'tcp': 6, 'udp': 17, 'icmp': 58}[protocol]
            errors = (f'  ct state related ct direction reply ct original ip6 daddr {manifest["prefix"]} '
                      f'ct protocol {"ipv6-icmp" if protocol == "icmp" else protocol} '
                      'icmpv6 type { destination-unreachable, packet-too-big, time-exceeded, parameter-problem } '
                      f'@th,64,4 6 @th,112,8 {number}')
            result.append(errors+f' {raw} @{name}_{protocol}_local_reply_error accept')
            for index, _ in enumerate(attachments(value)):
                result.append(errors+f' ip6 saddr {manifest["ipv6"]} '
                              f'{raw} @{name}_{protocol}_initial_error_{index} accept')
        result += ['  drop', ' }']
    require(len(result) <= 32768, 'NAT64 enforcement exceeds its generated rule bound.')
    return result


def local_errors(value):
    result = []
    for manifest in components(value):
        name, device = label(manifest), manifest['interface']
        result += [f'  oifname "{device}" meta nfproto ipv4 ip daddr vmap @{name}_clients',
                   f'  oifname "{device}" drop']
    return result


def manifests(value, retained=None):
    return [{**item, 'attachments': attachments(value)} for item in translation.manifests(value, retained)
            if item['component'] == 'nat64']


def render(value, retained=None):
    files = {}
    selected = manifests(value, retained)
    for manifest in selected:
        name = manifest['interface']
        state = manifest['state_directory']
        policy_dependency = (' lanrith-policy-guards.service'
                             if value.get('identity', {}).get('policy', {}).get('enabled', False) else '')
        files[manifest['config'].lstrip('/')] = manifest['text']
        files['usr/share/lanrith/'+name+'.json'] = canonical(manifest).decode()
        files['usr/lib/sysusers.d/80-lanrith-'+name+'.conf'] = f'u lanrith-{name} - "IPv6 translation" /\n'
        parent = '/var/lib/tayga-nat64-internal'
        # Create fresh directories without changing any installed custodian or
        # permissions. The allocator independently rejects service-owned state
        # until an explicit migration has authenticated and transferred it.
        tmpfiles = f'd {parent} - - - -\n' if name == 'nat64-internal' else ''
        files['usr/lib/tmpfiles.d/80-lanrith-'+name+'.conf'] = tmpfiles+f'd {state} - - - -\n'
        files['usr/lib/systemd/system/lanrith-'+name+'-network.service'] = (
            '[Unit]\nDescription=Configure IPv6 translation routes\n'
            'Requires=nftables.service systemd-networkd.service\n'
            'After=nftables.service systemd-networkd.service systemd-sysusers.service systemd-tmpfiles-setup.service\n'
            f'BindsTo=nftables.service\nBefore=lanrith-{name}.service\n'
            '[Service]\nType=oneshot\nRemainAfterExit=yes\n'
            'Environment=PYTHONPATH=/usr/lib/lanrith\n'
            f'ExecStart=/usr/bin/python3 -m lanrith.translation_runtime start {name}\n'
            f'ExecStop=/usr/bin/python3 -m lanrith.translation_runtime stop {name}\n'
            'NoNewPrivileges=yes\nProtectSystem=strict\nProtectHome=yes\nPrivateTmp=yes\n'
            'CapabilityBoundingSet=CAP_NET_ADMIN\nRestrictAddressFamilies=AF_NETLINK AF_UNIX AF_INET AF_INET6\n')
        files['usr/lib/systemd/system/lanrith-'+name+'.service'] = (
            '[Unit]\nDescription=Retained IPv6 translation and tuple identities\n'
            f'Requires=lanrith-{name}-network.service nftables.service{policy_dependency}\n'
            f'After=lanrith-{name}-network.service nftables.service{policy_dependency}\n'
            f'BindsTo=lanrith-{name}-network.service nftables.service\n'
            '[Service]\nEnvironment=PYTHONPATH=/usr/lib/lanrith\n'
            f'ExecStart=/usr/bin/python3 -m lanrith.nat64_runtime {name}\n'
            f'ExecStartPost=/usr/bin/python3 -m lanrith.nat64_runtime wait {name}\nTimeoutStartSec=40s\n'
            f'RuntimeDirectory=lanrith-{name}\nRuntimeDirectoryMode=0755\n'
            'Restart=on-failure\nRestartSec=2s\nNoNewPrivileges=yes\n'
            'MemoryMax=256M\nMemorySwapMax=0\nTasksMax=32\nLimitNOFILE=1024\n'
            'CapabilityBoundingSet=CAP_NET_ADMIN CAP_SETUID CAP_SETGID CAP_KILL\n'
            'ProtectSystem=strict\nProtectHome=yes\nPrivateTmp=yes\n'
            f'ReadWritePaths={state}\nRestrictAddressFamilies=AF_UNIX AF_NETLINK AF_INET AF_INET6\n'
            'DevicePolicy=closed\nDeviceAllow=/dev/net/tun rw\n'
            '[Install]\nWantedBy=multi-user.target\n')
    if selected:
        policy_managed = value.get('identity', {}).get('policy', {}).get('enabled', False)
        files['etc/router-policy-agent/nat64-runtime/runtime.json'] = canonical({
            'schema_version': 1,
            'components': [{**{
                'id': manifest['interface'],
                'status_directory': '/run/lanrith-'+manifest['interface'],
                'configuration_file': '/run/lanrith-'+manifest['interface']+'/tayga.conf',
                'executable': ('/usr/lib/lanrith/tayga-internal'
                               if manifest['interface'] == 'nat64-internal' else '/usr/sbin/tayga'),
                'username': 'lanrith-'+manifest['interface'],
            }, **({'pending_family': 'inet', 'pending_table': 'router_policy_agent',
                    'pending_set': 'native_n64_'+str(index)+'_pending'} if policy_managed else {})}
                for index, manifest in enumerate(selected)],
        }).decode()
    return files
