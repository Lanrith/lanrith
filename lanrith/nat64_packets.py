"""NAT64 tuple proofs shared by the compiler and bounded allocation publisher."""

import ipaddress as ip

from .nat64_allocations import validate


def label(manifest):
    return 'n64i' if manifest['interface'] == 'nat64-internal' else 'n64'


def transport(protocol, reply=False, error=False, family=6):
    if protocol == 'icmp':
        return f'@th,{(416 if family == 6 else 256) if error else 32},32'
    if error:
        return 'ct original proto-src . ct original proto-dst'
    return f'{protocol} {"dport" if reply else "sport"} . {protocol} {"sport" if reply else "dport"}'


def forward_key(client, target, protocol, interface='oifname'):
    return f'{interface} . {client} . {target} . {transport(protocol)}'


def return_key(client, target, protocol, *, error=False, family=6):
    return f'{client} . {target} . {transport(protocol, reply=True, error=error, family=family)}'


def match(protocol, family, reply=False):
    if protocol == 'icmp':
        return f'icmp{"v6" if family == 6 else ""} type echo-{"reply" if reply else "request"}'
    return f'meta l4proto {protocol}'


def client_chains(manifest, allocations):
    """Publish immutable identities as bounded per-client verdict-map targets.

    nft cannot concatenate a map result into a tuple lookup. A chain carrying a
    literal IPv6 identity performs that lookup without borrowing packet marks
    from the independent identity-policy guard.
    """
    validate(manifest, allocations)
    name, device = label(manifest), manifest['interface']
    lines = []
    for source, target in sorted(allocations.items(), key=lambda entry: ip.ip_address(entry[1])):
        chain = f'{name}_c{int(ip.ip_address(target)):08x}'
        lines += [f'add chain inet lanrith {chain}', f'flush chain inet lanrith {chain}']
        for protocol in ('tcp', 'udp', 'icmp'):
            prefix = f'add rule inet lanrith {chain} '
            for index, destination in enumerate(manifest['attachments']):
                lines.append(prefix+f'iifname "{device}" oifname "{destination}" {match(protocol, 4)} '
                             f'{source} . @nh,128,32 . {transport(protocol)} @{name}_{protocol}_forward_{index} accept')
            lines.append(prefix+f'oifname "{device}" ct state established ct direction reply {match(protocol, 4, True)} '
                         f'update @{name}_{protocol}_reply '
                         f'{{ {return_key(source, "@nh,96,32", protocol, family=4)} }} accept')
            errors = ('destination-unreachable, time-exceeded, parameter-problem')
            quoted = 256 if protocol == 'icmp' else 224
            raw = f'{source} . @th,192,32 . @th,{quoted},32'
            number = {'tcp': 6, 'udp': 17, 'icmp': 1}[protocol]
            for index, _ in enumerate(manifest['attachments']):
                lines.append(prefix+f'meta iif 0 oifname "{device}" icmp type {{ {errors} }} '
                             f'@th,64,8 0x45 @th,136,8 {number} @th,160,32 0x{int(ip.ip_address(target)):x} '
                             f'{raw} @{name}_{protocol}_initial_error_{index} '
                             f'update @{name}_{protocol}_local_reply_error {{ {raw} }} accept')
            lines.append(prefix+f'oifname "{device}" ct state related ct direction reply '
                         f'ct original ip saddr {target} ct protocol {protocol} icmp type {{ {errors} }} '
                         f'@th,64,8 0x45 update @{name}_{protocol}_reply_error '
                         f'{{ {return_key(source, "@th,192,32", protocol, error=True, family=4)} }} accept')
        lines.append(f'add rule inet lanrith {chain} drop')
    lines += [f'flush map inet lanrith {name}_clients', f'flush set inet lanrith {name}_ready']
    if allocations:
        elements = ', '.join(f'{target} : jump {name}_c{int(ip.ip_address(target)):08x}'
                             for source, target in sorted(allocations.items()))
        lines.append(f'add element inet lanrith {name}_clients {{ {elements} }}')
        lines.append(f'add element inet lanrith {name}_ready {{ '+', '.join(sorted(allocations))+' }')
    return '\n'.join(lines)+'\n'
