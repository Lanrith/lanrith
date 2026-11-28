"""Compile link readiness and IPv6 client delivery from router intent."""

import ipaddress as ip

from . import intent, integrations, routing, tun_policy
from .release import require


GLOBAL_UNICAST = ip.ip_network('2000::/3')


def families(addresses):
    versions = {ip.ip_interface(a).version for a in addresses}
    return 'both' if versions == {4, 6} else 'ipv6' if versions == {6} else 'ipv4'


def requires_carrier(network):
    return not (network.get('role') == 'management' and 'vlan' not in network and
                families(network['addresses']) == 'ipv4')


def required_uplink_families(uplink):
    return [family for family, default in (('ipv4', 'dhcp'), ('ipv6', 'ra'))
            if uplink.get(family, default) != 'disabled']


def provider_sources(value, network, prefixes=None):
    allocation = value['uplink'].get('downstream_prefix')
    if not allocation:
        return []
    pool = ip.ip_network(allocation)
    prefixes = network['addresses'] if prefixes is None else prefixes
    networks = (ip.ip_interface(address).network for address in prefixes)
    return list(ip.collapse_addresses(p for p in networks if p.version == 6 and p.subnet_of(GLOBAL_UNICAST)
                                      and p.subnet_of(pool)))


def routed(value, network):
    if 'ipv6_delivery' in network:
        return network['ipv6_delivery'] == 'routed'
    return (value['uplink'].get('delivery', 'routed') == 'routed'
            and network.get('forwarding', True) and bool(provider_sources(value, network)))


def upstream_routes(value, network):
    """A private upstream destination still needs a matching access grant."""
    routes = [ip.ip_network(a) for a in network.get('ipv6_upstream_routes', [])]
    routes.extend(ip.ip_network(a) for a in value['uplink'].get('private_services', []) if ':' in a)
    return list(ip.collapse_addresses(routes))


def local_routes(value, key):
    """Keep off-link services and routed LAN destinations reachable without a default."""
    network = value['networks'][key]
    routes = set(upstream_routes(value, network))
    for service in ('dns', 'ntp'):
        if network[service]:
            routes.update(ip.ip_network(a) for a in intent.service_addresses(value, service) if ':' in a)
    for other_key, other in value['networks'].items():
        sources = other.get('routed_prefixes', []) + routing.routed_sources(value, other_key)
        if other_key != key:
            sources += intent.gateway_addresses(other)
        routes.update(ip.ip_interface(a).network for a in sources if ':' in a)
    for route in value.get('routing', {}).get('static_routes', []):
        routes.update(p for p in integrations.prefixes(value, route['to']) if p.version == 6)
    routes.update(ip.ip_network(t['prefix']) for t in intent.translations(value).values()
                  if t['component'] == 'nat64')
    return list(ip.collapse_addresses(routes))


def validate(value):
    uplink = value['uplink']
    require(type(uplink.get('required_for_online', False)) is bool and
            (not uplink.get('required_for_online') or required_uplink_families(uplink)),
            'A required uplink needs at least one enabled address family.')
    compiler = None
    for network in value['networks'].values():
        require(network.get('ipv6_delivery', 'local') in ('local', 'routed'),
                'Unknown IPv6 client delivery model.')
        if 'ipv6_delivery' in network or 'ipv6_upstream_routes' in network:
            require(any(':' in a for a in network['addresses']), 'IPv6 client delivery needs an IPv6 LAN.')
        if routed(value, network):
            require(network.get('forwarding', True) and provider_sources(value, network) and
                    uplink.get('ipv6', 'ra') != 'disabled',
                    'Routed IPv6 clients need a LAN prefix within the declared downstream allocation.')
        for route in intent.sequence(network.get('ipv6_upstream_routes', []), 32):
            prefix = intent.network(route, 6)
            require(prefix.prefixlen > 0 and (prefix.subnet_of(GLOBAL_UNICAST) or
                    prefix.subnet_of(ip.ip_network('fc00::/7'))) and uplink.get('ipv6', 'ra') != 'disabled',
                    'An IPv6 upstream route must identify an assigned unicast destination.')
        selected = network.get('pref64')
        if selected is None and 'pref64' not in network:
            continue
        require(selected in ('nat64', 'nat64-internal') and selected in intent.translations(value) and
                network.get('ra') and network.get('forwarding', True),
                'PREF64 requires an enabled NAT64 translator on a forwarding RA network.')
        if compiler is None:
            compiler = tun_policy.Compiler(value)
        require(has_translation_grant(value, network, compiler, selected),
                'PREF64 requires an IPv6 access grant from this LAN to the selected translator.')


def has_translation_grant(value, network, compiler, selected):
    lan = [ip.ip_interface(a).network for a in network['addresses'] if ':' in a]
    for rule in intent.access(value)['rules']:
        if (rule['action'] != 'allow' or rule.get('family') == 'ipv4' or
                rule['protocol'] not in ('any', 'tcp', 'udp', 'icmpv6') or
                rule.get('direction') == 'reply' or 'new' not in rule.get('states', ['new'])):
            continue
        sources = (compiler.endpoint(entry, True) for entry in rule['from'])
        if not any(src['interface'] in (None, network['name']) and
                   (src['addresses'] is None or any(a.version == 6 and a.overlaps(p)
                    for a in src['addresses'] for p in lan)) for src in sources):
            continue
        if any(device == selected for entry in rule['to']
               for device, prefix in compiler.targets(compiler.endpoint(entry, False), 6)):
            return True
    return False


def pref64_units(value):
    """Expose immutable RA fragments only while the selected translator is active."""
    files = {}
    for translator in sorted({n['pref64'] for n in value['networks'].values() if 'pref64' in n}):
        unit = f'lanrith-pref64-{translator}.service'
        owner = f'lanrith-{translator}.service'
        fragment = f'/usr/lib/lanrith/networkd/pref64-{translator}.conf'
        prefix = intent.translations(value)[translator]['prefix']
        files[fragment[1:]] = f'[IPv6PREF64Prefix]\nPrefix={prefix}\nLifetimeSec=1800\n'
        directories = [f'/run/systemd/network/40-{key}.network.d'
                       for key, n in sorted(value['networks'].items()) if n.get('pref64') == translator]
        files[f'usr/lib/tmpfiles.d/lanrith-pref64-{translator}.conf'] = ''.join(
            f'd {directory} 0755 root root -\n' for directory in directories)
        paths = [directory+'/60-lanrith-pref64.conf' for directory in directories]
        files[f'etc/systemd/system/{owner}.d/65-lanrith-pref64.conf'] = f'[Unit]\nWants={unit}\n'
        files['usr/lib/systemd/system/'+unit] = (
            f'[Unit]\nDescription=Advertise the active {translator} prefix\nBindsTo={owner}\n'
            f'After={owner} systemd-networkd.service systemd-tmpfiles-setup.service\n'
            '[Service]\nType=oneshot\nRemainAfterExit=yes\n'
            + ''.join(f'ExecStart=/usr/bin/ln -sfn {fragment} {path}\n' for path in paths)
            + 'ExecStartPost=/usr/bin/networkctl reload\n'
            + 'ExecStopPost=/usr/bin/rm -f ' + ' '.join(paths) + '\n'
            + 'ExecStopPost=/usr/bin/networkctl reload\n'
            + 'TimeoutStartSec=30s\nTimeoutStopSec=30s\nNoNewPrivileges=yes\n'
            + 'CapabilityBoundingSet=\nProtectSystem=strict\nReadWritePaths=' + ' '.join(directories) + '\n'
            + 'ProtectHome=yes\nPrivateTmp=yes\nRestrictAddressFamilies=AF_UNIX AF_NETLINK\n')
    return files


def bus_policy():
    # Debian 257.13 reads these lists before its polkit checks. All runtime
    # DNS/NTP server settings on this image come from the compiled profile.
    members = ('SetNTP', 'SetLinkNTP', 'SetDNSSECNegativeTrustAnchors', 'SetLinkDNSSECNegativeTrustAnchors')
    rules = ''.join(f'    <deny send_destination="org.freedesktop.network1" send_member="{member}"/>\n'
                    for member in members)
    return ('<busconfig>\n  <policy context="default">\n' + rules + '  </policy>\n'
            '  <policy user="root">\n    <allow send_destination="org.freedesktop.network1"/>\n'
            '  </policy>\n</busconfig>\n')
