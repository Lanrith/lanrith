"""Public unicast destinations excluded from RFC 6052 well-known-prefix translation."""

import ipaddress as ip


WELL_KNOWN_PREFIX = ip.IPv6Network('64:ff9b::/96')

# IANA IPv4 Special-Purpose Address Registry, updated 2025-10-09.
# Include active Globally Reachable=False registrations. More-specific entries
# with the same result are already covered by their parent. The terminated
# 192.88.99.0/24 entry has no reachability field; 192.88.99.2/32 is active.
# RFC 1112 multicast is outside the unicast registry.
NON_GLOBAL = (
    '0.0.0.0/8', '10.0.0.0/8', '100.64.0.0/10', '127.0.0.0/8',
    '169.254.0.0/16', '172.16.0.0/12', '192.0.0.0/24', '192.0.2.0/24',
    '192.88.99.2/32', '192.168.0.0/16', '198.18.0.0/15', '198.51.100.0/24',
    '203.0.113.0/24', '224.0.0.0/4', '240.0.0.0/4',
)
GLOBAL_EXCEPTIONS = ('192.0.0.9/32', '192.0.0.10/32')


def excluding(networks, exceptions):
    for exception in map(ip.IPv4Network, exceptions):
        networks = [child for network in networks for child in
                    (network.address_exclude(exception) if exception.subnet_of(network) else [network])]
    return sorted(networks)


BLOCKED = tuple(excluding(list(map(ip.IPv4Network, NON_GLOBAL)), GLOBAL_EXCEPTIONS))


def embedded(network, prefix):
    return ip.IPv6Network((int(prefix.network_address) + int(network.network_address),
                           96 + network.prefixlen))
