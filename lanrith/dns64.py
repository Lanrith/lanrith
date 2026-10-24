"""DNS64 for public answers and declared local authoritative zones."""

import ipaddress as ip

from . import authoritative, intent


PORT = 5354


def active(value):
    return 'nat64' in intent.translations(value) and value['services']['dns']['enabled']


def local_zones(value):
    return sorted(authoritative.settings(value)['zones']) if authoritative.active(value) else []


def private_active(value):
    return active(value) and bool(local_zones(value))


def prefix(value, private=False):
    return intent.translations(value)['nat64-internal' if private else 'nat64']['prefix']


def rebind_guards(value):
    # Public answers must not redirect clients to local networks. Declared local
    # zones are explicit exceptions; forwarding permission is still independent.
    networks = [ip.ip_network(raw) for raw in (
        '0.0.0.0/8', '10.0.0.0/8', '100.64.0.0/10', '127.0.0.0/8', '169.254.0.0/16',
        '172.16.0.0/12', '192.0.0.0/24', '192.0.2.0/24', '192.88.99.2/32', '192.168.0.0/16',
        '198.18.0.0/15', '198.51.100.0/24', '203.0.113.0/24', '224.0.0.0/4', '240.0.0.0/4')]
    # Zero is handled by respip as NXDOMAIN. .9 and .10 are globally scoped
    # anycast addresses, unlike the rest of the 192.0.0.0/24 special-use block.
    for exception in ('0.0.0.0/32', '192.0.0.9/32', '192.0.0.10/32'):
        excluded = ip.ip_network(exception)
        networks = [child for network in networks for child in
                    (network.address_exclude(excluded) if excluded.subnet_of(network) else [network])]
    text = ''.join(f'  private-domain: "{zone}."\n' for zone in local_zones(value)+['ipv4only.arpa'])
    for network in sorted(networks):
        text += f'  private-address: {network}\n'
        embedded = ip.IPv6Network((int(ip.ip_network(prefix(value)).network_address)+int(network.network_address),
                                  96+network.prefixlen))
        text += f'  private-address: {embedded}\n'
    for network in ('::1/128', '::ffff:0:0/96', 'fc00::/7', 'fe80::/10', 'fec0::/10',
                    '2001:db8::/32', '3fff::/20', 'ff00::/8'):
        text += f'  private-address: {network}\n'
    return text


def server(value):
    if not active(value):
        return ''
    text = ('  module-config: "respip dns64 validator iterator"\n'
            '  response-ip: 0.0.0.0/32 always_nxdomain\n  response-ip: ::/128 always_nxdomain\n'
            f'  dns64-prefix: {prefix(value)}\n  dns64-synthall: no\n')
    if private_active(value):
        text += '  do-not-query-localhost: no\n'
        # The private instance uses the managed DNS source on its route back to
        # this resolver when a CNAME leaves a local authoritative zone.
        text += ''.join(f'  access-control: {address} allow\n' for address in intent.service_addresses(value, 'dns'))
    return text+rebind_guards(value)


def forwards(value):
    loopback = '::1' if value['uplink'].get('ipv4') == 'disabled' else '127.0.0.1'
    return ''.join(f'forward-zone:\n  name: "{zone}."\n  forward-addr: {loopback}@{PORT}\n'
                   for zone in local_zones(value)) if private_active(value) else ''


def render(value):
    if not private_active(value):
        return {}
    dns = intent.service_addresses(value, 'dns')
    local, stubs = authoritative.resolver_zones(value)
    text = (f'server:\n  interface: 127.0.0.1\n  interface: ::1\n  port: {PORT}\n'
            '  access-control: 127.0.0.1/32 allow\n  access-control: ::1/128 allow\n'
            '  access-control: 0.0.0.0/0 refuse\n  access-control: ::/0 refuse\n'
            '  username: ""\n  chroot: ""\n  pidfile: ""\n  do-not-query-localhost: no\n'
            '  module-config: "respip dns64 iterator"\n'
            '  response-ip: 0.0.0.0/32 always_nxdomain\n  response-ip: ::/128 always_nxdomain\n'
            f'  dns64-prefix: {prefix(value, True)}\n  dns64-synthall: no\n'
            '  hide-identity: yes\n  hide-version: yes\n'
            f'  outgoing-interface: {dns[0]}\n  outgoing-interface: {dns[1]}\n'
            +''.join(f'  access-control: {address} allow\n' for address in dns)+local)
    # A private CNAME which leaves its zone must get the public resolver's
    # validated answer and public synthesis prefix, without recursing in a loop.
    target = dns[1] if value['uplink'].get('ipv4') == 'disabled' else dns[0]
    text += f'forward-zone:\n  name: "."\n  forward-addr: {target}\n'+stubs
    return {
        'etc/unbound/unbound-private.conf': text,
        'usr/lib/systemd/system/lanrith-dns64-private.service': (
            '[Unit]\nDescription=Local-zone DNS64 synthesis\n'
            'Requires=lanrith-services.service named.service\n'
            'After=lanrith-services.service named.service\n'
            'BindsTo=lanrith-services.service nftables.service\n'
            '[Service]\nUser=unbound\nGroup=unbound\n'
            'NetworkNamespacePath=/run/netns/lanrith-services\n'
            'ExecStart=/usr/sbin/unbound -d -p -c /etc/unbound/unbound-private.conf\n'
            'Restart=on-failure\nRestartSec=2s\nNoNewPrivileges=yes\nCapabilityBoundingSet=\n'
            'ProtectSystem=strict\nProtectHome=yes\nPrivateTmp=yes\n'
            'RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX\n'
            '[Install]\nWantedBy=multi-user.target\n')}
