"""DNS64 for public answers and declared local authoritative zones."""

import ipaddress as ip

from . import authoritative, discovery, intent, public_nat64


PORT = 5354
REVERSE_PORT = 5356


def active(value):
    return 'nat64' in intent.translations(value) and value['services']['dns']['enabled']


def local_zones(value):
    return sorted(authoritative.settings(value)['zones']) if authoritative.active(value) else []


def private_active(value):
    return active(value) and (authoritative.active(value) or discovery.active(value))


def prefix(value, private=False):
    return intent.translations(value)['nat64-internal' if private else 'nat64']['prefix']


def rebind_guards(value):
    # Public answers must not redirect clients to local networks. Declared local
    # zones are explicit exceptions; forwarding permission is still independent.
    text = ''.join(f'  private-domain: "{zone}."\n' for zone in local_zones(value)+['ipv4only.arpa'])
    # Let respip return NXDOMAIN for A 0.0.0.0. Embedded zero must still be
    # excluded from public AAAA answers just like every other WKP destination.
    for network in public_nat64.excluding(public_nat64.BLOCKED, ['0.0.0.0/32']):
        text += f'  private-address: {network}\n'
    translation_prefix = ip.IPv6Network(prefix(value))
    for network in public_nat64.BLOCKED:
        text += f'  private-address: {public_nat64.embedded(network, translation_prefix)}\n'
    for network in ('::1/128', '::ffff:0:0/96', 'fc00::/7', 'fe80::/10', 'fec0::/10',
                    '2001:db8::/32', '3fff::/20', 'ff00::/8'):
        text += f'  private-address: {network}\n'
    return text


def reverse_zone(value):
    return discovery.reverse_zone(prefix(value, private=True))


def loopback(value):
    return '::1' if value['uplink'].get('ipv4') == 'disabled' else '127.0.0.1'


def reverse_forward(value):
    return (f'forward-zone:\n  name: "{reverse_zone(value)}"\n'
            f'  forward-addr: {loopback(value)}@{REVERSE_PORT}\n'
            '  forward-first: no\n  forward-tcp-upstream: yes\n')


def reverse_stubs(value):
    if not private_active(value):
        return {}
    zone = reverse_zone(value)
    blocked = value['services']['dns'].get('blocked_domains', [])
    # Respect an explicitly served apex and any enclosing local denial.
    if zone in {name.lower()+'.' for name in local_zones(value)} or any(
            ('.'+zone).endswith('.'+name.lower().rstrip('.')+'.') for name in blocked):
        return {}
    stubs = {}
    if authoritative.active(value):
        _, target = authoritative.resolver_path(value)
        for name in local_zones(value):
            if ('.'+name.lower()).endswith('.in-addr.arpa'):
                stubs[name.lower()+'.'] = [target]
    if discovery.active(value):
        for link in discovery.dns_manifest(value)['links']:
            for network in link['prefixes']:
                if ip.ip_network(network).version == 4:
                    stubs[discovery.reverse_zone(network)] = intent.service_addresses(value, 'discovery')
    return stubs


def reverse_configuration(value, stubs):
    # DNS64 must receive the new PTR event. Ordinary address queries continue
    # to use respip first on the two general resolvers.
    zone = reverse_zone(value)
    lines = [private_server(value, REVERSE_PORT).rstrip(), '  module-config: "dns64 iterator"',
             '  qname-minimisation: no', '  do-udp: no',
             '  local-zone: "." refuse', f'  local-zone: "{zone}" transparent']
    if discovery.active(value):
        lines.extend(discovery.resolver_budget(value, private=True))
    for name, targets in sorted(stubs.items()):
        lines += ['stub-zone:', f'  name: "{name}"', *(f'  stub-addr: {a}' for a in targets),
                  '  stub-prime: no', '  stub-first: no', '  stub-tcp-upstream: yes']
    # The iterator can consult this empty local root for any unmapped IPv4 PTR,
    # malformed reverse owner or alias outside the declared reverse authorities.
    lines += ['auth-zone:', '  name: "."', '  zonefile: "/etc/unbound/dns64-reverse.root"',
              '  for-downstream: no', '  for-upstream: yes', '  fallback-enabled: no']
    return '\n'.join(lines)+'\n'


def server(value):
    if not active(value):
        return ''
    text = ('  module-config: "respip dns64 validator iterator"\n'
            '  response-ip: 0.0.0.0/32 always_nxdomain\n  response-ip: ::/128 always_nxdomain\n'
            f'  dns64-prefix: {prefix(value)}\n  dns64-synthall: no\n')
    if private_active(value):
        text += '  do-not-query-localhost: no\n'
        if reverse_stubs(value):
            zone = reverse_zone(value)
            text += f'  local-zone: "{zone}" transparent\n  domain-insecure: "{zone}"\n'
        # The private instance uses the managed DNS source on its route back to
        # this resolver when a CNAME leaves a local authoritative zone.
        text += ''.join(f'  access-control: {address} allow\n' for address in intent.service_addresses(value, 'dns'))
    return text+rebind_guards(value)


def forwards(value):
    if not private_active(value):
        return ''
    local = ''.join(f'forward-zone:\n  name: "{zone}."\n  forward-addr: {loopback(value)}@{PORT}\n  forward-first: no\n'
                    for zone in local_zones(value))
    return local + (reverse_forward(value) if reverse_stubs(value) else '')


def private_server(value, port):
    dns = intent.service_addresses(value, 'dns')
    return (f'server:\n  interface: 127.0.0.1\n  interface: ::1\n  port: {port}\n'
            '  access-control: 127.0.0.1/32 allow\n  access-control: ::1/128 allow\n'
            '  access-control: 0.0.0.0/0 refuse\n  access-control: ::/0 refuse\n'
            '  username: ""\n  chroot: ""\n  pidfile: ""\n  do-not-query-localhost: no\n'
            f'  dns64-prefix: {prefix(value, True)}\n  dns64-synthall: no\n'
            '  hide-identity: yes\n  hide-version: yes\n'
            f'  outgoing-interface: {dns[0]}\n  outgoing-interface: {dns[1]}\n'
            +''.join(f'  access-control: {address} allow\n' for address in dns))


def unit(role, description, requires, hardening=''):
    return (
        f'[Unit]\nDescription={description}\nRequires={requires}\nAfter={requires}\n'
        'BindsTo=lanrith-services.service nftables.service\n'
        '[Service]\nUser=unbound\nGroup=unbound\n'
        'NetworkNamespacePath=/run/netns/lanrith-services\n'
        f'ExecStart=/usr/sbin/unbound -d -p -c /etc/unbound/unbound-{role}.conf\n'
        'Restart=on-failure\nRestartSec=2s\nNoNewPrivileges=yes\nCapabilityBoundingSet=\n'
        'ProtectSystem=strict\nProtectHome=yes\nPrivateTmp=yes\n'
        'RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX AF_NETLINK\n'
        +hardening+'[Install]\nWantedBy=multi-user.target\n')


def render(value):
    if not private_active(value):
        return {}
    dns = intent.service_addresses(value, 'dns')
    local, stubs = authoritative.resolver_zones(value)
    reverse = reverse_stubs(value)
    text = (private_server(value, PORT) + '  module-config: "respip dns64 iterator"\n'
            '  response-ip: 0.0.0.0/32 always_nxdomain\n  response-ip: ::/128 always_nxdomain\n'
            + local)
    if reverse:
        text += f'  local-zone: "{reverse_zone(value)}" transparent\n'
    # A private CNAME which leaves its zone must get the public resolver's
    # validated answer and public synthesis prefix, without recursing in a loop.
    target = dns[1] if value['uplink'].get('ipv4') == 'disabled' else dns[0]
    text += f'forward-zone:\n  name: "."\n  forward-addr: {target}\n'+stubs
    if reverse:
        text += reverse_forward(value)
    if discovery.active(value):
        text += discovery.resolver_configuration(value, private=True)
    dependencies = 'lanrith-services.service' + (' named.service' if authoritative.active(value) else '')
    files = {'etc/unbound/unbound-private.conf': text}
    if reverse:
        dependencies += ' lanrith-dns64-reverse.service'
        files.update({
            'etc/unbound/unbound-reverse.conf':
                reverse_configuration(value, reverse),
            'etc/unbound/dns64-reverse.root': '. 60 IN SOA localhost. nobody.invalid. 1 60 60 60 60\n'
                                            '. 60 IN NS localhost.\n',
            'usr/lib/systemd/system/lanrith-dns64-reverse.service':
                unit('reverse', 'Reverse lookups for the internal DNS64 prefix', 'lanrith-services.service',
                     'RestrictNetworkInterfaces=lo\n')})
    files['usr/lib/systemd/system/lanrith-dns64-private.service'] = unit(
        'private', 'Local-zone DNS64 synthesis', dependencies)
    return files
