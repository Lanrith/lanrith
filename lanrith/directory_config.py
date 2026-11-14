"""Compile exact directory-reader connectivity and credential-free TLS probes."""

import ipaddress as ip
import re
from urllib.parse import urlsplit

from .release import ReleaseError, canonical, require


HOST = re.compile(r'(?=.{1,253}\Z)[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?'
                  r'(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*\Z')


def selected(value):
    identity = value.get('identity', {})
    policy = identity.get('policy', {})
    return identity['directories'][policy['directory']] if policy.get('enabled', False) else None


def endpoint(settings):
    url = urlsplit(settings['url'])
    host = url.hostname
    require(isinstance(host, str) and '%' not in host, 'Directory endpoint cannot use a scoped address.')
    try:
        literal = ip.ip_address(host)
    except ValueError:
        literal = None
        require(HOST.fullmatch(host) and not host.replace('.', '').isdigit(), 'Directory hostname differs.')
    raw = settings.get('addresses', [str(literal)] if literal is not None else [])
    require(isinstance(raw, list) and 1 <= len(raw) <= 8 and all(isinstance(a, str) and '%' not in a for a in raw),
            'A named directory endpoint needs one to eight pinned IP addresses.')
    try:
        addresses = [ip.ip_address(a) for a in raw]
    except ValueError as error:
        raise ReleaseError('Directory address pins must be IP addresses.') from error
    require(len(set(addresses)) == len(addresses) and
            (literal is None or addresses == [literal]), 'Directory address pins differ from the endpoint.')
    for address in addresses:
        forbidden = ('0.0.0.0/8', '127.0.0.0/8', '169.254.0.0/16', '224.0.0.0/3') if address.version == 4 else (
            '::/128', '::1/128', '::ffff:0:0/96', 'fe80::/10', 'ff00::/8')
        require(not any(address in ip.ip_network(prefix) for prefix in forbidden),
                'Directory address needs an ordinary unicast endpoint.')
    return {'host': str(literal) if literal is not None else host,
            'port': url.port if url.port is not None else (636 if url.scheme == 'ldaps' else 389),
            'mode': 'ldaps' if url.scheme == 'ldaps' else 'starttls',
            'addresses': sorted(str(a) for a in addresses)}


def paths(value):
    from . import intent, service_plane
    settings = selected(value)
    if settings is None:
        return []
    target = endpoint(settings)
    local = {ip.ip_interface(a).ip for network in value['networks'].values()
             for a in intent.gateway_addresses(network)}
    local.update(ip.ip_interface(a).ip for a in value['uplink'].get('addresses', []))
    protected = intent.service_networks(value)
    protected += [ip.ip_network(component[key]) for component in intent.translations(value).values()
                  for key in ('prefix', 'pool')]
    result = []
    for address in target['addresses']:
        destination = ip.ip_address(address)
        require(destination not in local and not any(destination.version == p.version and destination in p
                                                     for p in protected),
                'Directory endpoint cannot claim a router, managed service or translator identity.')
        network = value['networks'][service_plane.destination_network(value, address)]
        require(network.get('forwarding', True) and 'namespace' not in network,
                'Directory endpoint needs an ordinary host attachment.')
        sources = sorted({str(ip.ip_interface(a).ip) for a in intent.gateway_addresses(network)
                          if ip.ip_interface(a).version == destination.version})
        require(sources, 'Directory attachment needs an address in the endpoint family.')
        result.append({'interface': network['name'], 'address': address, 'sources': sources, 'port': target['port']})
    return result


def output_rules(value):
    from .firewall import values
    identities = ('{ "router-policy-reader", "lanrith-directory-health" }'
                  if value.get('observability', {}).get('metrics', {}).get('enabled', False)
                  else '"router-policy-reader"')
    return [f'  meta skuid {identities} oifname "{p["interface"]}" '
            f'{"ip6" if ":" in p["address"] else "ip"} saddr {values(p["sources"])} '
            f'{"ip6" if ":" in p["address"] else "ip"} daddr {p["address"]} tcp dport {p["port"]} accept'
            for p in paths(value)]


def hosts(value):
    settings = selected(value)
    if settings is None:
        return ''
    target = endpoint(settings)
    if target['host'] in target['addresses']:
        return ''
    require(target['host'] not in {'localhost', 'ip6-localhost', 'ip6-loopback', value['hostname']},
            'Directory hostname conflicts with a local host identity.')
    return ''.join(address+' '+target['host']+'\n' for address in target['addresses'])


def render(value):
    settings = selected(value)
    if settings is None:
        return {}
    paths(value)
    if not value.get('observability', {}).get('metrics', {}).get('enabled', False):
        return {}
    policy = {'schema': 1, **endpoint(settings), 'ca_file': '/usr/share/lanrith/'+settings['ca_file']}
    return {
        'usr/share/lanrith/directory-health.json': canonical(policy).decode(),
        'usr/lib/sysusers.d/80-lanrith-directory-health.conf': 'u lanrith-directory-health - "Directory TLS observer" /\n',
        'usr/lib/systemd/system/lanrith-directory-health.service': (
            '[Unit]\nDescription=Observe verified directory TLS without credentials\n'
            'Requires=nftables.service\nBindsTo=nftables.service\nAfter=nftables.service systemd-networkd.service\n'
            '[Service]\nType=oneshot\nUser=lanrith-directory-health\nGroup=lanrith-directory-health\n'
            'ExecStart=/usr/lib/lanrith/directory-health\n'
            'RuntimeDirectory=lanrith-directory-health\nRuntimeDirectoryMode=0750\n'
            'RuntimeDirectoryPreserve=yes\nUMask=0027\nTimeoutStartSec=20s\n'
            'NoNewPrivileges=yes\nCapabilityBoundingSet=\nProtectSystem=strict\nProtectHome=yes\n'
            'PrivateTmp=yes\nPrivateDevices=yes\nProtectKernelTunables=yes\nProtectKernelModules=yes\n'
            'ProtectKernelLogs=yes\nProtectControlGroups=yes\n'
            'InaccessiblePaths=-/run/router-policy-reader -/run/router-policy-ipc -/var/lib/lanrith\n'
            'ReadWritePaths=/run/lanrith-directory-health\n'
            'RestrictAddressFamilies=AF_INET AF_INET6\nRestrictNamespaces=yes\n'
            'RestrictRealtime=yes\nRestrictSUIDSGID=yes\nLockPersonality=yes\n'
            'MemoryMax=64M\nMemorySwapMax=0\nTasksMax=8\nLimitNOFILE=64\n'),
        'usr/lib/systemd/system/lanrith-directory-health.timer': (
            '[Unit]\nDescription=Refresh verified directory TLS observations\n'
            '[Timer]\nOnBootSec=10s\nOnUnitActiveSec=30s\nRandomizedDelaySec=5s\nAccuracySec=1s\n'
            'Unit=lanrith-directory-health.service\n[Install]\nWantedBy=timers.target\n'),
    }
