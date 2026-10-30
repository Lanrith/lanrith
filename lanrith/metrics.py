"""Expose host metrics through a bounded proxy on the isolated service link."""

import ipaddress as ip

from . import integrations, intent, routing
from .release import canonical, require


COLLECTORS = ('arp', 'conntrack', 'cpu', 'cpufreq', 'diskstats', 'entropy', 'filefd', 'filesystem',
              'hwmon', 'interrupts', 'loadavg', 'meminfo', 'netclass', 'netdev', 'netstat',
              'powersupplyclass', 'pressure', 'processes', 'schedstat', 'sockstat', 'softnet', 'stat',
              'systemd', 'tcpstat', 'thermal_zone', 'time', 'timex', 'textfile', 'uname', 'vmstat')


def active(value):
    return value.get('observability', {}).get('metrics', {}).get('enabled', False)


def sources(value, component='metrics'):
    """Resolve each collector to one declared ordinary attachment."""
    if not value.get('observability', {}).get(component, {}).get('enabled', False):
        return []
    protected = intent.service_networks(value) + [ip.ip_network(component[key])
        for component in intent.translations(value).values() for key in ('prefix', 'pool')]
    owned, native = {}, {}
    for key, network in value['networks'].items():
        if not network.get('forwarding', True):
            continue
        owned[key] = [ip.ip_interface(a).network for a in network['addresses'] +
                      network.get('additional_subnets', []) + network.get('routed_prefixes', []) +
                      routing.routed_sources(value, key)]
        native[key] = list(owned[key])
        owned[key] += [p for route in value.get('routing', {}).get('static_routes', []) if route['network'] == key
                       for p in integrations.prefixes(value, route['to'])]
    result = {}
    for selector in integrations.endpoints(value, value['observability'][component]['clients']):
        require(set(selector) <= {'network', 'addresses'} and selector,
                'Metrics clients need network/address selectors without MAC or raw interface overrides.')
        selected = selector.get('network')
        require(selected is None or selected in owned, 'Metrics client requires an ordinary attachment.')
        addresses = selector.get('addresses', [str(p) for p in native.get(selected, [])])
        for address in addresses:
            prefix = ip.ip_network(address)
            invalid = ['0.0.0.0/8', '127.0.0.0/8', '169.254.0.0/16', '224.0.0.0/3'] if prefix.version == 4 else [
                '::/128', '::1/128', 'fe80::/10', 'ff00::/8']
            require(not any(prefix.overlaps(ip.ip_network(p)) for p in invalid), 'Invalid metrics source scope.')
            require(not any(prefix.version == p.version and prefix.overlaps(p) for p in protected),
                    'Metrics collectors cannot claim managed service or translator identities.')
            candidates = [key for key, pools in owned.items() if selected in (None, key) and
                          any(prefix.version == p.version and prefix.subnet_of(p) for p in pools)]
            require(len(candidates) == 1, 'Metrics source has no unambiguous declared attachment.')
            result.setdefault(candidates[0], set()).add(str(prefix))
    require(result, 'Metrics needs at least one reachable collector scope.')
    return [{'network': key, 'addresses': sorted(addresses)} for key, addresses in sorted(result.items())]


def manifest(value):
    from .service_plane import topology
    plane = topology(value)
    # Exporter reads the host's proc/sys data. Only the small HTTP proxy joins
    # the service namespace, with a fixed backend and an assigned source.
    return {'schema': 1, 'listeners': intent.service_addresses(value, 'metrics'),
            'backend': str(ip.ip_interface(plane['host_addresses'][0]).ip),
            'source': intent.service_addresses(value, 'metrics')[0]}


def router_manifest(value):
    from .runtime_plan import required_units
    return {'schema': 1, 'units': required_units(value),
            'interfaces': sorted({item['name'] for item in value['hardware']['interfaces'].values()
                                  if item.get('owner') != 'vpp'} |
                                 {item['name'] for item in value['networks'].values() if 'namespace' not in item}),
            'clients': [{'network': name, 'interface': item['name']} for name, item in value['networks'].items()
                        if item.get('forwarding', True) and 'namespace' not in item],
            'ntp': value['services']['ntp']['enabled']}


def render(value):
    if not active(value):
        return {}
    settings = manifest(value)
    sources(value)
    return {
        'usr/share/lanrith/metrics.json': canonical(settings).decode(),
        'usr/share/lanrith/router-metrics.json': canonical(router_manifest(value)).decode(),
        'usr/lib/sysusers.d/80-lanrith-metrics.conf': 'u lanrith-metrics - "Metrics proxy" /\n',
        'usr/lib/tmpfiles.d/80-lanrith-metrics.conf': 'd /var/lib/node_exporter/textfile_collector 0755 root root -\n',
        'usr/lib/systemd/system/lanrith-router-metrics.service': (
            '[Unit]\nDescription=Collect bounded router health in the host namespace\n'
            'Requires=var.mount\nAfter=var.mount nftables.service systemd-networkd.service\n'
            '[Service]\nType=oneshot\nUser=root\nGroup=root\nUMask=0022\n'
            'ExecStart=/usr/lib/lanrith/router-metrics\n'
            'ExecStopPost=/usr/lib/lanrith/router-metrics --on-stop\n'
            'TimeoutStartSec=25s\nTimeoutStopSec=2s\nKillMode=control-group\n'
            'CapabilityBoundingSet=CAP_NET_ADMIN\nNoNewPrivileges=yes\n'
            'ProtectSystem=strict\nProtectHome=yes\nPrivateTmp=yes\nPrivateDevices=yes\n'
            'ProtectKernelTunables=yes\nProtectKernelModules=yes\nProtectKernelLogs=yes\nProtectControlGroups=yes\n'
            'ReadWritePaths=/var/lib/node_exporter/textfile_collector\n'
            'RestrictAddressFamilies=AF_UNIX AF_NETLINK\nRestrictNamespaces=yes\n'
            'RestrictRealtime=yes\nRestrictSUIDSGID=yes\nLockPersonality=yes\n'
            'MemoryMax=64M\nMemorySwapMax=0\nTasksMax=16\nLimitNOFILE=128\n'),
        'usr/lib/systemd/system/lanrith-router-metrics.timer': (
            '[Unit]\nDescription=Refresh bounded router health\n\n'
            '[Timer]\nOnBootSec=15s\nOnUnitActiveSec=30s\nRandomizedDelaySec=5s\nAccuracySec=1s\n'
            'Unit=lanrith-router-metrics.service\n\n[Install]\nWantedBy=timers.target\n'),
        'usr/lib/systemd/system/prometheus-node-exporter.service': (
            '[Unit]\nDescription=Collect host network and system metrics\n'
            'PartOf=lanrith-metrics.service\nRequires=lanrith-services.service nftables.service\n'
            'After=lanrith-services.service nftables.service\n'
            'BindsTo=lanrith-services.service nftables.service\n[Service]\n'
            'Type=simple\nUser=prometheus\nGroup=prometheus\nPrivateNetwork=no\nNetworkNamespacePath=\n'
            'Environment=GOMAXPROCS=2\n'
            'ExecStart=/usr/bin/prometheus-node-exporter '+
            ' '.join(a.replace('$', '$$') for a in exporter_arguments(value))+'\n'
            'CapabilityBoundingSet=\nNoNewPrivileges=yes\nProtectSystem=strict\nProtectHome=yes\n'
            'PrivateTmp=yes\nProtectKernelTunables=yes\nProtectKernelModules=yes\nProtectControlGroups=yes\n'
            'RestrictAddressFamilies=AF_INET AF_INET6 AF_NETLINK AF_UNIX\nMemoryMax=256M\nTasksMax=32\n'
            'Restart=on-failure\nRestartSec=2s\n[Install]\nWantedBy=multi-user.target\n'),
        'usr/lib/systemd/system/lanrith-metrics.service': (
            '[Unit]\nDescription=Expose scoped host metrics\n'
            'Requires=lanrith-services.service prometheus-node-exporter.service\n'
            'After=lanrith-services.service prometheus-node-exporter.service\n'
            'BindsTo=lanrith-services.service nftables.service\n'
            '[Service]\nUser=lanrith-metrics\nGroup=lanrith-metrics\n'
            'NetworkNamespacePath=/run/netns/lanrith-services\n'
            'ExecStart=/usr/bin/python3 /usr/lib/lanrith/lanrith/metrics_runtime.py\n'
            'CapabilityBoundingSet=\nNoNewPrivileges=yes\nProtectSystem=strict\nProtectHome=yes\n'
            'PrivateTmp=yes\nProtectKernelTunables=yes\nProtectKernelModules=yes\nProtectControlGroups=yes\n'
            'RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX\n'
            'MemoryMax=64M\nTasksMax=8\nLimitNOFILE=128\n'
            'Restart=on-failure\nRestartSec=2s\n'
            '[Install]\nWantedBy=multi-user.target\n'),
    }


def exporter_arguments(value):
    return ['--web.listen-address='+manifest(value)['backend']+':9101', '--collector.disable-defaults',
            *('--collector.'+name for name in COLLECTORS),
            '--collector.netstat.fields=^(Ip|IpExt|Icmp|Tcp|TcpExt|Udp|UdpLite)_',
            '--collector.systemd.unit-include=^.+[.](service|socket)$',
            '--collector.textfile.directory=/var/lib/node_exporter/textfile_collector']


def client_rules(value, *, namespace=False, ingress=False):
    from .firewall import values
    from .service_plane import HOST_LINK
    result = []
    if not active(value):
        return result
    for source in sources(value):
        for family, protocol in ((4, 'ip'), (6, 'ip6')):
            clients = [a for a in source['addresses'] if ip.ip_network(a).version == family]
            if ingress:
                network = value['networks'][source['network']]
                native = [ip.ip_interface(a).network for a in network['addresses'] +
                          network.get('additional_subnets', []) + network.get('routed_prefixes', []) +
                          routing.routed_sources(value, source['network']) if ip.ip_interface(a).version == family]
                clients = [a for a in clients if not any(ip.ip_network(a).subnet_of(p) for p in native)]
            if not clients:
                continue
            listeners = [a for a in intent.service_addresses(value, 'metrics') if ip.ip_address(a).version == family]
            conditions = f'{protocol} saddr {values(clients)} {protocol} daddr {values(listeners)} tcp dport 9100'
            if not namespace:
                conditions = f'iifname "{value["networks"][source["network"]]["name"]}" '+conditions
                if not ingress:
                    conditions = f'oifname "{HOST_LINK}" '+conditions
            result.append('  '+conditions+(' return' if ingress else ' accept'))
            if ingress and family == 6:
                # An explicitly admitted on-link collector also needs neighbour
                # discovery with this router. Permit only link control traffic;
                # this must not admit its static route as an application source.
                network = value['networks'][source['network']]
                targets = [str(ip.ip_interface(a).ip) for a in intent.gateway_addresses(network)
                           if ip.ip_interface(a).version == 6] + ['fe80::/10', 'ff02::1:ff00:0/104']
                result.append(f'  iifname "{network["name"]}" ip6 saddr {values(clients)} '
                              f'ip6 daddr {values(targets)} ip6 hoplimit 255 '
                              'icmpv6 type { nd-neighbor-solicit, nd-neighbor-advert } icmpv6 code 0 return')
    return result


def backend_rule(value, *, namespace=False):
    from .service_plane import HOST_LINK
    if not active(value):
        return []
    settings = manifest(value)
    scope = 'meta skuid "lanrith-metrics"' if namespace else f'iifname "{HOST_LINK}"'
    return [f'  {scope} ip saddr {settings["source"]} ip daddr {settings["backend"]} tcp dport 9101 accept']
