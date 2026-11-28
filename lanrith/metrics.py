"""Expose host metrics through a bounded proxy on the isolated service link."""

import ipaddress as ip
import re

from . import dhcp4, integrations, intent, routing
from .metrics_runtime import BACKEND_PORT
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


def hook_inventory(*scripts):
    """Extract the base-chain declarations from our generated nft programs."""
    hooks = []
    priorities = {'filter': 0, 'dstnat': -100, 'srcnat': 100}
    for script in scripts:
        family = table = None
        for line in map(str.strip, script.splitlines()):
            if line.startswith('table '):
                _, family, table, _ = line.split()
            if not line.startswith('chain ') or ' hook ' not in line:
                continue
            header = re.fullmatch(r'chain (\w+) \{ type (\w+) hook (\w+)(?: device "([^"]+)")? '
                                  r'priority (-?\d+|[a-z]+); policy (accept|drop);.*', line)
            require(family is not None and header, 'Cannot inventory generated firewall hook.')
            name, kind, hook, device, priority, policy = header.groups()
            hooks.append({'family': family, 'table': table, 'name': name, 'type': kind, 'hook': hook,
                          'prio': priorities[priority] if priority.isalpha() else int(priority),
                          'policy': policy, **({'dev': device} if device else {})})
    return hooks


def router_manifest(value, *, rules=None, access_backend='tun'):
    from . import firewall, service_plane, tun_policy
    if rules is None:
        rules = (firewall.render(value, access_backend=access_backend),
                 service_plane.namespace_firewall(value, service_plane.topology(value)))
    guards = tun_policy.identity_egress(value) if access_backend == 'tun' else ''
    dhcp = {str(scope['id']): [pool['pool-id'] for pool in scope['pools']] for scope in dhcp4.scopes(value)}
    from .runtime_plan import advisory_timers, required_units
    return {'schema': 1, 'units': sorted(set(required_units(value)) | set(advisory_timers(value))),
            'interfaces': sorted({item['name'] for item in value['hardware']['interfaces'].values()
                                  if item.get('owner') != 'vpp'} |
                                 {item['name'] for item in value['networks'].values() if 'namespace' not in item}),
            'clients': [{'network': name, 'interface': item['name']} for name, item in value['networks'].items()
                        if item.get('forwarding', True) and 'namespace' not in item],
            'hooks': {'host': hook_inventory(rules[0], guards), 'services': hook_inventory(rules[1])},
            'dhcp4': dhcp, 'startup_set': bool(guards and 'tp_started' in rules[0]),
            'ntp': value['services']['ntp']['enabled'],
            'logs': value.get('observability', {}).get('logs', {}).get('enabled', False),
            'directory': value.get('identity', {}).get('policy', {}).get('enabled', False)}


def observer_socket(kind, identity, dependency, *, namespace=False):
    stem = 'lanrith-router-'+kind
    unit = 'usr/lib/systemd/system/'+stem
    return {unit+'.socket': (
                '[Unit]\nDescription=Read aggregate '+kind+' observations\n'
                '[Socket]\nListenStream=/run/'+stem+'.sock\nSocketMode=0600\nAccept=yes\n'
                'MaxConnections=2\nBacklog=2\nRemoveOnStop=yes\n'),
            unit+'@.service': (
                '[Unit]\nDescription=Measure '+kind+' for router metrics\nRequisite='+dependency+'\nAfter='+dependency+'\n'
                '[Service]\nUser='+identity+'\nGroup='+identity+'\n'
                'ExecStart=/usr/lib/lanrith/router-metrics --'+kind+'\n'
                'StandardInput=null\nStandardOutput=socket\nStandardError=journal\nRuntimeMaxSec=4s\nTimeoutStopSec=1s\n'
                + ('DynamicUser=yes\nNetworkNamespacePath=/run/netns/lanrith-services\n'
                   'AmbientCapabilities=CAP_NET_ADMIN\nCapabilityBoundingSet=CAP_NET_ADMIN\n'
                   'RestrictAddressFamilies=AF_NETLINK\n' if namespace else
                   'CapabilityBoundingSet=\nRestrictAddressFamilies=AF_UNIX\n') +
                'NoNewPrivileges=yes\nProtectSystem=strict\nProtectHome=yes\nPrivateTmp=yes\n'
                'PrivateDevices=yes\nProtectKernelTunables=yes\nProtectKernelModules=yes\n'
                'ProtectKernelLogs=yes\nProtectControlGroups=yes\nRestrictNamespaces=yes\n'
                'InaccessiblePaths=-/run/kea -/run/lanrith-kea-leases -/run/router-policy-ipc/requests.sock '
                '-/run/lanrith-policy -/run/credentials -/var/lib/lanrith\n'
                'MemoryMax=64M\nTasksMax=12\nLimitNOFILE=32\n')}


def render(value, *, rules=None, access_backend='tun'):
    if not active(value):
        return {}
    settings = manifest(value)
    sources(value)
    groups = []
    if value.get('observability', {}).get('logs', {}).get('enabled'):
        groups.append('alloy')
    if value.get('identity', {}).get('policy', {}).get('enabled'):
        groups.append('lanrith-directory-health')
    if value['services']['ntp']['enabled']:
        groups.append('_chrony')
    policy = router_manifest(value, rules=rules, access_backend=access_backend)
    observers = observer_socket('service-hooks', 'lr-firewall-metrics', 'lanrith-services.service', namespace=True)
    sockets = 'lanrith-router-service-hooks.socket'
    if policy['directory']:
        observers.update(observer_socket('policy-status', 'router-policy-operator', 'lanrith-policy-helper.service'))
        sockets += ' lanrith-router-policy-status.socket'
    return {
        **observers,
        **(ntp_observer() if value['services']['ntp']['enabled'] else {}),
        'usr/share/lanrith/metrics.json': canonical(settings).decode(),
        'usr/share/lanrith/router-metrics.json': canonical(policy).decode(),
        'usr/lib/sysusers.d/80-lanrith-metrics.conf': 'u lanrith-metrics - "Metrics proxy" /\n',
        'usr/lib/tmpfiles.d/80-lanrith-metrics.conf': ('d /var/lib/node_exporter/textfile_collector 0755 root root -\n'
            'r! /var/lib/node_exporter/textfile_collector/lanrith_router.prom - - - -\n'),
        'usr/lib/systemd/system/lanrith-router-metrics.service': (
            '[Unit]\nDescription=Collect bounded router health in the host namespace\n'
            'Requires=var.mount\nWants='+sockets+'\nAfter='+sockets+' var.mount nftables.service systemd-networkd.service\n'
            '[Service]\nType=oneshot\nUser=root\nGroup=root\nUMask=0022\n'
            + ('SupplementaryGroups='+' '.join(groups)+'\n' if groups else '') +
            'ExecStart=/usr/lib/lanrith/router-metrics\n'
            'ExecStopPost=/usr/lib/lanrith/router-metrics --on-stop\n'
            'TimeoutStartSec=25s\nTimeoutStopSec=10s\nKillMode=control-group\n'
            'CapabilityBoundingSet=CAP_NET_ADMIN\nNoNewPrivileges=yes\n'
            'ProtectSystem=strict\nProtectHome=yes\nPrivateTmp=yes\nPrivateDevices=yes\n'
            'ProtectKernelTunables=yes\nProtectKernelModules=yes\nProtectKernelLogs=yes\nProtectControlGroups=yes\n'
            'OpenFile=/proc/1/mountinfo:host-mountinfo:read-only,graceful\n'
            'InaccessiblePaths=-/run/kea -/run/lanrith-kea-leases -/run/router-policy-ipc\n'
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


def ntp_observer():
    return {
        'usr/lib/systemd/system/lanrith-ntp-health.service': (
            '[Unit]\nDescription=Observe Chrony without exposing its control socket\n'
            'Requires=lanrith-services.service\nBindsTo=lanrith-services.service\n'
            'After=lanrith-services.service chrony.service\n'
            '[Service]\nType=oneshot\nUser=_chrony\nGroup=_chrony\n'
            'NetworkNamespacePath=/run/netns/lanrith-services\n'
            'ExecStart=/usr/lib/lanrith/ntp-health\n'
            'RuntimeDirectory=lanrith-ntp-health\nRuntimeDirectoryMode=0750\n'
            'RuntimeDirectoryPreserve=yes\nUMask=0027\nTimeoutStartSec=15s\nTimeoutStopSec=5s\n'
            'NoNewPrivileges=yes\nCapabilityBoundingSet=\nProtectSystem=strict\nProtectHome=yes\n'
            'PrivateTmp=yes\nPrivateDevices=yes\nProtectKernelTunables=yes\nProtectKernelModules=yes\n'
            'ProtectKernelLogs=yes\nProtectControlGroups=yes\n'
            # chronyc creates its reply socket beside the daemon socket. Only
            # the existing service identity may write this private directory.
            'ReadWritePaths=/run/lanrith-ntp-health -/run/chrony\n'
            'InaccessiblePaths=-/run/router-policy-reader -/run/router-policy-ipc -/var/lib/lanrith\n'
            'RestrictAddressFamilies=AF_UNIX\nRestrictNamespaces=yes\n'
            'RestrictRealtime=yes\nRestrictSUIDSGID=yes\nLockPersonality=yes\n'
            'MemoryMax=64M\nMemorySwapMax=0\nTasksMax=8\nLimitNOFILE=64\n'),
        'usr/lib/systemd/system/lanrith-ntp-health.timer': (
            '[Unit]\nDescription=Refresh isolated NTP observations\n'
            '[Timer]\nOnBootSec=10s\nOnUnitActiveSec=30s\nRandomizedDelaySec=5s\nAccuracySec=1s\n'
            'Unit=lanrith-ntp-health.service\n[Install]\nWantedBy=timers.target\n'),
    }


def exporter_arguments(value):
    # Every enabled service link has an IPv4 and an IPv6 host address.
    # Keep the historical IPv4 expression and anchor each new IPv6 field.
    fields = ('^((Ip|IpExt|Icmp|Tcp|TcpExt|Udp|UdpLite)_.*|'
              'Ip6_(InOctets|OutOctets|InHdrErrors|InTooBigErrors|InNoRoutes|InAddrErrors|'
              'InUnknownProtos|InTruncatedPkts|OutNoRoutes)|'
              'Icmp6_(InMsgs|OutMsgs|InErrors|OutErrors|InCsumErrors)|'
              '(Udp6|UdpLite6)_(InDatagrams|OutDatagrams|NoPorts|InErrors|RcvbufErrors|SndbufErrors|InCsumErrors))$')
    return [f'--web.listen-address={manifest(value)["backend"]}:{BACKEND_PORT}', '--collector.disable-defaults',
            *('--collector.'+name for name in COLLECTORS),
            '--collector.netstat.fields='+fields,
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
    return [f'  {scope} ip saddr {settings["source"]} ip daddr {settings["backend"]} tcp dport {BACKEND_PORT} accept']


def local_backend_drop(value):
    if not active(value):
        return []
    return [f'  ip daddr {manifest(value)["backend"]} tcp dport {BACKEND_PORT} drop']
