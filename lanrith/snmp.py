"""Generate a scoped host SNMPv3 agent without embedding its credentials."""

import ipaddress as ip
from pathlib import PurePosixPath
import re

from . import bindings, intent, metrics
from .release import canonical, require


def active(value):
    return value.get('observability', {}).get('snmp', {}).get('enabled', False)


def listener(value):
    # Host networking preserves IF-MIB/IP-MIB visibility. Use the service
    # attachment's host address, preferring the provider address when present.
    return str(next(pool for pool in reversed(intent.service_networks(value)) if pool.version == 6).network_address + 1)


def sources(value):
    result = metrics.sources(value, 'snmp')
    require(all(ip.ip_network(address).version == 6 for item in result for address in item['addresses']),
            'SNMP collectors must use explicit IPv6 source scopes.')
    return result


def validate(value):
    if not active(value):
        return
    settings = value['observability']['snmp']
    require(re.fullmatch(r'[A-Za-z][A-Za-z0-9_.-]{2,31}', settings['username']), 'Invalid SNMPv3 username.')
    path = bindings.path(bindings.credential_path(value, settings['credential']))
    root = PurePosixPath(path).parent
    require(path.startswith('/var/lib/') and PurePosixPath(path).name == 'snmpd.conf' and
            root != PurePosixPath('/var/lib') and not root.is_relative_to('/var/lib/snmp'),
            'SNMP credentials require a private state directory separate from the persistent engine.')
    require(all(PurePosixPath(bindings.credential_path(value, other)).parent != root
                for other in bindings.credential_references(value) if other != settings['credential']),
            'SNMP activation requires its own private credential directory.')
    sources(value)


def manifest(value):
    settings = value['observability']['snmp']
    return {'schema': 1, 'server': listener(value), 'username': settings['username'],
            'credential_header': bindings.credential_header(value, settings['credential']),
            'state_directory': str(PurePosixPath(bindings.credential_path(value, settings['credential'])).parent)}


def client_rules(value, *, ingress=False):
    if not active(value):
        return []
    from .firewall import prefixes, values
    result = []
    for source in sources(value):
        network = value['networks'][source['network']]
        clients = source['addresses']
        if ingress:
            native = [ip.ip_network(address) for address in prefixes(network, 6, value)]
            clients = [a for a in clients if not any(ip.ip_network(a).subnet_of(p) for p in native)]
        if clients:
            scope = f'iifname "{network["name"]}" ip6 saddr {values(clients)} ip6 daddr {listener(value)}'
            result.append('  '+scope+' udp dport 161 '+('return' if ingress else 'accept'))
            if ingress:
                # Static attachment routes do not admit arbitrary applications.
                targets = [str(ip.ip_interface(a).ip) for a in intent.gateway_addresses(network)
                           if ip.ip_interface(a).version == 6] + ['fe80::/10', 'ff02::1:ff00:0/104']
                result.append(f'  iifname "{network["name"]}" ip6 saddr {values(clients)} '
                              f'ip6 daddr {values(targets)} ip6 hoplimit 255 '
                              'icmpv6 type { nd-neighbor-solicit, nd-neighbor-advert } icmpv6 code 0 return')
    return result


def input_rules(value):
    if not active(value):
        return []
    # Recheck the current collector scope even on a confirmed UDP tuple.
    return client_rules(value) + [f'  ip6 daddr {listener(value)} udp dport 161 drop']


def output_rules(value):
    if not active(value):
        return []
    from .firewall import values
    result = []
    for source in sources(value):
        network = value['networks'][source['network']]
        result.append(f'  oifname "{network["name"]}" ip6 saddr {listener(value)} '
                      f'ip6 daddr {values(source["addresses"])} udp sport 161 '
                      'ct direction reply ct state established accept')
    return result + [f'  oifname != "lo" ip6 saddr {listener(value)} udp sport 161 drop']


def render(value):
    if not active(value):
        return {}
    validate(value)
    policy = manifest(value)
    admitted = sorted({a for item in sources(value) for a in item['addresses']} | {policy['server']+'/128', '::1/128'})
    configuration = ('# Generated SNMPv3 read-only host agent. Credentials remain in encrypted state.\n'
                     f'agentAddress udp6:[{policy["server"]}]:161\n'
                     'sysLocation router-service-plane\nsysContact network-monitoring\n')
    for oid in ('.1.3.6.1.2.1.1', '.1.3.6.1.2.1.2', '.1.3.6.1.2.1.31',
                '.1.3.6.1.2.1.4', '.1.3.6.1.2.1.25', '.1.3.6.1.4.1.2021'):
        configuration += 'view lanrith included '+oid+'\n'
    configuration += f'rouser {policy["username"]} priv -V lanrith\n'
    state = policy['state_directory']
    unit = ('[Unit]\nDescription=Scoped authenticated and encrypted host SNMP\n'
            'Requires=lanrith-services.service nftables.service\n'
            'After=lanrith-services.service nftables.service\n'
            'BindsTo=lanrith-services.service nftables.service\n'
            f'ConditionPathExists={state}/snmpd.conf\n'
            '[Service]\nType=simple\nPrivateNetwork=no\nNetworkNamespacePath=\n'
            'ExecCondition=/usr/lib/lanrith/snmp-runtime prepare\n'
            'ExecStart=/usr/sbin/snmpd -f -LOw -u Debian-snmp -g Debian-snmp '
            f'-c {state}/snmpd.conf\n'
            'CapabilityBoundingSet=CAP_NET_BIND_SERVICE CAP_SETUID CAP_SETGID CAP_CHOWN CAP_DAC_READ_SEARCH CAP_FOWNER\n'
            'NoNewPrivileges=yes\nProtectSystem=strict\nProtectHome=yes\nPrivateTmp=yes\n'
            'ProtectKernelTunables=yes\nProtectKernelModules=yes\nProtectControlGroups=yes\n'
            'RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX AF_NETLINK\n'
            'IPAddressDeny=any\n'+''.join('IPAddressAllow='+a+'\n' for a in admitted)+
            f'ReadWritePaths=/var/lib/snmp {state} /run/lanrith-snmp\n'
            'MemoryMax=128M\nTasksMax=8\nLimitNOFILE=1024\n'
            'Restart=on-failure\nRestartSec=2s\n[Install]\nWantedBy=multi-user.target\n')
    return {'etc/snmp/snmpd.conf': configuration,
            'etc/lanrith/integrations/snmp-runtime-policy.json': canonical(policy).decode(),
            'usr/lib/systemd/system/snmpd.service': unit,
            'usr/lib/tmpfiles.d/80-lanrith-snmp.conf': (
                f'd {state} 0700 root root -\nd /run/lanrith-snmp 0700 root root -\n')}
