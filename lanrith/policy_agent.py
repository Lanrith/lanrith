"""Derive the policy helper's immutable ceiling from normalized router intent.

This is a contract generator. Runtime admission remains gated until native and
translated guard wiring and persistent classification have been qualified.
"""

import hashlib
import ipaddress as ip
from urllib.parse import urlsplit

from . import access, bindings, integrations, intent, routing, translation, service_plane
from .release import canonical, require


def _prefixes(value):
    return list(dict.fromkeys(str(ip.ip_network(prefix)) for prefix in value))


def _selector(value, selected, source):
    endpoint = access.selector(selected, value['networks'], value['hardware']['interfaces'],
                               value['uplink'], source=source)
    return {key: entry for key, entry in {
        'interface': endpoint['interface'],
        'addresses': [str(p) for p in endpoint['addresses']] if endpoint['addresses'] is not None else None,
        'mac': endpoint['mac'],
    }.items() if entry is not None}


def core_services(value):
    """Build fixed service connectivity from the same daemon/client geometry."""
    from . import service_plane, metrics
    plane = service_plane.topology(value)
    result = []
    for kind in ('dns', 'ntp', 'authoritative', 'discovery', 'metrics', 'radius'):
        if kind not in plane['endpoints']:
            continue
        clients = {}
        for entry in (metrics.sources(value) if kind == 'metrics' else service_plane.clients(value, kind)):
            network = value['networks'][entry['network']]
            require(network.get('forwarding', True), 'Core service client needs an ordinary attachment.')
            clients.setdefault(network['name'], set()).update(entry['addresses'])
        if clients:
            result.append({'kind': kind, 'interface': plane['host_link'],
                           'addresses': plane['endpoints'][kind],
                           'clients': [{'interface': interface, 'addresses': sorted(addresses)}
                                       for interface, addresses in sorted(clients.items())]})
    return result


def asymmetric_replies(value):
    """Expand only the declared IPv6 return tuples; never infer initiations."""
    result = []
    for declaration in value.get('routing', {}).get('asymmetric_replies', []):
        for source in integrations.endpoints(value, declaration['from']):
            for destination in integrations.endpoints(value, declaration['to']):
                result.append({
                    'mode': declaration['mode'],
                    'source_interface': value['networks'][source['network']]['name'],
                    'source_addresses': _prefixes(source['addresses']),
                    'destination_interface': value['networks'][destination['network']]['name'],
                    'destination_addresses': _prefixes(destination['addresses']),
                })
    return result


def baseline(value, retained_allocations=None):
    """Keep ordered owner intent separate from short-lived delegated grants."""
    policy = value.get('identity', {}).get('policy', {})
    require(policy.get('enabled', False), 'Policy helper contract requires an enabled identity policy.')
    zones = []
    router = []
    management = []
    for key, network in value['networks'].items():
        router.extend(str(ip.ip_network(str(ip.ip_interface(a).ip))) for a in intent.gateway_addresses(network))
        prefixes = [str(ip.ip_interface(a).network) for a in network['addresses']]
        prefixes += network.get('additional_subnets', []) + routing.routed_sources(value, key)
        if not network.get('forwarding', True):
            management.extend(prefixes)
            continue
        zones.append({'role': key, 'vlan': network.get('vlan', 0),
                      'interfaces': [network['name']], 'networks': _prefixes(prefixes)})
    router.extend(str(ip.ip_network(str(ip.ip_interface(address).ip)))
                  for address in value['uplink'].get('addresses', []))
    rules = []
    for rule in intent.access(value)['rules']:
        # The helper compiles connection initiations, not arbitrary packet-state
        # predicates. Reject unsupported predicates instead of discarding them.
        require(set(rule) <= {'action', 'authorization', 'from', 'to', 'protocol', 'ports',
                              'family', 'name', 'description', 'states'} and
                set(rule.get('states', ['new', 'established', 'related'])) == {'new', 'established', 'related'},
                'Policy helper contract does not support packet-state-specific access rules.')
        item = {key: rule[key] for key in ('action', 'authorization', 'protocol')}
        item.update({'from': [_selector(value, endpoint, True) for endpoint in rule['from']],
                     'to': [_selector(value, endpoint, False) for endpoint in rule['to']]})
        if 'ports' in rule:
            item['ports'] = sorted(rule['ports'])
        if 'family' in rule:
            item['family'] = 4 if rule['family'] == 'ipv4' else 6
        rules.append(item)
    limits = value.get('access', {}).get('delegation_limits', {})
    protected = [
        {'protection_id': 'P01', 'networks': _prefixes(router+management), 'roles': []},
        {'protection_id': 'P03', 'networks': _prefixes(str(p) for p in intent.service_networks(value)), 'roles': []},
    ]
    for selector in limits.get('networks', []):
        protected.append({'protection_id': 'P03', 'networks': [str(p) for p in integrations.prefixes(value, selector)], 'roles': []})
    endpoints = [{'protection_id': 'P02', 'networks': _prefixes(router),
                  'protocol': 'any', 'ports': [], 'destination_only': True}]
    for endpoint in limits.get('endpoints', []):
        endpoints.append({'protection_id': 'P02', 'networks': _prefixes(
            address for item in intent.expand(value, {'addresses': endpoint['addresses']}) for address in item['addresses']),
            'protocol': endpoint['protocol'], 'ports': sorted(endpoint['ports']), 'destination_only': True})
    translations = intent.translations(value)
    source_manifests = translation.manifests(value, retained_allocations)
    n46 = translations.get('nat46')
    result = {
        'schema_version': 1, 'generation': 'pending', 'zones': zones,
        'protected_networks': protected, 'protected_endpoints': endpoints, 'retained_blocks': [],
        'nat64': [{'id': component['interface'], 'prefix': component['prefix'],
                   'scope': 'private' if component['interface'] == 'nat64-internal' else 'global',
                   'source_pool': component['pool'], 'source_mappings': [
                       {'source': source, 'alias': target, 'ready': source in component['source_allocations']['active']}
                       for source, target in component['source_allocations'].get('reserved', {}).items()]}
                  for component in source_manifests if component['component'] == 'nat64'],
        'nat46': [{'id': name, 'alias': entry['ipv4'], 'target': entry['ipv6'], 'ready': True}
                  for name, entry in n46['mappings'].items()] if n46 else [],
        'nat46_pools': [n46['pool']] if n46 else [],
        'lease_seconds': 90, 'refresh_seconds': 30, 'maximum_devices': 4096, 'maximum_tuples': 16384,
        'network_model': {'schema_version': 1, 'managed_networks': policy['networks'],
                          'uplink_interface': value['hardware']['interfaces'][value['uplink']['interface']]['name'],
                          'rules': rules, 'core_services': core_services(value),
                          'core_egress': service_plane.egress(value),
                          'asymmetric_replies': asymmetric_replies(value),
                          'uplink_nat': intent.uplink_nat(value),
                          'service_prefixes': [str(prefix) for prefix in intent.service_networks(value)]
                                              if service_plane.topology(value)['endpoints'] else []},
    }
    if n46:
        result['network_model']['nat46_prefix'] = n46['prefix']
    require(all(zone['networks'] for zone in zones) and all(p in {n['role'] for n in zones} for p in policy['networks']),
            'Policy helper needs an addressed ordinary network for each managed boundary.')
    result['generation'] = hashlib.sha256(canonical(result)).hexdigest()
    return result


def runtime_contract(value):
    """Project only the immutable runtime inputs needed by the policy owner."""
    identity = value.get('identity', {})
    policy = identity.get('policy', {})
    require(policy.get('enabled', False), 'Policy runtime requires an enabled identity policy.')
    directory = identity['directories'][policy['directory']]
    endpoint = urlsplit(directory['url'])
    port = endpoint.port or (636 if endpoint.scheme == 'ldaps' else 389)
    host = '['+endpoint.hostname+']' if ':' in endpoint.hostname else endpoint.hostname
    directory_url = endpoint.scheme+'://'+host+':'+str(port)
    translations = []
    if value.get('translation', {}).get('nat46', {}).get('enabled'):
        translations.append({'kind': 'nat46', 'manifest': '/usr/share/lanrith/nat46.json'})
    if value.get('translation', {}).get('nat64', {}).get('enabled'):
        translations.extend([
            {'kind': 'nat64', 'manifest': '/usr/share/lanrith/nat64.json'},
            {'kind': 'nat64', 'manifest': '/usr/share/lanrith/nat64-internal.json'},
        ])
    translations.sort(key=lambda item: (item['kind'], item['manifest']))
    collector = None
    radius = identity.get('radius', {})
    if radius.get('enabled', False):
        admission_key = radius['admission']['network']
        admission = value['networks'][admission_key]
        ipv4 = next(ip.ip_interface(address).network for address in admission['addresses']
                    if ip.ip_interface(address).version == 4)
        subnet_id = intent.dhcp4_ids(value)[admission_key]
        attachment = value['hardware']['interfaces'][admission['interface']]['name']
        collector = {
            'radius_user': 'freerad',
            'nas_prefixes': sorted(set(str(ip.ip_network(client['address']))
                                           for client in radius['clients'].values())),
            'kea_user': '_kea',
            'kea_socket': '/run/kea/kea4-ctrl-socket',
            'subnet_id': subnet_id,
            'ipv4_prefix': str(ipv4),
            'vlan': admission['vlan'],
            'maximum_devices': 256,
            'interface': admission['name'],
            'parent': attachment,
        }
    return {
        'schema_version': 1,
        'profile_directory': '/etc/router-policy-agent/profile',
        'profile_metadata': '/usr/share/lanrith/policy-profile-metadata.json',
        'generation_directory': '/run/lanrith-policy/generation',
        'state_directory': '/var/lib/lanrith/policy-agent',
        'binding_directory': '/run/lanrith-policy/bindings',
        'nft_executable': '/usr/sbin/nft',
        'helper_executable': '/usr/bin/router-policy-helper',
        'recover_executable': '/usr/bin/router-policy-recover',
        'collector_executable': '/usr/bin/router-policy-collector',
        'managed_interfaces': sorted({value['networks'][key]['name'] for key in policy['networks']}),
        'directory': {
            'url': directory_url,
            'base_dn': directory['base_dn'],
            'bind_dn': directory['bind_dn'],
            'credential_name': directory['credential'],
            'ca_file': '/usr/share/lanrith/'+directory['ca_file'],
        },
        'binding_collector': collector,
        'translation_manifests': translations,
    }


def render(value, *, observer=None):
    """Emit private runtime policy and complete public service ownership."""
    policy = value.get('identity', {}).get('policy', {})
    if not policy.get('enabled', False):
        return {}
    contract = runtime_contract(value)
    if observer is not None:
        contract['observer'] = observer
    reference = contract['directory']['credential_name']
    credential = bindings.credential_path(value, reference)
    translators = []
    if value.get('translation', {}).get('nat46', {}).get('enabled'):
        translators.append('lanrith-nat46.service')
    if value.get('translation', {}).get('nat64', {}).get('enabled'):
        translators += ['lanrith-nat64.service', 'lanrith-nat64-internal.service']
    translation_dependencies = (' '+' '.join(translators)) if translators else ''
    guards = (
        '[Unit]\nDescription=Install the image-owned policy guard schema\n'
        'Requires=nftables.service systemd-networkd.service systemd-sysctl.service\n'
        'After=nftables.service systemd-networkd.service systemd-sysctl.service\nBindsTo=nftables.service\n'
        'Before=lanrith-policy-bootstrap.service'+translation_dependencies+'\n\n'
        '[Service]\nType=oneshot\nRemainAfterExit=yes\nUser=root\nGroup=root\nUMask=0077\n'
        'ExecStart=/usr/lib/lanrith/policy-runtime install-guards\nTimeoutStartSec=60s\n'
        'NoNewPrivileges=yes\nCapabilityBoundingSet=CAP_NET_ADMIN\nProtectSystem=strict\nProtectHome=yes\n'
        'PrivateTmp=yes\nRestrictAddressFamilies=AF_UNIX AF_NETLINK\nRestrictNamespaces=yes\n')
    bootstrap = (
        '[Unit]\nDescription=Install and restore the image-owned policy guards\n'
        'Requires=var.mount lanrith-policy-guards.service'+translation_dependencies+'\n'
        'After=var.mount lanrith-policy-guards.service'+translation_dependencies+'\n'
        'Before=lanrith-policy-bindings.service lanrith-policy-helper.service\n\n'
        '[Service]\nType=oneshot\nRemainAfterExit=yes\nUser=root\nGroup=root\nUMask=0077\n'
        'StateDirectory=lanrith/policy-agent\nStateDirectoryMode=0700\n'
        f'LoadCredential={reference}:{credential}\n'
        'ExecStart=/usr/lib/lanrith/policy-runtime bootstrap\nTimeoutStartSec=60s\n'
        'NoNewPrivileges=yes\nCapabilityBoundingSet=CAP_NET_ADMIN CAP_CHOWN CAP_DAC_OVERRIDE\n'
        'ProtectSystem=strict\nProtectHome=yes\nPrivateTmp=yes\n'
        'ReadWritePaths=/run /var/lib/lanrith/policy-agent /var/lib/lanrith/policy-enrollment\n'
        'RestrictAddressFamilies=AF_UNIX AF_NETLINK\nRestrictNamespaces=yes\n')
    radius = value.get('identity', {}).get('radius', {})
    binding_dependencies = ' kea-dhcp4-server.service freeradius.service' if radius.get('enabled', False) else ''
    binding_capabilities = ('CAP_DAC_OVERRIDE CAP_DAC_READ_SEARCH' if radius.get('enabled', False) else '')
    binding_families = 'AF_UNIX AF_NETLINK' if radius.get('enabled', False) else 'AF_UNIX'
    bindings_unit = (
        '[Unit]\nDescription=Refresh deny-by-default policy ownership evidence\n'
        'Requires=lanrith-policy-bootstrap.service'+binding_dependencies+'\n'
        'After=lanrith-policy-bootstrap.service'+binding_dependencies+'\n'
        'Before=lanrith-policy-helper.service\n\n'
        '[Service]\nType=exec\nUser=root\nGroup=root\nUMask=0077\n'
        'ExecStart=/usr/lib/lanrith/policy-runtime bindings-loop\nRestart=on-failure\nRestartSec=2s\n'
        'NoNewPrivileges=yes\nCapabilityBoundingSet='+binding_capabilities+'\nProtectSystem=strict\nProtectHome=yes\n'
        'PrivateTmp=yes\nPrivateDevices=yes\nProtectKernelTunables=yes\nProtectKernelModules=yes\n'
        'ProtectKernelLogs=yes\nProtectControlGroups=yes\n'
        'ReadWritePaths=/run/lanrith-policy/bindings /run/lanrith-policy/collector\n'
        'RestrictAddressFamilies='+binding_families+'\n'
        'RestrictNamespaces=yes\nRestrictRealtime=yes\nRestrictSUIDSGID=yes\nLockPersonality=yes\n'
        'MemoryMax=128M\nMemorySwapMax=0\nTasksMax=32\nLimitNOFILE=1024\n')
    helper_start = ('/usr/lib/lanrith/policy-runtime serve' if observer is not None else
                    '/usr/bin/router-policy-helper -config-directory /run/lanrith-policy/config '
                    '-binding-directory /run/lanrith-policy/bindings')
    helper = (
        '[Unit]\nDescription=Enforce image-bounded directory policy\n'
        'Wants=lanrith-policy-reader.service\n'
        'Requires=lanrith-policy-bootstrap.service lanrith-policy-bindings.service '
        'lanrith-policy-helper-requests.socket lanrith-policy-helper-status.socket\n'
        'After=lanrith-policy-bootstrap.service lanrith-policy-bindings.service '
        'lanrith-policy-helper-requests.socket lanrith-policy-helper-status.socket\n\n'
        '[Service]\nType=notify\nNotifyAccess=main\nTimeoutStartSec=100s\n'
        'Environment=GOMAXPROCS=2 GOMEMLIMIT=400MiB\n'
        'ExecStart='+helper_start+'\n'
        'ExecStopPost=-/usr/bin/router-policy-recover -config-directory /run/lanrith-policy/config -timeout 5s\n'
        'Sockets=lanrith-policy-helper-requests.socket lanrith-policy-helper-status.socket\n'
        'Restart=on-failure\nRestartSec=2s\nTimeoutStopSec=10s\nUser=root\nGroup=root\nUMask=0077\n'
        'NoNewPrivileges=yes\nCapabilityBoundingSet=CAP_NET_ADMIN\nProtectSystem=strict\nProtectHome=yes\n'
        'PrivateTmp=yes\nPrivateDevices=yes\nProtectKernelTunables=yes\nProtectKernelModules=yes\n'
        'ProtectKernelLogs=yes\nProtectControlGroups=yes\n'
        'ReadWritePaths=/run/lanrith-policy /var/lib/lanrith/policy-agent'+
        (' -/run/lanrith-policy-observations' if observer is not None else '')+'\n'
        'RestrictAddressFamilies=AF_UNIX AF_NETLINK\nRestrictNamespaces=yes\nRestrictRealtime=yes\n'
        'RestrictSUIDSGID=yes\nLockPersonality=yes\nMemoryMax=512M\nMemorySwapMax=0\n'
        'TasksMax=64\nLimitNOFILE=4096\n'+
        (f'SupplementaryGroups={observer["gid"]}\n' if observer is not None else ''))
    reader = (
        '[Unit]\nDescription=Read fresh directory policy over verified TLS\n'
        'Requires=lanrith-policy-helper.service\nAfter=lanrith-policy-helper.service systemd-networkd.service\n\n'
        '[Service]\nType=exec\nUser=router-policy-reader\nGroup=router-policy-reader\n'
        'ExecStart=/usr/bin/router-policy-reader -config-directory /run/router-policy-reader\n'
        'Restart=on-failure\nRestartSec=5s\nUMask=0077\nNoNewPrivileges=yes\nCapabilityBoundingSet=\n'
        'ProtectSystem=strict\nProtectHome=yes\nPrivateTmp=yes\nPrivateDevices=yes\n'
        'ProtectKernelTunables=yes\nProtectKernelModules=yes\nProtectKernelLogs=yes\nProtectControlGroups=yes\n'
        'RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6\nRestrictNamespaces=yes\nRestrictRealtime=yes\n'
        'RestrictSUIDSGID=yes\nLockPersonality=yes\nMemoryMax=256M\nMemorySwapMax=0\n'
        'TasksMax=64\nLimitNOFILE=1024\n')
    return {
        'etc/router-policy-agent/runtime/runtime.json': canonical(contract).decode(),
        # nft sends the complete immutable schema as one atomic transaction and
        # the helper inspects the complete listing. Bound both directions to the
        # same 16 MiB limit already enforced by the policy process.
        'usr/lib/sysctl.d/60-lanrith-policy-netlink.conf':
            'net.core.wmem_max = 16777216\nnet.core.rmem_max = 16777216\n',
        'usr/lib/systemd/system/lanrith-policy-guards.service': guards,
        'usr/lib/systemd/system/lanrith-policy-bootstrap.service': bootstrap,
        'usr/lib/systemd/system/lanrith-policy-bindings.service': bindings_unit,
        'usr/lib/systemd/system/lanrith-policy-helper.service': helper,
        'usr/lib/systemd/system/lanrith-policy-reader.service': reader,
    }
