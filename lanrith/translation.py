"""Deterministic translator configuration and persistent source allocations.

These manifests describe connectivity. The packet-path admission gate remains
separate: a TAYGA route or static map must never be treated as authorization.
"""

import hashlib
import ipaddress as ip
import re

from . import intent, nat64_allocations
from .release import HEX, canonical, require


def source_identities(value):
    """Only exact declared source hosts can acquire a fixed translated identity."""
    result = set()
    for rule in value.get('access', {}).get('rules', []):
        if rule.get('action') != 'allow':
            continue
        for source in intent.expand(value, rule['from']):
            for raw in source.get('addresses', []):
                prefix = ip.ip_network(raw)
                if prefix.version == 6 and prefix.prefixlen == 128:
                    result.add(str(prefix.network_address))
    return sorted(result, key=ip.ip_address)


def allocate(value, retained=None):
    """Retain explicit identities; allocate new hosts without reusing retired slots.

    Existing allocations are private migration state, not owner permission. The
    caller must bind this input to the image provenance. Retired entries remain
    reserved in state and translator maps so the dynamic allocator cannot reuse
    their addresses. Only active identities are candidates for access policy.
    """
    retained = {} if retained is None else retained
    require(isinstance(retained, dict), 'Invalid retained translation allocations.')
    component = intent.translations(value).get('nat64-internal')
    if component is None:
        require(not retained, 'Retained NAT64 allocations reference a disabled translator.')
        return {'reserved': {}, 'active': {}}
    pool = ip.ip_network(component['pool'])
    if 'schema' in retained:
        validate_history(retained, value.get('release', {}).get('image_id', 'lanrith'),
                         value['hardware'].get('machine_id'), str(pool))
        retained = retained['reserved']
    sources = [source for source in source_identities(value)
               if nat64_allocations.mappable_source(ip.ip_address(source), component)]
    reserved = reservations(component, retained, sources)
    return {'reserved': reserved, 'active': {key: reserved[key] for key in sources}}


def allocation_inputs(value, retained):
    """Bind both computed mappings and their accepted source release to the build."""
    result = {'translation_allocations': allocate(value, retained)}
    if 'schema' in retained:
        result['translation_history_sha256'] = hashlib.sha256(canonical(retained)).hexdigest()
    return result


def validate_history(history, image_id, machine_id, pool):
    require(isinstance(history, dict) and set(history) == {'schema', 'image_id', 'machine_id', 'deployment_sequence',
            'configuration_sha256', 'pool', 'reserved'} and type(history['schema']) is int and history['schema'] == 1
            and type(history['deployment_sequence']) is int and 1 <= history['deployment_sequence'] <= 999999999
            and isinstance(image_id, str) and re.fullmatch(r'[a-z][a-z0-9-]{0,47}', image_id)
            and isinstance(machine_id, str) and re.fullmatch(r'[a-f0-9]{32}', machine_id)
            and history['machine_id'] == machine_id and history['image_id'] == image_id and history['pool'] == pool
            and isinstance(history['configuration_sha256'], str) and HEX.fullmatch(history['configuration_sha256']),
            'Invalid reservation history or different release identity or pool.')


def reservations(component, retained, sources=()):
    require(isinstance(retained, dict) and len(retained) <= 4096, 'Invalid retained translation allocations.')
    pool = ip.ip_network(component['pool'])
    # The last /28 or /24 is reserved for stable sources. TAYGA static maps
    # reserve these addresses against its dynamic allocator.
    size = min(256, pool.num_addresses // 2)
    first = int(pool.broadcast_address) - size + 1
    occupied = set()
    reserved = {}
    for original, translated in retained.items():
        source, target = intent.address(original, 6), intent.address(translated, 4)
        require(nat64_allocations.mappable_source(source, component),
                'Retained NAT64 source conflicts with a translator prefix, control or reserved address.')
        require(str(source) == original and str(target) == translated and first <= int(target) < int(pool.broadcast_address) and
                target not in occupied, 'Duplicate, noncanonical or out-of-range retained source allocation.')
        occupied.add(target)
        reserved[original] = translated
    for source in sources:
        if source in reserved:
            continue
        candidate = first + int.from_bytes(hashlib.sha256(source.encode()).digest()[:4], 'big') % (size-1)
        for step in range(size-1):
            target = ip.IPv4Address(first + (candidate-first+step) % (size-1))
            if target not in occupied:
                reserved[source] = str(target)
                occupied.add(target)
                break
        else:
            require(False, 'Stable translator source allocation is exhausted.')
    return dict(sorted(reserved.items()))


def route_contexts(value, component, allocations, routes):
    """Compile ingress and source samples for read-only forwarding lookups."""
    from .tun_policy import client_prefixes

    def attachment(raw):
        address = ip.ip_address(raw)
        return next(interface for prefix, interface in routes if address in prefix)

    samples = {4: set(), 6: set()}
    name = component['interface']
    for key, network in value['networks'].items():
        if not network.get('forwarding', True):
            continue
        local = {ip.ip_interface(raw).ip for raw in intent.gateway_addresses(network)}
        if name == 'nat64':
            prefixes = [ip.ip_interface(raw).network for raw in network['addresses']]
        else:
            prefixes = client_prefixes(value, key)
        for prefix in prefixes:
            if name == 'nat46' and prefix.version != 4:
                continue
            # Pick a possible peer without probing a gateway or broadcast address.
            peer = next((host for host in prefix.hosts() if host not in local), None)
            if peer:
                samples[peer.version].add((network['name'], str(peer)))
    wan = value['hardware']['interfaces'][value['uplink']['interface']]['name']
    active = allocations['active'] if name == 'nat64-internal' else {}
    for source in active:
        samples[6].add((attachment(source), source))
    if name == 'nat46':
        return {'clients': sorted(samples[4]),
                'servers': {entry['ipv6']: attachment(entry['ipv6'])
                            for entry in component['mappings'].values()}}
    if name == 'nat64':
        # A read-only Internet lookup needs no lease, DNS record or live endpoint.
        public = next((a for a in value['uplink'].get('gateways', [])
                       if ip.ip_address(a).version == 4 and ip.ip_address(a).is_global), '192.0.0.9')
        peers = [(wan, public)] if value['uplink'].get('ipv4') != 'disabled' else []
    else:
        peers = sorted(samples[4])
    return {'clients': sorted(samples[6]), 'peers': peers}


def manifests(value, retained=None):
    from .tun_policy import route_scopes
    components = intent.translations(value)
    allocations = allocate(value, retained)
    routes = route_scopes(value, 6) if components else []
    result = []
    for name, component in components.items():
        path = '/etc/tayga'+('' if name == 'nat64' else '-'+name)+'.conf'
        state = '/var/lib/tayga'+('' if name == 'nat64' else '-'+name)
        if name == 'nat64-internal':
            state += '/'+component['pool'].replace('/', '-')
        text = (f'tun-device {name}\nipv4-addr {component["ipv4"]}\nipv6-addr {component["ipv6"]}\n'
                f'prefix {component["prefix"]}\n')
        if component['component'] == 'nat64':
            text += f'dynamic-pool {component["pool"]}\n'
        for entry in component['mappings'].values():
            text += f'map {entry["ipv4"]} {entry["ipv6"]}\n'
        if name == 'nat64-internal':
            for original, translated in allocations['reserved'].items():
                text += f'map {translated} {original}\n'
            text += 'udp-cksum-mode calc\n'
        # NAT46 has only static maps and algorithmic source addresses. It must
        # neither consume nor change the legacy directory kept for rollback.
        if component['component'] == 'nat64':
            text += f'data-dir {state}\n'
        result.append({**component, 'config': path, 'text': text,
                       'config_sha256': hashlib.sha256(text.encode()).hexdigest(),
                       'state_directory': state, 'unit': 'lanrith-'+name+'.service',
                       'addresses': [component['ipv4']+'/32', component['ipv6']+'/128'],
                       'routes': [component['pool'], component['prefix']],
                       'source_allocations': allocations if name == 'nat64-internal' else {},
                       'route_contexts': route_contexts(value, component, allocations, routes),
                       'authorization': 'none'})
    return result


def evidence(value, retained=None):
    result = manifests(value, retained)
    return {'schema': 1, 'translators': result,
            'sha256': hashlib.sha256(canonical(result)).hexdigest(), 'runtime_qualified': False}


def network_unit(name):
    return (
        '[Unit]\nDescription=Configure translator interface and routes\n'
        'Wants=systemd-networkd.service\n'
        'After=nftables.service systemd-networkd.service systemd-sysusers.service systemd-tmpfiles-setup.service\n'
        f'BindsTo=nftables.service\nBefore=lanrith-{name}.service\n'
        '[Service]\nType=oneshot\nRemainAfterExit=yes\n'
        'RuntimeDirectory=lanrith-translator-locks\nRuntimeDirectoryMode=0700\nRuntimeDirectoryPreserve=yes\n'
        'Environment=PYTHONPATH=/usr/lib/lanrith\n'
        f'ExecStart=/usr/bin/python3 -m lanrith.translation_runtime start {name}\n'
        f'ExecStop=/usr/bin/python3 -m lanrith.translation_runtime stop {name}\n'
        'NoNewPrivileges=yes\nProtectSystem=strict\nProtectHome=yes\nPrivateTmp=yes\n'
        'CapabilityBoundingSet=CAP_NET_ADMIN\nRestrictAddressFamilies=AF_NETLINK AF_UNIX AF_INET AF_INET6\n')


def render_native(value, retained=None):
    """Run the packaged translator directly on image-owned TUN interfaces.

    Systemd owns process lifecycle; TAYGA owns its native dynamic.map. Stable
    source allocations are compiled into the same immutable configuration.
    """
    files = {}
    for manifest in manifests(value, retained):
        name, state = manifest['interface'], manifest['state_directory']
        account = 'lanrith-'+name
        files[manifest['config'].lstrip('/')] = manifest['text']
        files['usr/share/lanrith/'+name+'.json'] = canonical(manifest).decode()
        files['usr/lib/sysusers.d/80-lanrith-'+name+'.conf'] = f'u {account} - "IP translation" /\n'
        if manifest['component'] == 'nat64':
            files['usr/lib/tmpfiles.d/80-lanrith-'+name+'.conf'] = f'd {state} 0750 {account} {account} -\n'
        files['usr/lib/systemd/system/lanrith-'+name+'-network.service'] = network_unit(name)
        # The existing admitted 0.9.6 package installs this path. All three
        # components use it; package/path renaming is independent of behavior.
        binary = '/usr/lib/lanrith/tayga-internal'
        files['usr/lib/systemd/system/lanrith-'+name+'.service'] = (
            '[Unit]\nDescription=Translate IP packets with TAYGA\n'
            f'Requires=lanrith-{name}-network.service nftables.service\n'
            f'After=lanrith-{name}-network.service nftables.service\n'
            f'BindsTo=lanrith-{name}-network.service nftables.service\n'
            f'[Service]\nType=exec\nUser={account}\nGroup={account}\n'
            'Environment=PYTHONPATH=/usr/lib/lanrith\n'
            f'ExecStartPre=+/usr/bin/python3 -m lanrith.translation_runtime reset {name}\n'
            f'ExecStart={binary} --nodetach --config {manifest["config"]}\n'
            f'ExecStopPost=+/usr/bin/python3 -m lanrith.translation_runtime reset {name}\n'
            'Restart=on-failure\nRestartSec=2s\nNoNewPrivileges=yes\n'
            'KillMode=control-group\nTimeoutStartSec=15s\nTimeoutStopSec=15s\n'
            'MemoryMax=128M\nMemorySwapMax=0\nTasksMax=16\nLimitNOFILE=256\n'
            'CapabilityBoundingSet=\nAmbientCapabilities=\nProtectSystem=strict\nProtectHome=yes\nPrivateTmp=yes\n'+
            (f'ReadWritePaths={state}\n' if manifest['component'] == 'nat64' else '')+
            'RestrictAddressFamilies=AF_NETLINK AF_UNIX AF_INET AF_INET6\nRestrictNamespaces=yes\n'
            'DevicePolicy=closed\nDeviceAllow=/dev/net/tun rw\n'
            '[Install]\nWantedBy=multi-user.target\n')
    return files
