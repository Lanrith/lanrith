"""Deterministic translator configuration and persistent source allocations.

These manifests describe connectivity. The packet-path admission gate remains
separate: a TAYGA route or static map must never be treated as authorization.
"""

import hashlib
import ipaddress as ip

from . import intent
from .release import canonical, require


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
    require(isinstance(retained, dict) and len(retained) <= 4096, 'Invalid retained translation allocations.')
    component = intent.translations(value).get('nat64-internal')
    if component is None:
        require(not retained, 'Retained NAT64 allocations reference a disabled translator.')
        return {'reserved': {}, 'active': {}}
    pool = ip.ip_network(component['pool'])
    # The last /28 or /24 is reserved for stable sources. TAYGA static maps
    # reserve these addresses against its dynamic allocator.
    size = min(256, pool.num_addresses // 2)
    first = int(pool.broadcast_address) - size + 1
    occupied = set()
    reserved = {}
    for original, translated in retained.items():
        source, target = intent.address(original, 6), intent.address(translated, 4)
        require(str(source) == original and str(target) == translated and first <= int(target) < int(pool.broadcast_address)
                and target not in occupied, 'Duplicate, noncanonical or out-of-range retained source allocation.')
        occupied.add(target)
        reserved[original] = translated
    for source in source_identities(value):
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
    active = {key: reserved[key] for key in source_identities(value)}
    return {'reserved': dict(sorted(reserved.items())), 'active': active}


def manifests(value, retained=None):
    components = intent.translations(value)
    allocations = allocate(value, retained)
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
                       'authorization': 'none'})
    return result


def evidence(value, retained=None):
    result = manifests(value, retained)
    return {'schema': 1, 'translators': result,
            'sha256': hashlib.sha256(canonical(result)).hexdigest(), 'runtime_qualified': False}
