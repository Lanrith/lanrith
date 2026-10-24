"""Bounded NAT64 source identities, retaining the TAYGA rollback file format.

An allocation is connectivity state, not permission. It never creates a packet
proof. Addresses are not reassigned automatically: an old conntrack entry or a
delayed translator packet must not acquire another client's source identity.
"""

import hashlib
import ipaddress as ip
import os
from pathlib import Path
import stat
import tempfile

from .release import read, require


MAXIMUM = 65534


def valid_source(source, manifest):
    address = ip.ip_address(source)
    require(address.version == 6 and address.ipv4_mapped is None and
            not (address.is_multicast or address.is_link_local or address.is_loopback or address.is_unspecified) and
            address not in ip.ip_network(manifest['prefix']) and address != ip.ip_address(manifest['ipv6']),
            'Invalid NAT64 source identity.')
    return str(address)


def validate(manifest, allocations):
    pool = ip.ip_network(manifest['pool'])
    require(isinstance(allocations, dict) and len(allocations) <= min(MAXIMUM, pool.num_addresses-3),
            'NAT64 allocation count exceeds its pool.')
    addresses = set()
    for source, target in allocations.items():
        require(valid_source(source, manifest) == source, 'Noncanonical NAT64 source identity.')
        address = ip.ip_address(target)
        require(str(address) == target and address in pool and
                address not in (pool.network_address, pool.broadcast_address, ip.ip_address(manifest['ipv4'])) and
                target not in addresses, 'Duplicate or reserved NAT64 source allocation.')
        addresses.add(target)
    for source, target in manifest.get('source_allocations', {}).get('reserved', {}).items():
        require(allocations.get(source) == target, 'Retained NAT64 source identity changed.')
    return allocations


def decode(manifest, content):
    """Import old dynamic maps without renewing permissions or recycling slots."""
    require(len(content) <= 8*1024*1024, 'NAT64 allocation file exceeds its bound.')
    result = dict(manifest.get('source_allocations', {}).get('reserved', {}))
    seen = set()
    for line in content.decode('ascii').splitlines():
        if not line.strip() or line.lstrip().startswith('#'):
            continue
        fields = line.split()
        require(len(fields) == 3, 'Malformed retained NAT64 allocation.')
        target, source, timestamp = fields
        require(timestamp.isascii() and timestamp.isdecimal() and 0 < int(timestamp) < 2**63,
                'Invalid retained NAT64 allocation timestamp.')
        require(source not in seen and (source not in result or result[source] == target),
                'Duplicate or reassigned retained NAT64 allocation.')
        seen.add(source)
        result[source] = target
    return validate(manifest, result)


def allocate(manifest, current, pending):
    """Deterministically add admitted sources; fail closed when the pool is full."""
    result = dict(validate(manifest, current))
    require(isinstance(pending, list) and len(pending) <= 4096, 'Too many pending NAT64 identities.')
    pool = ip.ip_network(manifest['pool'])
    used = {int(ip.ip_address(target)) for target in result.values()}
    used.update((int(pool.network_address), int(pool.broadcast_address), int(ip.ip_address(manifest['ipv4']))))
    for source in sorted(set(pending), key=ip.ip_address):
        require(valid_source(source, manifest) == source, 'Noncanonical pending NAT64 identity.')
        if source in result:
            continue
        if len(used) == pool.num_addresses:
            break
        seed = int.from_bytes(hashlib.sha256(source.encode()).digest()[:8], 'big')
        for offset in range(pool.num_addresses):
            address = int(pool.network_address) + (seed+offset) % pool.num_addresses
            if address not in used:
                result[source] = str(ip.IPv4Address(address))
                used.add(address)
                break
        # Exhaustion leaves this client unallocated. It must not replace a
        # previous client, nor prevent the retained clients from operating.
    return validate(manifest, result)


def encode(manifest, allocations, timestamp):
    require(type(timestamp) is int and 0 < timestamp < 2**63, 'Invalid allocation timestamp.')
    validate(manifest, allocations)
    text = '# Lanrith retained NAT64 identities; compatible with TAYGA dynamic.map.\n'
    for source, target in sorted(allocations.items(), key=lambda entry: ip.ip_address(entry[1])):
        text += f'{target}\t{source}\t{timestamp}\n'
    return text.encode()


def configuration(manifest, allocations):
    validate(manifest, allocations)
    text = (f'tun-device {manifest["interface"]}\nipv4-addr {manifest["ipv4"]}\n'
            f'ipv6-addr {manifest["ipv6"]}\nprefix {manifest["prefix"]}\n')
    for source, target in sorted(allocations.items()):
        text += f'map {target} {source}\n'
    if manifest['interface'] == 'nat64-internal':
        text += 'udp-cksum-mode calc\n'
    # No dynamic-pool or data-dir: only the allocator may change identities.
    return text.encode()


def load(manifest, directory):
    directory = Path(directory)
    info = directory.lstat()
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o022,
            'NAT64 allocation directory must be owned by root and not writable by other accounts.')
    path = directory/'dynamic.map'
    try:
        info = path.lstat()
    except FileNotFoundError:
        return decode(manifest, b'')
    require(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o022,
            'NAT64 allocation state has unsafe ownership or permissions.')
    return decode(manifest, read(path, 8*1024*1024))


def secure_state_directory(directory):
    """A legacy service-owned parent must pass explicit migration first."""
    directory = Path(directory)
    anchor = Path('/var/lib')
    require(directory.is_relative_to(anchor) and directory != anchor, 'Invalid NAT64 state root.')
    for parent in [directory, *directory.parents]:
        info = parent.lstat()
        require(stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o022,
                'NAT64 state ancestry requires explicit ownership migration.')
        if parent == anchor:
            break


def atomic_write(path, data, *, mode=0o600):
    """Publish and fsync before activating mappings; never replace a symlink."""
    path = Path(path)
    if path.exists() or path.is_symlink():
        info = path.lstat()
        require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and
                info.st_uid == 0 and not info.st_mode & 0o022, 'Unsafe NAT64 output file.')
    descriptor, temporary = tempfile.mkstemp(prefix='.lanrith-', dir=path.parent)
    try:
        with os.fdopen(descriptor, 'wb') as stream:
            os.fchmod(stream.fileno(), mode)
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        descriptor = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    finally:
        Path(temporary).unlink(missing_ok=True)
