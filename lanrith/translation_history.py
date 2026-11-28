"""Carry complete private NAT64 reservations from an accepted, verified image root."""

import argparse
import fcntl
import json
import os
from pathlib import Path
import tempfile

from . import intent, release, translation


def read_object(path):
    value = json.loads(release.read(path, 1024 * 1024), object_pairs_hook=release.unique)
    release.require(isinstance(value, dict), 'Expected an object in the NAT64 handover.')
    return value


def promote(root, destination, *, initialize=False):
    """Advance the private build input while retaining every previously accepted alias."""
    metadata = root/'usr/share/lanrith'
    installed = read_object(metadata/'installed.json')
    manifest = read_object(metadata/'nat64-internal.json')
    release.require(manifest.get('interface') == 'nat64-internal' and manifest.get('component') == 'nat64',
                    'Expected the private NAT64 translator manifest.')
    pool = intent.network(manifest.get('pool'), 4)
    release.require(pool.is_private and 16 <= pool.prefixlen <= 28, 'Invalid NAT64 source pool.')
    release.require(intent.address(manifest.get('ipv6'), 6) not in intent.network(manifest.get('prefix'), 6, 96),
                    'Private NAT64 control address overlaps the synthesis prefix.')
    allocations = manifest.get('source_allocations')
    release.require(isinstance(allocations, dict) and set(allocations) == {'active', 'reserved'}
                    and isinstance(allocations['active'], dict),
                    'Private NAT64 manifest lacks its complete reservation map.')
    reserved = translation.reservations(manifest, allocations['reserved'])
    release.require(all(source in reserved and reserved[source] == alias
                        for source, alias in allocations['active'].items()),
                    'Active NAT64 source differs from the complete reservation map.')
    record = {key: installed.get(key) for key in ('image_id', 'machine_id', 'deployment_sequence', 'configuration_sha256')}
    record.update(schema=1, pool=str(pool), reserved=reserved)
    translation.validate_history(record, record['image_id'], record['machine_id'], str(pool))
    release.require(destination.parent.resolve() == destination.parent.absolute(),
                    'Reservation history needs a canonical private directory.')
    directory = os.open(destination.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        fcntl.flock(directory, fcntl.LOCK_EX)
        if not destination.exists() and not destination.is_symlink():
            release.require(initialize, 'Latest reservation history is missing. Use --initialize only for the first handover.')
        else:
            release.require(not initialize, 'A reservation history already exists.')
            previous = read_object(destination)
            if 'schema' in previous:
                translation.validate_history(previous, record['image_id'], record['machine_id'], str(pool))
                if previous == record:
                    os.fsync(directory)
                    return
                release.require(previous['deployment_sequence'] < record['deployment_sequence'],
                                'Retain the latest reservation history across rollback.')
                previous = previous['reserved']
            previous = translation.reservations(manifest, previous)
            release.require(all(reserved.get(source) == alias for source, alias in previous.items()),
                            'The accepted image dropped or changed an existing reservation.')
        with tempfile.NamedTemporaryFile(dir=destination.parent, delete=False) as stream:
            temporary = Path(stream.name)
            try:
                stream.write(release.canonical(record))
                stream.flush()
                os.fsync(stream.fileno())
                os.replace(temporary, destination)
                os.fsync(directory)
            finally:
                temporary.unlink(missing_ok=True)
    finally:
        os.close(directory)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--accepted-root', required=True, type=Path,
                        help='Read-only root of the independently verified accepted release')
    parser.add_argument('--history', required=True, type=Path,
                        help='Current reviewed translation-allocations.json in a private build directory')
    parser.add_argument('--initialize', action='store_true', help='Create the first history when no migration map exists')
    args = parser.parse_args()
    try:
        promote(args.accepted_root, args.history, initialize=args.initialize)
    except (ValueError, OSError) as error:
        parser.exit(1, f'{error}\n')


if __name__ == '__main__':
    main()
