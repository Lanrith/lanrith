#!/usr/bin/env python3
"""Plan and check fresh peer authentication for a candidate and its fallback."""

import argparse
import hashlib
import json
from pathlib import Path
import re
import secrets
import subprocess
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from lanrith import credential_values, extension_credential_values, image_operation
from lanrith.extension_credential_operation import index
from lanrith.release import canonical, read, require, unique


PHASES = {'candidate': 'candidate', 'fallback': 'fallback', 'restored-candidate': 'candidate',
          'retired-fallback': 'fallback', 'retired-candidate': 'candidate'}


def bound(path, digest):
    raw = read(path, 256*1024)
    require(hashlib.sha256(raw).hexdigest() == digest, 'Credential catalog differs from slot metadata.')
    return json.loads(raw, object_pairs_hook=unique)


def inventory(root):
    metadata = root/'usr/share/lanrith'
    installed = json.loads(read(metadata/'installed.json', 65536), object_pairs_hook=unique)
    identity = image_operation.identity(installed)
    readers = {}
    path = metadata/'credentials.json'
    digest = installed['credential_catalog_sha256']
    if digest is not None:
        selected = credential_values.validate_catalog(bound(path, digest))
        for item in selected['credentials']:
            units = credential_values.STARTUP_UNITS[item['format']]
            if item['format'] == 'directory-password':
                # The v1 catalog spells both layouts identically. Read the
                # booted slot's helper declaration to identify its real reader.
                helpers = ['lanrith-policy-reader-setup.service', 'lanrith-policy-bootstrap.service']
                load = 'LoadCredential='+item['reference']+':'+item['path']
                found = []
                for helper in helpers:
                    unit = root/'usr/lib/systemd/system'/helper
                    if unit.is_file() and load in read(unit, 65536).decode().splitlines():
                        found.append(helper)
                require(len(found) == 1, 'Directory credential helper differs from the signed slot.')
                units = {found[0], 'lanrith-policy-reader.service'}
            readers[item['reference']] = sorted(units)
    else:
        require(not path.exists() and not path.is_symlink(), 'Unexpected core credential catalog.')
    for extension, row in index(installed).items():
        path = metadata/'extension-credentials'/(extension+'.json')
        selected = extension_credential_values.validate_catalog(extension, bound(path, row['sha256']))
        for item in selected['credentials']:
            readers[extension+'/'+item['reference']] = sorted(item['parameters']['consumers'])
    return {'identity': identity, 'readers': readers, 'peers': {name: {} for name in sorted(readers)}}


def slots(candidate, fallback):
    result = {'candidate': inventory(candidate), 'fallback': inventory(fallback)}
    new, old = (r['identity'] for r in result.values())
    require(new['image_id'] == old['image_id'] and new['deployment_sequence'] > old['deployment_sequence'],
            'Rotation needs successive candidate and fallback identities for the same image.')
    return result


def check(plan, inventories, phase, probe):
    require(isinstance(plan, dict) and set(plan) == set(inventories), 'Rotation slot inventory differs.')
    for name, expected in inventories.items():
        supplied = plan[name]
        require(isinstance(supplied, dict) and set(supplied) == set(expected) and
                supplied['identity'] == expected['identity'] and supplied['readers'] == expected['readers'] and
                isinstance(supplied['peers'], dict) and set(supplied['peers']) == set(expected['peers']),
                'Rotation plan differs from the slot catalogs.')
        for peers in supplied['peers'].values():
            require(isinstance(peers, dict) and 1 <= len(peers) <= 1024 and all(
                isinstance(peer, str) and re.fullmatch(r'[a-zA-Z0-9][a-zA-Z0-9._-]{0,127}', peer) and
                mode in ('overlap', 'reversal', 'unchanged') for peer, mode in peers.items()),
                'Each credential needs its peer identities and rotation policy.')
    require(probe.is_absolute() and probe.is_file(), 'Supply an absolute path to the trusted peer probe.')
    slot = plan[PHASES[phase]]
    results = []
    for name, peers in sorted(slot['peers'].items()):
        for peer, mode in sorted(peers.items()):
            expected = 'denied' if phase == 'retired-fallback' and mode != 'unchanged' else 'authenticated'
            request = {'phase': phase, 'identity': slot['identity'], 'reference': name, 'peer': peer,
                       'challenge': secrets.token_hex(16)}
            # The owner controls this adapter and authenticates the remote image
            # and peer. Suppress its diagnostics and publish only checked fields.
            response = subprocess.run([str(probe)], input=canonical(request), stdout=subprocess.PIPE,
                                      stderr=subprocess.DEVNULL, timeout=60, check=False)
            require(response.returncode == 0 and 0 < len(response.stdout) <= 4096,
                    'Peer probe unavailable for '+name+' at '+peer+'.')
            observed = json.loads(response.stdout, object_pairs_hook=unique)
            require(isinstance(observed, dict) and isinstance(observed.get('identity'), dict) and
                    image_operation.identity(observed['identity']) == slot['identity'] and
                    observed == {'identity': slot['identity'], 'challenge': request['challenge'],
                                 'outcome': expected}, 'Peer authentication differs for '+name+' at '+peer+'.')
            results.append({'reference': name, 'peer': peer, 'policy': mode, 'outcome': expected,
                            'challenge': request['challenge']})
    return {'phase': phase, 'identity': slot['identity'], 'results': results}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('candidate', 'fallback'):
        parser.add_argument('--'+name, type=Path, required=True, help='Read-only root of the verified slot')
    commands = parser.add_subparsers(dest='action', required=True)
    commands.add_parser('plan')
    run = commands.add_parser('check')
    run.add_argument('--phase', choices=PHASES, required=True)
    run.add_argument('--plan', type=Path, required=True)
    run.add_argument('--probe', type=Path, required=True)
    args = parser.parse_args()
    try:
        selected = slots(args.candidate, args.fallback)
        if args.action == 'check':
            selected = check(json.loads(read(args.plan, 4*1024*1024), object_pairs_hook=unique),
                             selected, args.phase, args.probe)
        print(json.dumps(selected, indent=2, sort_keys=True))
    except (KeyError, OSError, ValueError, TypeError, RecursionError, subprocess.SubprocessError) as error:
        from lanrith.release import ReleaseError
        sys.exit(str(error) if isinstance(error, ReleaseError) else 'Credential rotation evidence is unavailable.')


if __name__ == '__main__':
    main()
