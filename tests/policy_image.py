#!/usr/bin/env python3
"""Assemble directory policy with the actual packaged tools and inspect its root."""

import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from lanrith import build, release
from test_policy_agent import declaration


def run(*args):
    return subprocess.run(args, check=True, stdin=subprocess.DEVNULL,
                          capture_output=True, timeout=300).stdout


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--base', type=Path, required=True)
    parser.add_argument('--initrd-base', type=Path, required=True)
    parser.add_argument('--work', type=Path, required=True)
    args = parser.parse_args()
    release.require(args.work.is_absolute() and not args.work.exists() and not args.work.is_symlink(),
                    'Policy image qualification requires a new workspace.')
    args.work.mkdir(mode=0o700)
    # Keep peak disk usage bounded before the separate boot/update VM matrix.
    with tempfile.TemporaryDirectory(dir=args.work, prefix='assembly.') as directory, \
            tempfile.TemporaryDirectory(dir='/dev/shm', prefix='lanrith-policy-authority.') as authority:
        work, secret = Path(directory), Path(authority)
        run('openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
            '-subj', '/CN=Lanrith Disposable Policy Qualification Authority',
            '-keyout', str(secret/'test.key'), '-out', str(secret/'test.crt'))
        (secret/'test.key').chmod(0o600)
        value = declaration()
        value['networks']['home']['vlan'] = 1
        value['services'] = {'discovery': {'enabled': True, 'domain': 'devices.example.test',
            'alias_prefix': 'lab-', 'networks': ['home', 'devices']}}
        value['translation'] = {'nat64': {'enabled': True}, 'nat46': {'enabled': True,
            'mappings': {'application': {'ipv4': '10.255.200.10', 'ipv6': 'fd42:1234:5678:10::20'}}}}
        value['runtime'] = {'trust': {'trust/directory.pem': (secret/'test.crt').read_text()}}
        credential = secret/'directory-password'
        credential.write_bytes(b'synthetic-policy-image-password\n')
        credential.chmod(0o600)
        value['credentials'] = {'directory_bind': {'file': str(credential)}}
        assembly = work/'image'
        identity = build.assembly(value, args.base, assembly, version='0.1.0', sequence=1,
            certificate=secret/'test.crt', private_key=secret/'test.key', initrd_base=args.initrd_base)
        build.run(assembly)
        roots = list((assembly/'output').glob(identity['image_id']+'_1*.root.raw'))
        release.require(len(roots) == 1, 'Policy image has no unique split root filesystem.')
        root = work/'root'
        run('fsck.erofs', '--extract='+str(root), '--no-preserve-owner', '--no-preserve-perms', str(roots[0]))
        metadata = json.loads((root/'usr/share/lanrith/policy-profile-metadata.json').read_bytes())
        for filename, pin in (('profile.json', 'profile_sha256'), ('guards.nft', 'guards_sha256')):
            data = (root/'etc/router-policy-agent/profile'/filename).read_bytes()
            release.require(hashlib.sha256(data).hexdigest() == metadata[pin],
                            'Assembled policy artifact differs from its compiler pin.')
        program = json.loads((root/'usr/share/lanrith/policy-program.json').read_bytes())
        release.require(program['backend'] == 'tun' and program['objects'] and
                        program['program_sha256'] == metadata['floor_sha256'],
                        'Assembled policy lacks the compiled TUN program.')
        run(sys.executable, str(Path(__file__).parents[1]/'scripts/runtime-boundary.py'), str(root))
    print('Real directory-policy image assembly and compiled runtime boundary passed.', flush=True)


if __name__ == '__main__':
    main()
