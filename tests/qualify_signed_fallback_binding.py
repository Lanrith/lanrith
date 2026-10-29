#!/usr/bin/env python3
"""Qualify a bound initrd in a synthetic signed image, without boot authorization."""

import argparse
import datetime
import json
from pathlib import Path
import subprocess
import tempfile

from lanrith import build, config, release, update
from qualify_bound_observation_vm import require_matching_base


def command(*args):
    return subprocess.run(args, check=True, capture_output=True, timeout=600).stdout


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--base', type=Path, required=True)
    parser.add_argument('--initrd-base', type=Path, required=True)
    parser.add_argument('--work', type=Path, required=True)
    parser.add_argument('--result', type=Path, required=True)
    args = parser.parse_args()
    matched_files = require_matching_base(args.base)
    work = args.work
    release.require(work.is_absolute() and not work.exists() and work.parent.resolve() == work.parent,
                    'Qualification requires a new disposable workspace.')
    work.mkdir(mode=0o700)
    report = {'schema': 1, 'scope': 'synthetic-signed-binding-build-only', 'result': 'fail',
              'physical_homelab_qualified': False, 'automatic_fallback_qualified': False,
              'filesystem_sha256': release.file_record(args.base)['sha256'],
              'initrd_sha256': release.file_record(args.initrd_base)['sha256'],
              'test_sha256': release.file_record(Path(__file__))['sha256']}
    report['branch_overlay_files_matched'] = matched_files
    try:
        with tempfile.TemporaryDirectory(prefix='lanrith-binding-authority.', dir='/dev/shm') as temporary:
            private = Path(temporary)
            key, cert = private/'key', private/'cert'
            command('openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
                    '-subj', '/CN=Lanrith Synthetic Binding Authority', '-keyout', str(key), '-out', str(cert))
            key.chmod(0o600)
            previous = work/'previous'
            previous.mkdir(mode=0o700)
            files = {'uki': 'lanrith_9.efi'}
            for index, role in enumerate(update.PARTITION_ROLES, 1):
                uuid = f'12345678-1234-1234-1234-{index:012d}'
                files[role] = f'lanrith_9_{uuid}.{role}.raw'
            for role, name in files.items():
                (previous/name).write_bytes(('nonbootable synthetic '+role).encode())
            manifest = release.unsigned_manifest(previous, purpose='update', version='0.1.0', sequence=9,
                                                 configuration_sha256='a'*64, files=files)
            (previous/'release.json').write_bytes(release.canonical(manifest))
            release.sign(previous, key)
            release.verify(previous, cert, purpose='update', image_id='lanrith')
            value = config.load(Path(__file__).resolve().parents[1]/'examples/minimal.yaml')
            assembly = work/'candidate'
            identity = build.assembly(value, args.base.resolve(), assembly, version='0.1.0', sequence=10,
                certificate=cert, private_key=key, initrd_base=args.initrd_base.resolve(),
                fallback_release=previous, fallback_disk_by_id='/dev/disk/by-id/synthetic-disk',
                fallback_esp_uuid='abcdefab-1234-1234-1234-123456789abc')
            build.run(assembly)
            output = assembly/'output'
            uki = output/'lanrith_10.efi'
            archive = output/'initrd.cpio.zst'
            command('sbverify', '--cert', str(cert), str(uki))
            section = work/'uki-initrd.bin'
            command('objcopy', '--dump-section', '.initrd='+str(section), str(uki))
            release.require(section.read_bytes().count(archive.read_bytes()) == 1,
                            'Signed UKI does not contain exactly one generated initrd.')
            source = subprocess.Popen(['zstd', '-d', '-c', str(archive)], stdout=subprocess.PIPE,
                                      stderr=subprocess.DEVNULL)
            try:
                extracted = subprocess.run(['cpio', '-i', '--quiet', '--to-stdout',
                    'usr/share/lanrith/initrd-failure.json'], stdin=source.stdout,
                    capture_output=True, timeout=120, check=True).stdout
            finally:
                source.stdout.close()
            release.require(source.wait(timeout=120) == 0, 'Initrd archive failed to decompress.')
            embedded = json.loads(extracted, object_pairs_hook=release.unique)
            from lanrith import early_failure, repair
            expected = repair.signed_fallback_binding(previous, cert, image_id='lanrith')['fallback']
            early_failure.failure_identity(embedded)
            release.require(embedded['fallback_binding'] == {'disk_by_id': '/dev/disk/by-id/synthetic-disk',
                'esp_uuid': 'abcdefab-1234-1234-1234-123456789abc', 'release': expected},
                'Signed initrd binding differs from its verified source.')
            target = work/'update'
            build.update_payload(assembly, identity, target)
            release.sign(target, key)
            release.verify(target, cert, purpose='update', image_id='lanrith')
            release.require(not early_failure.FALLBACK_AUTHENTICATION_QUALIFIED,
                            'Unqualified automatic fallback was unexpectedly enabled.')
            report.update(result='pass', checks=['verified-synthetic-prior-release', 'signed-candidate-uki',
                'generated-initrd-in-signed-uki', 'exact-binding-in-initrd', 'signed-update-release',
                'fallback-remains-disabled'])
    finally:
        report['assessed_at'] = datetime.datetime.now(datetime.timezone.utc).isoformat()
        args.result.write_bytes(release.canonical(report))
    print('Synthetic signed fallback binding build passed.')


if __name__ == '__main__':
    main()
