#!/usr/bin/env python3
"""Prove first-boot slot expansion preserves signed bytes using regular files only."""

import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from lanrith import build, config
from lanrith.release import require
from lanrith.update import GUIDS


def run(*arguments):
    result = subprocess.run(arguments, stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=180)
    require(result.returncode == 0, Path(arguments[0]).name+' failed: '+result.stderr[-4096:])
    return result.stdout


def table(path):
    value = json.loads(run('sfdisk', '--json', str(path)))['partitiontable']
    require(value.get('sectorsize', 512) == 512, 'Unexpected test sector size.')
    return value['partitions']


def checksum(path, start, size):
    digest = hashlib.sha256()
    with path.open('rb') as stream:
        stream.seek(start)
        while size:
            block = stream.read(min(size, 1024*1024))
            require(block, 'Test image was truncated.')
            digest.update(block)
            size -= len(block)
    return digest.hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--work', type=Path, required=True)
    parser.add_argument('--result', type=Path)
    args = parser.parse_args()
    work = args.work
    require(work.is_absolute() and not work.exists() and work.parent.resolve() == work.parent,
            'Storage tests require a new canonical private workspace.')
    work.mkdir(mode=0o700)
    value = config.load(Path(__file__).resolve().parents[1]/'examples/minimal.yaml')
    value['hardware']['storage'] = {'esp_mib': 512, 'root_mib': 4096, 'state_mib': 2048}
    base = work/'unused-base.tar'
    with tarfile.open(base, 'w'):
        pass
    with tempfile.TemporaryDirectory(prefix='lanrith-storage-authority.', dir='/dev/shm') as temporary:
        authority = Path(temporary)
        key, certificate = authority/'test.key', authority/'test.crt'
        run('openssl', 'req', '-x509', '-newkey', 'rsa:3072', '-nodes', '-days', '1',
            '-subj', '/CN=Lanrith Disposable Storage Test Authority', '-keyout', str(key), '-out', str(certificate))
        key.chmod(0o600)
        # Retain the larger verity authority while using the supported TPM signer.
        pcr_key, pcr_certificate = authority/'pcr.key', authority/'pcr.crt'
        run('openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
            '-subj', '/CN=Lanrith Disposable Storage PCR Authority',
            '-keyout', str(pcr_key), '-out', str(pcr_certificate))
        pcr_key.chmod(0o600)
        assembly = work/'assembly'
        build.assembly(value, base, assembly, version='0.1.0', sequence=9,
                       certificate=certificate, private_key=key,
                       pcr_key=pcr_key, pcr_certificate=pcr_certificate)
        source = work/'source'
        for name in ('efi', 'boot', 'usr/share/fixture'):
            (source/name).mkdir(parents=True)
        (source/'usr/share/fixture/preserved').write_text('signed synthetic filesystem\n')
        image = work/'factory.raw'
        run('systemd-repart', '--empty=create', '--size=auto', '--dry-run=no', '--offline=yes',
            '--architecture=x86-64', '--seed='+value['hardware']['machine_id'],
            '--copy-source='+str(source), '--definitions='+str(assembly/'mkosi.repart'),
            '--private-key='+str(key), '--certificate='+str(certificate), str(image))
        original = table(image)
        require(len(original) == 4, 'Initial factory layout has an unexpected partition.')
        signed = {role: next(part for part in original if part['type'].lower() == guid)
                  for role, guid in GUIDS.items()}
        expected = {role: checksum(image, part['start']*512, part['size']*512) for role, part in signed.items()}
        with image.open('r+b') as stream:
            stream.truncate(16*1024*1024*1024)
        run('sfdisk', '--relocate', 'gpt-bak-std', str(image))
        definitions = work/'installed-definitions'
        definitions.mkdir()
        for name, text in build.storage_definitions(config.normalize(value), 9).items():
            # This is a geometry test. Encryption and TPM behavior are exercised
            # separately in the boot qualification matrix.
            (definitions/name).write_text(text.replace('Encrypt=tpm2', 'Encrypt=no'))
        run('systemd-repart', '--empty=refuse', '--dry-run=no', '--offline=yes',
            '--architecture=x86-64', '--seed='+value['hardware']['machine_id'],
            '--definitions='+str(definitions), str(image))
        expanded = table(image)
        require(len(expanded) == 8, 'First boot did not create both slots and state.')
        for role, guid in GUIDS.items():
            parts = [part for part in expanded if part['type'].lower() == guid]
            require(len(parts) == 2, 'The expanded layout lacks a matching inactive slot.')
            first = next(part for part in parts if part['uuid'] == signed[role]['uuid'])
            require(first['start'] == signed[role]['start'] and
                    checksum(image, first['start']*512, signed[role]['size']*512) == expected[role],
                    'Slot expansion moved or changed signed filesystem, hash or signature bytes.')
        result = args.result or work/'result.json'
        require(result.is_absolute() and result.parent.resolve() == result.parent and not result.exists(),
                'Storage result must be a new canonical file.')
        result.write_text(json.dumps({'schema': 1, 'result': 'pass',
            'test': 'factory-slot-expansion', 'original_signed_sha256': expected,
            'initial_partitions': len(original), 'expanded_partitions': len(expanded)}, sort_keys=True)+'\n')
    print('Real factory expansion preserved all signed data, hash and signature bytes.')


if __name__ == '__main__':
    main()
