"""Pin optional measured-boot and recovery inputs before offline signing."""

import hashlib
import json
import os
from pathlib import Path
import stat

from . import early_failure, release, repair


PATHS = {'pcr_key', 'pcr_certificate', 'recovery_hash', 'fallback_release'}
FIELDS = PATHS | {'fallback_disk_by_id', 'fallback_esp_uuid'}


def load(path):
    value = json.loads(release.read(path, 16384), object_pairs_hook=release.unique)
    release.require(isinstance(value, dict) and set(value) <= FIELDS and
                    all(isinstance(item, str) and item for item in value.values()), 'Invalid boot build inputs.')
    for name in PATHS & value.keys():
        target = Path(value[name])
        release.require(target.is_absolute() and target.resolve() == target and not target.is_symlink(),
                        'Boot build input paths must be canonical.')
        value[name] = target
    release.require(('pcr_key' in value) == ('pcr_certificate' in value), 'Both PCR signing inputs are required.')
    fallback = {'fallback_release', 'fallback_disk_by_id', 'fallback_esp_uuid'}
    release.require(not (fallback & value.keys()) or fallback <= value.keys(), 'Fallback build inputs are incomplete.')
    return value


def digest_fields(value):
    return {name: value[name] for name in (
        'pcr_public_key_sha256', 'recovery_credential_sha256', 'fallback_binding') if name in value}


def record(value, *, certificate, image_id, sequence, tpm_required=False):
    result = {'image_id': image_id}
    if 'pcr_certificate' in value:
        result['pcr_certificate_sha256'] = release.file_record(value['pcr_certificate'])['sha256']
        result['pcr_public_key_sha256'] = hashlib.sha256(release.public_key(value['pcr_certificate'])).hexdigest()
    elif tpm_required:
        result['pcr_public_key_sha256'] = hashlib.sha256(release.public_key(certificate)).hexdigest()
    if 'recovery_hash' in value:
        result['recovery_credential_sha256'] = release.file_record(value['recovery_hash'])['sha256']
    if 'fallback_release' in value:
        observed = repair.signed_fallback_binding(value['fallback_release'], certificate, image_id=image_id)
        result['fallback_binding'] = {'disk_by_id': value['fallback_disk_by_id'],
            'esp_uuid': value['fallback_esp_uuid'], 'release': observed['fallback']}
        early_failure.validate_fallback_binding(result['fallback_binding'], image=image_id, current_sequence=sequence)
        result['fallback_manifest_sha256'] = release.file_record(value['fallback_release']/'release.json')['sha256']
    return result


def stage(value, expected, *, private, work, private_copy):
    """Copy only admitted bytes into the existing private signing transaction."""
    if 'pcr_key' in value:
        private_copy(value['pcr_key'], private/'pcr.key', 65536)
        data = release.read(value['pcr_certificate'], 65536)
        release.require(hashlib.sha256(data).hexdigest() == expected['pcr_certificate_sha256'],
                        'PCR authority changed after preflight.')
        (private/'pcr.crt').write_bytes(data)
        (private/'pcr.crt').chmod(0o600)
    if 'recovery_hash' in value:
        private_copy(value['recovery_hash'], private/'recovery.hash', 512)
        release.require(release.file_record(private/'recovery.hash')['sha256'] == expected['recovery_credential_sha256'],
                        'Recovery credential changed after preflight.')
    if 'fallback_release' in value:
        manifest = release.verify(value['fallback_release'], private/'boot.crt', purpose='update', image_id=expected['image_id'])
        release.require(release.file_record(value['fallback_release']/'release.json')['sha256'] == expected['fallback_manifest_sha256'],
                        'Fallback manifest changed after preflight.')
        destination = work/'fallback'
        destination.mkdir(mode=0o700)
        records = {name: release.file_record(value['fallback_release']/name)
                   for name in ('release.json', 'release.json.sig')}
        records.update({item['name']: item for item in manifest['artifacts']})
        for name, record in records.items():
            descriptor = os.open(value['fallback_release']/name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
            with os.fdopen(descriptor, 'rb') as source:
                before = os.fstat(source.fileno())
                release.require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and
                                before.st_size == record['size'], 'Fallback snapshot source is unsafe.')
                target = os.open(destination/name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
                digest = hashlib.sha256()
                with os.fdopen(target, 'wb') as output:
                    remaining = record['size']
                    while remaining:
                        chunk = source.read(min(4*1024*1024, remaining))
                        release.require(chunk, 'Fallback snapshot source is truncated.')
                        output.write(chunk)
                        digest.update(chunk)
                        remaining -= len(chunk)
                    release.require(not source.read(1) and digest.hexdigest() == record['sha256'],
                                    'Fallback changed during snapshot.')
                    output.flush()
                    os.fsync(output.fileno())
                after = os.fstat(source.fileno())
                release.require((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) ==
                                (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns),
                                'Fallback changed during snapshot.')
        release.require(release.verify(destination, private/'boot.crt', purpose='update', image_id=expected['image_id']) == manifest,
                        'Fallback payload changed during snapshot.')
