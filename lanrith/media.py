"""Read-back verification for factory partitions and their signed USB payload."""

import hashlib
import json
from pathlib import Path
import re
import subprocess
import tempfile

from . import release


def command(*arguments):
    return subprocess.run(arguments, check=True, capture_output=True, text=True, timeout=1800).stdout


def partitions(original, written):
    """Relocating GPT may change disk bounds, never an authenticated partition."""
    release.require(original.get('label') == written.get('label') == 'gpt' and
                    original.get('id') == written.get('id') and
                    original.get('sectorsize', 512) == written.get('sectorsize', 512) == 512,
                    'Factory media disk identity or sector format differs.')
    before, after = original['partitions'], written['partitions']
    fields = ('start', 'size', 'type', 'uuid', 'name', 'attrs', 'bootable')
    release.require(len(after) == len(before)+1 and all(
        all(a.get(field) == b.get(field) for field in fields) for a, b in zip(before, after)),
        'Factory media changed an authenticated partition.')
    payload = after[-1]
    release.require(payload.get('name') == 'lanrith-factory-media' and
                    str(payload.get('type', '')).lower() == '0fc63daf-8483-4772-8e79-3d69d8477de4' and
                    type(payload.get('start')) is int and type(payload.get('size')) is int and
                    payload['size'] > 0 and all(type(p.get('start')) is int and type(p.get('size')) is int and
                        p['start'] > 0 and p['size'] > 0 and p['start']+p['size'] <= payload['start'] for p in before),
                    'Factory payload partition overlaps or has an unexpected identity.')
    return before, payload


def digest_range(stream, start, size):
    stream.seek(start)
    digest = hashlib.sha256()
    while size:
        block = stream.read(min(1024*1024, size))
        release.require(block, 'Factory media is truncated.')
        digest.update(block)
        size -= len(block)
    return digest.digest()


def verify_payload_mount(mount, device):
    """Confirm read-back uses the selected ext4 partition with restricted options."""
    release.require(isinstance(device, str) and re.fullmatch(r'/dev/[A-Za-z0-9_.-]+', device),
                    'Factory payload device identity is unsafe.')
    value = json.loads(command('findmnt', '--uniq', '--json', '--target', str(mount),
                               '--output', 'SOURCE,FSTYPE,TARGET,OPTIONS'))
    release.require(isinstance(value, dict) and isinstance(value.get('filesystems'), list),
                    'Factory payload mount observation is malformed.')
    rows = value['filesystems']
    release.require(len(rows) == 1 and isinstance(rows[0], dict) and rows[0].get('target') == str(mount) and
                    rows[0].get('fstype') == 'ext4' and isinstance(rows[0].get('source'), str) and
                    rows[0]['source'].startswith('/dev/') and
                    Path(rows[0]['source']).resolve() == Path(device).resolve() and
                    isinstance(rows[0].get('options'), str) and
                    {'ro', 'nodev', 'nosuid', 'noexec'} <= set(rows[0]['options'].split(',')),
                    'Factory payload is not the selected restricted read-only mount.')


def verify(target, root, certificate, manifest):
    image = root/next(a['name'] for a in manifest['artifacts'] if a['role'] == 'disk')
    original = json.loads(command('sfdisk', '--json', str(image)))['partitiontable']
    written = json.loads(command('sfdisk', '--json', target))['partitiontable']
    before, payload = partitions(original, written)
    with image.open('rb') as expected, Path(target).open('rb', buffering=0) as actual:
        for part in before:
            start, size = part['start']*512, part['size']*512
            release.require(start+size <= image.stat().st_size and
                            digest_range(expected, start, size) == digest_range(actual, start, size),
                            'Factory partition read-back differs from the signed image.')
    devices = json.loads(command('lsblk', '--json', '--paths', '--output',
                                 'NAME,TYPE,PARTUUID', target))['blockdevices']
    pending, matches = list(devices), []
    while pending:
        device = pending.pop()
        pending.extend(device.get('children', []))
        if device.get('type') == 'part' and device.get('partuuid', '').lower() == payload.get('uuid', '').lower():
            matches.append(device['name'])
    release.require(len(matches) == 1, 'Cannot identify the written factory payload partition.')
    mount = Path(tempfile.mkdtemp(prefix='lanrith-media-readback.', dir='/run'))
    try:
        command('mount', '-o', 'ro,noload,nodev,nosuid,noexec', '--', matches[0], str(mount))
        release.require(mount.is_mount(), 'Factory payload did not mount.')
        verify_payload_mount(mount, matches[0])
        observed = release.verify(mount/'release', certificate, purpose='factory',
            image_id=manifest['image_id'], expected_version=manifest['platform_version'],
            expected_configuration=manifest['configuration_sha256'])
        release.require(observed == manifest, 'Written factory payload differs from the selected signed release.')
        verify_payload_mount(mount, matches[0])
    finally:
        # Refuse recursive cleanup if the read-only payload cannot be unmounted.
        if mount.is_mount():
            command('umount', '--', str(mount))
            release.require(not mount.is_mount(), 'Factory payload remains mounted.')
        mount.rmdir()


def verify_recovery(target, root, certificate, manifest):
    """Read back dedicated recovery media without creating an installer payload."""
    observed = release.verify(root, certificate, purpose='recovery', image_id=manifest['image_id'])
    release.require(observed == manifest, 'Recovery release changed before read-back.')
    image = root/next(item['name'] for item in manifest['artifacts'] if item['role'] == 'disk')
    original = json.loads(command('sfdisk', '--json', str(image)))['partitiontable']
    written = json.loads(command('sfdisk', '--json', target))['partitiontable']
    fields = ('start', 'size', 'type', 'uuid', 'name', 'attrs', 'bootable')
    release.require(original.get('label') == written.get('label') == 'gpt' and
        original.get('id') == written.get('id') and
        original.get('sectorsize', 512) == written.get('sectorsize', 512) == 512 and
        len(original.get('partitions', [])) == len(written.get('partitions', [])) == 4 and
        all(all(a.get(field) == b.get(field) for field in fields)
            for a, b in zip(original['partitions'], written['partitions'])),
        'Recovery media partition identities differ.')
    with image.open('rb') as expected, Path(target).open('rb', buffering=0) as actual:
        for part in original['partitions']:
            start, size = part['start']*512, part['size']*512
            release.require(start > 0 and size > 0 and start+size <= image.stat().st_size and
                            digest_range(expected, start, size) == digest_range(actual, start, size),
                            'Recovery media read-back differs from its signed image.')
