"""Read-only, explicitly bound inputs for offline recovery inspection.

This does not admit a recovery image, authorize a boot, or perform repair. The
caller must be an authenticated recovery console rooted in an independently
verified image and must ensure exclusive offline access to the target disk.
"""

from contextlib import contextmanager
import json
import os
from pathlib import Path
import re
import stat
import tempfile

from . import release, repair, update


RECOVERY_KEY = re.compile(rb'(?:[a-z]{8}-){7}[a-z]{8}\Z')


ESP_GUID = 'c12a7328-f81f-11d2-ba4b-00a0c93ec93b'
LINUX_GUID = '0fc63daf-8483-4772-8e79-3d69d8477de4'


def canonical_disk(path):
    """Resolve one bound whole-disk identity to a canonical block device."""
    release.require(isinstance(path, str) and re.fullmatch(r'/dev/disk/by-id/[A-Za-z0-9_.:+-]{1,180}', path) and
                    path.rsplit('/', 1)[-1] not in ('.', '..') and not re.search(r'-part[0-9]+$', path),
                    'Invalid offline disk binding.')
    disk = Path(path).resolve(strict=True)
    release.require(disk.parent == Path('/dev') and re.fullmatch(r'[A-Za-z0-9_.-]+', disk.name) and
                    stat.S_ISBLK(disk.stat().st_mode), 'Offline disk is not a canonical block device.')
    return str(disk)


def disk_snapshot(disk):
    """Reject inconsistent GPT/kernel geometry before choosing a partition."""
    layout, rows = repair.disk_layout(disk), update.geometry(disk)
    sizes = {node: (end-start)*layout['sector'] for start, end, node in layout['extents']}
    release.require(len(rows) == len(sizes) and all(row.get('device') in sizes and
                    row.get('size') == sizes[row['device']] for row in rows),
                    'Offline disk geometry differs from GPT.')
    return layout, rows


def stable_snapshot(disk, before, mounted_device):
    """Allow only our own expected mount while requiring unchanged topology."""
    layout, rows = disk_snapshot(disk)
    old_layout, old_rows = before
    old = {row['device']: row for row in old_rows}
    current = {row['device']: row for row in rows}
    release.require(layout == old_layout and len(old) == len(old_rows) and len(current) == len(rows) and
                    current.keys() == old.keys(),
                    'Offline disk changed during inspection.')
    for device, prior in old.items():
        after = current[device]
        release.require({key: value for key, value in after.items() if key != 'mounted'} ==
                        {key: value for key, value in prior.items() if key != 'mounted'} and
                        after.get('mounted') == (True if device == mounted_device else prior.get('mounted')),
                        'Offline disk changed during inspection.')


def partition(rows, disk, uuid, guid, *, label=None):
    release.require(isinstance(uuid, str) and re.fullmatch(update.UUID, uuid), 'Invalid offline partition binding.')
    matches = [row for row in rows if row.get('disk') == disk and row.get('uuid') == uuid and
               row.get('type') == guid and (label is None or row.get('label') == label)]
    release.require(len(matches) == 1 and sum(row.get('uuid') == uuid for row in rows) == 1 and
                    not matches[0].get('mounted') and isinstance(matches[0].get('device'), str) and
                    re.fullmatch(r'/dev/[A-Za-z0-9_.-]+', matches[0]['device']),
                    'Offline partition is absent, ambiguous or in use.')
    device = Path(matches[0]['device'])
    release.require(device.resolve() == device and stat.S_ISBLK(device.stat().st_mode),
                    'Offline partition is not a canonical block device.')
    return str(device)


def verify_mount(point, device, filesystem):
    observed = json.loads(update.command(['findmnt', '--uniq', '--json', '--target', str(point),
                                          '--output', 'SOURCE,FSTYPE,TARGET,OPTIONS']))
    release.require(isinstance(observed, dict) and isinstance(observed.get('filesystems'), list),
                    'Offline mount observation is malformed.')
    rows = observed['filesystems']
    release.require(len(rows) == 1 and isinstance(rows[0], dict) and rows[0].get('target') == str(point) and
                    rows[0].get('fstype') == filesystem and isinstance(rows[0].get('source'), str) and
                    rows[0]['source'].startswith('/dev/') and Path(rows[0]['source']).resolve() == Path(device) and
                    isinstance(rows[0].get('options'), str), 'Offline mount differs from its bound partition.')
    options = set(rows[0]['options'].split(','))
    release.require({'ro', 'nodev', 'nosuid', 'noexec'} <= options and
                    (filesystem != 'ext4' or bool({'noload', 'norecovery'} & options)),
                    'Offline mount is not read-only and restricted.')


@contextmanager
def mounted(device, filesystem):
    """Mount one partition read-only and never recursively delete a mountpoint."""
    release.require(filesystem in ('ext4', 'vfat'), 'Unsupported offline filesystem.')
    point = Path(tempfile.mkdtemp(prefix='lanrith-offline-input.', dir='/run'))
    try:
        options = 'ro,nodev,nosuid,noexec' + (',noload' if filesystem == 'ext4' else '')
        update.command(['mount', '-t', filesystem, '-o', options, '--', device, str(point)])
        release.require(point.is_mount(), 'Offline partition did not mount.')
        verify_mount(point, device, filesystem)
        yield point
        verify_mount(point, device, filesystem)
    finally:
        if point.is_mount():
            update.command(['umount', '--', str(point)])
            release.require(not point.is_mount(), 'Offline partition remains mounted.')
        point.rmdir()


def inspect(value, *, target_disk, recovery_disk, certificate):
    """Inspect one signed offline release and installed slot without writes."""
    release.require(os.geteuid() == 0 and Path('/etc/initrd-release').is_file(),
                    'Offline inputs require a recovery initrd.')
    inputs = value['offline_inputs']
    source_disk = canonical_disk(inputs['release_disk_by_id'])
    release.require(canonical_disk(value['disk_by_id']) == target_disk and target_disk != recovery_disk and
                    source_disk != target_disk, 'Offline input and target disk identities overlap.')
    source_before, source_rows = disk_snapshot(source_disk)
    target_before, target_rows = disk_snapshot(target_disk)
    release.require(all(not row.get('mounted') for row in target_rows),
                    'Offline target disk has mounted or held partitions.')
    source_device = partition(source_rows, source_disk, inputs['release_partition_uuid'], LINUX_GUID,
                              label='lanrith-recovery-input')
    esp_device = partition(target_rows, target_disk, inputs['target_esp_uuid'], ESP_GUID)
    with mounted(source_device, 'ext4') as source:
        with mounted(esp_device, 'vfat') as esp:
            observed = repair.inspect_slot(source/'release', certificate, image_id=value['image_id'],
                                           disk=target_disk, esp=esp)
            release.require(isinstance(observed, dict) and observed.get('authorized_to_boot') is False,
                            'Offline inspection did not return a read-only observation.')
            release.require(canonical_disk(inputs['release_disk_by_id']) == source_disk and
                            canonical_disk(value['disk_by_id']) == target_disk,
                            'Offline disk changed during inspection.')
            stable_snapshot(source_disk, (source_before, source_rows), source_device)
            stable_snapshot(target_disk, (target_before, target_rows), esp_device)
            return observed
