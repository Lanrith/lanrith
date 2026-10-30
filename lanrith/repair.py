"""Read-only identification of an installed slot against an independent release.

This is an inspection primitive, not a repair image or permission to select a
boot entry. Its caller must supply trust from a separately authenticated
recovery environment, ensure exclusive offline access, and reverify immediately
before any separately authorized write.
"""

import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import stat

from . import release, update


def disk_layout(disk):
    """Reject overlapping or malformed GPT extents before inspecting a slot."""
    table = json.loads(update.command(['sfdisk', '--json', disk]))['partitiontable']
    rows, sector = table.get('partitions'), table.get('sectorsize')
    first, last = table.get('firstlba'), table.get('lastlba')
    release.require(table.get('label') == 'gpt' and table.get('device') == disk and
                    table.get('unit') == 'sectors' and sector in (512, 4096) and
                    type(first) is int and type(last) is int and 0 < first <= last and
                    isinstance(rows, list) and 1 <= len(rows) <= 128,
                    'Recovery GPT geometry is invalid.')
    capacity = update.command(['blockdev', '--getsize64', disk]).strip()
    release.require(re.fullmatch(r'[1-9][0-9]{0,19}', capacity) and
                    int(capacity) % sector == 0 and last < int(capacity)//sector,
                    'Recovery GPT exceeds the selected disk.')
    extents = []
    for row in rows:
        release.require(isinstance(row, dict) and isinstance(row.get('node'), str) and
                        type(row.get('start')) is int and type(row.get('size')) is int and
                        row['start'] >= first and row['size'] > 0 and
                        row['start']+row['size']-1 <= last, 'Recovery GPT extent is invalid.')
        extents.append((row['start'], row['start']+row['size'], row['node']))
    extents.sort()
    release.require(len({row[2] for row in extents}) == len(extents) and all(
        left[1] <= right[0] for left, right in zip(extents, extents[1:])),
        'Recovery GPT extents overlap or repeat.')
    return {'sector': sector, 'extents': extents}


def partition_digest(device, size):
    """Hash exactly the signed bytes without opening a writable disk handle."""
    release.require(isinstance(device, str) and re.fullmatch(r'/dev/[A-Za-z0-9_.-]+', device) and
                    type(size) is int and 0 < size <= 2**40, 'Unsafe recovery partition request.')
    descriptor = os.open(device, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    with os.fdopen(descriptor, 'rb', buffering=0) as stream:
        info = os.fstat(stream.fileno())
        release.require(stat.S_ISBLK(info.st_mode), 'Recovery partition is not a block device.')
        digest = hashlib.sha256()
        remaining = size
        while remaining:
            block = stream.read(min(remaining, 4*1024*1024))
            release.require(block, 'Recovery partition is truncated.')
            digest.update(block)
            remaining -= len(block)
        return digest.hexdigest()



def require_readonly_esp(esp):
    """Keep recovery inspection read-only even on older updater branches."""
    mount = json.loads(update.command(['findmnt', '--uniq', '--json', '--target', str(esp/'EFI'),
                                       '--output', 'TARGET,OPTIONS']))
    rows = mount.get('filesystems', [])
    release.require(len(rows) == 1 and isinstance(rows[0], dict) and rows[0].get('target') == str(esp) and
                    isinstance(rows[0].get('options'), str) and
                    {'ro', 'nodev', 'nosuid', 'noexec'} <= set(rows[0]['options'].split(',')),
                    'Recovery ESP is not read-only and restricted.')


def inspect_slot(root, certificate, *, image_id, disk, esp):
    """Check signed payload, GPT identities, UKI and partition bytes offline.

    A successful result is only a point-in-time observation. It does not prove
    TPM compatibility, persistent-data compatibility, Secure Boot trust, or
    authorization to boot or write the inspected slot.
    """
    release.require(isinstance(root, Path) and isinstance(certificate, Path) and
                    certificate.is_absolute() and certificate.resolve() == certificate and
                    certificate.parent != root and root not in certificate.parents,
                    'Recovery authority must be independent of the release.')
    release.require(isinstance(disk, str) and re.fullmatch(r'/dev/[A-Za-z0-9_.-]+', disk) and
                    Path(disk).resolve() == Path(disk), 'Unsafe recovery disk identity.')
    release.require(isinstance(esp, Path) and esp.is_absolute(), 'Unsafe recovery ESP identity.')
    manifest = release.verify(root, certificate, purpose='update', image_id=image_id)
    release.require(manifest['architecture'] == 'x86-64', 'Unsupported recovery architecture.')
    verified_esp = update.boot_esp({'esp': str(esp)}, disk=disk)
    require_readonly_esp(verified_esp)
    artifacts = {item['role']: item for item in manifest['artifacts']}
    sequence = manifest['deployment_sequence']
    base = f'{image_id}_{sequence}'
    release.require(artifacts['uki']['name'] == base+'.efi', 'Recovery UKI identity differs.')
    folder = verified_esp/'EFI/Linux'
    release.require(folder.is_dir() and not folder.is_symlink(), 'Recovery EFI directory is unsafe.')
    matches = [p for p in folder.iterdir() if re.fullmatch(
        re.escape(base)+r'(?:\+[0-9]+(?:-[0-9]+)?)?\.efi', p.name)]
    release.require(len(matches) == 1 and not matches[0].is_symlink(), 'Recovery boot entry is absent or ambiguous.')
    uki = release.file_record(matches[0])
    release.require(uki['size'] == artifacts['uki']['size'] and
                    hmac.compare_digest(uki['sha256'], artifacts['uki']['sha256']),
                    'Recovery boot entry differs from its signed release.')
    layout = disk_layout(disk)
    before = update.geometry(disk)
    extent_sizes = {node: (end-start)*layout['sector'] for start, end, node in layout['extents']}
    release.require(all(row.get('device') in extent_sizes and row.get('size') == extent_sizes[row['device']]
                        for row in before) and len(before) == len(extent_sizes),
                    'Recovery kernel partition geometry differs from GPT.')
    numbers, uuids = set(), set()
    for role in update.PARTITION_ROLES:
        artifact = artifacts[role]
        match = re.fullmatch(re.escape(base)+r'_('+update.UUID+r')\.'+re.escape(role)+r'\.raw', artifact['name'])
        release.require(match is not None, 'Recovery artifact identity differs.')
        uuid = match[1]
        label = f'l_{sequence}_{role.replace("-", "_")}'
        rows = [row for row in before if row.get('type') == update.GUIDS[role] and
                row.get('uuid') == uuid and row.get('label') == label]
        release.require(len(rows) == 1 and sum(row.get('uuid') == uuid for row in before) == 1,
                        'Recovery slot partition is absent or ambiguous.')
        row = rows[0]
        release.require(row.get('disk') == disk and not row.get('mounted') and
                        type(row.get('number')) is int and row['number'] not in numbers and
                        uuid not in uuids and type(row.get('size')) is int and row['size'] >= artifact['size'],
                        'Recovery slot partition is busy, undersized or overlaps another role.')
        numbers.add(row['number'])
        uuids.add(uuid)
        actual = partition_digest(row['device'], artifact['size'])
        release.require(hmac.compare_digest(actual, artifact['sha256']),
                        'Recovery slot bytes differ from their signed release.')
    release.require(disk_layout(disk) == layout and update.geometry(disk) == before and
                    update.boot_esp({'esp': str(esp)}, disk=disk) == verified_esp,
                    'Recovery disk identity changed during inspection.')
    require_readonly_esp(verified_esp)
    return {'schema': 1, 'scope': 'offline-slot-observation', 'image_id': image_id,
            'deployment_sequence': sequence, 'uki_name': matches[0].name,
            'manifest_sha256': hashlib.sha256(release.canonical(manifest)).hexdigest(),
            'authorized_to_boot': False}


def inspect_contracts(current_root, fallback_root, certificate, *, image_id, retained):
    """Compare separately signed releases and a caller-supplied state inventory.

    Retained state is an observation from the offline volume, not independently
    authenticated evidence. This does not inspect installed slot bytes or prove
    firmware, TPM, rollback authorization, or permission to boot. A caller must
    separately establish the provenance and completeness of that inventory.
    """
    from . import image_contract

    release.require(isinstance(current_root, Path) and isinstance(fallback_root, Path) and
                    isinstance(certificate, Path) and certificate.is_absolute() and
                    certificate.resolve() == certificate and current_root != fallback_root and
                    all(root not in certificate.parents and certificate.parent != root
                        for root in (current_root, fallback_root)),
                    'Recovery contract authority must be independent of both releases.')
    current = release.verify(current_root, certificate, purpose='update', image_id=image_id)
    fallback = release.verify(fallback_root, certificate, purpose='update', image_id=image_id)
    release.require(current['architecture'] == fallback['architecture'] and
                    fallback['deployment_sequence'] < current['deployment_sequence'] and
                    'image_contract' in current and 'image_contract' in fallback,
                    'Recovery release contracts are missing or not an older compatible pair.')
    current_contract, fallback_contract = current['image_contract'], fallback['image_contract']
    image_contract.compatible(current_contract, fallback_contract)
    image_contract.validate(retained)
    release.require(retained['machine_id'] == current_contract['machine_id'] and
                    retained['trust'] == current_contract['trust'] and
                    current_contract['state'].keys() <= retained['state'].keys(),
                    'Retained state inventory differs from the accepted image.')
    for name in retained['state'].keys() & fallback_contract['state'].keys():
        release.require(retained['state'][name]['writes'] in fallback_contract['state'][name]['reads'],
                        'Fallback cannot read retained state.')
    return {'schema': 1, 'scope': 'offline-contract-observation', 'image_id': image_id,
            'current_sequence': current['deployment_sequence'],
            'fallback_sequence': fallback['deployment_sequence'],
            'fallback_manifest_sha256': hashlib.sha256(release.canonical(fallback)).hexdigest(),
            'retained_state_authenticated': False, 'authorized_to_boot': False}



def signed_fallback_binding(root, certificate, *, image_id):
    """Derive payload identities from an independently authenticated release.

    This does not establish that the release is installed, is boot-compatible,
    is unrevoked or is authorized for rollback. Its caller must independently
    bind the physical disk and validate retained state and TPM policy.
    """
    release.require(isinstance(root, Path) and isinstance(certificate, Path) and certificate.is_absolute() and
                    certificate.resolve() == certificate and certificate.parent != root and
                    root not in certificate.parents, 'Recovery authority must be independent of the release.')
    manifest = release.verify(root, certificate, purpose='update', image_id=image_id)
    release.require(manifest['architecture'] == 'x86-64', 'Unsupported recovery architecture.')
    sequence = manifest['deployment_sequence']
    prefix = f'{image_id}_{sequence}'
    artifacts = {item['role']: item for item in manifest['artifacts']}
    uki = artifacts['uki']
    release.require(uki['name'] == prefix+'.efi', 'Recovery UKI identity differs.')
    partitions = {}
    uuids = set()
    for role in update.PARTITION_ROLES:
        item = artifacts[role]
        match = re.fullmatch(re.escape(prefix)+r'_('+update.UUID+r')\.'+re.escape(role)+r'\.raw', item['name'])
        release.require(match is not None and match[1] not in uuids, 'Recovery artifact identity differs.')
        uuids.add(match[1])
        partitions[role] = {'label': f'l_{sequence}_{role.replace("-", "_")}', 'uuid': match[1],
                            'size': item['size'], 'sha256': item['sha256']}
    return {'schema': 1, 'scope': 'signed-release-binding', 'image_id': image_id,
            'fallback': {'sequence': sequence, 'uki_name': uki['name'], 'uki_sha256': uki['sha256'],
                         'partitions': partitions}, 'authorized_to_boot': False}
