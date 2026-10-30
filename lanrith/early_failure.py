"""Recover a failed initrd to its authenticated steady-state fallback.

Legacy migration contracts retain separate disabled qualification gates."""

import os
import hmac
from pathlib import Path
import re
import stat
import tempfile

from .release import read, require
from .update import command

# Legacy migration paths require separate qualification. Fresh-install
# recovery instead validates the signed steady-state contract on every use.
FALLBACK_AUTHENTICATION_QUALIFIED = False
ROLLBACK_COMPATIBILITY_QUALIFIED = False
# No-root fallback requires separate real-initrd and firmware qualification.
ROOT_ABSENT_FALLBACK_QUALIFIED = False


def failure_identity(value):
    """Validate the minimal identity embedded in the signed failure initrd."""
    fields = {'image_id', 'deployment_sequence', 'uki_name'}
    require(isinstance(value, dict) and fields <= set(value) and
            set(value) <= fields | {'tpm_transition', 'fallback_binding', 'rollback_state', 'steady_state'},
            'Invalid initrd failure identity.')
    image = value['image_id']
    sequence = value['deployment_sequence']
    require(isinstance(image, str) and re.fullmatch(r'[a-z][a-z0-9-]{0,47}', image) and
            type(sequence) is int and 1 <= sequence <= 999999999 and
            isinstance(value['uki_name'], str), 'Invalid initrd failure image.')
    safe = re.fullmatch(re.escape(image)+r'_[A-Za-z0-9._-]{1,160}\.efi', value['uki_name'])
    current = re.search(r'([1-9][0-9]{0,8})\.efi$', value['uki_name'])
    require(safe is not None and current is not None and int(current[1]) == sequence,
            'Invalid initrd failure image.')
    if 'tpm_transition' in value:
        transition = value['tpm_transition']
        require(isinstance(transition, dict) and set(transition) == {'fallback'} and
                isinstance(transition['fallback'], dict) and set(transition['fallback']) == {'uki_name'} and
                isinstance(transition['fallback']['uki_name'], str), 'Invalid initrd fallback binding.')
        fallback = transition['fallback']['uki_name']
        safe = re.fullmatch(re.escape(image)+r'_[A-Za-z0-9._-]{1,160}\.efi', fallback)
        previous = re.search(r'([1-9][0-9]{0,8})\.efi$', fallback) if safe else None
        require(previous is not None and int(previous[1]) < sequence, 'Invalid initrd fallback image.')
    if 'fallback_binding' in value:
        validate_fallback_binding(value['fallback_binding'], image=image, current_sequence=sequence)
        if 'tpm_transition' in value:
            require(value['tpm_transition']['fallback']['uki_name'] == value['fallback_binding']['release']['uki_name'],
                    'Migration and fallback bindings differ.')
    if 'rollback_state' in value:
        from . import early_unlock, tpm_migration
        rollback = value['rollback_state']
        require('fallback_binding' in value and isinstance(rollback, dict) and
                set(rollback) == {'state_directory', 'tpm_policy', 'tpm_transition'} and
                isinstance(rollback['state_directory'], str) and len(rollback['state_directory']) <= 256 and
                re.fullmatch(r'/var/(?:[A-Za-z0-9_-]+/)*[A-Za-z0-9_-]+', rollback['state_directory']),
                'Invalid fallback state binding.')
        early_unlock.validate(rollback['tpm_policy'])
        transition = tpm_migration.validate(rollback['tpm_transition'])
        require((transition['phase'] == 'prepare' and transition['fallback'] is None and
                 'tpm_transition' not in value) or
                (transition['phase'] in ('enroll', 'enforce') and
                 transition['fallback'] == value['fallback_binding']['release']),
                'Fallback state and release bindings differ.')
    if 'steady_state' in value:
        from . import steady_recovery
        require('fallback_binding' in value and 'rollback_state' not in value and 'tpm_transition' not in value,
                'Steady fallback cannot contain a migration contract.')
        steady_recovery.validate(value['steady_state'])
    return value



def validate_fallback_binding(value, *, image, current_sequence):
    """Validate a signed initrd binding without authorizing its use."""
    from . import update

    require(isinstance(value, dict) and set(value) == {'disk_by_id', 'esp_uuid', 'release'} and
            isinstance(value['disk_by_id'], str) and
            re.fullmatch(r'/dev/disk/by-id/[A-Za-z0-9_.:+-]{1,180}', value['disk_by_id']) and
            value['disk_by_id'].rsplit('/', 1)[-1] not in ('.', '..') and
            not re.search(r'-part[0-9]+$', value['disk_by_id']) and
            isinstance(value['esp_uuid'], str) and re.fullmatch(update.UUID, value['esp_uuid']),
            'Invalid fallback disk binding.')
    fallback = value['release']
    require(isinstance(fallback, dict) and set(fallback) == {'sequence', 'uki_name', 'uki_sha256', 'partitions'} and
            type(fallback['sequence']) is int and 1 <= fallback['sequence'] < current_sequence and
            isinstance(fallback['uki_name'], str) and
            re.fullmatch(re.escape(image)+r'_[A-Za-z0-9._-]{1,160}\.efi', fallback['uki_name']) and
            isinstance(fallback['uki_sha256'], str) and re.fullmatch(r'[0-9a-f]{64}', fallback['uki_sha256']) and
            isinstance(fallback['partitions'], dict) and set(fallback['partitions']) == set(update.GUIDS),
            'Invalid fallback release binding.')
    version = fallback['uki_name'][len(image)+1:-4]
    suffix = re.search(r'([1-9][0-9]{0,8})$', version)
    require(suffix is not None and int(suffix[1]) == fallback['sequence'], 'Invalid fallback release identity.')
    uuids = {value['esp_uuid']}
    families = set()
    for role, item in fallback['partitions'].items():
        require(isinstance(item, dict) and set(item) == {'label', 'uuid', 'size', 'sha256'} and
                item['label'] in (f'l_{fallback["sequence"]}_{role.replace("-", "_")}',
                                  f'r_{version}_{role.replace("-", "_")}') and
                isinstance(item['uuid'], str) and re.fullmatch(update.UUID, item['uuid']) and item['uuid'] not in uuids and
                type(item['size']) is int and 0 < item['size'] <= 2**40 and
                isinstance(item['sha256'], str) and re.fullmatch(r'[0-9a-f]{64}', item['sha256']),
                'Invalid fallback partition binding.')
        uuids.add(item['uuid'])
        families.add(item['label'][0])
    require(len(families) == 1 and (families != {'l'} or version == str(fallback['sequence'])),
            'Mixed or inconsistent fallback partition labels.')
    return value


def observe_boot_esp(disk, expected_uuid):
    """Observe that the boot loader's ESP belongs to the selected GPT disk.

    This is not an authenticity, compatibility or boot-authorization proof.
    A caller must supply the expected UUID from a separately authenticated
    binding and verify the fallback payload and policy before any selection.
    """
    from . import repair, update

    require(os.geteuid() == 0 and Path('/etc/initrd-release').is_file(),
            'Boot disk observation requires the initrd.')
    require(isinstance(disk, str) and re.fullmatch(r'/dev/[A-Za-z0-9_.-]+', disk) and
            Path(disk).resolve() == Path(disk) and stat.S_ISBLK(Path(disk).stat().st_mode) and
            isinstance(expected_uuid, str) and re.fullmatch(update.UUID, expected_uuid),
            'Invalid boot disk binding.')
    variable = Path('/sys/firmware/efi/efivars/LoaderDevicePartUUID-4a67b082-0a4c-41cf-b6c7-440b29bb8c4f')
    def loader_uuid():
        data = read(variable, 4096)
        require(len(data) >= 6 and (len(data)-4) % 2 == 0, 'Malformed boot ESP observation.')
        try:
            value = data[4:].decode('utf-16-le').rstrip('\0').lower()
        except UnicodeError as error:
            from .release import ReleaseError
            raise ReleaseError('Malformed boot ESP observation.') from error
        require(re.fullmatch(update.UUID, value), 'Malformed boot ESP observation.')
        return value
    observed = loader_uuid()
    require(observed == expected_uuid, 'Boot loader ESP differs from its binding.')
    layout = repair.disk_layout(disk)
    rows = update.geometry(disk)
    sizes = {node: (end-start)*layout['sector'] for start, end, node in layout['extents']}
    require(len(rows) == len(sizes) and all(row.get('device') in sizes and
            row.get('size') == sizes[row['device']] for row in rows), 'Boot disk geometry differs from GPT.')
    matches = [row for row in rows if row.get('type') == 'c12a7328-f81f-11d2-ba4b-00a0c93ec93b' and
               row.get('uuid') == expected_uuid and row.get('disk') == disk]
    require(len(matches) == 1 and sum(row.get('uuid') == expected_uuid for row in rows) == 1,
            'Boot ESP is absent or ambiguous on the bound disk.')
    require(loader_uuid() == observed and repair.disk_layout(disk) == layout and update.geometry(disk) == rows,
            'Boot disk changed during observation.')
    return {'schema': 1, 'scope': 'boot-esp-observation', 'esp_uuid': observed,
            'authorized_to_boot': False}


def observe_bound_fallback(installed, esp):
    """Inspect bound installed bytes in initrd; this never authorizes a boot.

    The binding must come from the authenticated initrd. The caller must mount
    the boot ESP read-only and restrict concurrent disk access. Compatibility,
    firmware trust, revocation and retained-state integrity are not established.
    """
    from . import repair, release, update

    failure_identity(installed)
    require('fallback_binding' in installed and isinstance(esp, Path) and esp.is_absolute(),
            'Bound fallback observation is unavailable.')
    binding = installed['fallback_binding']
    disk = str(Path(binding['disk_by_id']).resolve(strict=True))
    observe_boot_esp(disk, binding['esp_uuid'])
    verified_esp = update.boot_esp({'esp': str(esp)}, disk=disk)
    repair.require_readonly_esp(verified_esp)
    folder = verified_esp/'EFI/Linux'
    require(folder.is_dir() and not folder.is_symlink(), 'Fallback EFI directory is unsafe.')
    fallback = binding['release']
    stem = fallback['uki_name'][:-4]
    def boot_entries():
        return [p for p in folder.iterdir() if re.fullmatch(
            re.escape(stem)+r'(?:\+[0-9]+(?:-[0-9]+)?)?\.efi', p.name)]
    matches = boot_entries()
    require(len(matches) == 1 and not matches[0].is_symlink(), 'Fallback boot entry is absent or ambiguous.')
    uki = release.file_record(matches[0])
    require(hmac.compare_digest(uki['sha256'], fallback['uki_sha256']), 'Fallback boot entry differs from binding.')
    layout, rows = repair.disk_layout(disk), update.geometry(disk)
    sizes = {node: (end-start)*layout['sector'] for start, end, node in layout['extents']}
    require(len(rows) == len(sizes) and all(row.get('device') in sizes and
            row.get('size') == sizes[row['device']] for row in rows), 'Fallback disk geometry differs from GPT.')
    numbers = set()
    for role, expected in fallback['partitions'].items():
        matches = [row for row in rows if row.get('type') == update.GUIDS[role] and
                   row.get('uuid') == expected['uuid'] and row.get('label') == expected['label']]
        require(len(matches) == 1 and sum(row.get('uuid') == expected['uuid'] for row in rows) == 1,
                'Fallback partition is absent or ambiguous.')
        row = matches[0]
        require(row.get('disk') == disk and not row.get('mounted') and
                type(row.get('number')) is int and row['number'] not in numbers and
                type(row.get('size')) is int and row['size'] >= expected['size'],
                'Fallback partition is busy, undersized or overlaps another role.')
        numbers.add(row['number'])
        require(hmac.compare_digest(repair.partition_digest(row['device'], expected['size']), expected['sha256']),
                'Fallback partition differs from binding.')
    require(repair.disk_layout(disk) == layout and update.geometry(disk) == rows and
            update.boot_esp({'esp': str(esp)}, disk=disk) == verified_esp and
            Path(binding['disk_by_id']).resolve(strict=True) == Path(disk) and
            boot_entries() == [verified_esp/'EFI/Linux'/uki['name']] and
            release.file_record(verified_esp/'EFI/Linux'/uki['name']) == uki,
            'Fallback changed during observation.')
    repair.require_readonly_esp(verified_esp)
    observe_boot_esp(disk, binding['esp_uuid'])
    return {'schema': 1, 'scope': 'bound-fallback-observation',
            'sequence': fallback['sequence'], 'authorized_to_boot': False}


def inspect_bound_fallback(installed):
    """Mount the bound boot ESP read-only for observation, then unmount it.

    This initrd-only operation does not authorize fallback and does not change
    boot entries. An unmount failure is fatal and never recursively removes the
    mountpoint. The caller must separately establish state and TPM compatibility.
    """
    from . import update

    failure_identity(installed)
    require('fallback_binding' in installed, 'Bound fallback observation is unavailable.')
    binding = installed['fallback_binding']
    disk = str(Path(binding['disk_by_id']).resolve(strict=True))
    observe_boot_esp(disk, binding['esp_uuid'])
    rows = update.geometry(disk)
    matches = [row for row in rows if row.get('disk') == disk and row.get('uuid') == binding['esp_uuid'] and
               row.get('type') == 'c12a7328-f81f-11d2-ba4b-00a0c93ec93b']
    require(len(matches) == 1 and sum(row.get('uuid') == binding['esp_uuid'] for row in rows) == 1 and
            not matches[0].get('mounted') and isinstance(matches[0].get('device'), str) and
            re.fullmatch(r'/dev/[A-Za-z0-9_.-]+', matches[0]['device']),
            'Bound boot ESP is absent, ambiguous or already mounted.')
    point = Path(tempfile.mkdtemp(prefix='lanrith-fallback-esp.', dir='/run'))
    try:
        update.command(['mount', '-t', 'vfat', '-o', 'ro,nodev,nosuid,noexec',
                        '--', matches[0]['device'], str(point)])
        require(point.is_mount(), 'Bound boot ESP did not mount.')
        return observe_bound_fallback(installed, point)
    finally:
        if point.is_mount():
            update.command(['umount', '--', str(point)])
            require(not point.is_mount(), 'Bound boot ESP remains mounted.')
        point.rmdir()


def observe_failed_boot(installed):
    """Inspect a bound prior default without authorizing a reboot or rollback."""
    require(os.geteuid() == 0 and Path('/etc/initrd-release').is_file(),
            'Initrd failure handling is unavailable in normal userspace.')
    failure_identity(installed)
    require('fallback_binding' in installed, 'Failed boot has no authenticated fallback binding.')
    root = Path('/sys/firmware/efi/efivars')
    vendor = '-4a67b082-0a4c-41cf-b6c7-440b29bb8c4f'
    def entry(name):
        data = read(root/(name+vendor), 4096)
        require(len(data) >= 6 and (len(data)-4) % 2 == 0, 'Malformed boot selection observation.')
        return data[4:].decode('utf-16-le').rstrip('\0')
    selected, default = entry('LoaderEntrySelected'), entry('LoaderEntryDefault')
    stable = re.sub(r'\+[0-9]+(?:-[0-9]+)?(?=\.efi$)', '', selected)
    require(stable == installed['uki_name'] and default != stable and
            default == installed['fallback_binding']['release']['uki_name'],
            'Failed boot has no distinct accepted default.')
    bound = installed.get('tpm_transition', {}).get('fallback')
    require(bound is None or default == bound['uki_name'], 'Failed migration default differs from its bound bridge.')
    observation = inspect_bound_fallback(installed)
    require(isinstance(observation, dict) and observation.get('authorized_to_boot') is False and
            observation.get('sequence') == installed['fallback_binding']['release']['sequence'],
            'Failed boot fallback observation differs from its binding.')
    require((entry('LoaderEntrySelected'), entry('LoaderEntryDefault')) == (selected, default),
            'Boot selection changed during fallback observation.')
    return {'schema': 1, 'scope': 'failed-boot-observation',
            'sequence': observation['sequence'], 'authorized_to_boot': False}


def observe_rollback_compatibility(installed):
    """Check signed fallback and current state; never authorize a reboot."""
    from . import factory, tpm_migration, update
    failure_identity(installed)
    require('rollback_state' in installed or 'steady_state' in installed,
            'Failed boot lacks a bound rollback state contract.')
    factory.secure_boot()
    disk = str(Path(installed['fallback_binding']['disk_by_id']).resolve(strict=True))
    root = Path('/sysroot')

    def candidate_root():
        require(not root.is_symlink() and (root.is_dir() or not root.exists()),
                'Candidate root mountpoint is unsafe.')
        if root.is_mount():
            verified_disk, active = factory.verified_root('/sysroot')
            require(verified_disk == disk, 'Verified candidate root is not on the bound disk.')
            return ('verified', verified_disk, active)
        require(ROOT_ABSENT_FALLBACK_QUALIFIED or 'steady_state' in installed,
                'Missing candidate root fallback is not qualified.')
        # The initrd is authenticated independently of its missing root. Bind
        # its boot ESP and disk, and let fallback() reject any slot with mounts
        # or holders; an absent root supplies no active partition numbers.
        observe_boot_esp(disk, installed['fallback_binding']['esp_uuid'])
        return ('absent', disk, set())

    root_state = candidate_root()
    active = root_state[2]
    rows = update.geometry(disk)
    candidates = [row for row in rows if row.get('disk') == disk and row.get('type') == factory.VAR_GUID and
                  row.get('label') == 'var']
    require(len(candidates) == 1 and isinstance(candidates[0].get('device'), str) and
            re.fullmatch(r'/dev/[A-Za-z0-9_.-]+', candidates[0]['device']),
            'Bound encrypted state is absent or ambiguous.')
    device = candidates[0]['device']
    if 'steady_state' in installed:
        from . import steady_recovery
        steady_recovery.observe(installed, disk, active, device)
        factory.secure_boot()
        require(update.geometry(disk) == rows and candidate_root() == root_state and
                Path(installed['fallback_binding']['disk_by_id']).resolve(strict=True) == Path(disk),
                'Rollback state or verified-root geometry changed during inspection.')
        return {'schema': 1, 'scope': 'rollback-compatibility-observation', 'authorized_to_boot': False}
    contract = {**installed['rollback_state'], 'image_id': installed['image_id'],
                'deployment_sequence': installed['deployment_sequence'], 'uki_name': installed['uki_name']}
    require(command(['cryptsetup', 'luksUUID', device]).strip() == contract['tpm_transition']['luks_uuid'],
            'Rollback state identity differs from its binding.')
    if contract['tpm_transition']['phase'] == 'prepare':
        observed = tpm_migration.legacy_fallback(contract, installed['fallback_binding'], disk, active, device)
        require(isinstance(observed, dict) and observed.get('scope') == 'legacy-fallback-observation' and
                observed.get('authorized_to_boot') is False, 'Legacy fallback observation differs.')
    else:
        tpm_migration.fallback(contract, disk, active, device)
    factory.secure_boot()
    require(update.geometry(disk) == rows and candidate_root() == root_state and
            Path(installed['fallback_binding']['disk_by_id']).resolve(strict=True) == Path(disk),
            'Rollback state or verified-root geometry changed during inspection.')
    return {'schema': 1, 'scope': 'rollback-compatibility-observation', 'authorized_to_boot': False}


def failed_boot(installed):
    """A qualified failed candidate returns to the bound accepted default."""
    require(os.geteuid() == 0 and Path('/etc/initrd-release').is_file(),
            'Initrd failure handling is unavailable in normal userspace.')
    require(FALLBACK_AUTHENTICATION_QUALIFIED or 'steady_state' in installed,
            'Automatic fallback is blocked pending authenticated fallback qualification.')
    require(ROLLBACK_COMPATIBILITY_QUALIFIED or 'steady_state' in installed,
            'Automatic fallback is blocked pending state and TPM rollback qualification.')
    observe_failed_boot(installed)
    observation = observe_rollback_compatibility(installed)
    require(isinstance(observation, dict) and observation.get('authorized_to_boot') is False,
            'Rollback compatibility observation differs.')
    observe_failed_boot(installed)
    # The updater leaves the old default in place and selects a candidate for
    # one boot. Reboot consumes no new authority and never changes EFI entries.
    command(['systemctl', '--force', 'reboot'])
