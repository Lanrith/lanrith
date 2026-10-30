"""Authenticate rollback compatibility for fresh steady-state installations."""

from . import early_unlock, factory, image_contract, release
from pathlib import Path


def validate(value):
    release.require(isinstance(value, dict) and set(value) == {
        'image_contract', 'fallback_contract', 'tpm_policy', 'state_directory'} and
        value['state_directory'] == '/var/lib/lanrith', 'Invalid steady rollback contract.')
    image_contract.compatible(value['image_contract'], value['fallback_contract'])
    if value['tpm_policy'] is not None:
        early_unlock.validate(value['tpm_policy'])
    expected = value['image_contract']['trust']['authorities']['pcr_policy']
    release.require(expected == (value['tpm_policy']['public_key_sha256'] if value['tpm_policy'] else None),
                    'Steady rollback PCR authority differs from its state contract.')
    return value


def compare(installed, previous, luks):
    """Compare only metadata read through the authenticated fallback verity root."""
    steady = validate(installed['steady_state'])
    binding = installed['fallback_binding']['release']
    release.require(isinstance(previous, dict) and previous.get('layout') == 'ab-verity-v1' and
        previous.get('image_id') == installed['image_id'] and
        previous.get('deployment_sequence') == binding['sequence'] and
        previous.get('uki_name') == binding['uki_name'] and
        image_contract.core(previous.get('image_contract')) == steady['fallback_contract'] and
        previous.get('machine_id') == steady['image_contract']['machine_id'] and
        previous.get('state_directory') == steady['state_directory'] and
        previous.get('tpm_policy') == steady['tpm_policy'] and 'tpm_transition' not in previous,
        'Fallback runtime or state policy differs from its signed contract.')
    policy = steady['tpm_policy']
    release.require(previous.get('boot', {}).get('tpm', 'required') == ('required' if policy else 'disabled'),
                    'Fallback TPM mode differs.')
    tokens = factory.enrollment_tokens(luks, tpm_required=policy is not None, policy=policy)
    release.require('systemd-recovery' in tokens, 'Fallback state lacks its recovery method.')
    if policy is None:
        release.require('systemd-tpm2' not in tokens, 'Unexpected TPM method on a manual-unlock image.')
    return {'schema': 1, 'scope': 'steady-fallback-state-observation', 'authorized_to_boot': False}


def observe(installed, disk, active, device):
    validate(installed['steady_state'])
    from . import tpm_migration
    tpm_migration.fallback(installed, disk, active, device)


def runtime_fallback(installed):
    """Recheck the accepted slot and retained state before a userspace fallback."""
    from . import early_failure, measured_boot, tpm_migration, update
    value = installed['image_contract']['recovery']
    release.require(isinstance(value, dict) and value['sequence'] == installed['deployment_sequence'] and
                    value['image_id'] == installed['image_id'], 'Running image has no bound fallback.')
    identity = {key: installed[key] for key in ('image_id', 'deployment_sequence', 'uki_name')}
    identity.update(fallback_binding=value['binding'], steady_state=installed['recovery_state'])
    early_failure.failure_identity(identity)
    factory.secure_boot()
    disk, state, luks = factory.state_metadata(installed)
    _, active = factory.verified_root('/')
    release.require(str(Path(value['binding']['disk_by_id']).resolve(strict=True)) == disk,
                    'Runtime fallback disk differs.')
    esp = update.boot_esp(installed, disk=disk)
    bound = value['binding']['release']
    uki = esp/'EFI/Linux'/bound['uki_name']
    update.require_default(uki)
    release.require(release.file_record(uki)['sha256'] == bound['uki_sha256'], 'Runtime fallback UKI differs.')
    if installed.get('tpm_policy'):
        measured_boot.verify(uki, installed['tpm_policy'])
    root_hash = tpm_migration.bound_uki_roothash(uki, bound['uki_sha256'])
    rows = update.geometry(disk)
    devices = {}
    for role, item in bound['partitions'].items():
        matches = [row for row in rows if row.get('disk') == disk and row.get('type') == update.GUIDS[role] and
            row.get('uuid') == item['uuid'] and row.get('label') == item['label'] and
            row.get('size', 0) >= item['size'] and row.get('number') not in active and not row.get('mounted')]
        release.require(len(matches) == 1, 'Runtime fallback slot is absent or busy.')
        release.require(tpm_migration.partition_digest(matches[0]['device'], item['size']) == item['sha256'],
                        'Runtime fallback partition differs.')
        devices[role] = matches[0]['device']
    tpm_migration.inspect_fallback_state(identity, luks, devices['root'], devices['verity'], root_hash)
    factory.secure_boot()
    release.require(factory.state_metadata(installed) == (disk, state, luks) and update.geometry(disk) == rows and
                    release.file_record(uki)['sha256'] == bound['uki_sha256'],
                    'Runtime fallback state changed during inspection.')
    update.require_default(uki)
    update.command(['systemctl', '--force', 'reboot'])
