"""Restore offline encrypted state from an authenticated, pinned backup.

Production writes require an admitted recovery initrd, exact target bindings,
a working offline recovery key, a separately retained measurement receipt and
explicit operator confirmation. Legacy experimental gate hooks remain isolated."""
import json
from . import recovery_authority
import os
from pathlib import Path
import re

from . import (factory, recovery_backup_files, recovery_backup_preflight, recovery_backup_verity,
               recovery_inputs, recovery_restore_layout, recovery_restore_target,
               recovery_restore_transaction, release, update)


RESTORE_WORKFLOW_QUALIFIED = False
BACKUP_FRESHNESS_QUALIFIED = False


def restore(value, name, secret, *, image_id, confirm):
    """Restore after authenticating the immutable backup and independent receipt.

    The caller owns the secret and must erase it. The confirmation callback must
    display the backup ID and measurement and return both confirmed values.
    The receipt is an operator selection, not an automatic freshness proof.
    """
    release.require(RESTORE_WORKFLOW_QUALIFIED and BACKUP_FRESHNESS_QUALIFIED or recovery_authority.permits('restore', value),
                    'Offline restore workflow is not qualified.')
    release.require(isinstance(name, str) and re.fullmatch(r'backup-[0-9a-f]{32}', name) and
                    isinstance(image_id, str) and re.fullmatch(r'[a-z][a-z0-9-]{0,47}', image_id) and
                    callable(confirm), 'Invalid offline restore request.')
    value = recovery_backup_preflight.policy(value)
    observation = recovery_backup_preflight.inspect_restore(value)
    release.require(observation.get('authorized_to_restore') is False and
                    observation.get('authorized_to_write') is False,
                    'Unexpected restore preflight authority.')
    installed = json.loads(release.read(Path('/sysroot/usr/share/lanrith/installed.json'), 65536),
                           object_pairs_hook=release.unique)
    release.require(isinstance(installed, dict) and installed.get('image_id') == image_id,
                    'Offline restore image identity differs from the verified recovery root.')
    recovery_disk, _ = factory.verified_root('/sysroot')
    disk = recovery_inputs.canonical_disk(value['target_disk_by_id'])
    backup = recovery_inputs.canonical_disk(value['backup_disk_by_id'])
    release.require(len({recovery_disk, disk, backup}) == 3, 'Offline restore disks overlap.')
    target_snapshot = recovery_inputs.disk_snapshot(disk)
    backup_snapshot = recovery_inputs.disk_snapshot(backup)
    target_rows, backup_rows = target_snapshot[1], backup_snapshot[1]
    release.require(all(not row.get('mounted') for row in target_rows+backup_rows),
                    'Offline restore disks became busy.')
    state = recovery_inputs.partition(target_rows, disk, value['state_partuuid'], factory.VAR_GUID, label='var')
    media = recovery_inputs.partition(backup_rows, backup, value['backup_partuuid'],
                                      recovery_inputs.LINUX_GUID, label='lanrith-backup')
    other_partitions = [row.get('device') for row in target_rows if row.get('device') != state]
    release.require(all(isinstance(path, str) and re.fullmatch(r'/dev/[A-Za-z0-9_.-]+', path)
                        for path in other_partitions) and len(other_partitions) == len(set(other_partitions)),
                    'Offline restore partition topology is invalid.')
    with recovery_inputs.mounted(media, 'ext4') as point:
        def backup_stable():
            factory.secure_boot()
            release.require(factory.verified_root('/sysroot')[0] == recovery_disk and
                            recovery_inputs.canonical_disk(value['target_disk_by_id']) == disk and
                            recovery_inputs.canonical_disk(value['backup_disk_by_id']) == backup and
                            update.command(['blockdev', '--getro', backup]).strip() == '1' and
                            update.command(['blockdev', '--getro', media]).strip() == '1',
                            'Offline restore backup binding changed.')
            recovery_inputs.stable_snapshot(backup, backup_snapshot, media)
            recovery_inputs.verify_mount(point, media, 'ext4')
        backup_stable()
        with recovery_backup_files.open_authenticated(point/'lanrith-backups', name, secret,
                image_id=image_id, volume_uuid=value['state_uuid']) as (source, authenticated):
            release.require(authenticated.get('authorized_to_restore') is False and
                            isinstance(authenticated.get('measurement_sha256'), str) and
                            re.fullmatch(r'[0-9a-f]{64}', authenticated['measurement_sha256']) and
                            os.fstat(source).st_size == observation['state_size'],
                            'Authenticated backup differs from the target capacity.')
            measurement = bytes.fromhex(authenticated['measurement_sha256'])
            layout = recovery_restore_layout.inspect_pinned(source, expected_uuid=value['state_uuid'],
                                                             expected_measurement=measurement)
            verified = recovery_restore_layout.verify_recovery_key_pinned(source, secret,
                expected_uuid=value['state_uuid'], expected_measurement=measurement)
            release.require(verified.get('key_verified') is True and verified.get('authorized_to_restore') is False,
                            'Backup recovery-key verification failed.')
            confirmation = confirm(name, measurement.hex())
            if not BACKUP_FRESHNESS_QUALIFIED:
                release.require(confirmation == {'backup_id': name, 'measurement_sha256': measurement.hex()},
                                'Restore requires the separately retained backup receipt and confirmation.')
            else:
                release.require(confirmation == name or confirmation == {
                    'backup_id': name, 'measurement_sha256': measurement.hex()}, 'Offline restore was not confirmed.')
            backup_stable()
            release.require(recovery_inputs.disk_snapshot(disk) == target_snapshot and
                            update.command(['blockdev', '--getro', disk]).strip() == '1' and
                            update.command(['blockdev', '--getro', state]).strip() == '1',
                            'Offline restore target changed before claim.')
            try:
                # Linux reports a partition read-only while its parent is
                # read-only. Explicitly protect the other partitions first,
                # then make the parent and bound state partition writable.
                for partition in other_partitions:
                    update.command(['blockdev', '--setro', partition])
                update.command(['blockdev', '--setrw', disk])
                update.command(['blockdev', '--setrw', state])
                def other_partitions_readonly():
                    release.require(all(update.command(['blockdev', '--getro', part]).strip() == '1'
                                        for part in other_partitions),
                                    'A non-target partition is not read-only.')
                other_partitions_readonly()
                with recovery_restore_target.claim(value, expected_size=observation['state_size']) as (target, check):
                    def revalidate():
                        backup_stable()
                        check()
                        other_partitions_readonly()
                        release.require(recovery_backup_verity.measure(source) == measurement,
                                        'Authenticated backup changed during restore.')
                    result = recovery_restore_transaction.restore_pinned(source, target,
                        expected_measurement=measurement, metadata_size=layout['metadata_size'],
                        data_offset=layout['data_offset'], revalidate=revalidate)
                    release.require(result.get('authorized_to_boot') is False,
                                    'Restore copy unexpectedly authorized a boot.')
            finally:
                # Attempt to protect the parent even if protecting the state
                # partition fails. A failure remains visible to the operator.
                try:
                    update.command(['blockdev', '--setro', state])
                    release.require(update.command(['blockdev', '--getro', state]).strip() == '1',
                                    'Restore state did not return to read-only mode.')
                finally:
                    update.command(['blockdev', '--setro', disk])
                    release.require(update.command(['blockdev', '--getro', disk]).strip() == '1',
                                    'Restore disk did not return to read-only mode.')
        backup_stable()
    return {'schema': 1, 'scope': 'experimental-offline-restore', 'authorized_to_boot': False}
